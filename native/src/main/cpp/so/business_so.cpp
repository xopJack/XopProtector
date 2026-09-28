#include "so/business_so.h"
#include "common/elf_util.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "crypto/aes.h"
#include "crypto/rc4.h"
#include "crypto/sha256.h"

#include "bytehook.h"
#include "dobby.h"
#include "json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <limits.h>
#include <link.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(__ANDROID__)
#include <android/api-level.h>
#include <android/dlext.h>
#include <sys/sendfile.h>
#include <sys/system_properties.h>
#endif

#ifndef __printflike
#if defined(__GNUC__)
#define __printflike(f, a) __attribute__((format(printf, f, a)))
#else
#define __printflike(f, a)
#endif
#endif

namespace protector::so {

struct SoKey {
    std::string name;
    uint8_t key[16]{};
    bool decrypted = false;
    bool in_flight = false;
};

static std::mutex g_mu;
/**
 * Basename whose in-memory executable image is already plaintext.
 * Set after a successful extract decrypt, or when this process proved the
 * mapped extract inode is L1 plaintext. Never set on a failed or early attempt.
 */
static std::unordered_set<std::string> g_extract_inode_decrypted;
/** In-memory .text write failed after the image was mapped. Do not run constructors. */
static std::unordered_set<std::string> g_text_write_failed;
/**
 * Write succeeded (bytes are plaintext) but prot restore failed.
 * A later decrypt must not RC4 again. Kept separate from
 * g_extract_inode_decrypted so constructor skipping still sees the failure.
 */
static std::unordered_set<std::string> g_text_left_plaintext;
/** -1 unknown, 0 denied, 1 file-backed RX mapping can be made writable. */
static std::atomic<int> g_file_execmod{-1};
static thread_local int g_in_execmod_probe = 0;
/** L1-published extract file identity. Match st_dev+st_ino, not basename alone. */
struct PlainInode {
    uint64_t dev = 0;
    uint64_t ino = 0;
};
static std::mutex g_plain_inode_mu;
static std::unordered_map<std::string, PlainInode> g_plain_inode;
static std::condition_variable g_cv;
static std::vector<SoKey> g_keys;
/** Basenames observed via dlopen before sokeys were available. */
static std::vector<std::string> g_pending;
static std::atomic_bool g_hooks_installed{false};
/** True if at least one of dlopen / android_dlopen_ext / __loader_* hooked. */
/** >0 while this thread is inside a linker mmap / call_constructors / dlopen hook. */
static thread_local int g_in_linker_hook = 0;

static std::atomic_bool g_dlopen_hooks_ok{false};
/** Linker mmap and/or soinfo::call_constructors hooked — extract-inode decrypt is safe. */
static std::atomic_bool g_extract_inode_hooks_ok{false};
/** Linker/libc open/openat rewrite so DT_NEEDED cannot map extract ciphertext. */
static std::atomic_bool g_linker_open_hooks_ok{false};
/** Process-local: full keyed materialize already completed successfully. */
static std::atomic_bool g_full_materialize_done{false};
/** Dropped leftover so_plain_ready / keyed mirrors from a previous process. */
static std::atomic_bool g_dropped_stale_mirrors{false};

static bool dlopen_hooks_ok() {
    return g_dlopen_hooks_ok.load(std::memory_order_acquire);
}

static bool extract_inode_hooks_ok() {
    return g_extract_inode_hooks_ok.load(std::memory_order_acquire);
}

static bool linker_open_hooks_ok() {
    return g_linker_open_hooks_ok.load(std::memory_order_acquire);
}

static bool needs_extract_inode(const std::string& base);
static bool defer_eager_disk(const std::string& base);
static void hide_extract_inode_helpers();
static void install_linker_extract_hooks();
static void decrypt_extract_inode_mapped();
static void pin_plain_needed_for_extract(const std::string& elf_so,
                                        const void* extinfo = nullptr);
static std::string keyed_warm_path(const std::string& out_dir, const std::string& name);

/** True after L1/L2 mapped plaintext for this keyed basename (skip in-memory RC4). */
static bool keyed_mapped_plain(const std::string& base);
static void mark_keyed_mapped_plain(const std::string& base);

/** Real /proc/self/maps via syscall (bypasses maps spoof hooks). */
static FILE* fopen_maps_raw();

/** Full keyed materialize into so_plain (eager path). Used by eager mode and as
 *  lazy fallback when dlopen hooks are unavailable (e.g. bytehook INITERR_SIG). */
static void materialize_all_keyed_sos();
static std::atomic_bool g_preload_done{false};
static std::atomic_bool g_fill_started{false};
static std::string g_protector_dir;
static std::string g_native_lib_dir;
/** Default Eager until config.json is applied (Phase 0 wiring). */
static std::atomic<int> g_so_decrypt_mode{static_cast<int>(SoDecryptMode::Eager)};

static constexpr const char* kSoPlainReady = "so_plain_ready";
/** Writable extract-equivalent tree (keyed hardlinks + dep/dir symlinks). */
static constexpr const char* kLibMirror = "lib_mirror";
/** Warm plaintext for extract-inode SOs — hidden from ClassLoader (not a load name). */
static constexpr const char* kOverlaySubdir = ".xop_plain";
static constexpr const char* kSoWarmDir = "so_warm";
static constexpr const char* kSoWarmReady = "so_warm_ready";
static constexpr uint8_t kPsw1Magic[4] = {'P', 'S', 'W', '1'};
/** Skip encrypting / hydrating blobs larger than this (avoid peak RAM). */
static constexpr off_t kWarmMaxPlainBytes = 64 * 1024 * 1024;

static uint8_t g_so_warm_key[16]{};
static std::atomic_bool g_so_warm_key_set{false};

void set_so_warm_key(const uint8_t key[16]) {
    if (key == nullptr) {
        g_so_warm_key_set.store(false, std::memory_order_release);
        memset(g_so_warm_key, 0, sizeof(g_so_warm_key));
        return;
    }
    memcpy(g_so_warm_key, key, 16);
    g_so_warm_key_set.store(true, std::memory_order_release);
}

static bool so_warm_key_ok() {
    return g_so_warm_key_set.load(std::memory_order_acquire);
}

void set_runtime_dirs(const std::string& protector_dir, const std::string& native_lib_dir) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!protector_dir.empty()) {
        g_protector_dir = protector_dir;
    }
    if (!native_lib_dir.empty()) {
        g_native_lib_dir = native_lib_dir;
    }
}

void set_so_decrypt_mode(SoDecryptMode mode) {
    g_so_decrypt_mode.store(static_cast<int>(mode), std::memory_order_relaxed);
    PLOGI("business so: so_decrypt_mode=%s",
          mode == SoDecryptMode::Lazy ? "lazy" : "eager");
}

SoDecryptMode so_decrypt_mode() {
    int v = g_so_decrypt_mode.load(std::memory_order_relaxed);
    return v == static_cast<int>(SoDecryptMode::Lazy) ? SoDecryptMode::Lazy
                                                      : SoDecryptMode::Eager;
}

/** Config/property gate for [XOP-SO] diagnostics (Release-safe when off). */
static std::atomic_bool g_so_diag_cfg{false};

void set_so_diag(bool on) {
    g_so_diag_cfg.store(on, std::memory_order_relaxed);
    if (on) {
        __android_log_print(ANDROID_LOG_INFO, PROTECTOR_LOG_TAG,
                            "[XOP-SO] so_diag enabled (config)");
    }
}

static bool prop_so_diag() {
#if defined(__ANDROID__)
    char v[PROP_VALUE_MAX]{};
    if (__system_property_get("debug.protector.so_diag", v) > 0) {
        return v[0] == '1' || v[0] == 't' || v[0] == 'T'
                || v[0] == 'y' || v[0] == 'Y';
    }
#endif
    return false;
}

bool so_diag_enabled() {
    if (g_so_diag_cfg.load(std::memory_order_relaxed)) return true;
    if (prop_so_diag()) return true;
#ifndef NDEBUG
    return true;
#else
    return false;
#endif
}

static void xop_so_log(int prio, const char* fmt, ...) __printflike(2, 3);
static void xop_so_log(int prio, const char* fmt, ...) {
    if (!so_diag_enabled()) return;
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(prio, PROTECTOR_LOG_TAG, fmt, ap);
    va_end(ap);
}

/**
 * Per-keyed-SO load/materialize status for A/B. Updated along the decrypt path;
 * illegal combos refuse further RC4/dlopen for that basename.
 */
struct SoDiagRec {
    const char* layer = "NONE";       // APK_EXTRACT / L1 / L2 / L3 / WARM_READY / MATERIALIZE
    const char* state = "UNKNOWN";    // ENCRYPTED / PLAINTEXT
    bool decrypt_applied = false;
    bool ready_hit = false;
    bool materialize_ok = false;
    std::string output;
};

static std::mutex g_diag_mu;
static std::unordered_map<std::string, SoDiagRec> g_diag;

static void diag_emit(const std::string& name, const SoDiagRec& r) {
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] name=%s source_layer=%s source_state=%s decrypt_applied=%d "
               "ready_hit=%d materialize_ok=%d output=%s",
               name.c_str(),
               r.layer != nullptr ? r.layer : "NONE",
               r.state != nullptr ? r.state : "UNKNOWN",
               r.decrypt_applied ? 1 : 0,
               r.ready_hit ? 1 : 0,
               r.materialize_ok ? 1 : 0,
               r.output.empty() ? "-" : r.output.c_str());
}

static void diag_set(const std::string& name,
                     const char* layer,
                     const char* state,
                     bool decrypt_applied,
                     bool ready_hit,
                     bool materialize_ok,
                     const std::string& output) {
    if (name.empty()) return;
    SoDiagRec snap;
    {
        std::lock_guard<std::mutex> lock(g_diag_mu);
        SoDiagRec& r = g_diag[name];
        if (layer != nullptr) r.layer = layer;
        if (state != nullptr) r.state = state;
        r.decrypt_applied = decrypt_applied;
        r.ready_hit = ready_hit;
        r.materialize_ok = materialize_ok;
        if (!output.empty()) r.output = output;
        snap = r;
    }
    diag_emit(name, snap);
}

/** True if this basename was already treated as plaintext (warm / prior RC4). */
static bool diag_is_plaintext(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_diag_mu);
    auto it = g_diag.find(name);
    if (it == g_diag.end()) return false;
    return it->second.state != nullptr && strcmp(it->second.state, "PLAINTEXT") == 0;
}

/** Packer's isPathSensitive (size + GLES/engine markers), not size-only. */
static constexpr uint64_t kExtractInodeMinText = 4ull * 1024 * 1024;
static constexpr off_t kExtractInodeMinFile = 16 * 1024 * 1024;

/** Packer so_text_diag expected plaintext .text meta (per ABI). */
struct TextDiagExpect {
    std::string abi; // e.g. arm64-v8a; may be empty on older diag
    uint64_t text_offset = 0;
    uint64_t text_size = 0;
    uint64_t text_sh_addr = 0;
    std::string text_sha256; // lowercase hex, 64 chars
    uint64_t file_size = 0;
    bool l2e = false;
};

static std::mutex g_textdiag_mu;
/** Basename → all ABI entries (never overwrite siblings). */
static std::unordered_map<std::string, std::vector<TextDiagExpect>> g_textdiag;
static std::atomic_bool g_textdiag_loaded{false};
/** True when so_text_diag v2 (or any entry has {@code l2e}) — runtime trusts the bit. */
static std::atomic_bool g_textdiag_l2e_mode{false};

static std::string to_hex_lower(const uint8_t* dig, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = kHex[(dig[i] >> 4) & 0xf];
        out[i * 2 + 1] = kHex[dig[i] & 0xf];
    }
    return out;
}

static bool hex_eq_ci(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'F') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'F') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

/** ABI folder from nativeLibraryDir (.../lib/arm64-v8a). */
static std::string device_abi() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_native_lib_dir.empty()) return {};
    auto slash = g_native_lib_dir.find_last_of("/\\");
    if (slash == std::string::npos) return g_native_lib_dir;
    return g_native_lib_dir.substr(slash + 1);
}

void load_so_text_diag(const std::string& protector_dir) {
    if (protector_dir.empty()) return;
    std::string path = protector_dir + "/so_text_diag.json";
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        g_textdiag_loaded.store(true, std::memory_order_release);
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] so_text_diag absent (ok for older packs) path=%s",
                   path.c_str());
        return;
    }
    std::string text((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());
    ifs.close();
    std::unordered_map<std::string, std::vector<TextDiagExpect>> next;
    size_t entry_n = 0;
    int diag_ver = 1;
    bool any_l2e_field = false;
    try {
        auto j = nlohmann::json::parse(text);
        if (j.contains("version") && j["version"].is_number()) {
            diag_ver = j["version"].get<int>();
        }
        if (j.contains("entries") && j["entries"].is_array()) {
            for (const auto& e : j["entries"]) {
                if (!e.is_object()) continue;
                std::string name;
                std::string abi;
                if (e.contains("name") && e["name"].is_string()) {
                    name = e["name"].get<std::string>();
                }
                if (e.contains("abi") && e["abi"].is_string()) {
                    abi = e["abi"].get<std::string>();
                }
                if (e.contains("path") && e["path"].is_string()) {
                    std::string p = e["path"].get<std::string>();
                    auto slash = p.find_last_of('/');
                    if (name.empty()) {
                        name = slash == std::string::npos ? p : p.substr(slash + 1);
                    }
                    if (abi.empty() && slash != std::string::npos && slash > 0) {
                        auto slash2 = p.find_last_of('/', slash - 1);
                        if (slash2 == std::string::npos) {
                            abi = p.substr(0, slash);
                        } else {
                            abi = p.substr(slash2 + 1, slash - slash2 - 1);
                        }
                    }
                }
                if (name.empty()) continue;
                TextDiagExpect exp;
                exp.abi = abi;
                if (e.contains("text_offset") && e["text_offset"].is_number()) {
                    exp.text_offset = e["text_offset"].get<uint64_t>();
                }
                if (e.contains("text_size") && e["text_size"].is_number()) {
                    exp.text_size = e["text_size"].get<uint64_t>();
                }
                if (e.contains("text_sh_addr") && e["text_sh_addr"].is_number()) {
                    exp.text_sh_addr = e["text_sh_addr"].get<uint64_t>();
                }
                if (e.contains("text_sha256") && e["text_sha256"].is_string()) {
                    exp.text_sha256 = e["text_sha256"].get<std::string>();
                }
                if (e.contains("file_size") && e["file_size"].is_number()) {
                    exp.file_size = e["file_size"].get<uint64_t>();
                }
                if (e.contains("l2e")) {
                    any_l2e_field = true;
                    if (e["l2e"].is_boolean()) {
                        exp.l2e = e["l2e"].get<bool>();
                    }
                }
                if (exp.text_size == 0 || exp.text_sha256.size() != 64) continue;
                next[name].push_back(std::move(exp));
                entry_n++;
            }
        }
    } catch (...) {
        PLOGW("business so: so_text_diag.json parse failed");
        g_textdiag_loaded.store(true, std::memory_order_release);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_textdiag_mu);
        g_textdiag.swap(next);
    }
    g_textdiag_loaded.store(true, std::memory_order_release);
    const bool l2e_mode = diag_ver >= 2 || any_l2e_field;
    g_textdiag_l2e_mode.store(l2e_mode, std::memory_order_release);
    size_t basename_n = 0;
    size_t l2e_n = 0;
    {
        std::lock_guard<std::mutex> lock(g_textdiag_mu);
        basename_n = g_textdiag.size();
        for (const auto& kv : g_textdiag) {
            for (const auto& row : kv.second) {
                if (row.l2e) {
                    l2e_n++;
                    break;
                }
            }
        }
    }
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] so_text_diag loaded entries=%zu basenames=%zu version=%d "
               "l2e_mode=%d l2e_basenames=%zu",
               entry_n, basename_n, diag_ver, l2e_mode ? 1 : 0, l2e_n);
    PLOGI("business so: so_text_diag loaded entries=%zu basenames=%zu version=%d "
          "l2e_mode=%d l2e_basenames=%zu",
          entry_n, basename_n, diag_ver, l2e_mode ? 1 : 0, l2e_n);
}

/**
 * Pick the expect row for this basename.
 * Priority: (1) on-disk .text meta match (2) device ABI (3) single candidate.
 */
static bool pick_textdiag_expect(const std::string& base,
                                 const Elf_Shdr* disk,
                                 TextDiagExpect* out) {
    if (out == nullptr || base.empty()) return false;
    const std::string abi = device_abi();
    std::lock_guard<std::mutex> lock(g_textdiag_mu);
    auto it = g_textdiag.find(base);
    if (it == g_textdiag.end() || it->second.empty()) return false;
    const auto& cands = it->second;

    if (disk != nullptr && disk->sh_size > 0) {
        for (const auto& c : cands) {
            if (static_cast<uint64_t>(disk->sh_offset) == c.text_offset
                && static_cast<uint64_t>(disk->sh_size) == c.text_size
                && static_cast<uint64_t>(disk->sh_addr) == c.text_sh_addr) {
                *out = c;
                return true;
            }
        }
    }

    if (!abi.empty()) {
        for (const auto& c : cands) {
            if (c.abi == abi) {
                *out = c;
                return true;
            }
        }
    }

    if (cands.size() == 1) {
        *out = cands[0];
        return true;
    }
    return false;
}

static void unlink_so_plain_if(const std::string& path) {
    if (path.find("/so_plain/") != std::string::npos) {
        unlink(path.c_str());
    }
}

static off_t file_size_path(const std::string& path);
static bool file_exists_path(const std::string& path);

/**
 * Verify on-disk ELF .text against packer so_text_diag.
 * @param check_hash when false only compares offset/size/sh_addr.
 * @param quiet probe mode — mismatch means "not plaintext (yet)" which is a
 *        normal state for the packaged extract before L1 publish (e.g. the
 *        extract dir is not app-writable and L2 is the strategy). Log INFO
 *        instead of FATAL; caller decides the fallback.
 * @return true if no expect, or meta(+hash) match.
 */
static bool verify_text_against_diag(const std::string& path,
                                     const std::string& base,
                                     bool check_hash,
                                     bool quiet = false) {
    auto fail_log = [&](const char* why) {
        if (quiet) {
            xop_so_log(ANDROID_LOG_INFO,
                       "[XOP-SO] name=%s not plaintext (%s) — L1 skip, "
                       "cipher extract is normal pre-publish path=%s",
                       base.c_str(), why, path.c_str());
        } else {
            xop_so_log(ANDROID_LOG_ERROR,
                       "[XOP-SO] FATAL name=%s %s path=%s",
                       base.c_str(), why, path.c_str());
        }
    };

    Elf_Shdr shdr{};
    get_elf_section(&shdr, path.c_str(), ".text");
    if (shdr.sh_size == 0 || shdr.sh_offset == 0) {
        // No .text — only fail if we have an expect for this name.
        TextDiagExpect unused;
        if (!pick_textdiag_expect(base, nullptr, &unused)) return true;
        fail_log("text meta: no .text on disk");
        return false;
    }

    TextDiagExpect exp;
    if (!pick_textdiag_expect(base, &shdr, &exp)) {
        // Basename present for other ABIs only, or ambiguous with no meta match.
        bool name_known = false;
        {
            std::lock_guard<std::mutex> lock(g_textdiag_mu);
            name_known = g_textdiag.find(base) != g_textdiag.end();
        }
        if (!name_known) return true;
        xop_so_log(quiet ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                   "[XOP-SO]%s name=%s text diag ABI ambiguous "
                   "(no meta/abi match) disk=0x%llx/0x%llx/0x%llx path=%s",
                   quiet ? "" : " FATAL",
                   base.c_str(),
                   static_cast<unsigned long long>(shdr.sh_offset),
                   static_cast<unsigned long long>(shdr.sh_size),
                   static_cast<unsigned long long>(shdr.sh_addr),
                   path.c_str());
        if (!quiet) {
            PLOGE("business so: .text diag ABI ambiguous %s", base.c_str());
        }
        return false;
    }

    if (static_cast<uint64_t>(shdr.sh_offset) != exp.text_offset
        || static_cast<uint64_t>(shdr.sh_size) != exp.text_size
        || static_cast<uint64_t>(shdr.sh_addr) != exp.text_sh_addr) {
        xop_so_log(quiet ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                   "[XOP-SO]%s name=%s abi=%s text meta MISMATCH "
                   "disk=0x%llx/0x%llx/0x%llx expect=0x%llx/0x%llx/0x%llx path=%s",
                   quiet ? "" : " FATAL",
                   base.c_str(),
                   exp.abi.empty() ? "?" : exp.abi.c_str(),
                   static_cast<unsigned long long>(shdr.sh_offset),
                   static_cast<unsigned long long>(shdr.sh_size),
                   static_cast<unsigned long long>(shdr.sh_addr),
                   static_cast<unsigned long long>(exp.text_offset),
                   static_cast<unsigned long long>(exp.text_size),
                   static_cast<unsigned long long>(exp.text_sh_addr),
                   path.c_str());
        if (!quiet) {
            PLOGE("business so: .text meta mismatch %s", base.c_str());
        }
        return false;
    }
    if (!check_hash) {
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] name=%s abi=%s text meta OK offset=0x%llx size=0x%llx",
                   base.c_str(),
                   exp.abi.empty() ? "?" : exp.abi.c_str(),
                   static_cast<unsigned long long>(shdr.sh_offset),
                   static_cast<unsigned long long>(shdr.sh_size));
        return true;
    }
    if (exp.text_size > static_cast<uint64_t>(SIZE_MAX)) return false;
    std::vector<uint8_t> buf(static_cast<size_t>(exp.text_size));
    FILE* fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) return false;
    if (fseek(fp, static_cast<long>(exp.text_offset), SEEK_SET) != 0
        || fread(buf.data(), 1, buf.size(), fp) != buf.size()) {
        fclose(fp);
        fail_log("text hash read fail");
        return false;
    }
    fclose(fp);
    uint8_t dig[32];
    protector::crypto::sha256(buf.data(), buf.size(), dig);
    memset(buf.data(), 0, buf.size());
    std::string got = to_hex_lower(dig, 32);
    if (!hex_eq_ci(got, exp.text_sha256)) {
        xop_so_log(quiet ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR,
                   "[XOP-SO]%s name=%s abi=%s text_sha256 MISMATCH "
                   "got=%s expect=%s path=%s",
                   quiet ? "" : " FATAL",
                   base.c_str(),
                   exp.abi.empty() ? "?" : exp.abi.c_str(),
                   got.c_str(), exp.text_sha256.c_str(), path.c_str());
        if (!quiet) {
            PLOGE("business so: .text sha256 mismatch %s", base.c_str());
        }
        return false;
    }
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] name=%s abi=%s text_sha256 OK size=0x%llx",
               base.c_str(),
               exp.abi.empty() ? "?" : exp.abi.c_str(),
               static_cast<unsigned long long>(exp.text_size));
    return true;
}

/**
 * Memoized plaintext probe for the packaged extract (L1 gating).
 * Returns false immediately when the extract dir is not app-writable (L1
 * publish impossible — extract stays ciphertext and L2 is the strategy) or
 * when no so_text_diag expect exists for this basename (cannot prove
 * plaintext). Cache keyed by (name, mtime, size) avoids re-hashing multi-MB
 * .text on every keyed dlopen; callers must invalidate after publishing.
 */
static bool extract_dir_writable(const std::string& nld);
static void note_plain_inode(const std::string& name, const std::string& path);

struct PlainProbe {
    std::string path;
    time_t mtime = 0;
    off_t size = 0;
    bool plain = false;
};
static std::mutex g_plainprobe_mu;
static std::unordered_map<std::string, PlainProbe> g_plainprobe;

static bool extract_holds_plaintext(const std::string& name,
                                    const std::string& extract) {
    if (name.empty() || extract.empty()) return false;
    std::string nld;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
    }
    if (!extract_dir_writable(nld)) return false;

    struct stat st {};
    if (stat(extract.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    {
        std::lock_guard<std::mutex> lock(g_plainprobe_mu);
        auto it = g_plainprobe.find(name);
        if (it != g_plainprobe.end() && it->second.path == extract
                && it->second.mtime == st.st_mtime
                && it->second.size == st.st_size) {
            return it->second.plain;
        }
    }
    // Require a diag row: without it we cannot distinguish plaintext from
    // packaged ciphertext — stay conservative and let L2 handle it.
    TextDiagExpect expect{};
    if (!pick_textdiag_expect(name, nullptr, &expect)) return false;
    const bool plain = verify_text_against_diag(
            extract, name, /*check_hash=*/true, /*quiet=*/true);
    {
        std::lock_guard<std::mutex> lock(g_plainprobe_mu);
        g_plainprobe[name] = PlainProbe{extract, st.st_mtime,
                                        static_cast<off_t>(st.st_size), plain};
    }
    if (plain) note_plain_inode(name, extract);
    return plain;
}

/** Drop the memo after WE publish plaintext onto the extract (content changed). */
static void note_extract_published(const std::string& name) {
    if (name.empty()) return;
    std::lock_guard<std::mutex> lock(g_plainprobe_mu);
    g_plainprobe.erase(name);
}

/** Remember the inode of an extract file this process published or proved plaintext. */
static void note_plain_inode(const std::string& name, const std::string& path) {
    if (name.empty() || path.empty()) return;
    struct stat st {};
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return;
    std::lock_guard<std::mutex> lock(g_plain_inode_mu);
    g_plain_inode[name] = PlainInode{static_cast<uint64_t>(st.st_dev),
                                     static_cast<uint64_t>(st.st_ino)};
}

static bool recorded_plain_inode(const std::string& name, const std::string& path) {
    if (name.empty() || path.empty()) return false;
    struct stat st {};
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return false;
    std::lock_guard<std::mutex> lock(g_plain_inode_mu);
    auto it = g_plain_inode.find(name);
    if (it == g_plain_inode.end()) return false;
    return it->second.dev == static_cast<uint64_t>(st.st_dev)
            && it->second.ino == static_cast<uint64_t>(st.st_ino);
}

/**
 * This path's inode is the L1 plaintext extract, or the diag hash says so.
 * Basename membership alone is not enough: a second extract inode may still
 * be ciphertext.
 */
static bool mapping_is_known_plaintext(const std::string& name, const std::string& path) {
    if (recorded_plain_inode(name, path)) return true;
    return extract_holds_plaintext(name, path);
}

/** Size + optional file_size from diag; used by warm ready. */
static bool mirror_size_matches_expect(const std::string& name,
                                       const std::string& dst,
                                       const std::string& src) {
    off_t ds = file_size_path(dst);
    off_t ss = file_size_path(src);
    if (ds <= 0 || ss <= 0 || ds != ss) return false;
    Elf_Shdr shdr{};
    get_elf_section(&shdr, dst.c_str(), ".text");
    TextDiagExpect exp;
    if (!pick_textdiag_expect(name, shdr.sh_size > 0 ? &shdr : nullptr, &exp)) {
        return true; // no diag row for this ABI — size match vs packaged is enough
    }
    if (exp.file_size > 0 && static_cast<uint64_t>(ds) != exp.file_size) {
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s abi=%s file_size MISMATCH "
                   "disk=%lld expect=%llu",
                   name.c_str(),
                   exp.abi.empty() ? "?" : exp.abi.c_str(),
                   static_cast<long long>(ds),
                   static_cast<unsigned long long>(exp.file_size));
        return false;
    }
    return true;
}

static void maybe_decrypt_by_name(const std::string& base);
static void decrypt_already_loaded();
PROTECTOR_ENCRYPT static bool decrypt_text_on_disk(const std::string& path, const std::string& base);
static SoKey* find_key_unlocked(const std::string& base);
static void ensure_plain_closure_for(const std::string& base);

static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    ifs.seekg(0, std::ios::end);
    auto sz = ifs.tellg();
    if (sz <= 0) return false;
    ifs.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    return static_cast<bool>(ifs.read(reinterpret_cast<char*>(out.data()), sz));
}

static uint16_t ru16(const uint8_t* p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static uint32_t ru32(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static std::string basename_of(const char* path) {
    if (path == nullptr || path[0] == 0) return {};
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return std::string(base);
}

bool load_sokeys(const std::string& path, const uint8_t* so_wrap_key) {
    if (so_wrap_key == nullptr) return false;
    std::vector<uint8_t> buf;
    if (!read_file(path, buf) || buf.size() < 4) {
        PLOGI("sokeys.bin absent — business SO protect off");
        return true;
    }
    if (buf[0] != 'P' || buf[1] != 'S' || buf[2] != 'O' || buf[3] != 'K') {
        PLOGE("sokeys bad magic");
        return false;
    }
    const uint8_t* enc = buf.data() + 4;
    size_t enc_len = buf.size() - 4;
    if (enc_len < crypto::GCM_NONCE_LEN + crypto::GCM_TAG_LEN) return false;
    size_t plain_len = enc_len - crypto::GCM_NONCE_LEN - crypto::GCM_TAG_LEN;
    std::vector<uint8_t> plain(plain_len);
    if (!crypto::aes128_gcm_decrypt(so_wrap_key, enc, enc_len, plain.data(), plain_len)) {
        PLOGE("sokeys AES-GCM decrypt failed");
        return false;
    }
    if (plain_len < 4) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    uint32_t count = ru32(plain.data());
    // Bound by remaining bytes (min entry = 2-byte name len + 0 name + 16 key).
    size_t max_by_size = (plain_len - 4) / 18;
    if (count > max_by_size || count > 4096u) {
        PLOGE("sokeys count out of range: %u max=%zu", count, max_by_size);
        memset(plain.data(), 0, plain.size());
        return false;
    }
    size_t cursor = 4;
    std::vector<SoKey> loaded;
    loaded.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        if (cursor + 2 > plain_len) {
            loaded.clear();
            memset(plain.data(), 0, plain.size());
            return false;
        }
        uint16_t nlen = ru16(plain.data() + cursor);
        cursor += 2;
        if (cursor + nlen + 16 > plain_len) {
            loaded.clear();
            memset(plain.data(), 0, plain.size());
            return false;
        }
        SoKey sk;
        sk.name.assign(reinterpret_cast<const char*>(plain.data() + cursor), nlen);
        cursor += nlen;
        memcpy(sk.key, plain.data() + cursor, 16);
        cursor += 16;
        loaded.push_back(std::move(sk));
    }
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_keys.swap(loaded);
    }
    g_cv.notify_all();
    memset(plain.data(), 0, plain.size());
    memset(buf.data(), 0, buf.size());
    PLOGI("sokeys loaded count=%zu", g_keys.size());

    // Flush dlopen observations that happened before keys were ready.
    std::vector<std::string> pending;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        pending.swap(g_pending);
    }
    for (const auto& name : pending) {
        // Closure materialize is for lazy cold start; eager still full-materializes next.
        if (so_decrypt_mode() == SoDecryptMode::Lazy) {
            ensure_plain_closure_for(name);
        }
        maybe_decrypt_by_name(name);
    }
    // Do not block cold start on scanning all already-mapped SOs — caller
    // schedules decrypt_already_loaded_async() after hooks / DexMerger.
    return true;
}

bool has_sokeys() {
    std::lock_guard<std::mutex> lock(g_mu);
    return !g_keys.empty();
}

static SoKey* find_key_unlocked(const std::string& base) {
    for (auto& k : g_keys) {
        if (k.name == base) return &k;
    }
    return nullptr;
}

/**
 * Path-sensitive megacores (Teigha/OSG Class B) must be mapped from the
 * packaged extract inode. Userspace path spoof is not enough: CAD-OSG looks up
 * static modules via the kernel-visible maps path. Helper-first so_plain loads
 * break "CAD-OSG init file ok".
 *
 * Packer {@code so_text_diag} v2 writes {@code l2e} from {@code isPathSensitive}
 * (size + GLES/engine markers). Size-only fallback is v1 packs only — it
 * misclassified libproj and SIGILL'd constructors on extract ciphertext.
 */
static bool needs_extract_inode(const std::string& base) {
    if (base.empty()) return false;
    TextDiagExpect exp{};
    if (pick_textdiag_expect(base, nullptr, &exp)) {
        if (g_textdiag_l2e_mode.load(std::memory_order_acquire)) {
            return exp.l2e;
        }
        return exp.text_size >= kExtractInodeMinText
                || exp.file_size >= static_cast<uint64_t>(kExtractInodeMinFile);
    }
    if (g_textdiag_l2e_mode.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(g_textdiag_mu);
        auto it = g_textdiag.find(base);
        if (it == g_textdiag.end()) return false;
        for (const auto& c : it->second) {
            if (c.l2e) return true;
        }
    }
    return false;
}

/**
 * Keep megacores off Application attach: no copy/RC4, no warm SHA-256, no
 * eager preload. First dlopen maps the packaged extract and decrypts .text
 * in RAM (L2e). Homepage SOs stay on the eager path.
 */
static bool defer_eager_disk(const std::string& base) {
    return needs_extract_inode(base);
}

static void mark_key_disk_done(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_mu);
    SoKey* key = find_key_unlocked(name);
    if (key != nullptr) {
        key->decrypted = true;
        key->in_flight = false;
    }
    g_cv.notify_all();
}

static int page_mprotect(void* start, size_t size, int prot) {
    int ps = getpagesize();
    uintptr_t s = reinterpret_cast<uintptr_t>(start) & ~static_cast<uintptr_t>(ps - 1);
    uintptr_t e = (reinterpret_cast<uintptr_t>(start) + size + ps - 1)
                  & ~static_cast<uintptr_t>(ps - 1);
    return mprotect(reinterpret_cast<void*>(s), e - s, prot);
}

enum class ClaimResult {
    /** Copied key; caller must decrypt then commit_key. */
    Claimed,
    /** Already decrypted — nothing to do. */
    AlreadyDone,
    /** Not in key table (SO not protected). */
    NotProtected,
    /**
     * Another thread owns the key. Caller is inside the linker, so waiting
     * would deadlock with any owner that still needs dlopen.
     */
    Busy,
};

/**
 * Claim a key for decrypt, or wait until an in-flight decrypt finishes.
 * Copies key material; no SoKey* escapes the lock.
 */
static ClaimResult claim_key(const std::string& base, uint8_t out_key[16]) {
    std::unique_lock<std::mutex> lock(g_mu);
    for (;;) {
        SoKey* key = find_key_unlocked(base);
        if (key == nullptr) return ClaimResult::NotProtected;
        if (key->decrypted) return ClaimResult::AlreadyDone;
        if (!key->in_flight) {
            key->in_flight = true;
            memcpy(out_key, key->key, 16);
            return ClaimResult::Claimed;
        }
        if (g_in_linker_hook > 0) {
            return ClaimResult::Busy;
        }
        g_cv.wait(lock);
    }
}

static void commit_key(const std::string& base, bool success) {
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(base);
        if (key != nullptr) {
            key->in_flight = false;
            if (success) {
                key->decrypted = true;
            }
        }
    }
    g_cv.notify_all();
}

static bool is_decrypted_unlocked(const std::string& base) {
    SoKey* key = find_key_unlocked(base);
    return key != nullptr && key->decrypted;
}

struct MappedText {
    uintptr_t addr = 0;
    size_t size = 0;
};

static bool parse_map_span(const char* line, uintptr_t* start, uintptr_t* end,
                           uint64_t* offset, bool* exec) {
    if (line == nullptr || start == nullptr || end == nullptr
            || offset == nullptr || exec == nullptr) {
        return false;
    }
    char perms[8] = {};
#ifdef __LP64__
    unsigned long long lo = 0;
    unsigned long long hi = 0;
    unsigned long long off = 0;
    if (sscanf(line, "%llx-%llx %7s %llx", &lo, &hi, perms, &off) != 4) return false;
#else
    unsigned long lo = 0;
    unsigned long hi = 0;
    unsigned long off = 0;
    if (sscanf(line, "%lx-%lx %7s %lx", &lo, &hi, perms, &off) != 4) return false;
#endif
    if (hi <= lo) return false;
    *start = static_cast<uintptr_t>(lo);
    *end = static_cast<uintptr_t>(hi);
    *offset = static_cast<uint64_t>(off);
    *exec = strchr(perms, 'x') != nullptr;
    return true;
}

/** Lowest PT_LOAD. Bias is trustworthy only against the maps row with this file offset. */
static bool read_min_pt_load(const char* path, uint64_t* vaddr, uint64_t* file_off) {
    if (path == nullptr || vaddr == nullptr || file_off == nullptr) return false;
    FILE* fp = fopen(path, "rb");
    if (fp == nullptr) return false;
    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
            || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
            || ehdr.e_phoff == 0
            || ehdr.e_phentsize != sizeof(Elf_Phdr)
            || ehdr.e_phnum == 0) {
        fclose(fp);
        return false;
    }
    if (fseek(fp, static_cast<long>(ehdr.e_phoff), SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }
    bool found = false;
    uint64_t min_v = UINT64_MAX;
    uint64_t min_off = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf_Phdr ph{};
        if (fread(&ph, 1, sizeof(ph), fp) != sizeof(ph)) break;
        if (ph.p_type != PT_LOAD) continue;
        if (!found || ph.p_vaddr < min_v) {
            min_v = ph.p_vaddr;
            min_off = ph.p_offset;
            found = true;
        }
    }
    fclose(fp);
    if (!found) return false;
    *vaddr = min_v;
    *file_off = min_off;
    return true;
}

/** Every page overlapping {@code .text} must be mapped executable. */
static bool text_pages_executable(uintptr_t start, size_t size) {
    if (size == 0) return false;
    const int ps = getpagesize();
    if (ps <= 0) return false;
    const auto page = static_cast<uintptr_t>(ps);
    if (start > static_cast<uintptr_t>(-1) - (size - 1)) return false;
    const uintptr_t first = start & ~(page - 1);
    const uintptr_t last = (start + size - 1) & ~(page - 1);
    if (last < first) return false;

    struct Span {
        uintptr_t lo;
        uintptr_t hi;
    };
    std::vector<Span> execs;
    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return false;
    std::string line;
    while (protector::read_maps_record(fp, &line)) {
        uintptr_t s = 0;
        uintptr_t e = 0;
        uint64_t off = 0;
        bool ex = false;
        if (!parse_map_span(line.c_str(), &s, &e, &off, &ex) || !ex) continue;
        execs.push_back(Span{s, e});
    }
    fclose(fp);
    if (execs.empty()) return false;
    for (uintptr_t p = first;;) {
        bool hit = false;
        for (const auto& sp : execs) {
            if (sp.lo <= p && p < sp.hi) {
                hit = true;
                break;
            }
        }
        if (!hit) return false;
        if (p == last) break;
        if (p > static_cast<uintptr_t>(-1) - page) return false;
        p += page;
        if (p < first) return false;
    }
    return true;
}

/**
 * Load bias from the maps row whose file offset is the lowest PT_LOAD, not from
 * whichever segment happens to be the lowest address mapped so far.
 * Returns false until that row exists and every .text page is executable.
 */
static bool locate_mapped_text(const std::string& path, MappedText* out) {
    if (out == nullptr || path.empty()) return false;
    out->addr = 0;
    out->size = 0;
    uint64_t p_vaddr = 0;
    uint64_t p_off = 0;
    if (!read_min_pt_load(path.c_str(), &p_vaddr, &p_off)) return false;
    const int ps = getpagesize();
    if (ps <= 0) return false;
    const uint64_t want = p_off & ~static_cast<uint64_t>(ps - 1);

    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return false;
    uintptr_t map_start = 0;
    bool found = false;
    std::string line;
    while (protector::read_maps_record(fp, &line)) {
        if (line.find(path) == std::string::npos) continue;
        uintptr_t s = 0;
        uintptr_t e = 0;
        uint64_t off = 0;
        bool ex = false;
        if (!parse_map_span(line.c_str(), &s, &e, &off, &ex)) continue;
        if (off != want) continue;
        map_start = s;
        found = true;
        break;
    }
    fclose(fp);
    if (!found) return false;
    if (p_vaddr != 0 && map_start < static_cast<uintptr_t>(p_vaddr)) return false;

    Elf_Shdr shdr{};
    get_elf_section(&shdr, path.c_str(), ".text");
    if (shdr.sh_size == 0) return false;
    const auto text = static_cast<uintptr_t>(map_start - static_cast<uintptr_t>(p_vaddr)
                                             + static_cast<uintptr_t>(shdr.sh_addr));
    const auto text_size = static_cast<size_t>(shdr.sh_size);
    if (!text_pages_executable(text, text_size)) return false;
    out->addr = text;
    out->size = text_size;
    return true;
}

static void note_text_write_failed(const std::string& name) {
    if (name.empty()) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_text_write_failed.insert(name);
}

static void clear_text_write_failed(const std::string& name) {
    if (name.empty()) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_text_write_failed.erase(name);
}

static bool text_write_failed(const std::string& name) {
    if (name.empty()) return false;
    std::lock_guard<std::mutex> lock(g_mu);
    return g_text_write_failed.count(name) != 0;
}

static void note_text_left_plaintext(const std::string& name) {
    if (name.empty()) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_text_left_plaintext.insert(name);
}

static bool text_left_plaintext(const std::string& name) {
    if (name.empty()) return false;
    std::lock_guard<std::mutex> lock(g_mu);
    return g_text_left_plaintext.count(name) != 0;
}

static int prot_from_perms(const char* perms) {
    int prot = 0;
    if (perms == nullptr) return PROT_READ | PROT_EXEC;
    if (strchr(perms, 'r') != nullptr) prot |= PROT_READ;
    if (strchr(perms, 'w') != nullptr) prot |= PROT_WRITE;
    if (strchr(perms, 'x') != nullptr) prot |= PROT_EXEC;
    if (prot == 0) prot = PROT_READ | PROT_EXEC;
    return prot;
}

struct PageSnap {
    uintptr_t page = 0;
    int prot = PROT_READ | PROT_EXEC;
};

/** Prot of each page covering {@code .text}, captured before we change it. */
static std::vector<PageSnap> snapshot_text_pages(uintptr_t start, size_t size) {
    std::vector<PageSnap> out;
    const int ps = getpagesize();
    if (ps <= 0 || size == 0) return out;
    const auto page = static_cast<uintptr_t>(ps);
    if (start > static_cast<uintptr_t>(-1) - (size - 1)) return out;
    const uintptr_t first = start & ~(page - 1);
    const uintptr_t last = (start + size - 1) & ~(page - 1);
    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return out;
    std::string line;
    while (protector::read_maps_record(fp, &line)) {
        uintptr_t s = 0;
        uintptr_t e = 0;
        uint64_t off = 0;
        bool ex = false;
        if (!parse_map_span(line.c_str(), &s, &e, &off, &ex)) continue;
        char perms[8] = {};
        sscanf(line.c_str(), "%*s %7s", perms);
        const int prot = prot_from_perms(perms);
        for (uintptr_t p = first;;) {
            if (s <= p && p < e) out.push_back(PageSnap{p, prot});
            if (p == last) break;
            if (p > static_cast<uintptr_t>(-1) - page) break;
            p += page;
        }
    }
    fclose(fp);
    return out;
}

/**
 * Pages that contain only .text go back to RX. A page that also holds writable
 * data keeps the prot it had before the write, so a shared RWX page does not
 * lose PROT_WRITE.
 */
static bool restore_text_pages(uintptr_t start, size_t size, const std::vector<PageSnap>& snaps) {
    const int ps = getpagesize();
    if (ps <= 0 || size == 0) return false;
    const auto page = static_cast<uintptr_t>(ps);
    const uintptr_t first = start & ~(page - 1);
    const uintptr_t last_byte = start + size - 1;
    const uintptr_t last = last_byte & ~(page - 1);
    bool ok = true;
    for (uintptr_t p = first;;) {
        int orig = PROT_READ | PROT_EXEC;
        for (const auto& s : snaps) {
            if (s.page == p) {
                orig = s.prot;
                break;
            }
        }
        const bool partial = p < start || (p + page - 1) > last_byte;
        const bool keep_write = partial && (orig & PROT_WRITE) != 0;
        const int want = keep_write ? orig : (PROT_READ | PROT_EXEC);
        if ((want & PROT_EXEC) == 0) ok = false;
        if (mprotect(reinterpret_cast<void*>(p), static_cast<size_t>(page), want) != 0) {
            ok = false;
        }
        if (p == last) break;
        if (p > static_cast<uintptr_t>(-1) - page) break;
        p += page;
    }
    return ok;
}

static bool write_via_process_vm(void* dst, const void* src, size_t size) {
#if defined(__NR_process_vm_writev)
    struct iovec local {};
    local.iov_base = const_cast<void*>(src);
    local.iov_len = size;
    struct iovec remote {};
    remote.iov_base = dst;
    remote.iov_len = size;
    const ssize_t n = syscall(__NR_process_vm_writev, static_cast<long>(getpid()),
                              &local, 1L, &remote, 1L, 0L);
    return n == static_cast<ssize_t>(size);
#else
    (void)dst;
    (void)src;
    (void)size;
    return false;
#endif
}

static bool vm_read_local(void* dst, uintptr_t src, size_t n) {
    if (dst == nullptr || n == 0) return false;
#if defined(__NR_process_vm_readv)
    struct iovec local {};
    local.iov_base = dst;
    local.iov_len = n;
    struct iovec remote {};
    remote.iov_base = reinterpret_cast<void*>(src);
    remote.iov_len = n;
    const ssize_t got = syscall(__NR_process_vm_readv, static_cast<long>(getpid()),
                                &local, 1L, &remote, 1L, 0L);
    if (got == static_cast<ssize_t>(n)) return true;
#endif
    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return false;
    bool readable = false;
    std::string line;
    while (protector::read_maps_record(fp, &line)) {
        uintptr_t s = 0;
        uintptr_t e = 0;
        uint64_t off = 0;
        bool ex = false;
        if (!parse_map_span(line.c_str(), &s, &e, &off, &ex)) continue;
        char perms[8] = {};
        if (sscanf(line.c_str(), "%*s %7s", perms) != 1) continue;
        if (strchr(perms, 'r') == nullptr) continue;
        if (n > e - s) continue;
        if (src >= s && src <= e - n) {
            readable = true;
            break;
        }
    }
    fclose(fp);
    if (!readable) return false;
    memcpy(dst, reinterpret_cast<const void*>(src), n);
    return true;
}

static bool write_via_proc_mem(void* dst, const void* src, size_t size) {
    const int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, "/proc/self/mem",
                                            O_RDWR | O_CLOEXEC));
    if (fd < 0) return false;
    const auto* in = static_cast<const uint8_t*>(src);
    const auto addr = reinterpret_cast<uintptr_t>(dst);
    size_t done = 0;
    bool ok = true;
    while (done < size) {
#if defined(__LP64__)
        const ssize_t n = pwrite(fd, in + done, size - done,
                                 static_cast<off_t>(addr + done));
#else
        const ssize_t n = pwrite64(fd, in + done, size - done,
                                   static_cast<off64_t>(addr + done));
#endif
        if (n <= 0) {
            ok = false;
            break;
        }
        done += static_cast<size_t>(n);
    }
    close(fd);
    return ok && done == size;
}

enum class TextWriteHow { None, Mprotect, External };

/** Copy plaintext into a mapped .text. Mprotect means the caller must restore prot. */
static TextWriteHow write_mapped_text(uint8_t* text, size_t size, const uint8_t* plain) {
    if (text == nullptr || plain == nullptr || size == 0) return TextWriteHow::None;
    if (page_mprotect(text, size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0
            || page_mprotect(text, size, PROT_READ | PROT_WRITE) == 0) {
        memcpy(text, plain, size);
        return TextWriteHow::Mprotect;
    }
    if (write_via_process_vm(text, plain, size) || write_via_proc_mem(text, plain, size)) {
        return TextWriteHow::External;
    }
    return TextWriteHow::None;
}

PROTECTOR_ENCRYPT static bool decrypt_loaded_text(const std::string& so_name) {
    if (so_name.empty()) return true;

    uint8_t key_bytes[16];
    ClaimResult claim = claim_key(so_name, key_bytes);
    if (claim == ClaimResult::NotProtected) return true;
    if (claim == ClaimResult::Busy) return false;
    // Restore failed after a successful write. Bytes are already plaintext.
    // RC4 again would re-encrypt them. Do not mark the extract inode decrypted:
    // constructors must stay blocked and dlclose must still drop the handle.
    if (text_left_plaintext(so_name)) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (claim == ClaimResult::Claimed) commit_key(so_name, false);
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s skip second RC4 — .text already "
                   "plaintext, prot restore failed",
                   so_name.c_str());
        return false;
    }

    // Prefer packaged extract mapping when present: so_plain may also appear in
    // maps while a second soinfo still points at extract ciphertext (L2e).
    // Do not return early on keyed_mapped_plain — that flag means *a* mapping
    // was plaintext, not that every inode is.
    std::string path;
    bool mapped_plain = false;
    {
        FILE* fp = fopen_maps_raw();
        if (fp != nullptr) {
            std::string line;
            std::string plain_hit;
            std::string pkg_hit;
            while (protector::read_maps_record(fp, &line)) {
                if (line.find("r-xp") == std::string::npos
                        && line.find("rwxp") == std::string::npos) {
                    continue;
                }
                std::string map_path;
                if (!protector::maps_pathname(line, &map_path)) continue;
                const bool memfd = map_path.find("/memfd:") != std::string::npos;
                const char* base = strrchr(map_path.c_str(), '/');
                base = base != nullptr ? base + 1 : map_path.c_str();
                bool name_hit = strcmp(base, so_name.c_str()) == 0;
                if (!name_hit && memfd && strncmp(base, "memfd:", 6) == 0) {
                    name_hit = strcmp(base + 6, so_name.c_str()) == 0;
                }
                if (!name_hit) continue;
                if (memfd || map_path.find("/so_plain/") != std::string::npos
                        || map_path.find("/lib_mirror/") != std::string::npos) {
                    if (plain_hit.empty()) plain_hit = map_path;
                } else if (pkg_hit.empty()) {
                    pkg_hit = map_path;
                }
            }
            fclose(fp);
            if (!pkg_hit.empty()) {
                path = std::move(pkg_hit);
                mapped_plain = false;
            } else if (!plain_hit.empty()) {
                path = std::move(plain_hit);
                mapped_plain = true;
            }
        }
    }
    if (path.empty()) {
        path = find_so_path(so_name.c_str());
        mapped_plain = path.find("/so_plain/") != std::string::npos
                || path.find("/lib_mirror/") != std::string::npos;
    }
    if (path.empty()) {
        if (claim == ClaimResult::Claimed) {
            memset(key_bytes, 0, sizeof(key_bytes));
            commit_key(so_name, false);
        }
        PLOGW("business so path missing: %s", so_name.c_str());
        return false;
    }

    if (!mapped_plain) {
        bool already = false;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            already = g_extract_inode_decrypted.count(so_name) != 0;
        }
        if (already) {
            memset(key_bytes, 0, sizeof(key_bytes));
            // Claimed must commit: leaving in_flight set blocks every later waiter.
            if (claim == ClaimResult::Claimed) {
                commit_key(so_name, true);
            }
            return true;
        }
    }

    // L1 extract is plaintext on disk. Path class still says "packaged", but
    // RC4 here would re-encrypt it. A different inode for the same basename
    // stays on the ciphertext path below.
    if (!mapped_plain && mapping_is_known_plaintext(so_name, path)) {
        memset(key_bytes, 0, sizeof(key_bytes));
        {
            std::lock_guard<std::mutex> lock(g_mu);
            g_extract_inode_decrypted.insert(so_name);
        }
        if (claim == ClaimResult::Claimed) {
            commit_key(so_name, true);
        }
        clear_text_write_failed(so_name);
        PLOGI("business so: skip in-memory RC4, extract already plaintext %s",
              so_name.c_str());
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] name=%s skip in-memory RC4 (extract plaintext) path=%s",
                   so_name.c_str(), path.c_str());
        return true;
    }

    if (claim == ClaimResult::AlreadyDone) {
        // Disk mirror is plaintext; if THIS mapping is also so_plain, skip.
        // If linker still mapped packaged ciphertext, force in-memory RC4.
        if (mapped_plain) {
            return true;
        }
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(so_name);
        if (key == nullptr) return true;
        memcpy(key_bytes, key->key, 16);
    }

    bool ok = false;
    MappedText loc{};
    if (!locate_mapped_text(path, &loc)) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (claim == ClaimResult::Claimed) commit_key(so_name, false);
        xop_so_log(ANDROID_LOG_WARN,
                   "[XOP-SO] name=%s in-memory decrypt deferred "
                   "(load base or .text not ready) path=%s",
                   so_name.c_str(), path.c_str());
        return false;
    }
    auto* text = reinterpret_cast<uint8_t*>(loc.addr);
    std::vector<uint8_t> tmp(loc.size);
    struct rc4_state st {};
    rc4_init(&st, key_bytes, 16);
    memset(key_bytes, 0, sizeof(key_bytes));
    rc4_crypt(&st, text, tmp.data(), static_cast<int>(loc.size));
    const auto snaps = snapshot_text_pages(loc.addr, loc.size);
    const TextWriteHow how = write_mapped_text(text, loc.size, tmp.data());
    memset(tmp.data(), 0, tmp.size());
    if (how == TextWriteHow::None) {
        note_text_write_failed(so_name);
        if (claim == ClaimResult::Claimed) commit_key(so_name, false);
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s in-memory .text write failed "
                   "(mprotect/process_vm_writev/proc mem) — refuse constructors path=%s",
                   so_name.c_str(), path.c_str());
        PLOGE("business so: refuse ciphertext constructors %s", so_name.c_str());
        return false;
    }
    __builtin___clear_cache(reinterpret_cast<char*>(text),
                            reinterpret_cast<char*>(text + loc.size));
    if (how == TextWriteHow::Mprotect && !restore_text_pages(loc.addr, loc.size, snaps)) {
        note_text_left_plaintext(so_name);
        note_text_write_failed(so_name);
        if (claim == ClaimResult::Claimed) commit_key(so_name, false);
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s .text prot restore failed — refuse constructors path=%s",
                   so_name.c_str(), path.c_str());
        PLOGE("business so: refuse constructors, prot restore failed %s", so_name.c_str());
        return false;
    }
    clear_text_write_failed(so_name);
    ok = true;
    // Extract-inode loads decrypt ciphertext that is still on disk. Mark so a
    // second RC4 (mmap + call_constructors) cannot re-encrypt the image.
    // Only after the bytes were actually decrypted — a deferred attempt must not
    // stick this basename.
    if (!mapped_plain) {
        mark_keyed_mapped_plain(so_name);
        std::lock_guard<std::mutex> lock(g_mu);
        g_extract_inode_decrypted.insert(so_name);
    }
    PLOGI("decrypted business SO .text: %s addr=0x%zx mapped=%s",
          so_name.c_str(), static_cast<size_t>(loc.addr),
          mapped_plain ? "so_plain" : "packaged");
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] name=%s decrypted .text mapped=%s size=0x%zx",
               so_name.c_str(), mapped_plain ? "so_plain" : "packaged",
               loc.size);
    if (claim == ClaimResult::Claimed) {
        commit_key(so_name, ok);
    }
    return ok;
}

static void maybe_decrypt_by_name(const std::string& base) {
    if (base.empty()) return;
    (void)decrypt_loaded_text(base);
}

/**
 * Android 6 (API≤23) linker rejects app-dir SOs that carry DT_VERNEED against
 * libc ("cannot find libc.so from verneed[0]…"). Clear VERNEEDNUM on so_plain
 * only — higher APIs keep symbol versions unchanged.
 */
static void strip_verneed_if_old_android(const std::string& path) {
#if defined(__ANDROID__)
    if (android_get_device_api_level() > 24) return;
    FILE* fp = fopen(path.c_str(), "r+b");
    if (fp == nullptr) return;
    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
        || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
        || ehdr.e_phoff == 0
        || ehdr.e_phentsize != sizeof(Elf_Phdr)
        || ehdr.e_phnum == 0) {
        fclose(fp);
        return;
    }
    if (fseek(fp, static_cast<long>(ehdr.e_phoff), SEEK_SET) != 0) {
        fclose(fp);
        return;
    }
#ifdef __LP64__
    using Dyn = Elf64_Dyn;
#else
    using Dyn = Elf32_Dyn;
#endif
    Elf_Off dyn_off = 0;
    size_t dyn_bytes = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf_Phdr ph{};
        if (fread(&ph, 1, sizeof(ph), fp) != sizeof(ph)) break;
        if (ph.p_type == PT_DYNAMIC) {
            dyn_off = ph.p_offset;
            dyn_bytes = static_cast<size_t>(ph.p_filesz);
            break;
        }
    }
    if (dyn_off == 0 || dyn_bytes < sizeof(Dyn)) {
        fclose(fp);
        return;
    }
    const size_t n = dyn_bytes / sizeof(Dyn);
    std::vector<Dyn> dyns(n);
    if (fseek(fp, static_cast<long>(dyn_off), SEEK_SET) != 0
        || fread(dyns.data(), sizeof(Dyn), n, fp) != n) {
        fclose(fp);
        return;
    }
    bool changed = false;
    for (size_t i = 0; i < n; i++) {
        if (dyns[i].d_tag == DT_NULL) break;
        // DT_VERNEEDNUM — zero count disables version-requirement walk.
        if (dyns[i].d_tag == DT_VERNEEDNUM && dyns[i].d_un.d_val != 0) {
            dyns[i].d_un.d_val = 0;
            changed = true;
        }
    }
    if (changed) {
        if (fseek(fp, static_cast<long>(dyn_off), SEEK_SET) == 0
            && fwrite(dyns.data(), sizeof(Dyn), n, fp) == n) {
            fflush(fp);
            PLOGI("business so: stripped DT_VERNEEDNUM for API≤24 %s", path.c_str());
        }
    }
    fclose(fp);
#else
    (void)path;
#endif
}

/**
 * Decrypt .text in the on-disk ELF before the real dlopen runs constructors
 * (DT_INIT / JNI_OnLoad). Post-dlopen memory decrypt is too late for init code.
 * Caller must have Claimed the key (in_flight); this commits on success/failure.
 */
PROTECTOR_ENCRYPT static bool rc4_text_on_disk_claimed(const std::string& path,
                                                       const std::string& base,
                                                       uint8_t key_bytes[16]) {
    // Illegal: PLAINTEXT + decrypt → double RC4 (RC4 is involution → re-encrypt).
    if (diag_is_plaintext(base)) {
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s refuse double RC4 "
                   "(source_state=PLAINTEXT decrypt_applied=would-be-true) path=%s",
                   base.c_str(), path.c_str());
        memset(key_bytes, 0, 16);
        commit_key(base, false);
        return false;
    }

    Elf_Shdr shdr{};
    get_elf_section(&shdr, path.c_str(), ".text");
    if (shdr.sh_size == 0 || shdr.sh_offset == 0) {
        xop_so_log(ANDROID_LOG_WARN,
                   "[XOP-SO] name=%s rc4 skip — no .text path=%s",
                   base.c_str(), path.c_str());
        memset(key_bytes, 0, 16);
        commit_key(base, false);
        return false;
    }

    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] name=%s rc4 begin path=%s text_offset=0x%llx text_size=0x%llx "
               "text_sh_addr=0x%llx",
               base.c_str(), path.c_str(),
               static_cast<unsigned long long>(shdr.sh_offset),
               static_cast<unsigned long long>(shdr.sh_size),
               static_cast<unsigned long long>(shdr.sh_addr));

    FILE* fp = fopen(path.c_str(), "r+b");
    if (!fp) {
        PLOGW("pre-decrypt open failed: %s", path.c_str());
        memset(key_bytes, 0, 16);
        commit_key(base, false);
        return false;
    }
    if (fseek(fp, static_cast<long>(shdr.sh_offset), SEEK_SET) != 0) {
        fclose(fp);
        memset(key_bytes, 0, 16);
        commit_key(base, false);
        return false;
    }
    std::vector<uint8_t> buf(static_cast<size_t>(shdr.sh_size));
    if (fread(buf.data(), 1, buf.size(), fp) != buf.size()) {
        fclose(fp);
        memset(key_bytes, 0, 16);
        memset(buf.data(), 0, buf.size());
        commit_key(base, false);
        return false;
    }
    std::vector<uint8_t> plain(buf.size());
    struct rc4_state st {};
    rc4_init(&st, key_bytes, 16);
    memset(key_bytes, 0, 16);
    rc4_crypt(&st, buf.data(), plain.data(), static_cast<int>(plain.size()));
    memset(buf.data(), 0, buf.size());
    if (fseek(fp, static_cast<long>(shdr.sh_offset), SEEK_SET) != 0
        || fwrite(plain.data(), 1, plain.size(), fp) != plain.size()) {
        fclose(fp);
        memset(plain.data(), 0, plain.size());
        commit_key(base, false);
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s rc4 partial write — refuse path=%s",
                   base.c_str(), path.c_str());
        unlink_so_plain_if(path);
        return false;
    }
    fflush(fp);
    fclose(fp);
    memset(plain.data(), 0, plain.size());
    strip_verneed_if_old_android(path);
    if (!verify_text_against_diag(path, base, /*check_hash=*/true)) {
        commit_key(base, false);
        unlink_so_plain_if(path);
        diag_set(base, "MATERIALIZE", "ENCRYPTED", false, false, false, path);
        return false;
    }
    commit_key(base, true);
    diag_set(base, "MATERIALIZE", "PLAINTEXT", /*decrypt_applied=*/true,
             /*ready_hit=*/false, /*materialize_ok=*/true, path);
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] name=%s rc4 ok text_offset=0x%llx text_size=0x%llx",
               base.c_str(),
               static_cast<unsigned long long>(shdr.sh_offset),
               static_cast<unsigned long long>(shdr.sh_size));
    PLOGI("pre-decrypted business SO .text on disk: %s", base.c_str());
    return true;
}

PROTECTOR_ENCRYPT static bool decrypt_text_on_disk(const std::string& path,
                                                   const std::string& base) {
    if (path.empty() || path[0] != '/' || base.empty()) return false;

    uint8_t key_bytes[16];
    ClaimResult claim = claim_key(base, key_bytes);
    if (claim == ClaimResult::NotProtected) return true;
    if (claim == ClaimResult::Busy) return false;
    if (claim == ClaimResult::AlreadyDone) {
        // Warm so_plain from an older build may still carry DT_VERNEED.
        strip_verneed_if_old_android(path);
        if (!verify_text_against_diag(path, base, /*check_hash=*/true)) {
            unlink_so_plain_if(path);
            {
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(base);
                if (key != nullptr) {
                    key->decrypted = false;
                    key->in_flight = false;
                }
            }
            g_cv.notify_all();
            return false;
        }
        return true;
    }
    return rc4_text_on_disk_claimed(path, base, key_bytes);
}

static bool file_exists_path(const std::string& path);
static bool copy_file_bytes(const std::string& src, const std::string& dst, bool force = false);
static bool is_system_soname(const std::string& need);
static int scrub_forbidden_from_so_plain(const std::string& out_dir);

/**
 * L1/L2/L3 keyed open plan (docs/so-load-contract.md).
 * L2: linker filename = extract path (dladdr); content = memfd (optional) or
 * so_plain via LIBRARY_FD. L3 keeps the so_plain path as fallback.
 */
struct KeyedOpenPlan {
    std::string base;
    std::string linker_name;
    std::string content_path;
    std::string so_plain_path;
    bool use_library_fd = false;
    /** Map packaged extract ciphertext; decrypt .text in RAM before constructors. */
    bool in_memory_decrypt = false;
};

static int g_extract_writable = -1; // -1 unknown, 0 no, 1 yes

/** L2b: stable extract paths for dladdr rewrite (keyed basename → extract abs). */
static std::mutex g_dladdr_mu;
static std::unordered_map<std::string, std::string> g_dladdr_extract;
/** Keyed SOs already mapped from plaintext (L1 / L2 fd / memfd) — skip in-memory RC4. */
static std::unordered_set<std::string> g_fd_mapped_plain;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
/** Skip memfd copy for huge SOs (path-sensitive megacores); L2 file fd still applies. */
static constexpr off_t kMemfdMaxBytes = 16 * 1024 * 1024;

/**
 * Copy {@code path} into an anonymous memfd. Returns -1 if unsupported, too
 * large, or copy failed — caller then opens so_plain as the L2 fd.
 */
static int create_memfd_from_path(const std::string& path, const char* name) {
#if defined(__ANDROID__) && defined(__NR_memfd_create)
    int src = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (src < 0) return -1;
    struct stat st {};
    if (fstat(src, &st) != 0 || st.st_size <= 0 || st.st_size > kMemfdMaxBytes) {
        close(src);
        return -1;
    }
    const char* tag = (name != nullptr && name[0] != '\0') ? name : "xopso";
    int mfd = static_cast<int>(syscall(__NR_memfd_create, tag, MFD_CLOEXEC));
    if (mfd < 0) {
        close(src);
        return -1;
    }
    off_t copied = 0;
    while (copied < st.st_size) {
        off_t off = copied;
        ssize_t n = sendfile(mfd, src, &off, static_cast<size_t>(st.st_size - copied));
        if (n <= 0) break;
        copied = off;
    }
    if (copied != st.st_size) {
        if (lseek(src, copied, SEEK_SET) < 0 || lseek(mfd, copied, SEEK_SET) < 0) {
            close(src);
            close(mfd);
            return -1;
        }
        char buf[256 * 1024];
        off_t left = st.st_size - copied;
        while (left > 0) {
            size_t want = sizeof(buf) < static_cast<size_t>(left)
                    ? sizeof(buf) : static_cast<size_t>(left);
            ssize_t r = read(src, buf, want);
            if (r <= 0) {
                close(src);
                close(mfd);
                return -1;
            }
            ssize_t w = 0;
            while (w < r) {
                ssize_t k = write(mfd, buf + w, static_cast<size_t>(r - w));
                if (k <= 0) {
                    close(src);
                    close(mfd);
                    return -1;
                }
                w += k;
            }
            left -= r;
        }
    }
    close(src);
    if (lseek(mfd, 0, SEEK_SET) != 0) {
        close(mfd);
        return -1;
    }
    return mfd;
#else
    (void)path;
    (void)name;
    return -1;
#endif
}

static void mark_keyed_mapped_plain(const std::string& base) {
    if (base.empty()) return;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    g_fd_mapped_plain.insert(base);
}

static void unmark_keyed_mapped_plain(const std::string& base) {
    if (base.empty()) return;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    g_fd_mapped_plain.erase(base);
}

static bool keyed_mapped_plain(const std::string& base) {
    if (base.empty()) return false;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    return g_fd_mapped_plain.count(base) != 0;
}

/**
 * Intentionally a no-op under plaintext warm reuse: so_plain mirrors must
 * survive L1/L2 maps so the next process can skip RC4 via so_plain_ready.
 * (PR12 in-process unlink conflicted with cross-launch warm; product chose speed.)
 */
static void maybe_drop_so_plain_mirror(const KeyedOpenPlan& plan) {
    (void)plan;
}

static std::string keyed_soname_from_fname(const char* fname) {
    if (fname == nullptr || fname[0] == '\0') return {};
    const char* memfd = strstr(fname, "memfd:");
    if (memfd != nullptr) {
        memfd += 6;
        const char* end = memfd;
        while (*end != '\0' && *end != ' ' && *end != ')') {
            ++end;
        }
        return std::string(memfd, static_cast<size_t>(end - memfd));
    }
    return basename_of(fname);
}

static bool extract_dir_writable(const std::string& nld) {
    if (nld.empty()) return false;
    if (g_extract_writable >= 0) return g_extract_writable == 1;
    std::string probe = nld + "/.xop_write_probe";
    FILE* fp = fopen(probe.c_str(), "wb");
    if (fp == nullptr) {
        g_extract_writable = 0;
        return false;
    }
    fclose(fp);
    unlink(probe.c_str());
    g_extract_writable = 1;
    return true;
}

/** Prefer archived packaged bytes (survives L1 extract overwrite) over live nld. */
static std::string keyed_packaged_src(const std::string& name, const std::string& nld) {
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
    }
    if (!cache_root.empty()) {
        std::string cipher = cache_root + "/so_cipher/" + name;
        if (file_exists_path(cipher)) return cipher;
    }
    return nld + "/" + name;
}

static void refresh_lib_mirror(const std::string& cache_root,
                               const std::string& nld,
                               const std::string& so_plain);
static void refresh_lib_mirror_from_runtime();
static bool plant_hardlink_or_copy(const std::string& src, const std::string& dst);
static bool symlink_plain_dep(const std::string& src, const std::string& dst);
static int plant_extract_sidecars(const std::string& dest, const std::string& nld);
static void publish_keyed_extract_mirrors(const std::string& cache_root,
                                          const std::string& nld,
                                          const std::string& so_plain);
static std::string extract_path_for_keyed(const std::string& base);
static const char* intern_extract_c_str(const std::string& base);
static const char* spoof_mapped_path_c_str(const char* path);

#ifdef __LP64__
using Elf_Ehdr_L = Elf64_Ehdr;
using Elf_Shdr_L = Elf64_Shdr;
using Elf_Sym_L = Elf64_Sym;
#else
using Elf_Ehdr_L = Elf32_Ehdr;
using Elf_Shdr_L = Elf32_Shdr;
using Elf_Sym_L = Elf32_Sym;
#endif

static void* resolve_linker_symbol(const char* elf_path, uintptr_t load_bias,
                                   const char* exact, const char* contains) {
    if (elf_path == nullptr || elf_path[0] == '\0') return nullptr;
    FILE* fp = fopen(elf_path, "rb");
    if (fp == nullptr) return nullptr;
    Elf_Ehdr_L ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
            || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(fp);
        return nullptr;
    }
    if (ehdr.e_shoff == 0 || ehdr.e_shentsize != sizeof(Elf_Shdr_L) || ehdr.e_shnum == 0) {
        fclose(fp);
        return nullptr;
    }
    std::vector<Elf_Shdr_L> shdrs(ehdr.e_shnum);
    if (fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET) != 0
            || fread(shdrs.data(), sizeof(Elf_Shdr_L), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        fclose(fp);
        return nullptr;
    }
    auto lookup_in = [&](const Elf_Shdr_L& symtab, const Elf_Shdr_L& strtab) -> void* {
        if (symtab.sh_entsize != sizeof(Elf_Sym_L) || symtab.sh_size == 0) return nullptr;
        size_t count = static_cast<size_t>(symtab.sh_size / sizeof(Elf_Sym_L));
        if (count == 0 || count > 2 * 1024 * 1024) return nullptr;
        std::vector<Elf_Sym_L> syms(count);
        std::vector<char> strs(static_cast<size_t>(strtab.sh_size));
        if (fseek(fp, static_cast<long>(symtab.sh_offset), SEEK_SET) != 0
                || fread(syms.data(), sizeof(Elf_Sym_L), count, fp) != count) {
            return nullptr;
        }
        if (fseek(fp, static_cast<long>(strtab.sh_offset), SEEK_SET) != 0
                || fread(strs.data(), 1, strs.size(), fp) != strs.size()) {
            return nullptr;
        }
        for (const auto& s : syms) {
            if (s.st_name == 0 || s.st_name >= strs.size()) continue;
            const char* nm = strs.data() + s.st_name;
            if (s.st_shndx == SHN_UNDEF || s.st_value == 0) continue;
            bool hit = false;
            if (exact != nullptr && strcmp(nm, exact) == 0) hit = true;
            if (!hit && contains != nullptr && strstr(nm, contains) != nullptr) hit = true;
            if (!hit) continue;
            return reinterpret_cast<void*>(load_bias + static_cast<uintptr_t>(s.st_value));
        }
        return nullptr;
    };
    void* found = nullptr;
    for (const auto& sh : shdrs) {
        if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
        if (sh.sh_link >= shdrs.size()) continue;
        const Elf_Shdr_L& strtab = shdrs[sh.sh_link];
        if (strtab.sh_type != SHT_STRTAB) continue;
        found = lookup_in(sh, strtab);
        if (found) break;
    }
    fclose(fp);
    return found;
}

/**
 * Address of a JUMP_SLOT/GLOB_DAT GOT cell in the mapped linker (imported
 * open/openat). Used when the symbol is SHN_UNDEF so Dobby cannot hook a
 * defined function.
 */
static void* resolve_linker_import_got(const char* elf_path, uintptr_t load_bias,
                                       const char* want) {
    if (elf_path == nullptr || elf_path[0] == '\0' || want == nullptr) return nullptr;
    FILE* fp = fopen(elf_path, "rb");
    if (fp == nullptr) return nullptr;
    Elf_Ehdr_L ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
            || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(fp);
        return nullptr;
    }
    if (ehdr.e_phoff == 0 || ehdr.e_phnum == 0 || ehdr.e_phentsize != sizeof(Elf_Phdr)) {
        fclose(fp);
        return nullptr;
    }
    std::vector<Elf_Phdr> ph(ehdr.e_phnum);
    if (fseek(fp, static_cast<long>(ehdr.e_phoff), SEEK_SET) != 0
            || fread(ph.data(), sizeof(Elf_Phdr), ehdr.e_phnum, fp) != ehdr.e_phnum) {
        fclose(fp);
        return nullptr;
    }
    const Elf_Phdr* dyn_ph = nullptr;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn_ph = &ph[i];
            break;
        }
    }
    if (dyn_ph == nullptr || dyn_ph->p_filesz == 0 || dyn_ph->p_filesz > 1 * 1024 * 1024) {
        fclose(fp);
        return nullptr;
    }
#ifdef __LP64__
    using DynT = Elf64_Dyn;
    using RelaT = Elf64_Rela;
    using SymT = Elf64_Sym;
#else
    using DynT = Elf32_Dyn;
    using RelaT = Elf32_Rel;
    using SymT = Elf32_Sym;
#endif
    std::vector<DynT> dyn(dyn_ph->p_filesz / sizeof(DynT));
    if (fseek(fp, static_cast<long>(dyn_ph->p_offset), SEEK_SET) != 0
            || fread(dyn.data(), sizeof(DynT), dyn.size(), fp) != dyn.size()) {
        fclose(fp);
        return nullptr;
    }
    uintptr_t jmprel = 0;
    size_t pltrelsz = 0;
    uintptr_t rel = 0;
    size_t relsz = 0;
    uintptr_t symtab = 0;
    uintptr_t strtab = 0;
    size_t syment = sizeof(SymT);
    size_t strsz = 0;
    bool jmprel_is_rela = true;
    for (const auto& d : dyn) {
        if (d.d_tag == DT_NULL) break;
        switch (d.d_tag) {
            case DT_JMPREL: jmprel = static_cast<uintptr_t>(d.d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = static_cast<size_t>(d.d_un.d_val); break;
            case DT_RELA: rel = static_cast<uintptr_t>(d.d_un.d_ptr); break;
            case DT_RELASZ: relsz = static_cast<size_t>(d.d_un.d_val); break;
            case DT_REL:
#ifndef __LP64__
                rel = static_cast<uintptr_t>(d.d_un.d_ptr);
#endif
                break;
            case DT_RELSZ:
#ifndef __LP64__
                relsz = static_cast<size_t>(d.d_un.d_val);
#endif
                break;
            case DT_SYMTAB: symtab = static_cast<uintptr_t>(d.d_un.d_ptr); break;
            case DT_STRTAB: strtab = static_cast<uintptr_t>(d.d_un.d_ptr); break;
            case DT_STRSZ: strsz = static_cast<size_t>(d.d_un.d_val); break;
            case DT_SYMENT: syment = static_cast<size_t>(d.d_un.d_val); break;
            case DT_PLTREL:
                jmprel_is_rela = (d.d_un.d_val == DT_RELA);
                break;
            default: break;
        }
    }
    (void)jmprel_is_rela;
    if (symtab == 0 || strtab == 0 || strsz == 0 || strsz > 8 * 1024 * 1024) {
        fclose(fp);
        return nullptr;
    }
    auto vaddr_to_off = [&](uintptr_t va) -> long {
        for (const auto& p : ph) {
            if (p.p_type != PT_LOAD) continue;
            if (va >= p.p_vaddr && va < p.p_vaddr + p.p_filesz) {
                return static_cast<long>(p.p_offset + (va - p.p_vaddr));
            }
        }
        return -1;
    };
    std::vector<char> strs(strsz);
    long str_off = vaddr_to_off(strtab);
    if (str_off < 0 || fseek(fp, str_off, SEEK_SET) != 0
            || fread(strs.data(), 1, strsz, fp) != strsz) {
        fclose(fp);
        return nullptr;
    }
    auto scan_rela = [&](uintptr_t table, size_t bytes) -> void* {
        if (table == 0 || bytes == 0 || bytes > 4 * 1024 * 1024) return nullptr;
        long off = vaddr_to_off(table);
        if (off < 0) return nullptr;
        size_t n = bytes / sizeof(RelaT);
        std::vector<RelaT> rels(n);
        if (fseek(fp, off, SEEK_SET) != 0
                || fread(rels.data(), sizeof(RelaT), n, fp) != n) {
            return nullptr;
        }
        for (const auto& r : rels) {
#ifdef __LP64__
            uint32_t type = ELF64_R_TYPE(r.r_info);
            uint32_t si = static_cast<uint32_t>(ELF64_R_SYM(r.r_info));
            const bool slot = type == 1026u || type == 1025u  // AARCH64 JUMP_SLOT / GLOB_DAT
                    || type == 7u || type == 6u;              // X86_64 JUMP_SLOT / GLOB_DAT
#else
            uint32_t type = ELF32_R_TYPE(r.r_info);
            uint32_t si = ELF32_R_SYM(r.r_info);
            const bool slot = type == 22u || type == 21u  // ARM JUMP_SLOT / GLOB_DAT
                    || type == 7u || type == 6u;          // i386 JUMP_SLOT / GLOB_DAT
#endif
            if (!slot) continue;
            long sym_off = vaddr_to_off(symtab + static_cast<uintptr_t>(si) * syment);
            if (sym_off < 0) continue;
            SymT sy{};
            if (fseek(fp, sym_off, SEEK_SET) != 0
                    || fread(&sy, 1, sizeof(sy), fp) != sizeof(sy)) {
                continue;
            }
            if (sy.st_name >= strsz) continue;
            if (strcmp(strs.data() + sy.st_name, want) != 0) continue;
            return reinterpret_cast<void*>(load_bias + static_cast<uintptr_t>(r.r_offset));
        }
        return nullptr;
    };
    void* hit = scan_rela(jmprel, pltrelsz);
    if (hit == nullptr) hit = scan_rela(rel, relsz);
    fclose(fp);
    return hit;
}

struct LinkerInfo {
    uintptr_t load_bias = 0;
    char path[512]{};
};

static int linker_phdr_cb(struct dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<LinkerInfo*>(data);
    if (info == nullptr || info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') {
        return 0;
    }
    const char* base = strrchr(info->dlpi_name, '/');
    base = base ? base + 1 : info->dlpi_name;
    if (strcmp(base, "linker") != 0 && strcmp(base, "linker64") != 0) return 0;
    out->load_bias = static_cast<uintptr_t>(info->dlpi_addr);
    strncpy(out->path, info->dlpi_name, sizeof(out->path) - 1);
    return 1;
}

static bool find_linker_info(LinkerInfo* out) {
    if (out == nullptr) return false;
    out->load_bias = 0;
    out->path[0] = 0;
    dl_iterate_phdr(linker_phdr_cb, out);
    if (out->path[0] != 0) return true;
    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return false;
    std::string line;
    while (protector::read_maps_record(fp, &line)) {
        if (line.find("r-xp") == std::string::npos && line.find("r-x") == std::string::npos) {
            continue;
        }
        std::string map_path;
        if (!protector::maps_pathname(line, &map_path)) continue;
#ifdef __LP64__
        unsigned long long start = 0;
        if (sscanf(line.c_str(), "%llx-", &start) != 1) continue;
#else
        unsigned long start = 0;
        if (sscanf(line.c_str(), "%lx-", &start) != 1) continue;
#endif
        const char* base = strrchr(map_path.c_str(), '/');
        base = base != nullptr ? base + 1 : map_path.c_str();
        if (strcmp(base, "linker") != 0 && strcmp(base, "linker64") != 0) continue;
        out->load_bias = static_cast<uintptr_t>(start);
        strncpy(out->path, map_path.c_str(), sizeof(out->path) - 1);
        fclose(fp);
        return true;
    }
    fclose(fp);
    return false;
}

static std::string fd_path_raw(int fd) {
    if (fd < 0) return {};
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    char buf[PATH_MAX];
    ssize_t n = syscall(__NR_readlinkat, AT_FDCWD, proc, buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = 0;
    return std::string(buf, static_cast<size_t>(n));
}

static thread_local int g_extract_decrypt_depth = 0;

static bool is_plaintext_helper_path(const char* path) {
    if (path == nullptr) return false;
    return strstr(path, "/so_plain/") != nullptr
            || strstr(path, "/lib_mirror/") != nullptr
            || strstr(path, "memfd:") != nullptr;
}

static std::string maps_basename(std::string path) {
    const std::string deleted = " (deleted)";
    if (path.size() > deleted.size()
            && path.compare(path.size() - deleted.size(), deleted.size(), deleted) == 0) {
        path.resize(path.size() - deleted.size());
    }
    return basename_of(path.c_str());
}

/** First non-helper maps path for {@code base}, or empty. */
static std::string first_packaged_map_path(const std::string& base) {
    if (base.empty()) return {};
    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return {};
    std::string line;
    std::string hit;
    while (protector::read_maps_record(fp, &line)) {
        std::string path;
        if (!protector::maps_pathname(line, &path)) continue;
        if (is_plaintext_helper_path(path.c_str())) continue;
        if (basename_of(path.c_str()) != base) continue;
        hit = std::move(path);
        break;
    }
    fclose(fp);
    return hit;
}

static bool extract_text_decrypt_ready(const std::string& base) {
    const std::string path = first_packaged_map_path(base);
    if (path.empty()) return false;
    MappedText loc{};
    return locate_mapped_text(path, &loc);
}

static void decrypt_extract_inode_mapped() {
    if (g_extract_decrypt_depth > 0) return;
    if (!has_sokeys()) return;
    std::unordered_set<std::string> pending;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (const auto& k : g_keys) {
            if (g_extract_inode_decrypted.count(k.name) == 0) {
                pending.insert(k.name);
            }
        }
    }
    if (pending.empty()) return;

    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return;
    std::vector<std::string> to_decrypt;
    std::unordered_set<std::string> saw_plain;
    std::string line;
    while (protector::read_maps_record(fp, &line)) {
        std::string path;
        if (!protector::maps_pathname(line, &path)) continue;
        if (path.find(".so") == std::string::npos) continue;
        if (is_plaintext_helper_path(path.c_str())) continue;
        std::string base = basename_of(path.c_str());
        auto it = pending.find(base);
        if (it == pending.end()) continue;
        if (mapping_is_known_plaintext(base, path)) {
            saw_plain.insert(base);
            continue;
        }
        to_decrypt.push_back(base);
        pending.erase(it);
        saw_plain.erase(base);
        if (pending.empty()) break;
    }
    fclose(fp);

    for (const auto& name : saw_plain) {
        if (pending.count(name) == 0) continue;
        std::lock_guard<std::mutex> lock(g_mu);
        g_extract_inode_decrypted.insert(name);
    }

    ++g_extract_decrypt_depth;
    for (const auto& name : to_decrypt) {
        (void)decrypt_loaded_text(name);
    }
    --g_extract_decrypt_depth;
}

using LinkerMmapFn = void* (*)(void*, size_t, int, int, int, off_t);
static LinkerMmapFn g_orig_linker_mmap = nullptr;
#if defined(__LP64__)
static LinkerMmapFn g_orig_linker_mmap64 = nullptr;
#endif
using LinkerCallCtorsFn = void (*)(void*);
static LinkerCallCtorsFn g_orig_call_constructors = nullptr;
using LoaderDlopenExt4Fn = void* (*)(const char*, int, const android_dlextinfo*, const void*);
static LoaderDlopenExt4Fn g_orig_loader_dlopen_ext = nullptr;
static std::string path_for_dlopen(const char* filename);
static void note_or_decrypt(const char* filename);
static void diag_log_dlopen(const std::string& base, const std::string& path, const char* note);
static bool is_keyed_basename(const std::string& base);
static bool file_execmod_ok();
static void* hooked_loader_android_dlopen_ext(const char* filename, int flags,
                                              const android_dlextinfo* extinfo,
                                              const void* caller);

struct LinkerHookScope {
    LinkerHookScope() { ++g_in_linker_hook; }
    ~LinkerHookScope() { --g_in_linker_hook; }
};

static void on_linker_file_mmap(const std::string& fpath) {
    if (g_in_execmod_probe > 0) return;
    if (fpath.empty() || is_plaintext_helper_path(fpath.c_str())) return;
    const std::string base = maps_basename(fpath);
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_extract_inode_decrypted.count(base) != 0) return;
        if (find_key_unlocked(base) == nullptr) return;
    }
    // Partial segment: lowest PT_LOAD may not be mapped yet. Do not RC4 and do
    // not mark the basename safe. call_constructors retries once the image is whole.
    if (!extract_text_decrypt_ready(base)) return;
    maybe_decrypt_by_name(base);
}

static void* hooked_linker_mmap(void* addr, size_t length, int prot, int flags,
                                int fd, off_t offset) {
    LinkerHookScope in_linker;
    void* p = g_orig_linker_mmap != nullptr
            ? g_orig_linker_mmap(addr, length, prot, flags, fd, offset)
            : mmap(addr, length, prot, flags, fd, offset);
    if (p == MAP_FAILED || fd < 0 || (flags & MAP_ANONYMOUS) != 0) return p;
    if ((prot & PROT_READ) == 0) return p;
    on_linker_file_mmap(fd_path_raw(fd));
    return p;
}

#if defined(__LP64__)
static void* hooked_linker_mmap64(void* addr, size_t length, int prot, int flags,
                                  int fd, off_t offset) {
    LinkerHookScope in_linker;
    void* p = g_orig_linker_mmap64 != nullptr
            ? g_orig_linker_mmap64(addr, length, prot, flags, fd, offset)
            : mmap(addr, length, prot, flags, fd, offset);
    if (p == MAP_FAILED || fd < 0 || (flags & MAP_ANONYMOUS) != 0) return p;
    if ((prot & PROT_READ) == 0) return p;
    on_linker_file_mmap(fd_path_raw(fd));
    return p;
}
#endif

/**
 * soinfo layout is not stable across API 23–35. Match only an absolute path
 * (starts with '/', ends with '/' + basename) in readable words, so a bare
 * DT_NEEDED soname cannot skip an unrelated constructor (for example libc).
 */
static bool soinfo_blocks_constructors(void* soinfo, std::string* hit) {
    if (soinfo == nullptr || hit == nullptr) return false;
    std::vector<std::string> failed;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        failed.reserve(g_text_write_failed.size());
        for (const auto& name : g_text_write_failed) {
            if (g_extract_inode_decrypted.count(name) == 0) failed.push_back(name);
        }
    }
    if (failed.empty()) return false;
    uintptr_t words[32];
    const auto base = reinterpret_cast<uintptr_t>(soinfo);
    if (!vm_read_local(words, base, sizeof(words))) return false;
    for (uintptr_t word : words) {
        if (word < 4096) continue;
        char buf[512];
        size_t n = 0;
        bool ended = false;
        while (n + 1 < sizeof(buf)) {
            if (n > 0 && word > static_cast<uintptr_t>(-1) - n) break;
            char c = 0;
            if (!vm_read_local(&c, word + n, 1)) break;
            buf[n++] = c;
            if (c == '\0') {
                ended = true;
                break;
            }
        }
        if (!ended || n < 2 || buf[0] != '/') continue;
        if (is_plaintext_helper_path(buf)) continue;
        const size_t len = n - 1;
        for (const auto& name : failed) {
            const std::string suffix = "/" + name;
            if (len < suffix.size()) continue;
            if (memcmp(buf + (len - suffix.size()), suffix.data(), suffix.size()) != 0) {
                continue;
            }
            *hit = name;
            return true;
        }
    }
    return false;
}

static void hooked_call_constructors(void* soinfo) {
    LinkerHookScope in_linker;
    // Must run before constructors even if mmap hook missed (ART/linker
    // mmap variants). Splash initOSG maps libopencv_world from extract.
    decrypt_extract_inode_mapped();
    std::string blocked;
    if (soinfo_blocks_constructors(soinfo, &blocked)) {
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s skip call_constructors — .text still ciphertext",
                   blocked.c_str());
        PLOGE("business so: skip constructors, in-memory .text write failed %s",
              blocked.c_str());
        return;
    }
    if (g_orig_call_constructors != nullptr) {
        g_orig_call_constructors(soinfo);
    }
}

static void install_linker_extract_hooks() {
    if (g_extract_inode_hooks_ok.load(std::memory_order_acquire)) return;
    LinkerInfo li{};
    if (!find_linker_info(&li) || li.path[0] == 0) {
        PLOGW("business so: linker not found — extract-inode decrypt disabled");
        return;
    }
    bool any = false;
    void* mmap_addr = resolve_linker_symbol(li.path, li.load_bias, "mmap", nullptr);
    if (mmap_addr != nullptr) {
        int rc = DobbyHook(mmap_addr, reinterpret_cast<dobby_dummy_func_t>(hooked_linker_mmap),
                           reinterpret_cast<dobby_dummy_func_t*>(&g_orig_linker_mmap));
        if (rc == 0) {
            any = true;
            PLOGI("business so: linker mmap hooked path=%s", li.path);
        } else {
            PLOGW("business so: linker mmap DobbyHook rc=%d", rc);
        }
    }
#if defined(__LP64__)
    // armeabi-v7a mmap64 takes off64_t. Hooking it with off_t mis-aligns the
    // offset and maps the wrong file pages. 32-bit keeps mmap only.
    void* mmap64_addr = resolve_linker_symbol(li.path, li.load_bias, "mmap64", nullptr);
    if (mmap64_addr != nullptr && mmap64_addr != mmap_addr) {
        int rc = DobbyHook(mmap64_addr,
                           reinterpret_cast<dobby_dummy_func_t>(hooked_linker_mmap64),
                           reinterpret_cast<dobby_dummy_func_t*>(&g_orig_linker_mmap64));
        if (rc == 0) {
            any = true;
            PLOGI("business so: linker mmap64 hooked");
        }
    }
#endif
    void* ctors = resolve_linker_symbol(li.path, li.load_bias, nullptr, "call_constructors");
    if (ctors == nullptr) {
        ctors = resolve_linker_symbol(li.path, li.load_bias, nullptr, "CallConstructors");
    }
    if (ctors != nullptr) {
        int rc = DobbyHook(ctors, reinterpret_cast<dobby_dummy_func_t>(hooked_call_constructors),
                           reinterpret_cast<dobby_dummy_func_t*>(&g_orig_call_constructors));
        if (rc == 0) {
            any = true;
            PLOGI("business so: linker call_constructors hooked path=%s", li.path);
        } else {
            PLOGW("business so: linker call_constructors DobbyHook rc=%d", rc);
        }
    } else {
        PLOGW("business so: linker call_constructors symbol missing path=%s", li.path);
    }
    // ART LoadNativeLibrary goes linker __loader_android_dlopen_ext (apex
    // libnativeloader → libdl). bytehook_hook_all does not see that export, so
    // keyed extract paths skip fake_android_dlopen_ext (Hi-MC libcpbase SIGILL).
    void* loader_ext = resolve_linker_symbol(li.path, li.load_bias,
                                             "__loader_android_dlopen_ext", nullptr);
    if (loader_ext == nullptr) {
        loader_ext = resolve_linker_symbol(li.path, li.load_bias,
                                           "android_dlopen_ext", nullptr);
    }
    if (loader_ext != nullptr) {
        int rc = DobbyHook(loader_ext,
                           reinterpret_cast<dobby_dummy_func_t>(hooked_loader_android_dlopen_ext),
                           reinterpret_cast<dobby_dummy_func_t*>(&g_orig_loader_dlopen_ext));
        if (rc == 0) {
            any = true;
            xop_so_log(ANDROID_LOG_INFO,
                       "[XOP-SO] linker __loader_android_dlopen_ext hooked");
            PLOGI("business so: linker __loader_android_dlopen_ext hooked");
        } else {
            PLOGW("business so: linker android_dlopen_ext DobbyHook rc=%d", rc);
        }
    }
    if (any) {
        g_extract_inode_hooks_ok.store(true, std::memory_order_release);
        hide_extract_inode_helpers();
        PLOGI("business so: extract-inode in-memory decrypt enabled");
    } else {
        PLOGW("business so: no linker mmap/ctors hook — keep so_plain path-load");
    }
}

static bool file_execmod_ok() {
    const int cached = g_file_execmod.load(std::memory_order_acquire);
    if (cached >= 0) return cached == 1;
    std::string nld;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
    }
    if (nld.empty()) {
        PLOGW("business so: execmod probe skipped (nativeLibraryDir empty)");
        return false;
    }
    DIR* dir = opendir(nld.c_str());
    if (dir == nullptr) {
        PLOGW("business so: execmod probe opendir %s errno=%d", nld.c_str(), errno);
        return false;
    }
    const int ps = getpagesize() > 0 ? getpagesize() : 4096;
    bool saw_so = false;
    bool mapped = false;
    bool ok = false;
    int saved_errno = 0;
    while (dirent* de = readdir(dir)) {
        const char* name = de->d_name;
        const size_t nlen = strlen(name);
        if (nlen < 4 || strcmp(name + nlen - 3, ".so") != 0) continue;
        saw_so = true;
        const std::string path = nld + "/" + name;
        ++g_in_execmod_probe;
        const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            saved_errno = errno;
            --g_in_execmod_probe;
            continue;
        }
        void* mapped_page = mmap(nullptr, static_cast<size_t>(ps), PROT_READ | PROT_EXEC,
                                 MAP_PRIVATE, fd, 0);
        close(fd);
        if (mapped_page == MAP_FAILED) {
            saved_errno = errno;
            --g_in_execmod_probe;
            continue;
        }
        mapped = true;
        int rc = mprotect(mapped_page, static_cast<size_t>(ps),
                          PROT_READ | PROT_WRITE | PROT_EXEC);
        if (rc != 0) {
            saved_errno = errno;
            rc = mprotect(mapped_page, static_cast<size_t>(ps), PROT_READ | PROT_WRITE);
            if (rc != 0) saved_errno = errno;
        }
        ok = rc == 0;
        munmap(mapped_page, static_cast<size_t>(ps));
        --g_in_execmod_probe;
        break;
    }
    closedir(dir);
    if (!mapped) {
        if (!saw_so) {
            PLOGW("business so: execmod probe found no packaged .so under %s", nld.c_str());
            return false;
        }
        g_file_execmod.store(0, std::memory_order_release);
        PLOGE("business so: execmod probe could not mmap packaged .so RX errno=%d",
              saved_errno);
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL execmod probe mmap RX failed errno=%d dir=%s",
                   saved_errno, nld.c_str());
        return false;
    }
    g_file_execmod.store(ok ? 1 : 0, std::memory_order_release);
    if (ok) {
        PLOGI("business so: file-backed execmod probe ok dir=%s", nld.c_str());
        xop_so_log(ANDROID_LOG_INFO, "[XOP-SO] execmod probe ok dir=%s", nld.c_str());
    } else {
        PLOGE("business so: file-backed execmod denied errno=%d dir=%s",
              saved_errno, nld.c_str());
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL execmod probe denied errno=%d dir=%s",
                   saved_errno, nld.c_str());
    }
    return ok;
}

static KeyedOpenPlan plan_keyed_open(const std::string& base, const std::string& plain_path) {
    KeyedOpenPlan plan;
    plan.base = base;
    plan.content_path = plain_path;
    plan.linker_name = plain_path;
    plan.so_plain_path = plain_path;
    plan.use_library_fd = false;
    if (base.empty() || plain_path.empty() || !file_exists_path(plain_path)) {
        return plan;
    }
    std::string nld;
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
    }
    if (nld.empty()) {
        {
            std::lock_guard<std::mutex> lock(g_diag_mu);
            SoDiagRec& r = g_diag[base];
            r.layer = "L3";
            if (r.state == nullptr || strcmp(r.state, "UNKNOWN") == 0) {
                r.state = "PLAINTEXT";
            }
            r.output = plain_path;
            diag_emit(base, r);
        }
        PLOGI("business so: load L3 so_plain (no nld) %s", base.c_str());
        return plan;
    }
    std::string extract = nld + "/" + base;
    // L1-fast: extract already holds verified plaintext (published during
    // materialize). Prefer this for ANY size — maps/dladdr match stock
    // /data/app/.../lib and fix Hi-MC OSG excavator transforms.
    if (extract_holds_plaintext(base, extract)) {
        plan.linker_name = extract;
        plan.content_path = extract;
        plan.use_library_fd = false;
        {
            std::lock_guard<std::mutex> lock(g_dladdr_mu);
            g_dladdr_extract[base] = extract;
        }
        {
            std::lock_guard<std::mutex> lock(g_diag_mu);
            SoDiagRec& r = g_diag[base];
            r.layer = "L1";
            if (r.state == nullptr || strcmp(r.state, "UNKNOWN") == 0) {
                r.state = "PLAINTEXT";
            }
            r.output = extract;
            diag_emit(base, r);
        }
        PLOGI("business so: load L1 extract (already plain) %s", base.c_str());
        return plan;
    }
    // L1-publish: small SOs only on the load path (large copies belong in
    // materialize worker — see publish_keyed_extract_mirrors).
    const off_t plain_sz = file_size_path(plain_path);
    const bool l1_size_ok = plain_sz > 0 && plain_sz <= 32 * 1024 * 1024;
    if (l1_size_ok && extract_dir_writable(nld) && file_exists_path(extract)
            && !cache_root.empty()) {
        std::string cipher_dir = cache_root + "/so_cipher";
        mkdir(cipher_dir.c_str(), 0700);
        std::string cipher = cipher_dir + "/" + base;
        bool archived = file_exists_path(cipher)
                || copy_file_bytes(extract, cipher, /*force=*/true);
        if (!archived) {
            PLOGW("business so: L1 cipher archive failed %s — trying L2", base.c_str());
        } else if (copy_file_bytes(plain_path, extract, /*force=*/true)) {
            note_extract_published(base);
            note_plain_inode(base, extract);
            plan.linker_name = extract;
            plan.content_path = extract;
            plan.use_library_fd = false;
            {
                std::lock_guard<std::mutex> lock(g_dladdr_mu);
                g_dladdr_extract[base] = extract;
            }
            {
                std::lock_guard<std::mutex> lock(g_diag_mu);
                SoDiagRec& r = g_diag[base];
                r.layer = "L1";
                if (r.state == nullptr || strcmp(r.state, "UNKNOWN") == 0) {
                    r.state = "PLAINTEXT";
                }
                r.output = extract;
                diag_emit(base, r);
            }
            PLOGI("business so: load L1 extract plain %s", base.c_str());
            return plan;
        } else {
            PLOGW("business so: L1 publish failed %s — trying L2", base.c_str());
        }
    }
    // L2e: map the packaged extract inode (stock /data/app/.../lib path) and
    // RC4 .text in memory before constructors. so_plain path-load keeps the
    // kernel maps path on code_cache, which breaks Teigha static modules.
    if (extract_inode_hooks_ok() && needs_extract_inode(base)
            && file_exists_path(extract)) {
        if (!file_execmod_ok()) {
            plan.linker_name.clear();
            plan.content_path.clear();
            plan.in_memory_decrypt = false;
            {
                std::lock_guard<std::mutex> lock(g_diag_mu);
                SoDiagRec& r = g_diag[base];
                r.layer = "L2e";
                r.state = "ENCRYPTED";
                r.output.clear();
                diag_emit(base, r);
            }
            diag_log_dlopen(base, {}, "blocked_execmod");
            PLOGE("business so: FATAL execmod denied, refuse L2e %s", base.c_str());
            xop_so_log(ANDROID_LOG_ERROR,
                       "[XOP-SO] FATAL name=%s execmod denied — refuse in-place "
                       "extract .text decrypt (so_plain path would break kernel maps)",
                       base.c_str());
            return plan;
        }
        pin_plain_needed_for_extract(extract);
        plan.linker_name = extract;
        plan.content_path = extract;
        plan.use_library_fd = false;
        plan.in_memory_decrypt = true;
        {
            std::lock_guard<std::mutex> lock(g_dladdr_mu);
            g_dladdr_extract[base] = extract;
        }
        {
            std::lock_guard<std::mutex> lock(g_diag_mu);
            SoDiagRec& r = g_diag[base];
            r.layer = "L2e";
            r.state = "ENCRYPTED";
            r.output = extract;
            diag_emit(base, r);
        }
        PLOGI("business so: load L2e extract inode + in-memory decrypt %s",
              base.c_str());
        return plan;
    }
    // Ensure lib_mirror has an entry ClassLoader can open. Prefer symlink →
    // extract when extract is already plain (maps resolve to /data/app).
    if (!cache_root.empty()) {
        std::string mirror_dir = cache_root + "/" + kLibMirror;
        std::string mirror_so = mirror_dir + "/" + base;
        mkdir(mirror_dir.c_str(), 0700);
        if (extract_holds_plaintext(base, extract)) {
            (void)symlink_plain_dep(extract, mirror_so);
        } else if (!file_exists_path(mirror_so) && file_exists_path(plain_path)) {
            (void)plant_hardlink_or_copy(plain_path, mirror_so);
        }
    }
    // Opportunistic extract map (hooks ok, so_plain not ready, not l2e=true).
    // path_for_dlopen only returns this path after the file-backed execmod probe.
    // Mark in-memory so a failed .text write dlcloses instead of reaching JNI_OnLoad.
    // needs_extract_inode stays off this branch: those SOs are L2e or FATAL above,
    // and must not use LIBRARY_FD (Teigha .rela.dyn).
    const bool extract_cipher = plain_path == extract && !extract.empty()
            && extract_inode_hooks_ok()
            && !extract_holds_plaintext(base, extract);
    const bool fd_load = !extract_cipher && !needs_extract_inode(base)
            && !plain_path.empty() && plain_path != extract;
    if (extract_cipher) {
        plan.in_memory_decrypt = true;
        plan.use_library_fd = false;
        plan.linker_name = plain_path;
        plan.content_path = plain_path;
    } else if (fd_load) {
        // Content stays the plaintext file. The dlopen name is the packaged
        // extract path only for the call that actually passes the fd. If that
        // fd cannot be opened, dlopen_keyed_plan path-loads content_path.
        plan.in_memory_decrypt = false;
        plan.use_library_fd = true;
        plan.content_path = plain_path;
        plan.so_plain_path = plain_path;
        if (!extract.empty() && file_exists_path(extract)) {
            plan.linker_name = extract;
        } else {
            plan.linker_name = plain_path;
        }
    } else if (plain_path == extract && !extract_holds_plaintext(base, extract)) {
        plan.linker_name.clear();
        plan.content_path.clear();
        plan.use_library_fd = false;
        PLOGE("business so: refuse ciphertext path-load %s", base.c_str());
        xop_so_log(ANDROID_LOG_ERROR,
                   "[XOP-SO] FATAL name=%s refuse ciphertext extract path-load",
                   base.c_str());
        return plan;
    } else {
        plan.in_memory_decrypt = false;
        plan.use_library_fd = false;
        plan.linker_name = plain_path;
        plan.content_path = plain_path;
    }
    {
        std::lock_guard<std::mutex> lock(g_dladdr_mu);
        g_dladdr_extract[base] = extract;
    }
    {
        std::lock_guard<std::mutex> lock(g_diag_mu);
        SoDiagRec& r = g_diag[base];
        r.layer = extract_cipher ? "L2e" : (fd_load ? "L2" : "L3");
        if (extract_cipher) {
            r.state = "ENCRYPTED";
        } else if (r.state == nullptr || strcmp(r.state, "UNKNOWN") == 0) {
            r.state = "PLAINTEXT";
        }
        r.output = plan.content_path;
        diag_emit(base, r);
    }
    if (extract_cipher) {
        PLOGI("business so: load opportunistic L2e extract inode %s", base.c_str());
    } else if (fd_load) {
        PLOGI("business so: load L2 fd name=%s content=%s",
              plan.linker_name.c_str(), plan.content_path.c_str());
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] name=%s L2 fd planned linker_name=%s content=%s",
                   base.c_str(), plan.linker_name.c_str(), plan.content_path.c_str());
    } else {
        PLOGI("business so: load plaintext path-load %s", base.c_str());
    }
    return plan;
}

#if defined(__ANDROID__)
using AndroidDlopenExtFn = void* (*)(const char*, int, const android_dlextinfo*);

static thread_local int g_in_keyed_plan_fallback = 0;

static AndroidDlopenExtFn resolve_android_dlopen_ext();

static void* invoke_android_dlopen_ext(const char* name, int flags,
                                       const android_dlextinfo* info,
                                       const void* loader_caller) {
    // Saved Dobby trampoline. dlsym(__loader_android_dlopen_ext) returns the
    // hooked entry and would re-enter hooked_loader_android_dlopen_ext.
    if (g_orig_loader_dlopen_ext != nullptr) {
        return g_orig_loader_dlopen_ext(name, flags, info, loader_caller);
    }
    AndroidDlopenExtFn ext = resolve_android_dlopen_ext();
    if (ext == nullptr) return nullptr;
    return ext(name, flags, info);
}

static void* dlopen_fallback_path(const char* path, int flags) {
    ++g_in_keyed_plan_fallback;
    void* h = dlopen(path, flags);
    --g_in_keyed_plan_fallback;
    return h;
}

static AndroidDlopenExtFn resolve_android_dlopen_ext() {
    static AndroidDlopenExtFn fn = nullptr;
    static std::once_flag once;
    std::call_once(once, []() {
        // Prefer the linker export — PLT hooks may shadow libc's android_dlopen_ext.
        fn = reinterpret_cast<AndroidDlopenExtFn>(
                dlsym(RTLD_DEFAULT, "__loader_android_dlopen_ext"));
        if (fn == nullptr) {
            fn = reinterpret_cast<AndroidDlopenExtFn>(
                    dlsym(RTLD_NEXT, "android_dlopen_ext"));
        }
        if (fn == nullptr) {
            fn = reinterpret_cast<AndroidDlopenExtFn>(
                    dlsym(RTLD_DEFAULT, "android_dlopen_ext"));
        }
    });
    return fn;
}
#endif

/**
 * Android 10+ rejects executable mappings from writable app dirs
 * (code_cache/so_plain) when the app targets API 29 or newer.
 */
static bool writable_app_exec_blocked() {
#if defined(__ANDROID__)
    if (android_get_device_api_level() < 29) return false;
    using TargetFn = int (*)();
    auto* fn = reinterpret_cast<TargetFn>(
            dlsym(RTLD_DEFAULT, "android_get_application_target_sdk_version"));
    if (fn == nullptr) return true;
    return fn() >= 29;
#else
    return false;
#endif
}

/** JNI_OnLoad runs after dlopen returns. A skipped constructor is not enough. */
static void* release_if_text_still_cipher(void* handle, const KeyedOpenPlan& plan) {
    if (handle == nullptr || !plan.in_memory_decrypt || !text_write_failed(plan.base)) {
        return handle;
    }
    dlclose(handle);
    PLOGE("business so: FATAL dlclose after .text write failed %s", plan.base.c_str());
    xop_so_log(ANDROID_LOG_ERROR,
               "[XOP-SO] FATAL name=%s dlclose — in-memory .text write failed, "
               "JNI_OnLoad must not run",
               plan.base.c_str());
    return nullptr;
}

/** Open keyed SO per L1/L2/L3. Does not go through bytehook stubs (avoids recursion). */
static void* dlopen_keyed_plan(const KeyedOpenPlan& plan, int flags,
                               const void* caller_extinfo,
                               const void* loader_caller = nullptr) {
    if (plan.content_path.empty()) return nullptr;
#if defined(__ANDROID__)
    if (plan.use_library_fd) {
        bool used_memfd = false;
        int fd = create_memfd_from_path(plan.content_path, plan.base.c_str());
        if (fd >= 0) {
            used_memfd = true;
        } else {
            fd = open(plan.content_path.c_str(), O_RDONLY | O_CLOEXEC);
        }
        if (fd >= 0) {
            android_dlextinfo info{};
            // Preserve only namespace from caller. Do NOT copy USE_LIBRARY_FD(_OFFSET)
            // — ClassLoader often passes an APK zip fd+offset; mixing that with our
            // so_plain fd makes L2 fail and fall back to L3 (so_plain path → TTIN).
            if (caller_extinfo != nullptr) {
                const auto* c = reinterpret_cast<const android_dlextinfo*>(caller_extinfo);
                if ((c->flags & ANDROID_DLEXT_USE_NAMESPACE) != 0 &&
                    c->library_namespace != nullptr) {
                    info.flags |= ANDROID_DLEXT_USE_NAMESPACE;
                    info.library_namespace = c->library_namespace;
                }
            }
            info.flags |= ANDROID_DLEXT_USE_LIBRARY_FD;
            info.library_fd = fd;
            info.library_fd_offset = 0;
            // Mark before ext() so .init_array / JNI_OnLoad skip in-memory RC4.
            mark_keyed_mapped_plain(plan.base);
            // linker_name is the extract path only while this fd is the content.
            void* h = invoke_android_dlopen_ext(plan.linker_name.c_str(), flags, &info,
                                                loader_caller);
            close(fd);
            if (h != nullptr) {
                maybe_drop_so_plain_mirror(plan);
                xop_so_log(ANDROID_LOG_INFO,
                           "[XOP-SO] name=%s L2 opened fd=%s linker_name=%s",
                           plan.base.c_str(), used_memfd ? "memfd" : "file",
                           plan.linker_name.c_str());
                if (used_memfd) {
                    PLOGI("business so: L2 content=memfd %s", plan.base.c_str());
                }
                return release_if_text_still_cipher(h, plan);
            }
            unmark_keyed_mapped_plain(plan.base);
            __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                    "L2 fail %s err=%s", plan.linker_name.c_str(), dlerror());
        } else {
            __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                    "L2 open fd fail %s errno=%d", plan.content_path.c_str(), errno);
        }
        // FD was not used. Never path-load linker_name (ciphertext extract).
        // targetSdk>=29 cannot execute so_plain from code_cache; fail closed.
        if (writable_app_exec_blocked()) {
            {
                std::lock_guard<std::mutex> lock(g_diag_mu);
                SoDiagRec& r = g_diag[plan.base];
                r.layer = "L2";
                r.output.clear();
                diag_emit(plan.base, r);
            }
            PLOGE("business so: FATAL L2 fd failed, refuse so_plain path-load %s",
                  plan.base.c_str());
            xop_so_log(ANDROID_LOG_ERROR,
                       "[XOP-SO] FATAL name=%s L2 fd failed — refuse so_plain "
                       "path-load (targetSdk>=29)",
                       plan.base.c_str());
            return nullptr;
        }
        {
            std::lock_guard<std::mutex> lock(g_diag_mu);
            SoDiagRec& r = g_diag[plan.base];
            r.layer = "L3";
            r.output = plan.content_path;
            diag_emit(plan.base, r);
        }
        return release_if_text_still_cipher(
                dlopen_fallback_path(plan.content_path.c_str(), flags), plan);
    }
    // Path load (no FD): L1 plaintext extract, or L2e in-memory decrypt.
    {
        android_dlextinfo info{};
        const android_dlextinfo* ext_arg = nullptr;
        if (caller_extinfo != nullptr) {
            const auto* c = reinterpret_cast<const android_dlextinfo*>(caller_extinfo);
            if ((c->flags & ANDROID_DLEXT_USE_NAMESPACE) != 0 &&
                c->library_namespace != nullptr) {
                info.flags |= ANDROID_DLEXT_USE_NAMESPACE;
                info.library_namespace = c->library_namespace;
                ext_arg = &info;
            }
        }
        if (!plan.in_memory_decrypt) {
            mark_keyed_mapped_plain(plan.base);
        }
        void* h = invoke_android_dlopen_ext(plan.linker_name.c_str(), flags, ext_arg,
                                            loader_caller);
        if (h != nullptr) {
            maybe_drop_so_plain_mirror(plan);
            if (plan.in_memory_decrypt) {
                PLOGI("business so: L2e extract path-load %s", plan.base.c_str());
            } else {
                PLOGI("business so: L2 path-load %s", plan.base.c_str());
            }
            return release_if_text_still_cipher(h, plan);
        }
        if (!plan.in_memory_decrypt) {
            unmark_keyed_mapped_plain(plan.base);
        }
        __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                "L2 path-load fail %s err=%s — libc dlopen",
                plan.linker_name.c_str(), dlerror());
    }
#else
    (void)caller_extinfo;
    (void)loader_caller;
#endif
    if (!plan.in_memory_decrypt) {
        mark_keyed_mapped_plain(plan.base);
    }
    void* h = dlopen_fallback_path(plan.content_path.c_str(), flags);
    if (h != nullptr) {
        // L1: extract holds plaintext; drop the so_plain duplicate. L3 (no nld): keep.
        if (plan.content_path != plan.so_plain_path) {
            maybe_drop_so_plain_mirror(plan);
        }
        return release_if_text_still_cipher(h, plan);
    }
    if (!plan.in_memory_decrypt) {
        unmark_keyed_mapped_plain(plan.base);
    }
    return nullptr;
}

static bool file_exists_path(const std::string& path);
static std::vector<std::string> read_dt_needed(const std::string& path);
static void copy_plain_deps(const std::string& out_dir, const std::string& nld);
static bool symlink_plain_dep(const std::string& src, const std::string& dst);
static bool is_system_soname(const std::string& need);

static off_t file_size_path(const std::string& path) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) return -1;
    return st.st_size;
}

static std::string keyed_warm_path(const std::string& out_dir, const std::string& name) {
    if (out_dir.empty() || name.empty()) return {};
    std::string ov = out_dir + "/" + kOverlaySubdir + "/" + name;
    if (file_exists_path(ov)) return ov;
    return out_dir + "/" + name;
}

/**
 * Hide extract-inode megacores from ClassLoader helper dirs so loadLibrary
 * falls through to packaged extract. Keep decrypted bytes under .xop_plain
 * for warm size checks (not a load name).
 */
static void hide_extract_inode_helpers() {
    if (!extract_inode_hooks_ok()) return;
    std::string cache_root;
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    if (cache_root.empty()) return;
    std::string plain = cache_root + "/so_plain";
    std::string overlay = plain + "/" + kOverlaySubdir;
    std::string mirror = cache_root + "/" + kLibMirror;
    mkdir(plain.c_str(), 0700);
    mkdir(overlay.c_str(), 0700);
    int hidden = 0;
    for (const auto& name : names) {
        if (!needs_extract_inode(name)) continue;
        std::string src = plain + "/" + name;
        std::string dst = overlay + "/" + name;
        if (file_exists_path(src)) {
            unlink(dst.c_str());
            if (rename(src.c_str(), dst.c_str()) != 0) {
                if (copy_file_bytes(src, dst, /*force=*/true)) {
                    unlink(src.c_str());
                }
            }
            hidden++;
        }
        unlink((mirror + "/" + name).c_str());
    }
    if (hidden > 0) {
        PLOGI("business so: hid %d extract-inode SO(s) from ClassLoader helpers",
              hidden);
    }
}

static void drop_so_plain_ready(const std::string& out_dir) {
    unlink((out_dir + "/" + kSoPlainReady).c_str());
}

static bool write_so_plain_ready(const std::string& out_dir, size_t count) {
    std::string path = out_dir + "/" + kSoPlainReady;
    FILE* fp = fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        PLOGE("business so: write %s failed errno=%d", kSoPlainReady, errno);
        return false;
    }
    fprintf(fp, "%zu\n", count);
    fflush(fp);
    fclose(fp);
    return true;
}

/** True when so_plain_ready exists and every keyed SO that exists in nld is mirrored. */
static bool so_plain_ready_ok(const std::string& out_dir,
                              const std::string& nld,
                              const std::vector<std::string>& names) {
    if (!file_exists_path(out_dir + "/" + kSoPlainReady)) return false;
    if (names.empty()) return false;
    for (const auto& name : names) {
        std::string src = keyed_packaged_src(name, nld);
        if (!file_exists_path(src)) continue; // other-ABI-only key
        if (defer_eager_disk(name)) continue;
        std::string dst = keyed_warm_path(out_dir, name);
        if (!mirror_size_matches_expect(name, dst, src)) return false;
    }
    return true;
}

/**
 * Warm reuse: size + ELF .text offset/size/addr only. Full SHA-256 of
 * megacore .text (libd3 ≈ 88 MiB) on every launch blocks the homepage.
 * Hash remains after RC4 on the materialize path.
 */
static bool so_plain_integrity_ok_or_scrub(const std::string& out_dir,
                                          const std::string& nld,
                                          const std::vector<std::string>& names) {
    bool have_diag = false;
    {
        std::lock_guard<std::mutex> lock(g_textdiag_mu);
        have_diag = !g_textdiag.empty();
    }
    if (!have_diag) return true;

    bool all_ok = true;
    for (const auto& name : names) {
        if (defer_eager_disk(name)) continue;
        std::string src = keyed_packaged_src(name, nld);
        if (!file_exists_path(src)) continue;
        std::string dst = keyed_warm_path(out_dir, name);
        if (!file_exists_path(dst)) {
            all_ok = false;
            continue;
        }
        if (!verify_text_against_diag(dst, name, /*check_hash=*/false)) {
            xop_so_log(ANDROID_LOG_ERROR,
                       "[XOP-SO] FATAL name=%s warm integrity fail — scrub mirror",
                       name.c_str());
            unlink(dst.c_str());
            all_ok = false;
        }
    }
    if (!all_ok) {
        drop_so_plain_ready(out_dir);
        PLOGE("business so: so_plain warm integrity failed — rematerialize");
    }
    return all_ok;
}

static void diag_mark_warm_ready(const std::string& out_dir,
                                 const std::vector<std::string>& names) {
    if (!so_diag_enabled()) return;
    for (const auto& name : names) {
        std::string dst = keyed_warm_path(out_dir, name);
        if (!file_exists_path(dst)) continue;
        diag_set(name, "WARM_READY", "PLAINTEXT", /*decrypt_applied=*/false,
                 /*ready_hit=*/true, /*materialize_ok=*/true, dst);
    }
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] warm ready hit count=%zu out_dir=%s",
               names.size(), out_dir.c_str());
}

/**
 * Discard leftover keyed mirrors was used when product refused cross-launch
 * plaintext. Plaintext warm restores reuse instead — keep this helper unused
 * (APK stamp still deletes so_plain/ on update).
 */
static void drop_cross_launch_so_plain(const std::string& out_dir,
                                       const std::vector<std::string>& names) {
    (void)out_dir;
    (void)names;
    // no-op: plaintext warm keeps so_plain across launches
}

static std::string so_warm_dir(const std::string& cache_root) {
    return cache_root + "/" + kSoWarmDir;
}

static std::string so_warm_blob_path(const std::string& warm_dir, const std::string& name) {
    return warm_dir + "/" + name + ".w1";
}

static bool read_all_file(const std::string& path, std::vector<uint8_t>* out) {
    if (out == nullptr) return false;
    out->clear();
    FILE* fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) return false;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return false;
    }
    long sz = ftell(fp);
    if (sz < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }
    out->resize(static_cast<size_t>(sz));
    size_t n = out->empty() ? 0 : fread(out->data(), 1, out->size(), fp);
    fclose(fp);
    if (n != out->size()) {
        out->clear();
        return false;
    }
    return true;
}

static bool write_all_file_atomic(const std::string& path, const uint8_t* data, size_t len) {
    if (data == nullptr && len != 0) return false;
    std::string tmp = path + ".tmp";
    unlink(tmp.c_str());
    FILE* fp = fopen(tmp.c_str(), "wb");
    if (fp == nullptr) return false;
    bool ok = len == 0 || fwrite(data, 1, len, fp) == len;
    if (ok) {
        fflush(fp);
#if defined(__ANDROID__)
        fsync(fileno(fp));
#endif
    }
    fclose(fp);
    if (!ok) {
        unlink(tmp.c_str());
        return false;
    }
    chmod(tmp.c_str(), 0600);
    unlink(path.c_str());
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

static bool random_nonce12(uint8_t out[12]) {
    if (out == nullptr) return false;
#if defined(__ANDROID__)
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < 12) {
        ssize_t n = read(fd, out + got, 12 - got);
        if (n <= 0) {
            close(fd);
            return false;
        }
        got += static_cast<size_t>(n);
    }
    close(fd);
    return true;
#else
    for (int i = 0; i < 12; i++) out[i] = static_cast<uint8_t>(i + 1);
    return true;
#endif
}

/**
 * Decrypt PSW1 blob → so_plain/name (ephemeral plaintext for this process).
 * @return true on success or SO not present in warm (caller falls back).
 *         false only when blob exists but is corrupt / auth fails.
 */
static bool try_hydrate_one_from_warm(const std::string& name,
                                      const std::string& warm_dir,
                                      const std::string& plain_dir,
                                      const std::string& nld) {
    if (!so_warm_key_ok() || name.empty() || is_system_soname(name)) return true;
    std::string src = keyed_packaged_src(name, nld);
    if (!file_exists_path(src)) {
        // Other-ABI-only entry.
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key != nullptr) {
            key->decrypted = true;
            key->in_flight = false;
            g_cv.notify_all();
        }
        return true;
    }
    off_t expect = file_size_path(src);
    if (expect <= 0 || expect > kWarmMaxPlainBytes) return true;

    std::string blob = so_warm_blob_path(warm_dir, name);
    std::vector<uint8_t> pkg;
    if (!read_all_file(blob, &pkg)) return true; // miss → cold path
    if (pkg.size() < 4 + 4 + crypto::GCM_NONCE_LEN + crypto::GCM_TAG_LEN) {
        unlink(blob.c_str());
        return false;
    }
    if (memcmp(pkg.data(), kPsw1Magic, 4) != 0) {
        unlink(blob.c_str());
        return false;
    }
    uint32_t plain_size = static_cast<uint32_t>(pkg[4])
            | (static_cast<uint32_t>(pkg[5]) << 8)
            | (static_cast<uint32_t>(pkg[6]) << 16)
            | (static_cast<uint32_t>(pkg[7]) << 24);
    if (static_cast<off_t>(plain_size) != expect
            || pkg.size() != 8 + crypto::GCM_NONCE_LEN + plain_size + crypto::GCM_TAG_LEN) {
        unlink(blob.c_str());
        return false;
    }
    std::vector<uint8_t> plain(plain_size);
    const uint8_t* gcm = pkg.data() + 8;
    size_t gcm_len = pkg.size() - 8;
    if (!crypto::aes128_gcm_decrypt(g_so_warm_key, gcm, gcm_len, plain.data(), plain.size())) {
        PLOGW("business so: so_warm auth fail %s — drop blob", name.c_str());
        unlink(blob.c_str());
        return false;
    }
    mkdir(plain_dir.c_str(), 0700);
    std::string dst = plain_dir + "/" + name;
    if (!write_all_file_atomic(dst, plain.data(), plain.size())) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    chmod(dst.c_str(), 0700);
    memset(plain.data(), 0, plain.size());
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key != nullptr) {
            key->decrypted = true;
            key->in_flight = false;
        }
    }
    g_cv.notify_all();
    return true;
}

/** True when every keyed SO present on this ABI has a valid warm hydrate. */
static bool try_hydrate_all_from_warm(const std::string& cache_root,
                                      const std::string& nld,
                                      const std::vector<std::string>& names) {
    if (!so_warm_key_ok() || cache_root.empty()) return false;
    std::string warm = so_warm_dir(cache_root);
    std::string ready = warm + "/" + kSoWarmReady;
    if (!file_exists_path(ready)) return false;
    std::string plain = cache_root + "/so_plain";
    mkdir(plain.c_str(), 0700);
    int need = 0;
    int ok = 0;
    for (const auto& name : names) {
        if (name.empty() || is_system_soname(name)) continue;
        std::string src = keyed_packaged_src(name, nld);
        if (!file_exists_path(src)) continue;
        off_t ss = file_size_path(src);
        // Oversized blobs are never cached; leave for RC4 / on-demand.
        if (ss <= 0 || ss > kWarmMaxPlainBytes) continue;
        need++;
        std::string blob = so_warm_blob_path(warm, name);
        if (!file_exists_path(blob)) return false;
        if (!try_hydrate_one_from_warm(name, warm, plain, nld)) return false;
        // After hydrate, decrypted flag set only on success path that wrote file.
        {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            if (key != nullptr && key->decrypted) ok++;
        }
    }
    if (need == 0 || ok != need) return false;
    PLOGI("business so: so_warm hydrate ok count=%d", ok);
    return true;
}

static bool persist_one_to_warm(const std::string& name,
                                const std::string& warm_dir,
                                const std::string& plain_path,
                                off_t expect_size) {
    if (!so_warm_key_ok() || name.empty() || is_system_soname(name)) return false;
    if (expect_size <= 0 || expect_size > kWarmMaxPlainBytes) return false;
    if (file_size_path(plain_path) != expect_size) return false;
    std::vector<uint8_t> plain;
    if (!read_all_file(plain_path, &plain) || static_cast<off_t>(plain.size()) != expect_size) {
        return false;
    }
    uint8_t nonce[12];
    if (!random_nonce12(nonce)) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    size_t gcm_cap = crypto::GCM_NONCE_LEN + plain.size() + crypto::GCM_TAG_LEN;
    std::vector<uint8_t> gcm(gcm_cap);
    size_t gcm_len = 0;
    if (!crypto::aes128_gcm_encrypt(g_so_warm_key, nonce, plain.data(), plain.size(),
                                    gcm.data(), gcm.size(), &gcm_len)) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    memset(plain.data(), 0, plain.size());
    std::vector<uint8_t> pkg(8 + gcm_len);
    memcpy(pkg.data(), kPsw1Magic, 4);
    uint32_t ps = static_cast<uint32_t>(expect_size);
    pkg[4] = static_cast<uint8_t>(ps);
    pkg[5] = static_cast<uint8_t>(ps >> 8);
    pkg[6] = static_cast<uint8_t>(ps >> 16);
    pkg[7] = static_cast<uint8_t>(ps >> 24);
    memcpy(pkg.data() + 8, gcm.data(), gcm_len);
    mkdir(warm_dir.c_str(), 0700);
    std::string blob = so_warm_blob_path(warm_dir, name);
    bool ok = write_all_file_atomic(blob, pkg.data(), pkg.size());
    memset(pkg.data(), 0, pkg.size());
    memset(gcm.data(), 0, gcm.size());
    return ok;
}

static void persist_all_to_warm(const std::string& cache_root,
                                const std::string& nld,
                                const std::vector<std::string>& names) {
    if (!so_warm_key_ok() || cache_root.empty()) return;
    std::string warm = so_warm_dir(cache_root);
    std::string plain = cache_root + "/so_plain";
    mkdir(warm.c_str(), 0700);
    int wrote = 0;
    int skip = 0;
    for (const auto& name : names) {
        if (name.empty() || is_system_soname(name)) continue;
        std::string src = keyed_packaged_src(name, nld);
        if (!file_exists_path(src)) continue;
        off_t ss = file_size_path(src);
        std::string dst = plain + "/" + name;
        bool dec = false;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            dec = key != nullptr && key->decrypted;
        }
        if (!dec || ss <= 0 || ss > kWarmMaxPlainBytes) {
            skip++;
            continue;
        }
        if (persist_one_to_warm(name, warm, dst, ss)) wrote++;
        else skip++;
    }
    // Ready mark only when every on-ABI keyed SO has a blob.
    bool complete = true;
    for (const auto& name : names) {
        if (name.empty() || is_system_soname(name)) continue;
        if (!file_exists_path(keyed_packaged_src(name, nld))) continue;
        off_t ss = file_size_path(keyed_packaged_src(name, nld));
        if (ss <= 0 || ss > kWarmMaxPlainBytes) continue; // optional skip not required
        if (!file_exists_path(so_warm_blob_path(warm, name))) {
            complete = false;
            break;
        }
    }
    if (complete && wrote > 0) {
        char body[32];
        int n = snprintf(body, sizeof(body), "%d\n", wrote);
        if (n > 0) {
            write_all_file_atomic(warm + "/" + kSoWarmReady,
                                  reinterpret_cast<const uint8_t*>(body),
                                  static_cast<size_t>(n));
        }
        PLOGI("business so: so_warm persist wrote=%d skip=%d ready=1", wrote, skip);
    } else {
        unlink((warm + "/" + kSoWarmReady).c_str());
        PLOGI("business so: so_warm persist wrote=%d skip=%d ready=0", wrote, skip);
    }
}

/** Stream-copy src→dst via temp+rename. When force=false, skip if sizes already match. */
static bool copy_file_bytes(const std::string& src, const std::string& dst, bool force) {
    off_t ss = file_size_path(src);
    if (ss <= 0) return false;
    // Already a complete mirror — skip rewrite (plain deps only).
    if (!force && file_size_path(dst) == ss) {
        return true;
    }

    std::string tmp = dst + ".tmp";
    unlink(tmp.c_str());
    FILE* in = fopen(src.c_str(), "rb");
    if (in == nullptr) return false;
    FILE* out = fopen(tmp.c_str(), "wb");
    if (out == nullptr) {
        fclose(in);
        return false;
    }

    char buf[256 * 1024];
    off_t written = 0;
    bool ok = true;
    while (written < ss) {
        size_t want = static_cast<size_t>(std::min<off_t>(sizeof(buf), ss - written));
        size_t n = fread(buf, 1, want, in);
        if (n == 0) {
            ok = false;
            break;
        }
        if (fwrite(buf, 1, n, out) != n) {
            ok = false;
            break;
        }
        written += static_cast<off_t>(n);
    }
    if (ok) {
        fflush(out);
#if defined(__ANDROID__)
        fsync(fileno(out));
#endif
    }
    fclose(out);
    fclose(in);
    if (!ok || written != ss) {
        unlink(tmp.c_str());
        return false;
    }
    chmod(tmp.c_str(), 0700);
    unlink(dst.c_str());
    if (rename(tmp.c_str(), dst.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return file_size_path(dst) == ss;
}

static bool materialize_one_keyed(const std::string& name,
                                  const std::string& out_dir,
                                  const std::string& nld);

/**
 * Copy+RC4 one keyed basename into so_plain if needed.
 * Serializes via claim_key so on-demand and background fill cannot force-copy
 * over each other (or over an already-mapped mirror).
 * @return false only when the SO is keyed, present in nld, and decrypt failed.
 */
static bool materialize_one_keyed(const std::string& name,
                                  const std::string& out_dir,
                                  const std::string& nld) {
    if (name.empty()) return true;
    // Class S: never mirror into so_plain (Conscrypt / GLES collision).
    if (is_system_soname(name)) {
        unlink((out_dir + "/" + name).c_str());
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key != nullptr) {
            key->decrypted = true;
            key->in_flight = false;
            g_cv.notify_all();
        }
        return true;
    }
    // Megacores: in-memory decrypt at first dlopen. Do not copy/RC4 100+ MiB
    // onto the Application attach / homepage path.
    if (defer_eager_disk(name)) {
        mark_key_disk_done(name);
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] name=%s eager skip disk (extract-inode L2e)",
                   name.c_str());
        return true;
    }
    if (nld.empty()) {
        PLOGW("business so: materialize_one nld unset for %s", name.c_str());
        return false;
    }
    std::string src = keyed_packaged_src(name, nld);
    std::string dst = out_dir + "/" + name;
    if (extract_inode_hooks_ok() && needs_extract_inode(name)) {
        std::string overlay = out_dir + "/" + kOverlaySubdir;
        mkdir(overlay.c_str(), 0700);
        dst = overlay + "/" + name;
    }

    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] name=%s materialize begin src=%s dst=%s",
               name.c_str(), src.c_str(), dst.c_str());

    // Other-ABI-only key: nothing on this device.
    if (!file_exists_path(src)) {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key == nullptr) return true;
        key->decrypted = true;
        key->in_flight = false;
        g_cv.notify_all();
        return true;
    }

    for (int attempt = 0; attempt < 2; attempt++) {
        uint8_t key_bytes[16];
        ClaimResult claim = claim_key(name, key_bytes);
        if (claim == ClaimResult::NotProtected) return true;
        if (claim == ClaimResult::Busy) {
            memset(key_bytes, 0, sizeof(key_bytes));
            return false;
        }
        if (claim == ClaimResult::AlreadyDone) {
            std::string warm = keyed_warm_path(out_dir, name);
            if (file_exists_path(warm) && file_size_path(warm) == file_size_path(src)) {
                if (!verify_text_against_diag(warm, name, /*check_hash=*/true)) {
                    unlink(warm.c_str());
                    unlink(dst.c_str());
                    {
                        std::lock_guard<std::mutex> lock(g_mu);
                        SoKey* key = find_key_unlocked(name);
                        if (key != nullptr) {
                            key->decrypted = false;
                            key->in_flight = false;
                        }
                    }
                    g_cv.notify_all();
                    memset(key_bytes, 0, sizeof(key_bytes));
                    continue;
                }
                diag_set(name, "MATERIALIZE", "PLAINTEXT", /*decrypt_applied=*/false,
                         /*ready_hit=*/false, /*materialize_ok=*/true, warm);
                xop_so_log(ANDROID_LOG_INFO,
                           "[XOP-SO] name=%s materialize reuse AlreadyDone dst=%s",
                           name.c_str(), warm.c_str());
                return true;
            }
            // Marked done but mirror missing/truncated — reclaim and rebuild.
            {
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = false;
                    key->in_flight = false;
                }
            }
            g_cv.notify_all();
            memset(key_bytes, 0, sizeof(key_bytes));
            continue;
        }

        // Claimed: exclusive owner for copy + decrypt.
        mkdir(out_dir.c_str(), 0700);
        const off_t ss = file_size_path(src);
        const off_t ds = file_size_path(dst);
        // Only rewrite when missing or size mismatch — never force-clobber a
        // same-sized file that may already be mmap'd as plaintext (warm reuse).
        const bool need_copy = ds <= 0 || ss <= 0 || ds != ss;
        if (need_copy) {
            xop_so_log(ANDROID_LOG_INFO,
                       "[XOP-SO] name=%s materialize copy+rc4 src_state=ENCRYPTED "
                       "src_size=%lld dst_size=%lld",
                       name.c_str(), static_cast<long long>(ss),
                       static_cast<long long>(ds));
            if (!copy_file_bytes(src, dst, /*force=*/true)) {
                PLOGW("business so: on-demand copy failed %s", name.c_str());
                memset(key_bytes, 0, sizeof(key_bytes));
                commit_key(name, false);
                unlink_so_plain_if(dst);
                diag_set(name, "MATERIALIZE", "ENCRYPTED", false, false, false, dst);
                return false;
            }
            return rc4_text_on_disk_claimed(dst, name, key_bytes);
        }
        // Same-sized leftover from a prior launch — treat as plaintext warm.
        if (!verify_text_against_diag(dst, name, /*check_hash=*/true)) {
            // Corrupt/stale leftover — force rebuild via copy+rc4.
            unlink(dst.c_str());
            if (!copy_file_bytes(src, dst, /*force=*/true)) {
                memset(key_bytes, 0, sizeof(key_bytes));
                commit_key(name, false);
                return false;
            }
            return rc4_text_on_disk_claimed(dst, name, key_bytes);
        }
        memset(key_bytes, 0, sizeof(key_bytes));
        commit_key(name, true);
        strip_verneed_if_old_android(dst);
        diag_set(name, "MATERIALIZE", "PLAINTEXT", /*decrypt_applied=*/false,
                 /*ready_hit=*/false, /*materialize_ok=*/true, dst);
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] name=%s materialize warm-size-match no-rc4 dst=%s",
                   name.c_str(), dst.c_str());
        return true;
    }
    PLOGW("business so: materialize_one give up %s", name.c_str());
    diag_set(name, "MATERIALIZE", "ENCRYPTED", false, false, false, dst);
    return false;
}

/**
 * Depth-first: materialize keyed DT_NEEDED deps, then the root if keyed.
 * ELF headers are read from packaged nld (ciphertext .text is fine for DYNAMIC).
 * Prevents linker from resolving encrypted deps when a parent loads from /data/app.
 */
static bool materialize_keyed_closure(const std::string& root,
                                      const std::string& out_dir,
                                      const std::string& nld,
                                      std::unordered_set<std::string>& visiting) {
    if (root.empty()) return true;
    if (visiting.count(root)) return true; // cycle
    visiting.insert(root);

    std::string elf_path;
    if (!nld.empty() && file_exists_path(nld + "/" + root)) {
        elf_path = nld + "/" + root;
    } else if (file_exists_path(out_dir + "/" + root)) {
        elf_path = out_dir + "/" + root;
    }

    bool ok = true;
    if (!elf_path.empty()) {
        for (const auto& need : read_dt_needed(elf_path)) {
            bool need_keyed = false;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                need_keyed = find_key_unlocked(need) != nullptr;
            }
            if (!need_keyed) continue;
            if (!materialize_keyed_closure(need, out_dir, nld, visiting)) {
                ok = false;
            }
        }
    }
    visiting.erase(root);

    bool self_keyed = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        self_keyed = find_key_unlocked(root) != nullptr;
    }
    if (self_keyed && !materialize_one_keyed(root, out_dir, nld)) {
        ok = false;
    }
    return ok;
}

/**
 * Lazy/on-demand: ensure so_plain has plaintext for {@code base} (if keyed) and
 * all keyed DT_NEEDED deps. Unkeyed NEEDED of this ELF are symlinked from extract.
 * Does not scan the whole nativeLibraryDir (that was attach-path cost).
 */
static void ensure_plain_closure_for(const std::string& base) {
    if (base.empty() || !has_sokeys()) return;
    std::string nld;
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
    }
    if (cache_root.empty()) return;
    std::string out_dir = cache_root + "/so_plain";
    mkdir(out_dir.c_str(), 0700);
    std::unordered_set<std::string> visiting;
    if (!materialize_keyed_closure(base, out_dir, nld, visiting)) {
        PLOGW("business so: keyed closure incomplete for %s", base.c_str());
    }
    std::string elf_path = out_dir + "/" + base;
    if (!file_exists_path(elf_path) && !nld.empty() && file_exists_path(nld + "/" + base)) {
        elf_path = nld + "/" + base;
    }
    if (!nld.empty() && file_exists_path(elf_path)) {
        for (const auto& need : read_dt_needed(elf_path)) {
            if (need.empty() || is_system_soname(need)) continue;
            bool need_keyed = false;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                need_keyed = find_key_unlocked(need) != nullptr;
            }
            if (need_keyed) continue;
            std::string src = nld + "/" + need;
            if (!file_exists_path(src)) continue;
            symlink_plain_dep(src, out_dir + "/" + need);
        }
    }
}

/** Create so_plain/name -> nld/name symlink; replace regular-file duplicates. */
static bool symlink_plain_dep(const std::string& src, const std::string& dst) {
    char buf[4096];
    ssize_t n = readlink(dst.c_str(), buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        if (src == buf) return false; // already correct
    }
    struct stat st {};
    if (lstat(dst.c_str(), &st) == 0) {
        unlink(dst.c_str());
    }
    if (symlink(src.c_str(), dst.c_str()) != 0) {
        PLOGW("business so: symlink plain dep failed %s -> %s errno=%d",
              dst.c_str(), src.c_str(), errno);
        return false;
    }
    return true;
}

static bool name_ends_with_so(const std::string& name) {
    return name.size() > 3 && name.compare(name.size() - 3, 3, ".so") == 0;
}

/**
 * Teigha/OSG dirname(mapped SO) looks beside the library for .tx modules,
 * osgPlugins-* trees, and other non-SO sidecars. so_plain normally only has
 * keyed .so mirrors — symlink extract sidecars here so L2 maps (so_plain fd)
 * still resolve TG_ModelerGeometry.tx etc.
 */
static int plant_extract_sidecars(const std::string& dest, const std::string& nld) {
    if (dest.empty() || nld.empty() || dest == nld) return 0;
    DIR* dir = opendir(nld.c_str());
    if (dir == nullptr) return 0;
    int n = 0;
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') continue;
        std::string name = ent->d_name;
        if (name_ends_with_so(name)) continue;
        std::string src = nld + "/" + name;
        std::string dst = dest + "/" + name;
        struct stat st {};
        if (lstat(src.c_str(), &st) != 0) continue;
        if (symlink_plain_dep(src, dst)) n++;
    }
    closedir(dir);
    if (n > 0) {
        PLOGI("business so: extract sidecars planted=%d dest=%s", n, dest.c_str());
    }
    return n;
}

/**
 * Plant keyed plaintext into lib_mirror as a hardlink (preferred) or copy.
 * Symlink would make /proc/maps resolve to so_plain and break path-sensitive
 * engines that dirname() the mapped path for osgPlugins / models.
 */
static bool plant_hardlink_or_copy(const std::string& src, const std::string& dst) {
    struct stat ss {};
    if (stat(src.c_str(), &ss) != 0 || !S_ISREG(ss.st_mode) || ss.st_size <= 0) {
        return false;
    }
    struct stat ds {};
    if (stat(dst.c_str(), &ds) == 0 && S_ISREG(ds.st_mode)
            && ds.st_dev == ss.st_dev && ds.st_ino == ss.st_ino) {
        return true; // already hard-linked
    }
    if (lstat(dst.c_str(), &ds) == 0) {
        unlink(dst.c_str());
    }
    if (link(src.c_str(), dst.c_str()) == 0) {
        return true;
    }
    return copy_file_bytes(src, dst, /*force=*/true);
}

/**
 * After so_plain materialize: if extract dir is writable, publish plaintext onto
 * /data/app/.../lib (archive cipher first). Small SOs sync; megacores (>32MB)
 * on a detached worker to avoid ANR. Enables L1-fast + lib_mirror→extract.
 */
static void publish_keyed_extract_mirrors(const std::string& cache_root,
                                          const std::string& nld,
                                          const std::string& so_plain) {
    if (cache_root.empty() || nld.empty() || so_plain.empty()) return;
    if (!extract_dir_writable(nld)) return;
    std::string cipher_dir = cache_root + "/so_cipher";
    mkdir(cipher_dir.c_str(), 0700);
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    std::vector<std::string> large;
    int ok = 0;
    int skip = 0;
    int fail = 0;
    constexpr off_t kSyncMax = 32 * 1024 * 1024;
    for (const auto& name : names) {
        std::string plain = so_plain + "/" + name;
        std::string extract = nld + "/" + name;
        if (!file_exists_path(plain) || !file_exists_path(extract)) {
            skip++;
            continue;
        }
        if (extract_holds_plaintext(name, extract)) {
            skip++;
            continue;
        }
        const off_t sz = file_size_path(plain);
        if (sz > kSyncMax) {
            large.push_back(name);
            continue;
        }
        // Distinguish skip(already) vs fail: re-check existence only.
        std::string cipher = cipher_dir + "/" + name;
        bool archived = file_exists_path(cipher)
                || copy_file_bytes(extract, cipher, /*force=*/true);
        if (!archived) {
            fail++;
            continue;
        }
        if (copy_file_bytes(plain, extract, /*force=*/true)
                && verify_text_against_diag(extract, name, /*check_hash=*/true)) {
            ok++;
            note_extract_published(name);
            note_plain_inode(name, extract);
            xop_so_log(ANDROID_LOG_INFO,
                       "[XOP-SO] name=%s source_layer=L1_PUBLISH source_state=PLAINTEXT "
                       "decrypt_applied=0 ready_hit=0 materialize_ok=1 output=%s",
                       name.c_str(), extract.c_str());
        } else {
            fail++;
        }
    }
    if (ok > 0 || fail > 0) {
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] extract publish ok=%d skip=%d fail=%d large_async=%zu nld=%s",
                   ok, skip, fail, large.size(), nld.c_str());
    }
    if (!large.empty()) {
        std::thread([cache_root, nld, so_plain, cipher_dir, large]() {
#if defined(__ANDROID__)
            const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
            if (tid > 0) setpriority(PRIO_PROCESS, tid, 10);
#endif
            int lok = 0;
            int lfail = 0;
            for (const auto& name : large) {
                std::string plain = so_plain + "/" + name;
                std::string extract = nld + "/" + name;
                if (!file_exists_path(plain) || !file_exists_path(extract)) {
                    continue;
                }
                if (extract_holds_plaintext(name, extract)) {
                    continue;
                }
                std::string cipher = cipher_dir + "/" + name;
                bool archived = file_exists_path(cipher)
                        || copy_file_bytes(extract, cipher, /*force=*/true);
                if (!archived) {
                    lfail++;
                    continue;
                }
                if (copy_file_bytes(plain, extract, /*force=*/true)
                        && verify_text_against_diag(extract, name, /*check_hash=*/true)) {
                    lok++;
                    note_extract_published(name);
                    note_plain_inode(name, extract);
                    xop_so_log(ANDROID_LOG_INFO,
                               "[XOP-SO] name=%s source_layer=L1_PUBLISH_ASYNC "
                               "source_state=PLAINTEXT decrypt_applied=0 ready_hit=0 "
                               "materialize_ok=1 output=%s",
                               name.c_str(), extract.c_str());
                } else {
                    lfail++;
                }
            }
            // Refresh mirror so next dlopen / warm start prefers extract.
            refresh_lib_mirror(cache_root, nld, so_plain);
            xop_so_log(ANDROID_LOG_INFO,
                       "[XOP-SO] extract publish async done ok=%d fail=%d",
                       lok, lfail);
        }).detach();
    }
}

/**
 * Writable extract-equivalent directory under code_cache:
 *   lib_mirror/<name>.so  — keyed: hardlink/copy from so_plain; else symlink→nld
 *   lib_mirror/<subdir>/  — symlink→nld (osgPlugins, data trees, …)
 * nativeLibraryDir and keyed dlopen prefer this over bare so_plain.
 */
static void refresh_lib_mirror(const std::string& cache_root,
                               const std::string& nld,
                               const std::string& so_plain) {
    if (cache_root.empty() || nld.empty() || so_plain.empty()) return;
    std::string mirror = cache_root + "/" + kLibMirror;
    mkdir(mirror.c_str(), 0700);
    DIR* dir = opendir(nld.c_str());
    if (dir == nullptr) {
        PLOGW("business so: lib_mirror opendir nld failed %s errno=%d",
              nld.c_str(), errno);
        return;
    }
    int keyed_n = 0;
    int dep_n = 0;
    int dir_n = 0;
    int other_n = 0;
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') continue;
        std::string name = ent->d_name;
        std::string src = nld + "/" + name;
        std::string dst = mirror + "/" + name;
        struct stat st {};
        if (lstat(src.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            if (symlink_plain_dep(src, dst)) dir_n++;
            continue;
        }
        const bool is_so = name.size() > 3
                && name.compare(name.size() - 3, 3, ".so") == 0;
        if (is_so) {
            // Class S must still appear beside keyed megacores in lib_mirror:
            // OSG/Teigha often dlopen(dirname(self)+"/libGLESv3.so") etc. Never
            // plant them into so_plain (Conscrypt), but DO symlink → extract so
            // the mirror tree matches stock nativeLibraryDir layout.
            if (is_system_soname(name)) {
                if (symlink_plain_dep(src, dst)) dep_n++;
                continue;
            }
            bool keyed = false;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                keyed = find_key_unlocked(name) != nullptr;
            }
            if (keyed) {
                if (extract_inode_hooks_ok() && needs_extract_inode(name)) {
                    unlink(dst.c_str());
                    continue;
                }
                std::string plain = so_plain + "/" + name;
                if (!file_exists_path(plain)) continue;
                // When extract already holds plaintext, symlink so ClassLoader
                // open resolves to /data/app/... (stock maps path). Else hardlink
                // so_plain (L2 / non-writable extract).
                if (extract_holds_plaintext(name, src)) {
                    if (symlink_plain_dep(src, dst)) keyed_n++;
                } else if (plant_hardlink_or_copy(plain, dst)) {
                    keyed_n++;
                }
            } else {
                if (symlink_plain_dep(src, dst)) dep_n++;
            }
            continue;
        }
        // Non-SO files beside libs (.tx, data) — keep path layout.
        if (symlink_plain_dep(src, dst)) other_n++;
    }
    closedir(dir);
    // L2 maps dirname() is often so_plain — plant the same sidecars there.
    plant_extract_sidecars(so_plain, nld);
    hide_extract_inode_helpers();
    PLOGI("business so: lib_mirror refresh keyed=%d deps=%d dirs=%d other=%d path=%s",
          keyed_n, dep_n, dir_n, other_n, mirror.c_str());
}

static void refresh_lib_mirror_from_runtime() {
    std::string nld;
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
    }
    if (nld.empty() || cache_root.empty()) return;
    refresh_lib_mirror(cache_root, nld, cache_root + "/so_plain");
}

/**
 * Class S — never plant under so_plain (system/OpenSSL/GLES collision).
 * Keep in sync with packer BusinessSoProtector SYSTEM_SONAME_* lists.
 */
static bool is_system_soname(const std::string& need) {
    if (need.empty()) return false;
    static const char* kExact[] = {
            "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
            "libc++.so", "libstdc++.so",
            "libandroid.so", "libjnigraphics.so",
            "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so", "libGLESv3.so",
            "libOpenSLES.so", "libOpenMAXAL.so",
            "libvulkan.so", "libcamera2ndk.so",
    };
    for (const char* e : kExact) {
        if (need == e) return true;
    }
    if (need.compare(0, 9, "libcrypto") == 0) return true;
    if (need.compare(0, 6, "libssl") == 0) return true;
    if (need.compare(0, 7, "libGLESv") == 0) return true;
    return false;
}

/** Remove Class S leftovers from so_plain (old encrypt-all packages / bad deps). */
static int scrub_forbidden_from_so_plain(const std::string& out_dir) {
    if (out_dir.empty()) return 0;
    DIR* dir = opendir(out_dir.c_str());
    if (dir == nullptr) return 0;
    int n = 0;
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') continue;
        std::string name = ent->d_name;
        if (name.size() <= 3 || name.compare(name.size() - 3, 3, ".so") != 0) continue;
        if (!is_system_soname(name)) continue;
        std::string path = out_dir + "/" + name;
        if (unlink(path.c_str()) == 0) {
            n++;
            __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                    "scrub Class S from so_plain: %s", name.c_str());
        }
    }
    closedir(dir);
    return n;
}

/**
 * Ensure non-keyed DT_NEEDED deps are visible beside keyed so_plain mirrors as
 * <b>symlinks</b> to the packaged extract (same inode → no dual libc++).
 * Never plant Class S (crypto/GLES/…). Call before keyed dlopen/preload.
 */
static void copy_plain_deps(const std::string& out_dir, const std::string& nld) {
    if (nld.empty() || out_dir.empty()) return;
    scrub_forbidden_from_so_plain(out_dir);
    bool progress = true;
    int linked = 0;
    int refreshed = 0;
    int skipped_sys = 0;
    while (progress) {
        progress = false;
        DIR* dir = opendir(out_dir.c_str());
        if (dir == nullptr) return;
        std::vector<std::string> bases;
        while (dirent* ent = readdir(dir)) {
            if (ent->d_name[0] == '.') continue;
            std::string n = ent->d_name;
            if (n.size() > 3 && n.compare(n.size() - 3, 3, ".so") == 0) {
                bases.push_back(std::move(n));
            }
        }
        closedir(dir);
        for (const auto& base : bases) {
            std::string base_path = out_dir + "/" + base;
            struct stat st {};
            if (lstat(base_path.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
                continue;
            }
            for (const auto& need : read_dt_needed(base_path)) {
                {
                    std::lock_guard<std::mutex> lock(g_mu);
                    if (find_key_unlocked(need) != nullptr) continue;
                }
                if (is_system_soname(need)) {
                    std::string dst = out_dir + "/" + need;
                    if (unlink(dst.c_str()) == 0) skipped_sys++;
                    continue;
                }
                std::string src = nld + "/" + need;
                if (!file_exists_path(src)) continue;
                std::string dst = out_dir + "/" + need;
                if (symlink_plain_dep(src, dst)) {
                    linked++;
                    progress = true;
                }
            }
        }
    }
    DIR* dir = opendir(out_dir.c_str());
    if (dir != nullptr) {
        while (dirent* ent = readdir(dir)) {
            if (ent->d_name[0] == '.') continue;
            std::string n = ent->d_name;
            if (n.size() <= 3 || n.compare(n.size() - 3, 3, ".so") != 0) continue;
            if (is_system_soname(n)) {
                if (unlink((out_dir + "/" + n).c_str()) == 0) skipped_sys++;
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(g_mu);
                if (find_key_unlocked(n) != nullptr) continue;
            }
            std::string src = nld + "/" + n;
            if (!file_exists_path(src)) continue;
            std::string dst = out_dir + "/" + n;
            struct stat lst {};
            if (lstat(dst.c_str(), &lst) == 0 && S_ISREG(lst.st_mode)) {
                if (symlink_plain_dep(src, dst)) refreshed++;
            } else if (lstat(dst.c_str(), &lst) != 0) {
                if (symlink_plain_dep(src, dst)) linked++;
            }
        }
        closedir(dir);
    }
    plant_extract_sidecars(out_dir, nld);
    if (linked > 0 || refreshed > 0 || skipped_sys > 0) {
        PLOGI("business so: plain deps symlink linked=%d refreshed=%d scrub_sys=%d",
              linked, refreshed, skipped_sys);
    }
}

static void materialize_all_keyed_sos() {
    if (!has_sokeys()) return;
    if (g_full_materialize_done.load(std::memory_order_acquire)) {
        PLOGI("business so: full materialize already done this process");
        // Still refresh dep symlinks (GLES blacklist / libc++ links).
        std::string nld;
        std::string cache_root;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            nld = g_native_lib_dir;
            cache_root = g_protector_dir;
        }
        if (!nld.empty() && !cache_root.empty()) {
            copy_plain_deps(cache_root + "/so_plain", nld);
            publish_keyed_extract_mirrors(cache_root, nld, cache_root + "/so_plain");
            refresh_lib_mirror(cache_root, nld, cache_root + "/so_plain");
        }
        return;
    }
    auto t0 = std::chrono::steady_clock::now();
    std::string nld;
    std::string cache_root;
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    if (nld.empty() || cache_root.empty()) {
        PLOGW("business so: dirs unset — skip full materialize (nld=%d cache=%d)",
              nld.empty() ? 0 : 1, cache_root.empty() ? 0 : 1);
        return;
    }
    std::string out_dir = cache_root + "/so_plain";
    mkdir(out_dir.c_str(), 0700);
    scrub_forbidden_from_so_plain(out_dir);

    // Warm reuse: prior launch left decrypted mirrors + ready mark.
    if (so_plain_ready_ok(out_dir, nld, names)
        && so_plain_integrity_ok_or_scrub(out_dir, nld, names)) {
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (auto& k : g_keys) k.decrypted = true;
        }
        g_cv.notify_all();
        diag_mark_warm_ready(out_dir, names);
        copy_plain_deps(out_dir, nld);
        g_full_materialize_done.store(true, std::memory_order_release);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        PLOGI("business so: reuse so_plain count=%zu cost_ms=%lld", names.size(),
              static_cast<long long>(ms));
        publish_keyed_extract_mirrors(cache_root, nld, out_dir);
        refresh_lib_mirror(cache_root, nld, out_dir);
        return;
    }

    std::atomic<int> ok{0};
    std::atomic<int> fail{0};
    unsigned hw = std::thread::hardware_concurrency();
    unsigned workers = hw == 0 ? 2u : std::min(2u, hw);
    if (names.size() < workers) workers = static_cast<unsigned>(std::max<size_t>(1, names.size()));

    auto worker = [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; i++) {
            const std::string& name = names[i];
            if (is_system_soname(name)) {
                unlink((out_dir + "/" + name).c_str());
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = true;
                    key->in_flight = false;
                }
                ok.fetch_add(1);
                continue;
            }
            if (defer_eager_disk(name)) {
                mark_key_disk_done(name);
                xop_so_log(ANDROID_LOG_INFO,
                           "[XOP-SO] name=%s eager skip disk (extract-inode L2e)",
                           name.c_str());
                ok.fetch_add(1);
                continue;
            }
            std::string src = keyed_packaged_src(name, nld);
            std::string dst = out_dir + "/" + name;
            if (!file_exists_path(src)) {
                // Basename in sokeys from another ABI only — nothing to decrypt here.
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = true;
                    key->in_flight = false;
                }
                ok.fetch_add(1);
                continue;
            }
            // Skip when this process already decrypted and mirror size matches.
            // Cross-launch warm hits so_plain_ready_ok before the worker pool.
            // Cold start without ready: always recopy from packaged ciphertext
            // so leftover plaintext is never RC4'd a second time.
            const off_t ss = file_size_path(src);
            bool already = false;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                already = key != nullptr && key->decrypted;
            }
            if (already && ss > 0 && file_size_path(dst) == ss) {
                ok.fetch_add(1);
                continue;
            }
            if (!copy_file_bytes(src, dst, /*force=*/true)) {
                fail.fetch_add(1);
                PLOGW("business so: materialize copy failed %s", name.c_str());
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = false;
                    key->in_flight = false;
                }
            }
            g_cv.notify_all();
            if (decrypt_text_on_disk(dst, name)) {
                ok.fetch_add(1);
            } else {
                fail.fetch_add(1);
                PLOGW("business so: materialize decrypt failed %s", name.c_str());
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(workers);
    size_t chunk = (names.size() + workers - 1) / workers;
    for (unsigned w = 0; w < workers; w++) {
        size_t begin = static_cast<size_t>(w) * chunk;
        if (begin >= names.size()) break;
        size_t end = std::min(names.size(), begin + chunk);
        threads.emplace_back(worker, begin, end);
    }
    for (auto& th : threads) th.join();

    // Retry any keyed SO that did not decrypt (parallel IO can flake on some devices).
    std::vector<std::string> retry;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (const auto& k : g_keys) {
            if (!k.decrypted) retry.push_back(k.name);
        }
    }
    for (const auto& name : retry) {
        if (defer_eager_disk(name)) {
            mark_key_disk_done(name);
            continue;
        }
        std::string src = keyed_packaged_src(name, nld);
        std::string dst = out_dir + "/" + name;
        if (!file_exists_path(src)) {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            if (key != nullptr) {
                key->decrypted = true;
                key->in_flight = false;
            }
            continue;
        }
        if (!copy_file_bytes(src, dst, /*force=*/true)) {
            PLOGE("business so: materialize retry copy failed %s", name.c_str());
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            if (key != nullptr) {
                key->decrypted = false;
                key->in_flight = false;
            }
        }
        g_cv.notify_all();
        if (!decrypt_text_on_disk(dst, name)) {
            PLOGE("business so: materialize retry failed %s", name.c_str());
        }
    }

    int ok_n = 0;
    int fail_n = 0;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (const auto& k : g_keys) {
            if (k.decrypted) ok_n++;
            else fail_n++;
        }
    }
    // Persist reuse mark whenever every keyed SO was decrypted (ignore plain-dep extras).
    if (fail_n == 0 && ok_n > 0) {
        if (!write_so_plain_ready(out_dir, static_cast<size_t>(ok_n))) {
            PLOGE("business so: so_plain_ready not written (warm reuse disabled)");
        } else {
            g_full_materialize_done.store(true, std::memory_order_release);
        }
    } else {
        drop_so_plain_ready(out_dir);
        if (fail_n > 0) {
            PLOGE("business so: materialize incomplete ok=%d fail=%d (no warm reuse)",
                  ok_n, fail_n);
        }
    }
    // Copy plaintext DT_NEEDED deps into so_plain so ClassLoader-only dir still resolves.
    copy_plain_deps(out_dir, nld);
    // Publish large megacores onto extract before mirror refresh so L1-fast
    // and lib_mirror→extract symlinks take effect on the next (or late) dlopen.
    publish_keyed_extract_mirrors(cache_root, nld, out_dir);
    refresh_lib_mirror(cache_root, nld, out_dir);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
    PLOGI("business so: materialize so_plain ok=%d fail=%d workers=%u cost_ms=%lld",
          ok_n, fail_n, workers, static_cast<long long>(ms));
}

void materialize_decrypted_sos() {
    if (!has_sokeys()) return;
    auto t0 = std::chrono::steady_clock::now();
    std::string cache_root;
    size_t keyed_n = 0;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
        keyed_n = g_keys.size();
    }
    if (cache_root.empty()) {
        PLOGW("business so: dirs unset — skip materialize");
        return;
    }
    std::string out_dir = cache_root + "/so_plain";
    mkdir(out_dir.c_str(), 0700);

    // Attach must not RC4/hash/pin the full keyed set when dlopen hooks can
    // rewrite the load onto so_plain (Hi-MC homepage). Extract-inode mmap
    // hooks alone are not enough: ClassLoader is helper-first, so an empty
    // so_plain falls through to packaged ciphertext and decrypts inside the
    // app's loadLibrary. That overlaps ad-SDK init with the first layout.
    // bytehook init failure (dlopen hooks down, mmap hooks up) takes this path.
    if (!dlopen_hooks_ok()) {
        PLOGW("business so: dlopen hooks down — force full materialize "
              "(extract_ok=%d)",
              extract_inode_hooks_ok() ? 1 : 0);
        materialize_all_keyed_sos();
        return;
    }
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] attach skip full materialize hooks_ok=%d extract_ok=%d "
               "openat_ok=%d keyed=%zu cost_ms=%lld",
               dlopen_hooks_ok() ? 1 : 0,
               extract_inode_hooks_ok() ? 1 : 0,
               linker_open_hooks_ok() ? 1 : 0,
               keyed_n, static_cast<long long>(ms));
    PLOGI("business so: attach skip full materialize hooks_ok=%d keyed=%zu cost_ms=%lld",
          dlopen_hooks_ok() ? 1 : 0, keyed_n, static_cast<long long>(ms));
    (void)ms;
    (void)keyed_n;
}

/** Read DT_NEEDED basenames from an on-disk ELF (empty on parse failure).
 *  Streams headers only — must not mmap/slurp multi-100MB SOs (e.g. libd3). */
static std::vector<std::string> read_dt_needed(const std::string& path) {
    std::vector<std::string> out;
    FILE* fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) return out;

    Elf_Ehdr eh{};
    if (fread(&eh, 1, sizeof(eh), fp) != sizeof(eh)
        || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0
        || eh.e_phoff == 0 || eh.e_phnum == 0
        || eh.e_phentsize != sizeof(Elf_Phdr)) {
        fclose(fp);
        return out;
    }

    std::vector<Elf_Phdr> ph(eh.e_phnum);
    if (fseek(fp, static_cast<long>(eh.e_phoff), SEEK_SET) != 0
        || fread(ph.data(), sizeof(Elf_Phdr), eh.e_phnum, fp) != eh.e_phnum) {
        fclose(fp);
        return out;
    }

    const Elf_Phdr* dyn = nullptr;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = &ph[i];
            break;
        }
    }
    if (dyn == nullptr || dyn->p_filesz == 0 || dyn->p_filesz > 16 * 1024 * 1024) {
        fclose(fp);
        return out;
    }

#ifdef __LP64__
    using Dyn = Elf64_Dyn;
#else
    using Dyn = Elf32_Dyn;
#endif
    std::vector<Dyn> dyns(dyn->p_filesz / sizeof(Dyn));
    if (dyns.empty()
        || fseek(fp, static_cast<long>(dyn->p_offset), SEEK_SET) != 0
        || fread(dyns.data(), sizeof(Dyn), dyns.size(), fp) != dyns.size()) {
        fclose(fp);
        return out;
    }

    uint64_t strtab_vaddr = 0;
    for (const auto& d : dyns) {
        if (d.d_tag == DT_NULL) break;
        if (d.d_tag == DT_STRTAB) {
            strtab_vaddr = d.d_un.d_ptr;
            break;
        }
    }
    if (strtab_vaddr == 0) {
        fclose(fp);
        return out;
    }

    uint64_t strtab_off = 0;
    bool mapped = false;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        uint64_t v0 = ph[i].p_vaddr;
        uint64_t v1 = v0 + ph[i].p_filesz;
        if (strtab_vaddr >= v0 && strtab_vaddr < v1) {
            strtab_off = ph[i].p_offset + (strtab_vaddr - v0);
            mapped = true;
            break;
        }
    }
    if (!mapped) {
        fclose(fp);
        return out;
    }

    for (const auto& d : dyns) {
        if (d.d_tag == DT_NULL) break;
        if (d.d_tag != DT_NEEDED) continue;
        uint64_t off = strtab_off + d.d_un.d_val;
        if (fseek(fp, static_cast<long>(off), SEEK_SET) != 0) continue;
        char name[256];
        size_t len = 0;
        while (len + 1 < sizeof(name)) {
            int c = fgetc(fp);
            if (c == EOF || c == 0) break;
            name[len++] = static_cast<char>(c);
        }
        name[len] = 0;
        if (len > 0) {
            out.emplace_back(name, len);
        }
    }
    fclose(fp);
    return out;
}

static bool file_exists_path(const std::string& path) {
    struct stat st {};
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

/**
 * Depth-first load so DT_NEEDED never falls through to encrypted extract
 * copies (linker internal resolve bypasses dlopen hooks). Keyed SOs use L1/L2/L3.
 * Megacores stay on L2e (extract inode); do not pin them from so_plain.
 */
static thread_local const void* g_pin_extinfo = nullptr;

static void preload_one(const std::string& plain_dir,
                        const std::string& base,
                        std::unordered_set<std::string>& visiting,
                        std::unordered_set<std::string>& loaded,
                        int& ok,
                        int& fail) {
    if (base.empty() || loaded.count(base)) return;
    if (visiting.count(base)) return; // cycle
    if (is_system_soname(base)) return; // Class S — never pin from so_plain
    if (needs_extract_inode(base)) return; // L2e at first real dlopen
    std::string path = plain_dir + "/" + base;
    if (!file_exists_path(path)) return; // system / absent dep — let linker resolve

    visiting.insert(base);
    for (const auto& need : read_dt_needed(path)) {
        preload_one(plain_dir, need, visiting, loaded, ok, fail);
    }
    bool keyed = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        keyed = find_key_unlocked(base) != nullptr;
    }
    void* h = nullptr;
    if (keyed) {
        KeyedOpenPlan plan = plan_keyed_open(base, path);
        h = dlopen_keyed_plan(plan, RTLD_NOW | RTLD_GLOBAL, g_pin_extinfo);
    } else {
        h = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
    }
    visiting.erase(base);
    if (h != nullptr) {
        loaded.insert(base);
        ok++;
    } else {
        fail++;
        PLOGW("business so: preload failed %s: %s", base.c_str(), dlerror());
    }
}

/**
 * Background: fill remaining keyed SOs into so_plain on a low-priority thread.
 * On full success writes so_plain_ready for next-launch reuse. Idempotent.
 * Does not block Application attach / first frame.
 */
static void fill_so_plain_async() {
    if (!has_sokeys()) return;
    bool expected = false;
    if (!g_fill_started.compare_exchange_strong(expected, true)) return;

    std::string nld;
    std::string cache_root;
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    if (nld.empty() || cache_root.empty() || names.empty()) {
        PLOGW("business so: background fill skipped (dirs/keys unset)");
        return;
    }
    std::string out_dir = cache_root + "/so_plain";

    std::thread([nld, names, out_dir, cache_root]() {
#if defined(__ANDROID__)
        // Lower *this thread* only — PRIO_PROCESS with who=0 would renice the app.
        const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
        if (tid > 0) {
            setpriority(PRIO_PROCESS, tid, 10);
        }
#endif
        auto t0 = std::chrono::steady_clock::now();
        mkdir(out_dir.c_str(), 0700);
#if defined(__ANDROID__)
        // Do not compete with first-frame on-demand loads / in-memory decrypt.
        sleep(20);
#endif
        if (so_plain_ready_ok(out_dir, nld, names)
            && so_plain_integrity_ok_or_scrub(out_dir, nld, names)) {
            diag_mark_warm_ready(out_dir, names);
            publish_keyed_extract_mirrors(cache_root, nld, out_dir);
            refresh_lib_mirror(cache_root, nld, out_dir);
            xop_so_log(ANDROID_LOG_INFO,
                       "[XOP-SO] background fill skip — so_plain_ready already ok");
            return;
        }
        for (const auto& name : names) {
            if (defer_eager_disk(name)) mark_key_disk_done(name);
        }

        // Snapshot which still need work (on-demand may have finished some).
        std::vector<std::string> pending;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (const auto& k : g_keys) {
                if (defer_eager_disk(k.name)) continue;
                if (!k.decrypted) pending.push_back(k.name);
            }
        }

        std::atomic<int> ok{0};
        std::atomic<int> fail{0};
        if (!pending.empty()) {
            unsigned hw = std::thread::hardware_concurrency();
            unsigned workers = hw == 0 ? 2u : std::min(2u, hw);
            if (pending.size() < workers) {
                workers = static_cast<unsigned>(std::max<size_t>(1, pending.size()));
            }
            auto worker = [&](size_t begin, size_t end) {
                for (size_t i = begin; i < end; i++) {
                    if (materialize_one_keyed(pending[i], out_dir, nld)) {
                        ok.fetch_add(1);
                    } else {
                        fail.fetch_add(1);
                    }
                }
            };
            std::vector<std::thread> threads;
            threads.reserve(workers);
            size_t chunk = (pending.size() + workers - 1) / workers;
            for (unsigned w = 0; w < workers; w++) {
                size_t begin = static_cast<size_t>(w) * chunk;
                if (begin >= pending.size()) break;
                size_t end = std::min(pending.size(), begin + chunk);
                threads.emplace_back(worker, begin, end);
            }
            for (auto& th : threads) th.join();
        }

        // Retry failures once (flaky IO).
        std::vector<std::string> retry;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (const auto& k : g_keys) {
                if (defer_eager_disk(k.name)) continue;
                if (!k.decrypted) retry.push_back(k.name);
            }
        }
        for (const auto& name : retry) {
            (void)materialize_one_keyed(name, out_dir, nld);
        }

        copy_plain_deps(out_dir, nld);
        publish_keyed_extract_mirrors(cache_root, nld, out_dir);
        refresh_lib_mirror(cache_root, nld, out_dir);

        int ok_n = 0;
        int fail_n = 0;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (const auto& k : g_keys) {
                if (k.decrypted) ok_n++;
                else fail_n++;
            }
        }

        bool mirrors_ok = fail_n == 0 && ok_n > 0;
        if (mirrors_ok) {
            for (const auto& name : names) {
                if (defer_eager_disk(name)) continue;
                std::string src = keyed_packaged_src(name, nld);
                if (!file_exists_path(src)) continue; // other-ABI-only key
                off_t ds = file_size_path(out_dir + "/" + name);
                off_t ss = file_size_path(src);
                if (ds <= 0 || ss <= 0 || ds != ss) {
                    mirrors_ok = false;
                    break;
                }
            }
        }

        if (mirrors_ok) {
            if (!write_so_plain_ready(out_dir, static_cast<size_t>(ok_n))) {
                PLOGE("business so: background fill so_plain_ready write failed");
            } else {
                PLOGI("business so: background fill ready ok=%d", ok_n);
            }
        } else {
            drop_so_plain_ready(out_dir);
            PLOGW("business so: background fill incomplete ok=%d fail=%d (no ready)",
                  ok_n, fail_n);
        }

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        PLOGI("business so: background fill done pending=%zu workers_ok=%d "
              "workers_fail=%d final_ok=%d final_fail=%d cost_ms=%lld",
              pending.size(), ok.load(), fail.load(), ok_n, fail_n,
              static_cast<long long>(ms));
    }).detach();
}

void preload_so_plain() {
    bool expected = false;
    if (!g_preload_done.compare_exchange_strong(expected, true)) {
        return; // already done this process
    }
    if (!has_sokeys()) return;
    const bool hooks = dlopen_hooks_ok() || extract_inode_hooks_ok();
    PLOGI("business so: preload begin on-demand hooks_ok=%d", hooks ? 1 : 0);
    auto t0 = std::chrono::steady_clock::now();
    std::string cache_root;
    size_t keyed_n = 0;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
        keyed_n = g_keys.size();
    }
    if (cache_root.empty()) return;

    if (!hooks) {
        PLOGW("business so: preload — hooks missing, force full materialize + pin");
        materialize_all_keyed_sos();
        std::string plain_dir = cache_root + "/so_plain";
        std::unordered_set<std::string> visiting;
        std::unordered_set<std::string> loaded;
        int ok = 0;
        int fail = 0;
        std::vector<std::string> keyed;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (const auto& k : g_keys) keyed.push_back(k.name);
        }
        for (const auto& name : keyed) {
            if (defer_eager_disk(name)) continue;
            preload_one(plain_dir, name, visiting, loaded, ok, fail);
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] preload fallback pin ok=%d fail=%d keyed=%zu cost_ms=%lld",
                   ok, fail, keyed.size(), static_cast<long long>(ms));
        PLOGI("business so: preload fallback pin ok=%d fail=%d keyed=%zu cost_ms=%lld",
              ok, fail, keyed.size(), static_cast<long long>(ms));
        (void)ms;
        return;
    }

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] preload skip pin (on-demand openat) keyed=%zu cost_ms=%lld",
               keyed_n, static_cast<long long>(ms));
    PLOGI("business so: preload skip pin on-demand keyed=%zu cost_ms=%lld",
          keyed_n, static_cast<long long>(ms));
    fill_so_plain_async();
}

/**
 * Linker DT_NEEDED is resolved from ApplicationInfo.nativeLibraryDir (packaged
 * extract) and bypasses dlopen hooks. That hits ciphertext for keyed SOs even
 * when the parent was path-loaded from so_plain (Hi-MC splash ZHDOSG.init →
 * libcpbase-jni → extract/libcpbase.so SIGILL). Pin the ELF's keyed
 * non-megacore DT_NEEDED from so_plain first (RTLD_GLOBAL, caller namespace).
 */
static thread_local int g_pin_needed_depth = 0;
static void pin_plain_needed_for_extract(const std::string& elf_so,
                                        const void* extinfo) {
    if (elf_so.empty() || g_pin_needed_depth > 8) return;
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
    }
    if (cache_root.empty()) return;
    std::string plain_dir = cache_root + "/so_plain";
    const void* prev_ext = g_pin_extinfo;
    if (extinfo != nullptr) g_pin_extinfo = extinfo;
    ++g_pin_needed_depth;
    std::unordered_set<std::string> visiting;
    std::unordered_set<std::string> loaded;
    int ok = 0;
    int fail = 0;
    for (const auto& need : read_dt_needed(elf_so)) {
        if (need.empty() || is_system_soname(need) || needs_extract_inode(need)) {
            continue;
        }
        bool keyed = false;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            keyed = find_key_unlocked(need) != nullptr;
        }
        if (!keyed) continue;
        // Never disk-RC4 DT_NEEDED on the load path. Existing so_plain is
        // optional; missing deps map extract and decrypt in RAM (mmap/ctors).
        if (!file_exists_path(plain_dir + "/" + need)) continue;
        preload_one(plain_dir, need, visiting, loaded, ok, fail);
    }
    --g_pin_needed_depth;
    g_pin_extinfo = prev_ext;
    if (ok + fail > 0) {
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] pin needed from %s ok=%d fail=%d",
                   basename_of(elf_so.c_str()).c_str(), ok, fail);
    }
}

/**
 * Return path that real dlopen should use. Protected SOs are always mirrored into
 * a writable protector cache and decrypted there — avoids read-only /data/app lib
 * trees and stale page-cache issues so JNI_OnLoad / .init_array see plaintext.
 */
static bool diag_blocks_dlopen(const std::string& base) {
    if (extract_inode_hooks_ok() && needs_extract_inode(base)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_diag_mu);
    auto it = g_diag.find(base);
    if (it == g_diag.end()) return false;
    const SoDiagRec& r = it->second;
    // Illegal: still ENCRYPTED with no decrypt applied — never map ciphertext.
    if (r.state != nullptr && strcmp(r.state, "ENCRYPTED") == 0 && !r.decrypt_applied) {
        return true;
    }
    if (!r.materialize_ok && r.state != nullptr && strcmp(r.state, "ENCRYPTED") == 0) {
        return true;
    }
    return false;
}

static void diag_log_dlopen(const std::string& base, const std::string& path,
                            const char* note) {
    SoDiagRec snap;
    {
        std::lock_guard<std::mutex> lock(g_diag_mu);
        auto it = g_diag.find(base);
        if (it != g_diag.end()) {
            if (!path.empty()) it->second.output = path;
            snap = it->second;
        } else {
            snap.output = path;
        }
    }
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] name=%s dlopen %s source_layer=%s source_state=%s "
               "decrypt_applied=%d ready_hit=%d path=%s",
               base.c_str(),
               note != nullptr ? note : "ok",
               snap.layer != nullptr ? snap.layer : "NONE",
               snap.state != nullptr ? snap.state : "UNKNOWN",
               snap.decrypt_applied ? 1 : 0,
               snap.ready_hit ? 1 : 0,
               path.empty() ? "-" : path.c_str());
}

static std::string path_for_dlopen(const char* filename) {
    if (filename == nullptr || filename[0] == '\0') return {};
    if (!has_sokeys()) return filename;
    std::string base = basename_of(filename);
    if (base.empty()) return filename;

    // Class S: never rewrite to so_plain; let linker use system/Apex/extract.
    if (is_system_soname(base)) {
        std::string cache_root;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            cache_root = g_protector_dir;
            SoKey* key = find_key_unlocked(base);
            if (key != nullptr) {
                key->decrypted = true;
                key->in_flight = false;
            }
        }
        g_cv.notify_all();
        if (!cache_root.empty()) {
            unlink((cache_root + "/so_plain/" + base).c_str());
        }
        return filename;
    }

    if (extract_inode_hooks_ok()) {
        std::string nld;
        std::string cache_root;
        bool keyed = false;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            nld = g_native_lib_dir;
            cache_root = g_protector_dir;
            keyed = find_key_unlocked(base) != nullptr;
        }
        if (!keyed) {
            return filename;
        }
        std::string extract = nld.empty() ? std::string() : (nld + "/" + base);
        const bool class_b = needs_extract_inode(base);
        std::string cache = cache_root.empty()
                ? std::string() : (cache_root + "/so_plain/" + base);
        if (!class_b && !cache.empty() && file_exists_path(cache)) {
            // Plaintext content for plan_keyed_open. The plan opens it via
            // memfd / LIBRARY_FD; this return is not a path-load name.
            hide_extract_inode_helpers();
            diag_log_dlopen(base, cache, "so_plain_warm");
            return cache;
        }
        if (!extract.empty() && file_exists_path(extract)) {
            if (!file_execmod_ok()) {
                if (class_b) {
                    PLOGE("business so: FATAL execmod denied, refuse L2e dlopen %s",
                          base.c_str());
                    xop_so_log(ANDROID_LOG_ERROR,
                               "[XOP-SO] FATAL name=%s execmod denied — refuse l2e "
                               "extract load",
                               base.c_str());
                    diag_log_dlopen(base, {}, "blocked_execmod");
                    return {};
                }
                // Do not map extract ciphertext. plan_keyed_open still opens
                // the materialized so_plain via memfd / USE_LIBRARY_FD.
                PLOGW("business so: execmod denied, skip opportunistic L2e %s "
                      "— materialize so_plain",
                      base.c_str());
                xop_so_log(ANDROID_LOG_WARN,
                           "[XOP-SO] name=%s execmod denied, opportunistic L2e "
                           "skipped (so_plain via fd)",
                           base.c_str());
            } else {
                hide_extract_inode_helpers();
                pin_plain_needed_for_extract(extract);
                diag_log_dlopen(base, extract, class_b ? "l2e_extract" : "l2e_ondemand");
                return extract;
            }
        }
    }

    // Hooks missing, or opportunistic L2e refused because execmod failed.
    // Materialize keyed self + DT_NEEDED onto so_plain.
    ensure_plain_closure_for(base);

    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (find_key_unlocked(base) == nullptr) {
            return filename; // not protected (deps already handled when lazy)
        }
    }

    std::string cache_root;
    std::string nld;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
        nld = g_native_lib_dir;
    }
    std::string plain_dir = cache_root.empty() ? std::string() : (cache_root + "/so_plain");
    std::string cache = plain_dir.empty() ? std::string() : (plain_dir + "/" + base);

    auto finish_ok = [&](const std::string& path) -> std::string {
        if (diag_blocks_dlopen(base)) {
            xop_so_log(ANDROID_LOG_ERROR,
                       "[XOP-SO] FATAL name=%s refuse dlopen ENCRYPTED without decrypt "
                       "path=%s",
                       base.c_str(), path.c_str());
            PLOGE("business so: refuse ciphertext dlopen (diag ENCRYPTED) %s",
                  base.c_str());
            diag_log_dlopen(base, {}, "blocked_encrypted");
            return {};
        }
        diag_log_dlopen(base, path, "ok");
        return path;
    };

    // Already pointing at the decrypted mirror — never RC4 twice (RC4 is involution).
    if (!cache.empty() && filename[0] == '/' && std::string(filename) == cache) {
        bool done = false;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            done = is_decrypted_unlocked(base);
        }
        if (done || decrypt_text_on_disk(cache, base)) {
            return finish_ok(cache);
        }
        PLOGE("business so: refuse ciphertext dlopen (so_plain decrypt failed) %s",
              base.c_str());
        diag_log_dlopen(base, {}, "blocked_so_plain_decrypt");
        return {};
    }
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (!cache.empty() && is_decrypted_unlocked(base)) {
            // file_exists checked outside — path stable after materialize
        } else {
            goto need_mirror;
        }
    }
    if (file_exists_path(cache)) {
        return finish_ok(cache);
    }
need_mirror:

    // On-demand exclusive materialize (claim + conditional copy) — avoid racing
    // a force rewrite against background fill / an already-mapped so_plain file.
    if (!cache_root.empty() && !nld.empty() && !plain_dir.empty()) {
        if (materialize_one_keyed(base, plain_dir, nld)) {
            if (file_exists_path(cache)) return finish_ok(cache);
        }
        // Never fall back to packaged ciphertext — that SIGILL's in .init_array.
        PLOGE("business so: refuse ciphertext dlopen (on-demand materialize failed) %s",
              base.c_str());
        diag_log_dlopen(base, {}, "blocked_ondemand_materialize");
        return {};
    }

    // Source must be the packaged (possibly encrypted) extract — not so_plain.
    std::string abs;
    if (filename[0] == '/' && (plain_dir.empty()
                                || std::string(filename).compare(0, plain_dir.size(), plain_dir) != 0)) {
        abs = filename;
    } else if (!nld.empty()) {
        abs = keyed_packaged_src(base, nld);
    } else if (filename[0] == '/') {
        abs = filename;
    }
    if (abs.empty()) {
        PLOGE("business so: refuse dlopen — no source for keyed %s", base.c_str());
        diag_log_dlopen(base, {}, "blocked_no_source");
        return {};
    }

    if (cache_root.empty()) {
        // No writable mirror dir — decrypt in place only if path is writable.
        if (decrypt_text_on_disk(abs, base)) return finish_ok(abs);
        PLOGE("business so: refuse ciphertext dlopen (no cache) %s", base.c_str());
        diag_log_dlopen(base, {}, "blocked_no_cache");
        return {};
    }
    mkdir(plain_dir.c_str(), 0700);

    if (!copy_file_bytes(abs, cache, /*force=*/true)) {
        PLOGE("business so: refuse ciphertext dlopen (copy failed) %s", base.c_str());
        diag_log_dlopen(base, {}, "blocked_copy");
        return {};
    }

    // Fresh mirror from packaged lib — allow decrypt even if a prior attempt marked done.
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(base);
        if (key != nullptr) {
            key->decrypted = false;
            key->in_flight = false;
        }
    }
    g_cv.notify_all();

    if (decrypt_text_on_disk(cache, base)) {
        return finish_ok(cache);
    }
    PLOGE("business so: refuse ciphertext dlopen (decrypt failed) %s", base.c_str());
    diag_log_dlopen(base, {}, "blocked_decrypt");
    return {};
}

static void note_or_decrypt(const char* filename) {
    std::string base = basename_of(filename);
    if (base.empty()) return;
    bool have_keys = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        have_keys = !g_keys.empty();
        if (!have_keys) {
            // Remember for flush when sokeys arrive (early dlopen before initApp).
            for (const auto& p : g_pending) {
                if (p == base) return;
            }
            g_pending.push_back(base);
            return;
        }
    }
    maybe_decrypt_by_name(base);
}

static thread_local int g_in_loader_dlopen = 0;
static void* hooked_loader_android_dlopen_ext(const char* filename, int flags,
                                              const android_dlextinfo* extinfo,
                                              const void* caller) {
    LinkerHookScope in_linker;
    if (g_orig_loader_dlopen_ext == nullptr) {
        return nullptr;
    }
    if (g_in_loader_dlopen > 0 || filename == nullptr || filename[0] == '\0') {
        return g_orig_loader_dlopen_ext(filename, flags, extinfo, caller);
    }
    ++g_in_loader_dlopen;
    std::string rewritten = path_for_dlopen(filename);
    void* h = nullptr;
    if (rewritten.empty()) {
        const std::string base = basename_of(filename);
        if (is_keyed_basename(base)) {
            PLOGE("business so: linker dlopen blocked for keyed SO %s", filename);
            xop_so_log(ANDROID_LOG_ERROR,
                       "[XOP-SO] FATAL name=%s linker dlopen refused (empty rewrite)",
                       base.c_str());
        } else {
            h = g_orig_loader_dlopen_ext(filename, flags, extinfo, caller);
            if (h != nullptr) note_or_decrypt(filename);
        }
    } else {
        std::string base = basename_of(filename);
        if (base.empty()) base = basename_of(rewritten.c_str());
        if (is_keyed_basename(base)) {
            xop_so_log(ANDROID_LOG_INFO,
                       "[XOP-SO] linker dlopen plan %s content=%s",
                       filename, rewritten.c_str());
            // DT_NEEDED search uses nativeLibraryDir and does not re-enter here.
            pin_plain_needed_for_extract(rewritten, extinfo);
            KeyedOpenPlan plan = plan_keyed_open(base, rewritten);
            // g_orig inside the plan — do not dlsym the hooked loader.
            h = dlopen_keyed_plan(plan, flags, extinfo, caller);
            if (h != nullptr && !plan.content_path.empty()) {
                note_or_decrypt(plan.content_path.c_str());
            }
        } else {
            if (rewritten != filename) {
                xop_so_log(ANDROID_LOG_INFO,
                           "[XOP-SO] linker dlopen rewrite %s -> %s",
                           filename, rewritten.c_str());
            }
            h = g_orig_loader_dlopen_ext(rewritten.c_str(), flags, extinfo, caller);
            if (h != nullptr) note_or_decrypt(rewritten.c_str());
        }
    }
    --g_in_loader_dlopen;
    return h;
}

static bool is_keyed_basename(const std::string& base) {
    if (base.empty()) return false;
    std::lock_guard<std::mutex> lock(g_mu);
    return find_key_unlocked(base) != nullptr;
}

static void* fake_dlopen(const char* filename, int flags) {
    BYTEHOOK_STACK_SCOPE();
    if (g_in_keyed_plan_fallback > 0) {
        return BYTEHOOK_CALL_PREV(fake_dlopen, filename, flags);
    }
    std::string path = path_for_dlopen(filename);
    if (path.empty()) {
        if (filename != nullptr && filename[0] != '\0'
            && is_keyed_basename(basename_of(filename))) {
            PLOGE("business so: dlopen blocked for keyed SO %s", filename);
            return nullptr;
        }
        void* h = BYTEHOOK_CALL_PREV(fake_dlopen, filename, flags);
        if (h) note_or_decrypt(filename);
        return h;
    }
    std::string base = basename_of(filename);
    if (base.empty()) base = basename_of(path.c_str());
    if (is_keyed_basename(base)) {
        pin_plain_needed_for_extract(path, nullptr);
        KeyedOpenPlan plan = plan_keyed_open(base, path);
        void* h = dlopen_keyed_plan(plan, flags, nullptr);
        if (h) note_or_decrypt(plan.content_path.c_str());
        return h;
    }
    void* h = BYTEHOOK_CALL_PREV(fake_dlopen, path.c_str(), flags);
    if (h) note_or_decrypt(path.c_str());
    return h;
}

static void* fake_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    BYTEHOOK_STACK_SCOPE();
    std::string path = path_for_dlopen(filename);
    if (path.empty()) {
        if (filename != nullptr && filename[0] != '\0'
            && is_keyed_basename(basename_of(filename))) {
            PLOGE("business so: android_dlopen_ext blocked for keyed SO %s", filename);
            return nullptr;
        }
        void* h = BYTEHOOK_CALL_PREV(fake_android_dlopen_ext, filename, flags, extinfo);
        if (h) note_or_decrypt(filename);
        return h;
    }
    std::string base = basename_of(filename);
    if (base.empty()) base = basename_of(path.c_str());
    if (is_keyed_basename(base)) {
        pin_plain_needed_for_extract(path, extinfo);
        KeyedOpenPlan plan = plan_keyed_open(base, path);
        void* h = dlopen_keyed_plan(plan, flags, extinfo);
        if (h) note_or_decrypt(plan.content_path.c_str());
        return h;
    }
    void* h = BYTEHOOK_CALL_PREV(fake_android_dlopen_ext, path.c_str(), flags, extinfo);
    if (h) note_or_decrypt(path.c_str());
    return h;
}

static std::string extract_path_for_keyed(const std::string& base) {
    if (base.empty()) return {};
    {
        std::lock_guard<std::mutex> lock(g_dladdr_mu);
        auto it = g_dladdr_extract.find(base);
        if (it != g_dladdr_extract.end() && !it->second.empty()) {
            return it->second;
        }
    }
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_native_lib_dir.empty()) return {};
    return g_native_lib_dir + "/" + base;
}

/** Stable C string in g_dladdr_extract for hooked APIs that return a path pointer. */
static const char* intern_extract_c_str(const std::string& base) {
    if (base.empty()) return nullptr;
    std::string extract = extract_path_for_keyed(base);
    if (extract.empty()) return nullptr;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    auto it = g_dladdr_extract.find(base);
    if (it == g_dladdr_extract.end()) {
        it = g_dladdr_extract.emplace(base, std::move(extract)).first;
    }
    return it->second.c_str();
}

/**
 * If {@code path} is a keyed so_plain / lib_mirror / memfd mapping, return the
 * interned packaged extract path. Kernel maps/readlink always show the FD inode
 * (so_plain); Teigha/OSG dirname() that path for modules and APK-relative assets.
 */
static const char* spoof_mapped_path_c_str(const char* path) {
    if (path == nullptr || path[0] == '\0') return nullptr;
    const bool hide = strstr(path, "/so_plain/") != nullptr
            || strstr(path, "/lib_mirror/") != nullptr
            || strstr(path, "memfd:") != nullptr;
    if (!hide) return nullptr;
    std::string base = keyed_soname_from_fname(path);
    if (base.empty() || !is_keyed_basename(base)) return nullptr;
    return intern_extract_c_str(base);
}

static ssize_t rewrite_readlink_buf(char* buf, size_t bufsiz, ssize_t n) {
    if (n <= 0 || buf == nullptr || bufsiz == 0) return n;
    char tmp[4096];
    size_t copy = static_cast<size_t>(n) < sizeof(tmp) - 1
            ? static_cast<size_t>(n) : sizeof(tmp) - 1;
    memcpy(tmp, buf, copy);
    tmp[copy] = '\0';
    const char* spoof = spoof_mapped_path_c_str(tmp);
    if (spoof == nullptr) return n;
    size_t sl = strlen(spoof);
    if (sl > bufsiz) {
        memcpy(buf, spoof, bufsiz);
        return static_cast<ssize_t>(bufsiz);
    }
    memcpy(buf, spoof, sl);
    return static_cast<ssize_t>(sl);
}

static ssize_t fake_readlink(const char* pathname, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(fake_readlink, pathname, buf, bufsiz);
    return rewrite_readlink_buf(buf, bufsiz, n);
}

static ssize_t fake_readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t n = BYTEHOOK_CALL_PREV(fake_readlinkat, dirfd, pathname, buf, bufsiz);
    return rewrite_readlink_buf(buf, bufsiz, n);
}

static char* fake_realpath(const char* path, char* resolved) {
    BYTEHOOK_STACK_SCOPE();
    const char* direct = spoof_mapped_path_c_str(path);
    auto write_spoof = [](const char* spoof, char* resolved_buf) -> char* {
        if (spoof == nullptr) return nullptr;
        size_t sl = strlen(spoof);
        if (sl >= PATH_MAX) {
            errno = ENAMETOOLONG;
            return nullptr;
        }
        if (resolved_buf == nullptr) {
            char* out = static_cast<char*>(std::malloc(sl + 1));
            if (out == nullptr) {
                errno = ENOMEM;
                return nullptr;
            }
            memcpy(out, spoof, sl + 1);
            return out;
        }
        memcpy(resolved_buf, spoof, sl + 1);
        return resolved_buf;
    };
    if (direct != nullptr) {
        return write_spoof(direct, resolved);
    }
    char* r = BYTEHOOK_CALL_PREV(fake_realpath, path, resolved);
    if (r == nullptr) return nullptr;
    const char* spoof = spoof_mapped_path_c_str(r);
    if (spoof == nullptr) return r;
    char* out = write_spoof(spoof, resolved);
    if (out != nullptr && resolved == nullptr && out != r) {
        std::free(r);
    }
    return out != nullptr ? out : r;
}

#if defined(__ANDROID__)
static char* fake_realpath_chk(const char* path, char* resolved, size_t resolved_len) {
    BYTEHOOK_STACK_SCOPE();
    (void)resolved_len;
    return fake_realpath(path, resolved);
}
#endif

/**
 * L2b: LIBRARY_FD may map so_plain or memfd; rewrite dli_fname to the extract
 * path recorded at L1m/L2 open so OSG/path-sensitive code matches stock layout.
 * L1m maps show lib_mirror — still rewrite to extract when recorded.
 */
static int fake_dladdr(const void* addr, Dl_info* info) {
    BYTEHOOK_STACK_SCOPE();
    int r = BYTEHOOK_CALL_PREV(fake_dladdr, addr, info);
    if (r == 0 || info == nullptr || info->dli_fname == nullptr) return r;
    const char* spoof = spoof_mapped_path_c_str(info->dli_fname);
    if (spoof != nullptr) {
        info->dli_fname = spoof;
    }
    return r;
}

static void decrypt_already_loaded() {
    // Copy names under lock — never hold SoKey* across unlock (load_sokeys swap).
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    for (const auto& name : names) {
        if (find_so_path(name.c_str()).empty()) continue;
        (void)decrypt_loaded_text(name);
    }
}

void decrypt_already_loaded_async() {
    if (!has_sokeys()) return;
    static std::atomic_bool started{false};
    bool expected = false;
    if (!started.compare_exchange_strong(expected, true)) return;
    std::thread([]() {
        decrypt_already_loaded();
        PLOGI("business so: decrypt_already_loaded (async) done");
    }).detach();
}

/** Real /proc/self/maps — bypasses libc fopen/open hooks (maps spoof). */
static FILE* fopen_maps_raw() {
    int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, "/proc/self/maps",
                                      O_RDONLY | O_CLOEXEC));
    if (fd < 0) return nullptr;
    FILE* fp = fdopen(fd, "r");
    if (fp == nullptr) close(fd);
    return fp;
}

static bool is_proc_maps_path(const char* pathname) {
    if (pathname == nullptr) return false;
    // /proc/self/maps, /proc/<pid>/maps
    if (strcmp(pathname, "/proc/self/maps") == 0) return true;
    if (strncmp(pathname, "/proc/", 6) != 0) return false;
    const char* slash = strrchr(pathname, '/');
    return slash != nullptr && strcmp(slash, "/maps") == 0;
}

static std::string plaintext_path_for_keyed(const std::string& base) {
    if (base.empty()) return {};
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
    }
    if (cache_root.empty()) return {};
    std::string plain = cache_root + "/so_plain/" + base;
    if (file_exists_path(plain)) return plain;
    std::string mirror = cache_root + "/" + kLibMirror + "/" + base;
    if (file_exists_path(mirror)) return mirror;
    return {};
}

/**
 * Rewrite one /proc/maps line: so_plain / lib_mirror / memfd keyed paths → extract.
 * OSG/Teigha dirname() the mapped path; stock layout uses /data/app/.../lib/.
 */
static std::string rewrite_maps_line(const std::string& line_in) {
    const bool from_plain = line_in.find("/so_plain/") != std::string::npos;
    const bool from_mirror = line_in.find("/lib_mirror/") != std::string::npos;
    const bool from_memfd = line_in.find("/memfd:") != std::string::npos
            || line_in.find(" /memfd:") != std::string::npos;
    if (!from_plain && !from_mirror && !from_memfd) return line_in;

    const auto slash = line_in.rfind('/');
    if (slash == std::string::npos || slash + 1 >= line_in.size()) return line_in;
    size_t name_end = line_in.size();
    if (line_in.back() == '\n') --name_end;
    if (name_end > slash + 1 && line_in[name_end - 1] == '\r') --name_end;
    if (from_memfd) {
        const auto sp = line_in.find(' ', slash + 1);
        if (sp != std::string::npos && sp < name_end) name_end = sp;
    }
    if (name_end <= slash + 1) return line_in;
    const size_t name_len = name_end - (slash + 1);
    if (name_len < 4 || name_len >= 256) return line_in;
    const std::string base = line_in.substr(slash + 1, name_len);
    if (!is_keyed_basename(base)) return line_in;
    const std::string extract = extract_path_for_keyed(base);
    if (extract.empty()) return line_in;

    const auto path_at = line_in.find(" /");
    if (path_at == std::string::npos) return line_in;
    const bool nl = !line_in.empty() && line_in.back() == '\n';
    std::string out = line_in.substr(0, path_at + 1);
    out += extract;
    if (nl) out.push_back('\n');
    return out;
}

static int build_spoofed_maps_fd() {
#if defined(__ANDROID__) && defined(__NR_memfd_create)
    FILE* in = fopen_maps_raw();
    if (in == nullptr) return -1;
    int out = static_cast<int>(syscall(__NR_memfd_create, "xop_maps", MFD_CLOEXEC));
    if (out < 0) {
        fclose(in);
        return -1;
    }
    std::string line;
    while (protector::read_maps_record(in, &line)) {
        line = rewrite_maps_line(line);
        if (line.empty()) continue;
        ssize_t w = write(out, line.data(), line.size());
        size_t n = line.size();
        if (w < 0 || static_cast<size_t>(w) != n) {
            close(out);
            fclose(in);
            return -1;
        }
    }
    fclose(in);
    if (lseek(out, 0, SEEK_SET) < 0) {
        close(out);
        return -1;
    }
    return out;
#else
    return -1;
#endif
}

static FILE* fake_fopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    if (path != nullptr && mode != nullptr && is_proc_maps_path(path)
            && mode[0] == 'r') {
        int fd = build_spoofed_maps_fd();
        if (fd >= 0) {
            FILE* fp = fdopen(fd, mode);
            if (fp != nullptr) return fp;
            close(fd);
        }
    }
    return BYTEHOOK_CALL_PREV(fake_fopen, path, mode);
}

/**
 * If the linker/app opens extract ciphertext for a keyed non-L2e SO
 * (absolute packaged path or relative DT_NEEDED name via dirfd), redirect to
 * so_plain after on-demand RC4. L2e keeps the extract inode.
 */
static thread_local int g_in_keyed_open_rewrite = 0;

static bool is_packaged_lib_abs(const char* pathname) {
    if (pathname == nullptr || pathname[0] != '/') return false;
    std::string nld;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
    }
    if (!nld.empty() && strncmp(pathname, nld.c_str(), nld.size()) == 0) {
        char next = pathname[nld.size()];
        return next == '\0' || next == '/';
    }
    if (strstr(pathname, "/data/app/") != nullptr && strstr(pathname, "/lib/") != nullptr) {
        return true;
    }
    if (strstr(pathname, "/lib/arm64") != nullptr
            || strstr(pathname, "/lib/armeabi") != nullptr
            || strstr(pathname, "lib/arm64-v8a") != nullptr
            || strstr(pathname, "lib/armeabi-v7a") != nullptr
            || strstr(pathname, "lib/x86") != nullptr) {
        return true;
    }
    return false;
}

static std::string redirect_keyed_open_path(const char* pathname) {
    if (pathname == nullptr || pathname[0] == '\0') return {};
    if (strstr(pathname, "/so_plain/") != nullptr) return {};
    if (strstr(pathname, "/lib_mirror/") != nullptr) return {};
    if (strstr(pathname, "/.xop_plain/") != nullptr) return {};
    std::string base = basename_of(pathname);
    if (!is_keyed_basename(base)) return {};
    if (extract_inode_hooks_ok()) return {};
    const bool abs = pathname[0] == '/';
    if (abs && !is_packaged_lib_abs(pathname)) return {};
    if (g_in_keyed_open_rewrite > 0) return {};
    ++g_in_keyed_open_rewrite;
    ensure_plain_closure_for(base);
    --g_in_keyed_open_rewrite;
    std::string plain = plaintext_path_for_keyed(base);
    if (plain.empty()) return {};
    if (abs && plain == pathname) return {};
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] open rewrite %s -> %s",
               pathname, plain.c_str());
    return plain;
}

static int fake_openat(int dirfd, const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    if (pathname != nullptr && is_proc_maps_path(pathname)
            && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = build_spoofed_maps_fd();
        if (fd >= 0) return fd;
    }
    std::string redir = redirect_keyed_open_path(pathname);
    const char* use = redir.empty() ? pathname : redir.c_str();
    return BYTEHOOK_CALL_PREV(fake_openat, dirfd, use, flags, mode);
}

static int fake_open(const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0 || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    if (pathname != nullptr && is_proc_maps_path(pathname)
            && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = build_spoofed_maps_fd();
        if (fd >= 0) return fd;
    }
    std::string redir = redirect_keyed_open_path(pathname);
    const char* use = redir.empty() ? pathname : redir.c_str();
    return BYTEHOOK_CALL_PREV(fake_open, use, flags, mode);
}

#if defined(__ANDROID__)
static int fake___openat(int dirfd, const char* pathname, int flags, int mode) {
    BYTEHOOK_STACK_SCOPE();
    if (pathname != nullptr && is_proc_maps_path(pathname)
            && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = build_spoofed_maps_fd();
        if (fd >= 0) return fd;
    }
    std::string redir = redirect_keyed_open_path(pathname);
    const char* use = redir.empty() ? pathname : redir.c_str();
    return BYTEHOOK_CALL_PREV(fake___openat, dirfd, use, flags, mode);
}
#endif

using LinkerOpenat4Fn = int (*)(int, const char*, int, int);
static LinkerOpenat4Fn g_orig_linker_openat4 = nullptr;
using LinkerOpen3Fn = int (*)(const char*, int, int);
static LinkerOpen3Fn g_orig_linker_open3 = nullptr;

static int hooked_linker_openat4(int dirfd, const char* pathname, int flags, int mode) {
    static thread_local int depth = 0;
    auto call_orig = [&](int d, const char* p, int f, int m) -> int {
        if (g_orig_linker_openat4 != nullptr) {
            return g_orig_linker_openat4(d, p, f, m);
        }
        return static_cast<int>(syscall(__NR_openat, d, p, f, m));
    };
    if (depth > 0) return call_orig(dirfd, pathname, flags, mode);
    ++depth;
    if (pathname != nullptr && is_proc_maps_path(pathname)
            && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = build_spoofed_maps_fd();
        if (fd >= 0) {
            --depth;
            return fd;
        }
    }
    std::string redir = redirect_keyed_open_path(pathname);
    const char* use = redir.empty() ? pathname : redir.c_str();
    int fd = call_orig(dirfd, use, flags, mode);
    --depth;
    return fd;
}

static int hooked_linker_open3(const char* pathname, int flags, int mode) {
    static thread_local int depth = 0;
    auto call_orig = [&](const char* p, int f, int m) -> int {
        if (g_orig_linker_open3 != nullptr) {
            return g_orig_linker_open3(p, f, m);
        }
        return static_cast<int>(syscall(__NR_openat, AT_FDCWD, p, f, m));
    };
    if (depth > 0) return call_orig(pathname, flags, mode);
    ++depth;
    if (pathname != nullptr && is_proc_maps_path(pathname)
            && (flags & O_ACCMODE) == O_RDONLY) {
        int fd = build_spoofed_maps_fd();
        if (fd >= 0) {
            --depth;
            return fd;
        }
    }
    std::string redir = redirect_keyed_open_path(pathname);
    const char* use = redir.empty() ? pathname : redir.c_str();
    int fd = call_orig(use, flags, mode);
    --depth;
    return fd;
}

static bool patch_got_slot(void* slot, void* fake, void** orig_out) {
    if (slot == nullptr || fake == nullptr || orig_out == nullptr) return false;
    int ps = getpagesize();
    uintptr_t page = reinterpret_cast<uintptr_t>(slot) & ~static_cast<uintptr_t>(ps - 1);
    if (mprotect(reinterpret_cast<void*>(page), static_cast<size_t>(ps) * 2,
                 PROT_READ | PROT_WRITE) != 0) {
        return false;
    }
    *orig_out = *reinterpret_cast<void**>(slot);
    *reinterpret_cast<void**>(slot) = fake;
    return *orig_out != nullptr;
}

static bool hook_linker_import(const char* linker_path, const char* sym, void* fake) {
    if (linker_path == nullptr || linker_path[0] == '\0' || sym == nullptr) return false;
    bytehook_stub_t s = bytehook_hook_single(
            linker_path, nullptr, sym, fake, nullptr, nullptr);
    if (s != nullptr) {
        PLOGI("business so: linker %s GOT hooked path=%s", sym, linker_path);
        return true;
    }
    const char* base = strrchr(linker_path, '/');
    base = base ? base + 1 : linker_path;
    if (strcmp(base, linker_path) != 0) {
        s = bytehook_hook_single(base, nullptr, sym, fake, nullptr, nullptr);
        if (s != nullptr) {
            PLOGI("business so: linker %s GOT hooked basename=%s", sym, base);
            return true;
        }
    }
    return false;
}

static void install_linker_open_hooks() {
    LinkerInfo li{};
    if (!find_linker_info(&li) || li.path[0] == 0) {
        PLOGW("business so: linker not found — openat rewrite skipped");
        return;
    }
    bool any = false;
    any |= hook_linker_import(li.path, "openat", reinterpret_cast<void*>(fake_openat));
    any |= hook_linker_import(li.path, "open", reinterpret_cast<void*>(fake_open));
#if defined(__ANDROID__)
    any |= hook_linker_import(li.path, "__openat", reinterpret_cast<void*>(fake___openat));
#endif
    any |= hook_linker_import(li.path, "openat64", reinterpret_cast<void*>(fake_openat));
    any |= hook_linker_import(li.path, "open64", reinterpret_cast<void*>(fake_open));

    const char* defined_syms[] = {"openat", "__openat", nullptr};
    for (int i = 0; defined_syms[i] != nullptr; i++) {
        void* addr = resolve_linker_symbol(li.path, li.load_bias, defined_syms[i], nullptr);
        if (addr == nullptr) continue;
        int rc = DobbyHook(addr, reinterpret_cast<dobby_dummy_func_t>(hooked_linker_openat4),
                           reinterpret_cast<dobby_dummy_func_t*>(&g_orig_linker_openat4));
        if (rc == 0) {
            any = true;
            PLOGI("business so: linker %s DobbyHook path=%s", defined_syms[i], li.path);
            break;
        }
    }

    if (g_orig_linker_openat4 == nullptr) {
        const char* imports[] = {"openat", "__openat", nullptr};
        for (int i = 0; imports[i] != nullptr; i++) {
            void* slot = resolve_linker_import_got(li.path, li.load_bias, imports[i]);
            if (slot == nullptr) continue;
            void* orig = nullptr;
            if (patch_got_slot(slot, reinterpret_cast<void*>(hooked_linker_openat4), &orig)) {
                g_orig_linker_openat4 = reinterpret_cast<LinkerOpenat4Fn>(orig);
                any = true;
                PLOGI("business so: linker %s GOT patched path=%s", imports[i], li.path);
                break;
            }
        }
    }

    g_linker_open_hooks_ok.store(any, std::memory_order_release);
    if (any) {
        xop_so_log(ANDROID_LOG_INFO,
                   "[XOP-SO] linker open/openat rewrite enabled path=%s", li.path);
    } else {
        xop_so_log(ANDROID_LOG_WARN,
                   "[XOP-SO] linker open/openat hook failed path=%s", li.path);
        PLOGW("business so: linker open/openat hook failed path=%s", li.path);
    }
}

struct DlIteratePkg {
    int (*user_cb)(struct dl_phdr_info*, size_t, void*);
    void* user_data;
};

static int dl_iterate_rewrite_cb(struct dl_phdr_info* info, size_t size, void* data) {
    auto* pkg = reinterpret_cast<DlIteratePkg*>(data);
    if (info == nullptr || pkg == nullptr || pkg->user_cb == nullptr) return 0;
    struct dl_phdr_info copy = *info;
    const char* spoof = spoof_mapped_path_c_str(info->dlpi_name);
    if (spoof != nullptr) {
        copy.dlpi_name = spoof;
    }
    return pkg->user_cb(&copy, size, pkg->user_data);
}

static int fake_dl_iterate_phdr(int (*cb)(struct dl_phdr_info*, size_t, void*),
                                void* data) {
    BYTEHOOK_STACK_SCOPE();
    if (cb == nullptr) {
        return BYTEHOOK_CALL_PREV(fake_dl_iterate_phdr, cb, data);
    }
    DlIteratePkg pkg{cb, data};
    return BYTEHOOK_CALL_PREV(fake_dl_iterate_phdr, dl_iterate_rewrite_cb, &pkg);
}

void install_business_so_hooks() {
    bool expected = false;
    if (!g_hooks_installed.compare_exchange_strong(expected, true)) {
        // Already installed — if keys just arrived, flush pending / loaded.
        if (has_sokeys()) {
            std::vector<std::string> pending;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                pending.swap(g_pending);
            }
            for (const auto& name : pending) maybe_decrypt_by_name(name);
            if (!dlopen_hooks_ok()) {
                PLOGW("business so: dlopen hooks down — force full materialize "
                      "(extract_ok=%d)",
                      extract_inode_hooks_ok() ? 1 : 0);
                materialize_all_keyed_sos();
            }
            decrypt_already_loaded_async();
        }
        return;
    }

    bytehook_stub_t s1 = bytehook_hook_all(
            nullptr, "dlopen", reinterpret_cast<void*>(fake_dlopen), nullptr, nullptr);
    if (s1) PLOGI("business so: dlopen hooked (early-capable)");
    else PLOGW("business so: dlopen hook failed");

    bytehook_stub_t s2 = bytehook_hook_all(
            nullptr, "android_dlopen_ext",
            reinterpret_cast<void*>(fake_android_dlopen_ext), nullptr, nullptr);
    if (s2) PLOGI("business so: android_dlopen_ext hooked");
    else PLOGW("business so: android_dlopen_ext hook failed");

    // Android 10+ libnativeloader often exposes this instead of android_dlopen_ext.
    bytehook_stub_t s3 = bytehook_hook_all(
            nullptr, "__loader_android_dlopen_ext",
            reinterpret_cast<void*>(fake_android_dlopen_ext), nullptr, nullptr);
    if (s3) PLOGI("business so: __loader_android_dlopen_ext hooked");
    else PLOGW("business so: __loader_android_dlopen_ext hook failed");

    bytehook_stub_t s4 = bytehook_hook_all(
            nullptr, "dladdr", reinterpret_cast<void*>(fake_dladdr), nullptr, nullptr);
    if (s4) PLOGI("business so: dladdr hooked (L2b path rewrite)");
    else PLOGW("business so: dladdr hook failed");

    bytehook_stub_t s4b = bytehook_hook_all(
            nullptr, "__loader_dladdr", reinterpret_cast<void*>(fake_dladdr),
            nullptr, nullptr);
    if (s4b) PLOGI("business so: __loader_dladdr hooked (L2b path rewrite)");
    else PLOGW("business so: __loader_dladdr hook failed");

    bytehook_stub_t s5 = bytehook_hook_all(
            nullptr, "fopen", reinterpret_cast<void*>(fake_fopen), nullptr, nullptr);
    if (s5) PLOGI("business so: fopen hooked (maps spoof)");
    else PLOGW("business so: fopen hook failed");

    bytehook_stub_t s6 = bytehook_hook_all(
            nullptr, "openat", reinterpret_cast<void*>(fake_openat), nullptr, nullptr);
    if (s6) PLOGI("business so: openat hooked (maps spoof + keyed open redirect)");
    else PLOGW("business so: openat hook failed");

    bytehook_stub_t s7 = bytehook_hook_all(
            nullptr, "open", reinterpret_cast<void*>(fake_open), nullptr, nullptr);
    if (s7) PLOGI("business so: open hooked");
    else PLOGW("business so: open hook failed");

    bytehook_stub_t s7b = bytehook_hook_all(
            nullptr, "__openat", reinterpret_cast<void*>(fake___openat), nullptr, nullptr);
    if (s7b) PLOGI("business so: __openat hooked");
    else PLOGW("business so: __openat hook failed");

    bytehook_stub_t s8 = bytehook_hook_all(
            nullptr, "dl_iterate_phdr", reinterpret_cast<void*>(fake_dl_iterate_phdr),
            nullptr, nullptr);
    if (s8) PLOGI("business so: dl_iterate_phdr hooked");
    else PLOGW("business so: dl_iterate_phdr hook failed");

    bytehook_stub_t s9 = bytehook_hook_all(
            nullptr, "readlink", reinterpret_cast<void*>(fake_readlink), nullptr, nullptr);
    if (s9) PLOGI("business so: readlink hooked (L2b path rewrite)");
    else PLOGW("business so: readlink hook failed");

    bytehook_stub_t s10 = bytehook_hook_all(
            nullptr, "readlinkat", reinterpret_cast<void*>(fake_readlinkat),
            nullptr, nullptr);
    if (s10) PLOGI("business so: readlinkat hooked (L2b path rewrite)");
    else PLOGW("business so: readlinkat hook failed");

    bytehook_stub_t s11 = bytehook_hook_all(
            nullptr, "realpath", reinterpret_cast<void*>(fake_realpath), nullptr, nullptr);
    if (s11) PLOGI("business so: realpath hooked (L2b path rewrite)");
    else PLOGW("business so: realpath hook failed");

    bytehook_stub_t s12 = bytehook_hook_all(
            nullptr, "__realpath_chk", reinterpret_cast<void*>(fake_realpath_chk),
            nullptr, nullptr);
    if (s12) PLOGI("business so: __realpath_chk hooked");
    else PLOGW("business so: __realpath_chk hook failed");

    install_linker_extract_hooks();
    install_linker_open_hooks();

    const bool any = (s1 != nullptr) || (s2 != nullptr) || (s3 != nullptr);
    g_dlopen_hooks_ok.store(any, std::memory_order_release);
    xop_so_log(ANDROID_LOG_INFO,
               "[XOP-SO] bytehook dlopen=%d android_dlopen_ext=%d loader_ext=%d openat=%d",
               s1 != nullptr ? 1 : 0, s2 != nullptr ? 1 : 0, s3 != nullptr ? 1 : 0,
               s6 != nullptr ? 1 : 0);
    if (!any) {
        PLOGW("business so: all dlopen-family hooks failed (bytehook init?)");
        if (has_sokeys() && !dlopen_hooks_ok()) {
            PLOGW("business so: dlopen hooks down — force full materialize "
                  "(extract_ok=%d)",
                  extract_inode_hooks_ok() ? 1 : 0);
            materialize_all_keyed_sos();
        }
    }

    // Eager scan deferred — see decrypt_already_loaded_async from init_app.
}

/**
 * True when /proc/self/maps has an executable mapping of {@code base} whose
 * path is <b>not</b> so_plain (typically packaged extract ciphertext).
 * Android 6 often fails L2/L3 dlopen(so_plain) (verneed) and falls back to the
 * encrypted extract while disk materialize already marked the key decrypted.
 */
static bool packaged_so_mapped(const std::string& base) {
    if (base.empty()) return false;
    FILE* fp = fopen_maps_raw();
    if (fp == nullptr) return false;
    std::string line;
    bool hit = false;
    while (protector::read_maps_record(fp, &line)) {
        // r-xp / rwxp — skip non-executable (file read caches).
        if (line.find("r-xp") == std::string::npos && line.find("rwxp") == std::string::npos) {
            continue;
        }
        std::string path;
        if (!protector::maps_pathname(line, &path)) continue;
        if (path.find("/so_plain/") != std::string::npos) continue;
        if (maps_basename(path) == base) {
            hit = true;
            break;
        }
    }
    fclose(fp);
    return hit;
}

bool ensure_decrypted(const char* so_basename) {
    if (so_basename == nullptr || so_basename[0] == '\0') return true;
    std::string base = basename_of(so_basename);
    if (base.empty()) base = so_basename;

    bool tracked = false;
    bool disk_done = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(base);
        if (key == nullptr) return true; // not protected
        disk_done = key->decrypted;
        tracked = true;
    }

    // Disk so_plain may already be plaintext (key.decrypted) while the linker
    // still mapped packaged ciphertext — common on API≤23 when L2/L3 verneed
    // fails. Only skip when no packaged executable mapping remains.
    if (disk_done && !packaged_so_mapped(base)) {
        return true;
    }

    // On-demand: ensure so_plain + keyed deps first (all modes).
    ensure_plain_closure_for(base);

    if (!decrypt_loaded_text(base)) {
        PLOGE("ensure_decrypted failed: %s", base.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lock(g_mu);
    bool ok = is_decrypted_unlocked(base);
    if (!ok && tracked) {
        PLOGE("ensure_decrypted: still encrypted after claim: %s", base.c_str());
    }
    return ok;
}

} // namespace protector::so
