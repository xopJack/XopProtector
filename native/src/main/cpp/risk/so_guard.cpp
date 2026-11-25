#include "risk/so_guard.h"
#include "risk/risk.h"
#include "common/elf_util.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "common/runtime_state.h"
#include "crypto/sha256.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif

namespace protector::risk {

static std::atomic_bool g_so_guard_ready{false};
static std::atomic_bool g_expected_ready{false};
static std::atomic_bool g_integrity_failed{false};
static uint8_t* g_bitcode_addr = nullptr;
static size_t g_bitcode_size = 0;
static uintptr_t g_so_base = 0;
static uint8_t g_hmac_key[32];
static uint8_t g_expected_mac[32];

static bool resolve_self(Dl_info* info, std::string* so_path) {
    if (dladdr(reinterpret_cast<const void*>(&so_guard_init), info) == 0
        || info->dli_fbase == nullptr) {
        return false;
    }
    g_so_base = reinterpret_cast<uintptr_t>(info->dli_fbase);
    if (info->dli_fname != nullptr && info->dli_fname[0] == '/') {
        so_path->assign(info->dli_fname);
    } else if (info->dli_fname != nullptr) {
        *so_path = find_so_path(info->dli_fname);
    }
    if (so_path->empty()) {
        *so_path = find_so_path("libprotector.so");
    }
    return !so_path->empty();
}

static bool map_bitcode() {
    if (g_bitcode_addr != nullptr && g_bitcode_size > 0) {
        return true;
    }
    Dl_info info{};
    std::string so_path;
    if (!resolve_self(&info, &so_path)) {
        return false;
    }
    Elf_Shdr shdr{};
    get_elf_section(&shdr, so_path.c_str(), SECTION_NAME_BITCODE);
    if (shdr.sh_size == 0 || (shdr.sh_flags & SHF_ALLOC) == 0) {
        return false;
    }
    g_bitcode_addr = reinterpret_cast<uint8_t*>(info.dli_fbase) + shdr.sh_addr;
    g_bitcode_size = static_cast<size_t>(shdr.sh_size);
    (void)madvise(g_bitcode_addr, g_bitcode_size, MADV_DONTDUMP);
    return true;
}

PROTECTOR_ENCRYPT void so_guard_init() {
    if (!map_bitcode()) {
        PLOGW("so_guard_init: .bitcode not mapped (HMAC deferred)");
    }

    FILE* st = fopen("/proc/self/status", "r");
    if (st) {
        char line[256];
        int tracer = -1;
        while (fgets(line, sizeof(line), st)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                sscanf(line + 10, "%d", &tracer);
                break;
            }
        }
        fclose(st);
        if (tracer == 0) {
            prctl(PR_SET_DUMPABLE, 0);
        }
    }

    g_so_guard_ready.store(true, std::memory_order_release);
    PLOGI("so_guard ready mapped=%d size=%zu",
          (g_bitcode_addr != nullptr && g_bitcode_size > 0) ? 1 : 0, g_bitcode_size);
}

const char* so_guard_abi() {
#if defined(__aarch64__)
    return "arm64-v8a";
#elif defined(__arm__)
    return "armeabi-v7a";
#elif defined(__x86_64__)
    return "x86_64";
#elif defined(__i386__)
    return "x86";
#else
    return "unknown";
#endif
}

bool so_guard_integrity_failed() {
    return g_integrity_failed.load(std::memory_order_acquire);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool parse_hmac_hex(const std::string& hex, uint8_t out[32]) {
    if (hex.size() != 64) return false;
    for (int i = 0; i < 32; i++) {
        int hi = hex_nibble(hex[static_cast<size_t>(i * 2)]);
        int lo = hex_nibble(hex[static_cast<size_t>(i * 2 + 1)]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

static bool mac32_eq(const uint8_t a[32], const uint8_t b[32]) {
    uint8_t d = 0;
    for (int i = 0; i < 32; i++) {
        d |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return d == 0;
}

static void fail_so_integrity(const char* reason) {
    g_integrity_failed.store(true, std::memory_order_release);
    mark_environment_degraded();
    schedule_integrity_exit();
    PLOGE("so_guard bitcode hmac fail: %s", reason != nullptr ? reason : "mismatch");
}

static bool find_unique_master_payload(const uint8_t* buf, size_t len, size_t* payload_off) {
    static const uint8_t kMagic[16] = {
            0x58, 0x4f, 0x50, 0x4b, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52, 0, 0, 0, 0, 0, 0
    };
    if (buf == nullptr || payload_off == nullptr || len < 48) {
        return false;
    }
    int count = 0;
    size_t found = 0;
    for (size_t i = 0; i + 48 <= len; i++) {
        if (memcmp(buf + i, kMagic, 16) == 0) {
            count++;
            found = i + 16;
        }
    }
    if (count != 1) {
        return false;
    }
    *payload_off = found;
    return true;
}

static bool so_guard_bitcode_hmac_ok() {
    if (!g_expected_ready.load(std::memory_order_acquire)) {
        return false;
    }
    if (g_bitcode_addr == nullptr || g_bitcode_size == 0) {
        return false;
    }
    size_t payload_off = 0;
    if (!find_unique_master_payload(g_bitcode_addr, g_bitcode_size, &payload_off)) {
        return false;
    }
    /* Match packer hmacBitcodePostWipe: magic stays, 32-byte payload is zeros.
     * Do not require the in-place wipe to have already landed (const slot). */
    const uint8_t zeros[32] = {0};
    const void* parts[3] = {
            g_bitcode_addr,
            zeros,
            g_bitcode_addr + payload_off + 32
    };
    size_t lens[3] = {
            payload_off,
            32,
            g_bitcode_size - payload_off - 32
    };
    uint8_t mac[32];
    protector::crypto::hmac_sha256_parts(g_hmac_key, sizeof(g_hmac_key),
                                         parts, lens, 3, mac);
    bool ok = mac32_eq(mac, g_expected_mac);
    memset(mac, 0, sizeof(mac));
    return ok;
}

bool so_guard_bind_hmac(const uint8_t* hmac_key, size_t key_len, const std::string& expected_hex) {
    if (hmac_key == nullptr || key_len != 32) {
        return false;
    }
    uint8_t expected[32];
    if (!parse_hmac_hex(expected_hex, expected)) {
        return false;
    }
    memcpy(g_hmac_key, hmac_key, 32);
    memcpy(g_expected_mac, expected, 32);
    memset(expected, 0, sizeof(expected));
    g_expected_ready.store(true, std::memory_order_release);

    if (!map_bitcode()) {
        PLOGW("so_guard bitcode hmac deferred: section not mapped abi=%s", so_guard_abi());
        return true;
    }
    if (!so_guard_bitcode_hmac_ok()) {
        fail_so_integrity("bind");
        return false;
    }
    PLOGI("so_guard bitcode hmac bound abi=%s", so_guard_abi());
    return true;
}

/** Cap maps walks — desktop forks can expose very large /proc/self/maps. */
constexpr int kSoGuardMapsMaxLines = 8192;

struct SoGuardMapsHits {
    bool rwx = false;
    bool dump_tools = false;
};

/** One maps pass for RWX-on-self and dump/hook tooling. */
static SoGuardMapsHits maps_scan_so_guard() {
    SoGuardMapsHits hits;
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return hits;
    char line[512];
    int lines = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (++lines > kSoGuardMapsMaxLines) break;
        if (!hits.dump_tools) {
            if (strstr(line, "memdump")
                || strstr(line, "libGameGuardian")
                || strstr(line, "frida-gadget")
                || strstr(line, "frida-agent")
                || strstr(line, "libdump.so")) {
                hits.dump_tools = true;
            }
        }
        if (!hits.rwx && g_so_base != 0) {
            unsigned long start = 0, end = 0;
            char perms[8] = {0};
            if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {
                bool wx = (strchr(perms, 'w') != nullptr && strchr(perms, 'x') != nullptr);
                if (wx) {
                    if (strstr(line, "libprotector") != nullptr) {
                        hits.rwx = true;
                    } else if (start >= g_so_base && start < g_so_base + 16ull * 1024 * 1024
                            && end > g_so_base && strstr(line, ".so") != nullptr
                            && strstr(line, "/") == nullptr) {
                        // Anonymous RWX abutting our SO often means inline trampoline.
                        hits.rwx = true;
                    }
                }
            }
        }
        if (hits.rwx && hits.dump_tools) break;
    }
    fclose(fp);
    return hits;
}

PROTECTOR_ENCRYPT void so_guard_check() {
    if (!g_so_guard_ready.load(std::memory_order_acquire)) return;
    int flags = runtime_state().config.risk_flags.load(std::memory_order_relaxed);
    if ((flags & FLAG_DISABLE_SO_INTEGRITY) != 0) return;

    if (g_expected_ready.load(std::memory_order_acquire)) {
        if (g_bitcode_addr == nullptr || g_bitcode_size == 0) {
            (void)map_bitcode();
        }
        if (g_bitcode_addr != nullptr && g_bitcode_size > 0 && !so_guard_bitcode_hmac_ok()) {
            fail_so_integrity("check");
            return;
        }
    }

    const SoGuardMapsHits maps = maps_scan_so_guard();
    if (maps.rwx) {
        PLOGW("so_guard: RWX mapping on libprotector");
        handle_risk("so_rwx", CrashKind::SigIll);
        return;
    }
    if (maps.dump_tools) {
        PLOGW("so_guard: dump/hook tooling in maps");
        handle_risk("so_dump_tool", CrashKind::SigSegv);
    }
}

} // namespace protector::risk
