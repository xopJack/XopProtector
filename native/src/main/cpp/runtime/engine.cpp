#include "runtime/engine.h"
#include "common/log.h"
#include "common/runtime_state.h"
#include "common/protector_macro.h"
#include "codeitem/multi_dex_code.h"
#include "crypto/sha256.h"
#include "crypto/apk_sign.h"
#include "crypto/key_ladder.h"
#include "crypto/dex_asset.h"
#include "dex/dex_file.h"
#include "hook/hooks.h"
#include "risk/risk.h"
#include "risk/so_guard.h"
#include "report/threat_report.h"
#include "so/business_so.h"
#include "vm/pvm2_interp.h"
#include "common/sys_io.h"

#include <android/api-level.h>
#include <algorithm>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <cctype>
#include <atomic>
#include <vector>
#include <unordered_map>

#include "json.hpp"

namespace protector::runtime {

static JavaVM* g_vm = nullptr;
/** False until Java enables checks after ClassLoader + DexMerger are ready. */
static std::atomic_bool g_junk_verify_enabled{false};

/** Protector assets (config.json / code.bin / dexes.zip HMAC) — syscall read. */
static std::string read_file(const std::string& path) {
    std::string out;
    if (!protector::sys_read_file(path.c_str(), out)) {
        return {};
    }
    return out;
}

static bool file_exists(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && st.st_size > 0;
}

/** Previous launch left .prepatched + classes*.dex — skip dexes.zip decrypt. */
static bool has_warm_dex_cache(const std::string& dir) {
    if (!file_exists(dir + "/.prepatched")) return false;
    DIR* d = opendir(dir.c_str());
    if (d == nullptr) return false;
    bool found = false;
    while (dirent* ent = readdir(d)) {
        const char* n = ent->d_name;
        if (n == nullptr) continue;
        size_t len = strlen(n);
        if (len > 4 && strncmp(n, "classes", 7) == 0 && strcmp(n + len - 4, ".dex") == 0) {
            std::string path = dir + "/" + n;
            if (file_exists(path)) {
                found = true;
                break;
            }
        }
    }
    closedir(d);
    return found;
}

/** Verify HMAC-SHA256 over config payload (everything before "_hmac").
 *  Uses a constant-time hex compare to avoid timing side-channels.
 *  On mismatch calls crash_exit() — clean exit, hard to trace. */
static void verify_config_hmac(const std::string& json_text) {
    // Locate the _hmac field injected by the packer.
    auto hmac_key_pos = json_text.find("\"_hmac\"");
    if (hmac_key_pos == std::string::npos) {
        PLOGE("config.json missing _hmac field");
        protector::risk::crash_exit();
        return;
    }

    // Payload is everything before the comma that separates _hmac.
    size_t payload_end = hmac_key_pos;
    while (payload_end > 0 &&
           (json_text[payload_end - 1] == ',' || json_text[payload_end - 1] == ' ')) {
        payload_end--;
    }
    std::string payload = json_text.substr(0, payload_end);

    // Extract expected HMAC hex value.
    auto colon = json_text.find(':', hmac_key_pos);
    auto val_start = json_text.find('"', colon + 1);
    auto val_end = json_text.find('"', val_start + 1);
    if (colon == std::string::npos || val_start == std::string::npos
            || val_end == std::string::npos || val_end <= val_start) {
        PLOGE("config.json _hmac malformed");
        protector::risk::crash_exit();
        return;
    }
    std::string expected_hex = json_text.substr(val_start + 1, val_end - val_start - 1);
    if (expected_hex.size() != 64) {
        PLOGE("config.json _hmac wrong length");
        protector::risk::crash_exit();
        return;
    }

    uint8_t hmac_key[PROTECTOR_HMAC_KEY_SIZE];
    auto& cfg = runtime_state().config;
    if (cfg.hmac_key.size() != PROTECTOR_HMAC_KEY_SIZE) {
        PLOGE("HMAC key missing — key ladder failed");
        protector::risk::crash_exit();
        return;
    }
    memcpy(hmac_key, cfg.hmac_key.data(), PROTECTOR_HMAC_KEY_SIZE);

    // Compute HMAC-SHA256.
    uint8_t mac[32];
    protector::crypto::hmac_sha256(hmac_key, PROTECTOR_HMAC_KEY_SIZE,
                                   payload.data(), payload.size(), mac);
    memset(hmac_key, 0, sizeof(hmac_key));

    // Constant-time hex comparison.
    static const char kHex[] = "0123456789abcdef";
    int diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (kHex[mac[i] >> 4] ^ expected_hex[static_cast<size_t>(i * 2)]);
        diff |= (kHex[mac[i] & 0xf] ^ expected_hex[static_cast<size_t>(i * 2 + 1)]);
    }

    if (diff != 0) {
        PLOGE("config.json HMAC mismatch — config was tampered");
        protector::risk::crash_exit();
    }
}

static void parse_config_json(const std::string& json_text) {
    auto& cfg = runtime_state().config;
    if (json_text.empty()) {
        PLOGW("config.json empty");
        return;
    }
    // Verify integrity before trusting any config value.
    verify_config_hmac(json_text);
    try {
        auto j = nlohmann::json::parse(json_text);
        if (j.contains("application_name") && j["application_name"].is_string()) {
            cfg.application_name = j["application_name"].get<std::string>();
        }
        if (j.contains("package") && j["package"].is_string()) {
            cfg.package_name = j["package"].get<std::string>();
        }
        if (j.contains("insns_xor_key") && j["insns_xor_key"].is_number_integer()) {
            cfg.insns_xor_key = j["insns_xor_key"].get<uint32_t>();
        }
        // Prefer SO-embedded AES key; reject plaintext key-in-config fallback.
        if (j.contains("risk_flags") && j["risk_flags"].is_number_integer()) {
            cfg.risk_flags.store(j["risk_flags"].get<int>(), std::memory_order_relaxed);
        }
        if (j.contains("rasp_action") && j["rasp_action"].is_number_integer()) {
            int action = j["rasp_action"].get<int>();
            if (action < 0 || action > 2) action = static_cast<int>(RaspAction::Block);
            cfg.rasp_action.store(action, std::memory_order_relaxed);
        }
        if (j.contains("app_sign_sha256") && j["app_sign_sha256"].is_string()) {
            cfg.app_sign_sha256 = j["app_sign_sha256"].get<std::string>();
        }
        if (j.contains("protect_so")) {
            if (j["protect_so"].is_boolean()) {
                cfg.protect_so = j["protect_so"].get<bool>();
            } else if (j["protect_so"].is_number_integer()) {
                cfg.protect_so = j["protect_so"].get<int>() != 0;
            }
        }
        if (j.contains("encrypt_assets")) {
            if (j["encrypt_assets"].is_boolean()) {
                cfg.encrypt_assets = j["encrypt_assets"].get<bool>();
            } else if (j["encrypt_assets"].is_number_integer()) {
                cfg.encrypt_assets = j["encrypt_assets"].get<int>() != 0;
            }
        }
        // Missing so_decrypt_mode → Eager (old APKs / unsigned configs).
        cfg.so_decrypt_mode = SoDecryptMode::Eager;
        if (j.contains("so_decrypt_mode") && j["so_decrypt_mode"].is_string()) {
            std::string mode = j["so_decrypt_mode"].get<std::string>();
            for (auto& c : mode) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            if (mode == "lazy") {
                cfg.so_decrypt_mode = SoDecryptMode::Lazy;
            } else if (mode != "eager") {
                PLOGW("config so_decrypt_mode='%s' unknown — using eager",
                      j["so_decrypt_mode"].get<std::string>().c_str());
                cfg.so_decrypt_mode = SoDecryptMode::Eager;
            }
        }
        protector::so::set_so_decrypt_mode(cfg.so_decrypt_mode);
        cfg.so_diag = false;
        if (j.contains("so_diag")) {
            if (j["so_diag"].is_boolean()) {
                cfg.so_diag = j["so_diag"].get<bool>();
            } else if (j["so_diag"].is_number_integer()) {
                cfg.so_diag = j["so_diag"].get<int>() != 0;
            }
        }
        protector::so::set_so_diag(cfg.so_diag);
        cfg.vmp_lru = 32;
        if (j.contains("vmp_lru") && j["vmp_lru"].is_number_integer()) {
            int n = j["vmp_lru"].get<int>();
            if (n < 1) n = 1;
            if (n > 256) n = 256;
            cfg.vmp_lru = n;
        }
        if (j.contains("dex_hmac") && j["dex_hmac"].is_string()) {
            cfg.dex_hmac = j["dex_hmac"].get<std::string>();
        }
        if (j.contains("code_hmac") && j["code_hmac"].is_string()) {
            cfg.code_hmac = j["code_hmac"].get<std::string>();
        }
        if (j.contains("code_methods_hmac") && j["code_methods_hmac"].is_string()) {
            cfg.code_methods_hmac = j["code_methods_hmac"].get<std::string>();
        }
        cfg.bitcode_hmac.clear();
        if (j.contains("bitcode_hmac") && j["bitcode_hmac"].is_object()) {
            for (auto it = j["bitcode_hmac"].begin(); it != j["bitcode_hmac"].end(); ++it) {
                if (it.value().is_string()) {
                    cfg.bitcode_hmac[it.key()] = it.value().get<std::string>();
                }
            }
        }
        bool report_enabled = true;
        if (j.contains("report_enabled")) {
            if (j["report_enabled"].is_boolean()) {
                report_enabled = j["report_enabled"].get<bool>();
            } else if (j["report_enabled"].is_number_integer()) {
                report_enabled = j["report_enabled"].get<int>() != 0;
            }
        }
        protector::report::set_report_enabled(report_enabled);
        PLOGI("config app=%s xor=0x%x aes=%s dex_aes=%s assets_aes=%s risk_flags=0x%x rasp=%d report=%d protect_so=%d so_decrypt=%s so_diag=%d encrypt_assets=%d vmp_lru=%d sign=%s",
              cfg.application_name.c_str(), cfg.insns_xor_key,
              cfg.insns_aes_key.size() == 16 ? "yes" : "no",
              cfg.dex_aes_key.size() == 16 ? "yes" : "no",
              cfg.assets_aes_key.size() == 16 ? "yes" : "no",
              cfg.risk_flags.load(std::memory_order_relaxed),
              cfg.rasp_action.load(std::memory_order_relaxed),
              report_enabled ? 1 : 0,
              cfg.protect_so ? 1 : 0,
              cfg.so_decrypt_mode == SoDecryptMode::Lazy ? "lazy" : "eager",
              cfg.so_diag ? 1 : 0,
              cfg.encrypt_assets ? 1 : 0,
              cfg.vmp_lru,
              cfg.app_sign_sha256.empty() ? "(none)" : "set");
        // Keep K_hmac for dex/code/bitcode HMAC checks (not a single checkIntegrity).
    } catch (const std::exception& e) {
        PLOGE("config.json parse failed: %s", e.what());
    } catch (...) {
        PLOGE("config.json parse failed");
    }
}

static void junk_code_protect(JNIEnv* env) {
#ifndef DEBUG
    static std::atomic_bool verified{false};
    if (verified.load(std::memory_order_relaxed)) return;

    // Resolve JunkClass WITHOUT initializing it. JNI FindClass runs <clinit>;
    // Class.forName(name, false, cl) does not.
    static constexpr const char kJunkClassJava[] = "com.yqsh.protector.junkcode.JunkClass";

    jobject cl = nullptr;
    // Prefer JniBridge's ClassLoader (available during early ACF bootstrap).
    jclass bridgeCls = env->FindClass("com/yqsh/protector/shell/JniBridge");
    if (bridgeCls != nullptr) {
        jclass classCls = env->GetObjectClass(bridgeCls);
        jmethodID getCl = env->GetMethodID(classCls, "getClassLoader",
                                           "()Ljava/lang/ClassLoader;");
        if (getCl != nullptr) {
            cl = env->CallObjectMethod(bridgeCls, getCl);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                cl = nullptr;
            }
        }
    } else {
        env->ExceptionClear();
    }

    // Fallback: Application ClassLoader once ActivityThread has an app.
    if (cl == nullptr) {
        jclass at = env->FindClass("android/app/ActivityThread");
        if (at != nullptr) {
            jmethodID curApp = env->GetStaticMethodID(at, "currentApplication",
                                                      "()Landroid/app/Application;");
            jobject app = (curApp != nullptr)
                    ? env->CallStaticObjectMethod(at, curApp) : nullptr;
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                app = nullptr;
            }
            if (app != nullptr) {
                jclass ctxClz = env->GetObjectClass(app);
                jmethodID getCl = env->GetMethodID(ctxClz, "getClassLoader",
                                                   "()Ljava/lang/ClassLoader;");
                cl = (getCl != nullptr) ? env->CallObjectMethod(app, getCl) : nullptr;
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    cl = nullptr;
                }
            }
        } else {
            env->ExceptionClear();
        }
    }

    jclass klass = nullptr;
    if (cl != nullptr) {
        jclass classCls = env->FindClass("java/lang/Class");
        jmethodID forName = classCls != nullptr
                ? env->GetStaticMethodID(
                        classCls, "forName",
                        "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;")
                : nullptr;
        jstring name = env->NewStringUTF(kJunkClassJava);
        if (forName != nullptr && name != nullptr) {
            klass = reinterpret_cast<jclass>(
                    env->CallStaticObjectMethod(classCls, forName, name, JNI_FALSE, cl));
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                klass = nullptr;
            }
        }
    }

    if (klass == nullptr) {
        PLOGE("junk class missing");
        protector::risk::crash_hang();  // hang — waste attacker's time on junk tamper
        return;
    }
    env->DeleteLocalRef(klass);
    verified.store(true, std::memory_order_relaxed);
#else
    (void)env;
#endif
}

void maybe_verify_junk_class() {
#ifndef DEBUG
    if (!g_junk_verify_enabled.load(std::memory_order_acquire)) return;
    if (g_vm == nullptr) return;
    if ((rand() & 31) != 0) return;

    // ART callbacks are usually already attached; never Attach/Detach here.
    JNIEnv* env = nullptr;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK
        || env == nullptr) {
        return;
    }
    junk_code_protect(env);
#endif
}

void enable_junk_verify(JNIEnv*, jclass) {
#ifndef DEBUG
    g_junk_verify_enabled.store(true, std::memory_order_release);
    PLOGI("junk verify enabled");
    maybe_verify_junk_class();
#else
    (void)0;
#endif
}

static std::string bytes_to_hex_lower(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[data[i] & 0xf];
    }
    return out;
}

static bool hex_equals_ci(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (tolower(static_cast<unsigned char>(a[i]))
            != tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

/** HMAC-SHA256(data) vs lowercase hex; constant-time nibble compare. */
static bool hmac_matches_hex(const std::vector<uint8_t>& key,
                             const void* data, size_t len,
                             const std::string& expected_hex) {
    if (key.size() != PROTECTOR_HMAC_KEY_SIZE || expected_hex.size() != 64
            || data == nullptr) {
        return false;
    }
    uint8_t mac[32];
    protector::crypto::hmac_sha256(key.data(), key.size(), data, len, mac);
    std::string got = bytes_to_hex_lower(mac, 32);
    memset(mac, 0, sizeof(mac));
    int diff = 0;
    for (size_t i = 0; i < 64; i++) {
        diff |= tolower(static_cast<unsigned char>(got[i]))
                ^ tolower(static_cast<unsigned char>(expected_hex[i]));
    }
    return diff == 0;
}

static void require_file_hmac(const std::string& path, const std::string& expected_hex,
                              const char* tag) {
    auto& cfg = runtime_state().config;
    if (expected_hex.size() != 64) {
        PLOGE("%s hmac missing", tag);
        protector::risk::crash_exit();
        return;
    }
    std::string data = read_file(path);
    if (data.empty()) {
        PLOGE("%s empty for hmac", tag);
        protector::risk::crash_exit();
        return;
    }
    if (!hmac_matches_hex(cfg.hmac_key, data.data(), data.size(), expected_hex)) {
        PLOGE("%s hmac mismatch", tag);
        protector::risk::crash_exit();
    }
}

static void put_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 24));
}

/** Canonical method-set encoding — must match packer CodeMethodsIntegrity.encode. */
static std::vector<uint8_t> encode_code_methods(
        const std::unordered_map<int, std::unordered_map<uint32_t, CodeItem*>>& code_map) {
    struct Row {
        int dex;
        uint32_t idx;
        uint32_t flags;
    };
    std::vector<Row> rows;
    for (const auto& dex : code_map) {
        for (const auto& kv : dex.second) {
            const CodeItem* item = kv.second;
            if (item == nullptr) continue;
            rows.push_back(Row{dex.first, item->method_idx, item->flags});
        }
    }
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.dex != b.dex) return a.dex < b.dex;
        if (a.idx != b.idx) return a.idx < b.idx;
        return a.flags < b.flags;
    });
    std::vector<uint8_t> out;
    out.reserve(4u + rows.size() * 12u);
    put_u32_le(out, static_cast<uint32_t>(rows.size()));
    for (const Row& r : rows) {
        put_u32_le(out, static_cast<uint32_t>(r.dex));
        put_u32_le(out, r.idx);
        put_u32_le(out, r.flags);
    }
    return out;
}

static void require_code_methods_hmac() {
    auto& state = runtime_state();
    const std::string& expected = state.config.code_methods_hmac;
    if (expected.size() != 64) {
        PLOGE("code_methods_hmac missing");
        protector::risk::crash_exit();
        return;
    }
    std::vector<uint8_t> encoded = encode_code_methods(state.code_map);
    if (!hmac_matches_hex(state.config.hmac_key, encoded.data(), encoded.size(), expected)) {
        PLOGE("code_methods_hmac mismatch");
        protector::risk::crash_exit();
    }
}

static std::string jstring_utf8(JNIEnv* env, jstring js) {
    if (env == nullptr || js == nullptr) {
        return {};
    }
    const char* c = env->GetStringUTFChars(js, nullptr);
    if (c == nullptr) {
        return {};
    }
    std::string s(c);
    env->ReleaseStringUTFChars(js, c);
    return s;
}

/** ApplicationInfo.sourceDir — file path, not PackageManager certificates. */
static std::string apk_path_from_context(JNIEnv* env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return {};
    }
    if (env->PushLocalFrame(16) < 0) {
        env->ExceptionClear();
        return {};
    }
    auto pop = [&]() { env->PopLocalFrame(nullptr); };
    jclass ctxCls = env->GetObjectClass(context);
    if (!ctxCls || env->ExceptionCheck()) {
        env->ExceptionClear();
        pop();
        return {};
    }
    jmethodID getAi = env->GetMethodID(ctxCls, "getApplicationInfo",
                                       "()Landroid/content/pm/ApplicationInfo;");
    if (!getAi || env->ExceptionCheck()) {
        env->ExceptionClear();
        pop();
        return {};
    }
    jobject ai = env->CallObjectMethod(context, getAi);
    if (!ai || env->ExceptionCheck()) {
        env->ExceptionClear();
        pop();
        return {};
    }
    jclass aiCls = env->GetObjectClass(ai);
    jfieldID src = env->GetFieldID(aiCls, "sourceDir", "Ljava/lang/String;");
    if (!src || env->ExceptionCheck()) {
        env->ExceptionClear();
        pop();
        return {};
    }
    auto js = static_cast<jstring>(env->GetObjectField(ai, src));
    std::string path = jstring_utf8(env, js);
    pop();
    return path;
}

/**
 * PackageManager first-signer SHA-256. Diagnostic only — never fail-closed.
 * Native APK Signing Block parse is authoritative.
 */
static std::string pm_first_signer_sha256_hex(JNIEnv* env, jobject context) {
    if (env == nullptr || context == nullptr) {
        return {};
    }
    if (env->PushLocalFrame(64) < 0) {
        env->ExceptionClear();
        return {};
    }
    auto fail = [&]() -> std::string {
        env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        return {};
    };

    jclass ctxCls = env->GetObjectClass(context);
    if (!ctxCls || env->ExceptionCheck()) {
        return fail();
    }
    jmethodID getPm = env->GetMethodID(ctxCls, "getPackageManager",
                                       "()Landroid/content/pm/PackageManager;");
    jmethodID getPkg = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
    if (!getPm || !getPkg || env->ExceptionCheck()) {
        return fail();
    }
    jobject pm = env->CallObjectMethod(context, getPm);
    jstring packageName = static_cast<jstring>(env->CallObjectMethod(context, getPkg));
    if (!pm || !packageName || env->ExceptionCheck()) {
        return fail();
    }

    int api = android_get_device_api_level();
    jint flags = (api >= 28) ? 0x08000000 : 0x40; // GET_SIGNING_CERTIFICATES / GET_SIGNATURES

    jclass pmCls = env->GetObjectClass(pm);
    if (!pmCls || env->ExceptionCheck()) {
        return fail();
    }
    jmethodID getPi = env->GetMethodID(pmCls, "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPi || env->ExceptionCheck()) {
        return fail();
    }
    jobject packageInfo = env->CallObjectMethod(pm, getPi, packageName, flags);
    if (!packageInfo || env->ExceptionCheck()) {
        return fail();
    }

    jbyteArray certBytes = nullptr;
    jclass piCls = env->GetObjectClass(packageInfo);
    if (!piCls || env->ExceptionCheck()) {
        return fail();
    }
    if (api >= 28) {
        jfieldID siField = env->GetFieldID(piCls, "signingInfo",
                                           "Landroid/content/pm/SigningInfo;");
        if (!siField || env->ExceptionCheck()) {
            return fail();
        }
        jobject signingInfo = env->GetObjectField(packageInfo, siField);
        if (!signingInfo || env->ExceptionCheck()) {
            return fail();
        }
        jclass siCls = env->GetObjectClass(signingInfo);
        jmethodID getSigners = env->GetMethodID(siCls, "getApkContentsSigners",
                "()[Landroid/content/pm/Signature;");
        if (!getSigners || env->ExceptionCheck()) {
            return fail();
        }
        auto signatures = static_cast<jobjectArray>(
                env->CallObjectMethod(signingInfo, getSigners));
        if (!signatures || env->ExceptionCheck() || env->GetArrayLength(signatures) == 0) {
            return fail();
        }
        jobject signature = env->GetObjectArrayElement(signatures, 0);
        if (!signature || env->ExceptionCheck()) {
            return fail();
        }
        jclass sigCls = env->GetObjectClass(signature);
        jmethodID toByteArray = env->GetMethodID(sigCls, "toByteArray", "()[B");
        if (!toByteArray || env->ExceptionCheck()) {
            return fail();
        }
        certBytes = static_cast<jbyteArray>(env->CallObjectMethod(signature, toByteArray));
    } else {
        jfieldID sigField = env->GetFieldID(piCls, "signatures",
                                            "[Landroid/content/pm/Signature;");
        if (!sigField || env->ExceptionCheck()) {
            return fail();
        }
        auto signatures = static_cast<jobjectArray>(
                env->GetObjectField(packageInfo, sigField));
        if (!signatures || env->ExceptionCheck() || env->GetArrayLength(signatures) == 0) {
            return fail();
        }
        jobject signature = env->GetObjectArrayElement(signatures, 0);
        if (!signature || env->ExceptionCheck()) {
            return fail();
        }
        jclass sigCls = env->GetObjectClass(signature);
        jmethodID toByteArray = env->GetMethodID(sigCls, "toByteArray", "()[B");
        if (!toByteArray || env->ExceptionCheck()) {
            return fail();
        }
        certBytes = static_cast<jbyteArray>(env->CallObjectMethod(signature, toByteArray));
    }

    if (!certBytes || env->ExceptionCheck()) {
        return fail();
    }

    jclass mdCls = env->FindClass("java/security/MessageDigest");
    if (!mdCls || env->ExceptionCheck()) {
        return fail();
    }
    jmethodID getInstance = env->GetStaticMethodID(mdCls, "getInstance",
            "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    if (!getInstance || env->ExceptionCheck()) {
        return fail();
    }
    jstring alg = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdCls, getInstance, alg);
    if (!md || env->ExceptionCheck()) {
        return fail();
    }
    jmethodID digest = env->GetMethodID(mdCls, "digest", "([B)[B");
    if (!digest || env->ExceptionCheck()) {
        return fail();
    }
    auto hashArr = static_cast<jbyteArray>(env->CallObjectMethod(md, digest, certBytes));
    if (!hashArr || env->ExceptionCheck()) {
        return fail();
    }

    jsize hashLen = env->GetArrayLength(hashArr);
    if (hashLen != 32) {
        return fail();
    }
    jbyte* hashBytes = env->GetByteArrayElements(hashArr, nullptr);
    if (hashBytes == nullptr) {
        return fail();
    }
    std::string actual = bytes_to_hex_lower(reinterpret_cast<const uint8_t*>(hashBytes), 32);
    env->ReleaseByteArrayElements(hashArr, hashBytes, JNI_ABORT);
    env->PopLocalFrame(nullptr);
    return actual;
}

/** SHA-256 of first v2/v3 signer cert from the APK file (not PackageManager). */
static void verify_app_signature(JNIEnv* env, jobject context, const std::string& expected) {
    if (expected.empty()) {
        protector::risk::crash_exit();
        return;
    }
    std::string apk = runtime_state().apk_path;
    if (apk.empty()) {
        apk = apk_path_from_context(env, context);
        if (!apk.empty()) {
            runtime_state().apk_path = apk;
        }
    }
    if (apk.empty()) {
        PLOGE("apk path empty — native v2/v3 parse required");
        protector::risk::crash_abort();
        return;
    }
    uint8_t digest[32];
    if (!protector::crypto::apk_first_signer_cert_sha256(apk.c_str(), digest)) {
        PLOGE("no parseable APK v2/v3 signer cert");
        protector::risk::crash_abort();
        return;
    }
    std::string actual = bytes_to_hex_lower(digest, 32);
    if (!hex_equals_ci(actual, expected)) {
        PLOGW("signature mismatch expected=%s actual=%s", expected.c_str(), actual.c_str());
        protector::risk::crash_abort();
        return;
    }
    PLOGI("app signature ok (native v2/v3)");
    std::string pm = pm_first_signer_sha256_hex(env, context);
    if (!pm.empty() && !hex_equals_ci(pm, actual)) {
        PLOGW("PackageManager cert digest differs from native (ignored)");
    }
}

void on_load(JavaVM* vm) {
    g_vm = vm;
    if (runtime_state().sdk_level == 0) {
        runtime_state().sdk_level = android_get_device_api_level();
    }
    PLOGI("protector native on_load, sdk=%d", runtime_state().sdk_level);
}

PROTECTOR_ENCRYPT void init_app(JNIEnv* env, jclass, jstring protector_dir_j,
                                jstring package_name_j, jstring apk_path_j) {
    auto& state = runtime_state();
    std::lock_guard<std::mutex> lock(state.mutex);

    if (package_name_j != nullptr) {
        std::string pkg = jstring_utf8(env, package_name_j);
        if (!pkg.empty()) {
            state.app_package = std::move(pkg);
        }
    }
    if (apk_path_j != nullptr) {
        std::string apk = jstring_utf8(env, apk_path_j);
        if (!apk.empty()) {
            state.apk_path = std::move(apk);
        }
    }

    if (state.inited.load()) return;

    if (protector_dir_j == nullptr) {
        PLOGE("protectorDir is null");
        return;
    }
    const char* dir_c = env->GetStringUTFChars(protector_dir_j, nullptr);
    if (dir_c == nullptr) {
        PLOGE("GetStringUTFChars failed");
        return;
    }
    std::string dir = dir_c;
    env->ReleaseStringUTFChars(protector_dir_j, dir_c);
    if (dir.empty()) {
        PLOGE("protectorDir empty");
        return;
    }

    state.dexes_zip_path = dir + "/dexes.zip";
    std::string code_path = dir + "/code.bin";
    std::string config_path = dir + "/config.json";
    state.code_bin_path = code_path;
    protector::report::set_report_dir(dir);
    // Keep existing nativeLibraryDir if Java already called setNativeLibraryDir.
    protector::so::set_runtime_dirs(dir, "");
    protector::so::load_so_text_diag(dir);

    const bool warm = has_warm_dex_cache(dir);
    if (!file_exists(code_path)) {
        PLOGW("code.bin missing under %s", dir.c_str());
        return;
    }
    if (!warm && !file_exists(state.dexes_zip_path)) {
        PLOGW("dexes.zip missing under %s (no warm cache)", dir.c_str());
        return;
    }
    if (warm) {
        PLOGI("warm cache: skip dexes.zip decrypt");
    }

    uint8_t cert[32];
    if (state.apk_path.empty()
            || !protector::crypto::apk_first_signer_cert_sha256(state.apk_path.c_str(), cert)) {
        PLOGE("native v2/v3 cert required for key ladder");
        protector::risk::crash_abort();
        return;
    }
    if (state.app_package.empty()) {
        PLOGE("package name required for key ladder");
        protector::risk::crash_abort();
        return;
    }
    uint8_t master[32];
    if (!protector::crypto::recover_k_master(master)) {
        PLOGE("K_master recover failed");
        memset(master, 0, sizeof(master));
        protector::risk::crash_abort();
        return;
    }
    protector::crypto::DerivedKeys keys{};
    bool derived = protector::crypto::derive_app_keys(
            master, cert, state.app_package.c_str(), &keys);
    memset(master, 0, sizeof(master));
    if (!derived) {
        memset(&keys, 0, sizeof(keys));
        PLOGE("HKDF derive failed");
        protector::risk::crash_abort();
        return;
    }
    state.config.dex_aes_key.assign(keys.dex, keys.dex + 16);
    state.config.insns_aes_key.assign(keys.insn, keys.insn + 16);
    state.config.so_aes_key.assign(keys.so, keys.so + 16);
    state.config.so_warm_key.assign(keys.sowarm, keys.sowarm + 16);
    state.config.assets_aes_key.assign(keys.assets, keys.assets + 16);
    state.config.hmac_key.assign(keys.hmac, keys.hmac + 32);
    protector::so::set_so_warm_key(keys.sowarm);
    memset(&keys, 0, sizeof(keys));

    if (!file_exists(config_path)) {
        PLOGE("config.json missing");
        protector::risk::crash_exit();
        return;
    }
    parse_config_json(read_file(config_path));
    if (state.config.package_name.empty()
            || state.config.package_name != state.app_package) {
        PLOGE("config package mismatch");
        protector::risk::crash_abort();
        return;
    }
    std::string cert_hex = bytes_to_hex_lower(cert, 32);
    if (!hex_equals_ci(cert_hex, state.config.app_sign_sha256)) {
        PLOGE("config cert mismatch");
        protector::risk::crash_abort();
        return;
    }

    {
        const char* abi = protector::risk::so_guard_abi();
        auto it = state.config.bitcode_hmac.find(abi);
        if (it == state.config.bitcode_hmac.end()) {
            PLOGE("config missing bitcode_hmac for %s", abi);
            protector::risk::crash_exit();
            return;
        }
        if (!protector::risk::so_guard_bind_hmac(state.config.hmac_key.data(),
                                                 state.config.hmac_key.size(),
                                                 it->second)) {
            PLOGE("bitcode hmac mismatch");
            protector::risk::crash_exit();
            return;
        }
    }

    if (!warm) {
        require_file_hmac(state.dexes_zip_path, state.config.dex_hmac, "dexes.zip");
    }

    // Main-path Frida/hook screen before decrypting business assets.
    protector::risk::scan_hooks_and_frida_now();

    if (state.config.insns_aes_key.size() != 16) {
        PLOGE("missing insn AES key");
        protector::risk::crash_exit();
        return;
    }

    auto wipe_so_key = [&]() {
        if (!state.config.so_aes_key.empty()) {
            memset(state.config.so_aes_key.data(), 0, state.config.so_aes_key.size());
            state.config.so_aes_key.clear();
        }
    };

    // Decrypt PDX1-wrapped dexes.zip and extract classes*.dex in one pass
    // (no plaintext ZIP on disk). Warm starts already have prepatched dexes.
    if (!warm && state.config.dex_aes_key.size() == 16) {
        std::string sokeys_path = dir + "/sokeys.bin";
        const uint8_t* so_key = state.config.so_aes_key.size() == 16
                ? state.config.so_aes_key.data() : nullptr;
        if (!protector::so::load_sokeys(sokeys_path, so_key)) {
            PLOGE("sokeys load failed");
            protector::risk::crash_exit();
            return;
        }
        if (state.config.protect_so && !protector::so::has_sokeys()) {
            PLOGE("protect_so set but sokeys.bin missing or empty — refuse init");
            protector::risk::crash_exit();
            return;
        }
        wipe_so_key();
        if (!crypto::decrypt_and_extract_dexes(state.dexes_zip_path,
                                               state.config.dex_aes_key.data(),
                                               dir)) {
            PLOGE("dexes.zip decrypt/extract failed");
            memset(state.config.dex_aes_key.data(), 0, state.config.dex_aes_key.size());
            state.config.dex_aes_key.clear();
            protector::risk::crash_exit();
            return;
        }
        memset(state.config.dex_aes_key.data(), 0, state.config.dex_aes_key.size());
        state.config.dex_aes_key.clear();
        if (protector::so::has_sokeys()) {
            unlink(sokeys_path.c_str());
        }
        protector::so::materialize_decrypted_sos();
    } else if (warm) {
        std::string sokeys_path = dir + "/sokeys.bin";
        const uint8_t* so_key = state.config.so_aes_key.size() == 16
                ? state.config.so_aes_key.data() : nullptr;
        if (file_exists(sokeys_path)) {
            if (!protector::so::load_sokeys(sokeys_path, so_key)) {
                PLOGE("warm sokeys load failed");
                protector::risk::crash_exit();
                return;
            }
            if (state.config.protect_so && !protector::so::has_sokeys()) {
                PLOGE("protect_so set but warm sokeys empty — refuse init");
                protector::risk::crash_exit();
                return;
            }
            if (protector::so::has_sokeys()) {
                unlink(sokeys_path.c_str());
            }
            protector::so::materialize_decrypted_sos();
        } else if (state.config.protect_so) {
            PLOGW("warm: sokeys.bin missing (SO decrypt on dlopen may fail until keys present)");
        }
        wipe_so_key();
        if (!state.config.dex_aes_key.empty()) {
            memset(state.config.dex_aes_key.data(), 0, state.config.dex_aes_key.size());
            state.config.dex_aes_key.clear();
        }
    } else {
        PLOGE("missing dex AES key");
        protector::risk::crash_exit();
        return;
    }

    // Install ART hooks before parsing/applying code.bin so DefineClass can patch.
    protector::hook::install_hooks();
    protector::so::install_business_so_hooks();
    // decrypt_already_loaded_async is deferred until after DexMerger (Java calls
    // finishBusinessSoDecrypt) so we do not race ART while mapping dexes.
    std::string code_data = read_file(code_path);
    if (code_data.empty()) {
        PLOGE("failed to read code.bin");
        return;
    }
    if (!hmac_matches_hex(state.config.hmac_key, code_data.data(), code_data.size(),
                          state.config.code_hmac)) {
        PLOGE("code.bin hmac mismatch");
        auto* p = reinterpret_cast<volatile char*>(code_data.data());
        for (size_t i = 0; i < code_data.size(); i++) p[i] = 0;
        protector::risk::crash_exit();
        return;
    }
    // Keep encrypted code.bin on disk (avoids re-copy from APK every launch).
    // Contents are also held in memory for this process.
    protector::vm::clear_true_vmp_lru();
    for (auto& dex : state.code_map) {
        for (auto& kv : dex.second) {
            delete kv.second;
        }
    }
    state.code_map.clear();

    if (!codeitem::parse(reinterpret_cast<const uint8_t*>(code_data.data()),
                         code_data.size(), state.code_blob, state.code_map)) {
        PLOGE("parse code.bin failed");
        auto* p = reinterpret_cast<volatile char*>(code_data.data());
        for (size_t i = 0; i < code_data.size(); i++) p[i] = 0;
        return;
    }
    // Wipe temporary file buffer; code_blob holds the working copy.
    {
        auto* p = reinterpret_cast<volatile char*>(code_data.data());
        for (size_t i = 0; i < code_data.size(); i++) p[i] = 0;
    }

    require_code_methods_hmac();
    if (!protector::dex::verify_code_methods_in_extracted_dexes(dir.c_str())) {
        PLOGE("code.bin methods do not match extracted DEX");
        protector::risk::crash_exit();
        return;
    }

    if (!protector::vm::prepare_true_vmp_images()) {
        PLOGE("TRUE_VMP prepare failed");
        protector::risk::crash_exit();
        return;
    }

    state.inited.store(true);
    protector::risk::arm_java_heartbeat();
    PLOGI("init_app ok, dexes=%s", state.dexes_zip_path.c_str());

    junk_code_protect(env);
    // Second scan after hooks installed — catches late injectors.
    protector::risk::scan_hooks_and_frida_now();
}

void verify_signature(JNIEnv* env, jclass, jobject context) {
    const std::string& expected = runtime_state().config.app_sign_sha256;
    if (expected.empty()) {
        PLOGE("app_sign_sha256 empty — fail closed");
        protector::risk::crash_exit();
        return;
    }
    protector::risk::scan_hooks_and_frida_now();
    verify_app_signature(env, context, expected);
}

jstring read_application_name(JNIEnv* env, jclass) {
    return env->NewStringUTF(runtime_state().config.application_name.c_str());
}

jstring native_version(JNIEnv* env, jclass) {
    return env->NewStringUTF("protector-native/0.7.1");
}

jboolean environment_degraded(JNIEnv*, jclass) {
    return runtime_state().environment_degraded.load(std::memory_order_acquire)
                   ? JNI_TRUE
                   : JNI_FALSE;
}

jstring drain_threat_reports(JNIEnv* env, jclass) {
    std::string json = protector::report::drain_threats_json();
    return env->NewStringUTF(json.c_str());
}

} // namespace protector::runtime
