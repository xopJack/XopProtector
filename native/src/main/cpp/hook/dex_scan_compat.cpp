#include "hook/dex_scan_compat.h"

#include "common/log.h"
#include "common/runtime_state.h"
#include "common/protector_macro.h"
#include "runtime/engine.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

namespace protector::hook {
namespace {

std::mutex g_mu;
bool g_installed = false;
std::string g_facade;
std::string g_apk;
size_t g_jni_entry_offset = 0;

using OpenDexO = jobject (*)(JNIEnv*, jclass, jstring, jstring, jint, jobject, jobjectArray);
using OpenDexN = jlong (*)(JNIEnv*, jclass, jstring, jstring, jint);

OpenDexO g_orig_o = nullptr;
OpenDexN g_orig_n = nullptr;

static bool path_equals_apk(JNIEnv* env, jstring source) {
    if (source == nullptr || g_apk.empty()) {
        return false;
    }
    const char* utf = env->GetStringUTFChars(source, nullptr);
    if (utf == nullptr) {
        return false;
    }
    bool eq = (strcmp(utf, g_apk.c_str()) == 0);
    env->ReleaseStringUTFChars(source, utf);
    return eq;
}

/** Class-name scan: new DexFile(apk) → outputName null, loader null (API 26+). */
static bool should_redirect(JNIEnv* env, jstring source, jstring output, jobject loader) {
    if (g_facade.empty() || g_apk.empty()) {
        return false;
    }
    if (output != nullptr) {
        return false;
    }
    if (loader != nullptr) {
        return false;
    }
    return path_equals_apk(env, source);
}

static jobject hook_open_o(JNIEnv* env, jclass cls, jstring source, jstring output,
                           jint flags, jobject loader, jobjectArray elements) {
    jstring use = source;
    if (should_redirect(env, source, output, loader)) {
        use = env->NewStringUTF(g_facade.c_str());
        if (use == nullptr) {
            use = source;
        }
    }
    return g_orig_o(env, cls, use, output, flags, loader, elements);
}

static jlong hook_open_n(JNIEnv* env, jclass cls, jstring source, jstring output, jint flags) {
    jstring use = source;
    if (should_redirect(env, source, output, /*loader=*/nullptr)) {
        use = env->NewStringUTF(g_facade.c_str());
        if (use == nullptr) {
            use = source;
        }
    }
    return g_orig_n(env, cls, use, output, flags);
}

/** Ensure ArtMethod page is writable. Never downgrade — ART still writes hotness etc. */
static bool mprotect_art_rw(void* addr, size_t len) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        page = 4096;
    }
    uintptr_t start = reinterpret_cast<uintptr_t>(addr) & ~static_cast<uintptr_t>(page - 1);
    uintptr_t end = (reinterpret_cast<uintptr_t>(addr) + len + page - 1)
            & ~static_cast<uintptr_t>(page - 1);
    return mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ | PROT_WRITE) == 0;
}

static bool calibrate_jni_entry_offset(JNIEnv* env) {
    if (g_jni_entry_offset != 0) {
        return true;
    }
    jclass bridge = env->FindClass("com/yqsh/protector/shell/JniBridge");
    if (bridge == nullptr) {
        env->ExceptionClear();
        return false;
    }
    jmethodID mid = env->GetStaticMethodID(bridge, "nativeVersion", "()Ljava/lang/String;");
    env->DeleteLocalRef(bridge);
    if (mid == nullptr) {
        env->ExceptionClear();
        return false;
    }
    // Address registered in JNI_OnLoad for JniBridge.nativeVersion.
    auto known = reinterpret_cast<uintptr_t>(&protector::runtime::native_version);
    // ARM Thumb: clear low bit when comparing (ArtMethod may store either form).
    auto norm = [](uintptr_t p) -> uintptr_t { return p & ~static_cast<uintptr_t>(1); };

    auto* base = reinterpret_cast<uint8_t*>(mid);
    constexpr size_t kMaxScan = 384;
    for (size_t off = 0; off + sizeof(void*) <= kMaxScan; off += sizeof(void*)) {
        void* slot;
        memcpy(&slot, base + off, sizeof(void*));
        if (norm(reinterpret_cast<uintptr_t>(slot)) == norm(known)) {
            g_jni_entry_offset = off;
            PLOGI("dex_scan_compat: jni entry offset=%zu", off);
            return true;
        }
    }
    PLOGW("dex_scan_compat: ArtMethod JNI entry not found (fail-open)");
    return false;
}

static void* read_jni_entry(jmethodID mid) {
    auto* p = reinterpret_cast<uint8_t*>(mid) + g_jni_entry_offset;
    void* slot;
    memcpy(&slot, p, sizeof(void*));
    return slot;
}

static bool write_jni_entry(jmethodID mid, void* fn) {
    auto* p = reinterpret_cast<uint8_t*>(mid) + g_jni_entry_offset;
    if (!mprotect_art_rw(p, sizeof(void*))) {
        PLOGW("dex_scan_compat: mprotect RW failed (trying write anyway)");
    }
    memcpy(p, &fn, sizeof(void*));
    // Do NOT set PROT_READ-only — shared ArtMethod pages must stay writable.
    return read_jni_entry(mid) == fn;
}

static bool install_open_o(JNIEnv* env, jclass dexFile) {
    jmethodID mid = env->GetStaticMethodID(
            dexFile, "openDexFileNative",
            "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/ClassLoader;"
            "[Ldalvik/system/DexPathList$Element;)Ljava/lang/Object;");
    if (mid == nullptr) {
        env->ExceptionClear();
        return false;
    }
    void* orig = read_jni_entry(mid);
    if (orig == nullptr) {
        PLOGW("dex_scan_compat: openDexFileNative(O) entry null");
        return false;
    }
    g_orig_o = reinterpret_cast<OpenDexO>(orig);
    if (!write_jni_entry(mid, reinterpret_cast<void*>(&hook_open_o))) {
        PLOGW("dex_scan_compat: patch openDexFileNative(O) failed");
        g_orig_o = nullptr;
        return false;
    }
    PLOGI("dex_scan_compat: hooked openDexFileNative (API26+)");
    return true;
}

static bool install_open_n(JNIEnv* env, jclass dexFile) {
    jmethodID mid = env->GetStaticMethodID(
            dexFile, "openDexFileNative",
            "(Ljava/lang/String;Ljava/lang/String;I)J");
    if (mid == nullptr) {
        env->ExceptionClear();
        return false;
    }
    void* orig = read_jni_entry(mid);
    if (orig == nullptr) {
        PLOGW("dex_scan_compat: openDexFileNative(N) entry null");
        return false;
    }
    g_orig_n = reinterpret_cast<OpenDexN>(orig);
    if (!write_jni_entry(mid, reinterpret_cast<void*>(&hook_open_n))) {
        PLOGW("dex_scan_compat: patch openDexFileNative(N) failed");
        g_orig_n = nullptr;
        return false;
    }
    PLOGI("dex_scan_compat: hooked openDexFileNative (pre-O)");
    return true;
}

} // namespace

bool dex_scan_compat_enabled() {
    return runtime_state().config.dex_scan_compat;
}

PROTECTOR_ENCRYPT bool install_dex_scan_compat(JNIEnv* env, const char* facade_path) {
    if (env == nullptr || facade_path == nullptr || facade_path[0] == 0) {
        return false;
    }
    if (!dex_scan_compat_enabled()) {
        PLOGI("dex_scan_compat disabled by config");
        return false;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    g_facade = facade_path;
    g_apk = runtime_state().apk_path;
    if (g_apk.empty()) {
        PLOGW("dex_scan_compat: apk_path empty — skip");
        return false;
    }
    if (g_installed) {
        PLOGI("dex_scan_compat: already installed, facade updated");
        return true;
    }
    if (!calibrate_jni_entry_offset(env)) {
        return false;
    }
    jclass dexFile = env->FindClass("dalvik/system/DexFile");
    if (dexFile == nullptr) {
        env->ExceptionClear();
        PLOGW("dex_scan_compat: DexFile class missing");
        return false;
    }
    bool ok = false;
    if (runtime_state().sdk_level >= 26) {
        ok = install_open_o(env, dexFile);
        if (!ok) {
            ok = install_open_n(env, dexFile);
        }
    } else {
        ok = install_open_n(env, dexFile);
        if (!ok) {
            ok = install_open_o(env, dexFile);
        }
    }
    env->DeleteLocalRef(dexFile);
    if (ok) {
        g_installed = true;
        PLOGI("dex_scan_compat: ok apk=%s facade=%s", g_apk.c_str(), g_facade.c_str());
    }
    return ok;
}

} // namespace protector::hook
