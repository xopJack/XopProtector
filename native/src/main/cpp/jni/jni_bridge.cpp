#include <jni.h>
#include "common/log.h"
#include "common/protector_macro.h"
#include "dex/dex_file.h"
#include "risk/risk.h"
#include "runtime/engine.h"
#include "so/business_so.h"
#include "vm/pvm2_interp.h"
#include "crypto/assets_crypt.h"
#include "report/threat_report.h"
#include "common/runtime_state.h"

#include <atomic>
#include <string>

#define JNI_BRIDGE "com/yqsh/protector/shell/JniBridge"
#define JNI_VMBRIDGE "com/yqsh/protector/shell/VmBridge"
#define JNI_PROXY_APP "com/yqsh/protector/shell/ProxyApplication"

static jclass g_jni_bridge_class = nullptr;
static jclass g_proxy_app_class = nullptr;

static bool shell_heartbeat_ok(JNIEnv* env, jclass clazz, jobject shell) {
    if (env == nullptr || clazz == nullptr || shell == nullptr) return false;
    if (g_jni_bridge_class == nullptr || g_proxy_app_class == nullptr) return false;
    if (!env->IsSameObject(clazz, g_jni_bridge_class)) return false;
    if (!env->IsInstanceOf(shell, g_proxy_app_class)) return false;
    return true;
}

/** Java→Native heartbeat: records a ping so the risk thread knows the
 *  Java shell is still intact. Caller must be JniBridge + a live ProxyApplication. */
static void native_heartbeat(JNIEnv* env, jclass clazz, jobject shell) {
    if (!shell_heartbeat_ok(env, clazz, shell)) {
        PLOGE("java shell heartbeat rejected");
        protector::risk::handle_risk("java_shell", protector::risk::CrashKind::Abort);
        return;
    }
    protector::risk::record_java_heartbeat();
    protector::runtime::maybe_verify_junk_class();
}

static jobject native_interpret(JNIEnv* env, jclass, jint dexIndex, jint methodIdx,
                                jobjectArray args) {
    return protector::vm::interpret(env, dexIndex, static_cast<uint32_t>(methodIdx), args);
}

static void native_set_native_lib_dir(JNIEnv* env, jclass, jstring dir) {
    if (dir == nullptr) return;
    const char* utf = env->GetStringUTFChars(dir, nullptr);
    if (utf == nullptr) return;
    protector::so::set_runtime_dirs({}, utf);
    env->ReleaseStringUTFChars(dir, utf);
}

static void native_ensure_business_so(JNIEnv* env, jclass, jstring name) {
    if (name == nullptr) return;
    const char* utf = env->GetStringUTFChars(name, nullptr);
    if (utf == nullptr) return;
    bool ok = protector::so::ensure_decrypted(utf);
    env->ReleaseStringUTFChars(name, utf);
    if (!ok) {
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),
                      "business SO .text decrypt failed");
    }
}

static void native_finish_business_so(JNIEnv*, jclass) {
    // Attach does not pin the keyed set. Linker openat rewrite + on-demand
    // closure keep DT_NEEDED off extract ciphertext. Fallback full pin only
    // when hooks are missing. Idempotent.
    protector::so::preload_so_plain();
    protector::so::decrypt_already_loaded_async();
}

static void native_report_threat(JNIEnv* env, jclass, jstring reason) {
    // Soft path for Java NetGuard: always record; may mark degraded; never
    // Block-crash here (proxy/VPN false positives must not kill the process).
    std::string reason_str = "java_threat";
    if (reason != nullptr) {
        const char* utf = env->GetStringUTFChars(reason, nullptr);
        if (utf != nullptr) {
            reason_str.assign(utf);
            env->ReleaseStringUTFChars(reason, utf);
        }
    }
    int action = protector::runtime_state().config.rasp_action.load(std::memory_order_relaxed);
    protector::report::report_threat(reason_str.c_str(), action);
    if (action != static_cast<int>(protector::RaspAction::Alert)) {
        protector::risk::mark_environment_degraded();
    }
}

static void native_prepatch_extracted(JNIEnv* env, jclass, jstring dir) {
    if (dir == nullptr) return;
    const char* utf = env->GetStringUTFChars(dir, nullptr);
    if (utf == nullptr) return;
    protector::dex::prepatch_extracted_dexes(utf);
    env->ReleaseStringUTFChars(dir, utf);
}

static JNINativeMethod g_methods[] = {
        {"initApp", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
         (void*)protector::runtime::init_app},
        {"setNativeLibraryDir", "(Ljava/lang/String;)V", (void*)native_set_native_lib_dir},
        {"enableJunkVerify", "()V", (void*)protector::runtime::enable_junk_verify},
        {"prepatchExtractedDexes", "(Ljava/lang/String;)V", (void*)native_prepatch_extracted},
        {"readApplicationName", "()Ljava/lang/String;",
         (void*)protector::runtime::read_application_name},
        {"nativeVersion", "()Ljava/lang/String;",
         (void*)protector::runtime::native_version},
        {"verifySignature", "(Landroid/content/Context;)V",
         (void*)protector::runtime::verify_signature},
        {"heartbeat", "(Landroid/app/Application;)V", (void*)native_heartbeat},
        {"isEnvironmentDegraded", "()Z",
         (void*)protector::runtime::environment_degraded},
        {"drainThreatReports", "()Ljava/lang/String;",
         (void*)protector::runtime::drain_threat_reports},
        {"ensureBusinessSo", "(Ljava/lang/String;)V",
         (void*)native_ensure_business_so},
        {"finishBusinessSoDecrypt", "()V",
         (void*)native_finish_business_so},
        {"decryptAssetBlob", "([B)[B",
         (void*)protector::assets::decrypt_asset_blob_jni},
        {"reportThreat", "(Ljava/lang/String;)V",
         (void*)native_report_threat},
};

static JNINativeMethod g_vm_methods[] = {
        {"interpret", "(II[Ljava/lang/Object;)Ljava/lang/Object;", (void*)native_interpret},
};

PROTECTOR_ENCRYPT JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    if (vm == nullptr) {
        return JNI_ERR;
    }
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK
            || env == nullptr) {
        return JNI_ERR;
    }
    jclass clazz = env->FindClass(JNI_BRIDGE);
    if (!clazz) {
        PLOGE("cannot find JniBridge");
        return JNI_ERR;
    }
    if (env->RegisterNatives(clazz, g_methods, sizeof(g_methods) / sizeof(g_methods[0])) != 0) {
        PLOGE("RegisterNatives JniBridge failed");
        return JNI_ERR;
    }
    g_jni_bridge_class = reinterpret_cast<jclass>(env->NewGlobalRef(clazz));
    env->DeleteLocalRef(clazz);
    if (g_jni_bridge_class == nullptr) {
        PLOGE("JniBridge NewGlobalRef failed");
        return JNI_ERR;
    }

    jclass proxyCls = env->FindClass(JNI_PROXY_APP);
    if (!proxyCls) {
        PLOGE("cannot find ProxyApplication");
        return JNI_ERR;
    }
    g_proxy_app_class = reinterpret_cast<jclass>(env->NewGlobalRef(proxyCls));
    env->DeleteLocalRef(proxyCls);
    if (g_proxy_app_class == nullptr) {
        PLOGE("ProxyApplication NewGlobalRef failed");
        return JNI_ERR;
    }

    jclass vmCls = env->FindClass(JNI_VMBRIDGE);
    if (!vmCls) {
        PLOGE("cannot find VmBridge");
        return JNI_ERR;
    }
    if (env->RegisterNatives(vmCls, g_vm_methods,
                             sizeof(g_vm_methods) / sizeof(g_vm_methods[0])) != 0) {
        PLOGE("RegisterNatives VmBridge failed");
        return JNI_ERR;
    }
    protector::runtime::on_load(vm);
    return JNI_VERSION_1_6;
}
