#include "crypto/section_decrypt.h"
#include "common/protector_macro.h"
#include "common/elf_util.h"
#include "common/log.h"
#include "common/runtime_state.h"
#include "crypto/aes.h"
#include "crypto/rc4.h"
#include "crypto/sha256.h"
#include "crypto/apk_sign.h"
#include "crypto/key_ladder.h"
#include "hook/hooks.h"
#include "risk/risk.h"
#include "risk/so_guard.h"
#include "so/business_so.h"

#include <android/log.h>
#include <android/api-level.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>

namespace protector {

namespace {

struct __attribute__((packed)) XopWrapSlot {
    uint8_t magic[16];
    uint8_t wrapped[16];
};

/* K_wrap lives outside .bitcode (needed to RC4-decrypt it). Hidden, no
 * PROTECTOR_* identifier. Packer finds the section by name and the magic. */
__attribute__((section(SECTION_NAME_PROTWRAP), used, visibility("hidden"), aligned(1)))
static volatile XopWrapSlot g_xop_wrap = {
        {0x58, 0x4f, 0x50, 0x4b, 0x57, 0x52, 0x41, 0x50, 0, 0, 0, 0, 0, 0, 0, 0},
        {0}
};

} // namespace


static int page_mprotect(void* start, void* end, int prot) {
    uintptr_t start_addr = PROTECTOR_PAGE_START(reinterpret_cast<uintptr_t>(start));
    uintptr_t end_addr =
            PROTECTOR_PAGE_START(reinterpret_cast<uintptr_t>(end) - 1) + get_cache_page_size();
    size_t size = end_addr - start_addr;
    if (mprotect(reinterpret_cast<void*>(start_addr), size, prot) != 0) {
        PLOGW("mprotect fail err=%s", strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * Bootstrap pad for K_wrap. Must live outside .bitcode because it is needed
 * to RC4-decrypt .bitcode itself. Split so a single 16-byte literal is not
 * sitting next to the wrap slot.
 */
static bool recover_k_wrap(uint8_t out[16]) {
    // clang-format off
    const uint8_t a[8] = {0x3b, 0x7c, 0x19, 0x5e, 0xa2, 0xdf, 0x48, 0x31};
    const uint8_t b[8] = {0x6c, 0x85, 0xea, 0x27, 0x54, 0x9b, 0x0f, 0xd6};
    // clang-format on
    bool any = false;
    for (int i = 0; i < 8; i++) {
        out[i] = static_cast<uint8_t>(g_xop_wrap.wrapped[i]) ^ a[i];
        out[i + 8] = static_cast<uint8_t>(g_xop_wrap.wrapped[i + 8]) ^ b[i];
        any = any || (out[i] != 0) || (out[i + 8] != 0);
    }
    return any;
}

static void wipe_k_wrap_slot() {
    auto* slot = const_cast<uint8_t*>(g_xop_wrap.wrapped);
    (void)page_mprotect(slot, slot + 16, PROT_READ | PROT_WRITE);
    memset(slot, 0, 16);
}

static void decrypt_section(const char* section_name, int temp_prot, int target_prot) {
    Dl_info info{};
    if (dladdr(reinterpret_cast<const void*>(&decrypt_section), &info) == 0
        || info.dli_fbase == nullptr) {
        PLOGE("dladdr failed for section decrypt");
        abort();
    }

    std::string so_path;
    if (info.dli_fname != nullptr) {
        if (info.dli_fname[0] == '/') {
            so_path.assign(info.dli_fname);
        } else {
            so_path = find_so_path(info.dli_fname);
        }
    }
    if (so_path.empty()) {
        so_path = find_so_path("libprotector.so");
    }
    if (so_path.empty()) {
        PLOGE("cannot resolve protector.so path");
        abort();
    }

    Elf_Shdr shdr{};
    get_elf_section(&shdr, so_path.c_str(), section_name);
    if (shdr.sh_size == 0) {
        PLOGE("section %s missing", section_name);
        abort();
    }

    if ((shdr.sh_flags & SHF_ALLOC) == 0) {
        PLOGE("section %s is not SHF_ALLOC; cannot decrypt in-memory", section_name);
        abort();
    }

    auto* target = reinterpret_cast<uint8_t*>(info.dli_fbase) + shdr.sh_addr;
    if (page_mprotect(target, target + shdr.sh_size, temp_prot) != 0) {
        abort();
    }

    // Size-preserving RC4 for executable .bitcode (ELF section length is fixed).
    // code.bin method bodies use AES-GCM separately.
    auto* bitcode = static_cast<uint8_t*>(malloc(shdr.sh_size));
    if (!bitcode) {
        abort();
    }
    uint8_t wrap[16];
    if (!recover_k_wrap(wrap)) {
        PLOGE("K_wrap slot empty");
        abort();
    }
    struct rc4_state dec_state {};
    rc4_init(&dec_state, wrap, 16);
    rc4_crypt(&dec_state, target, bitcode, static_cast<int>(shdr.sh_size));
    memcpy(target, bitcode, shdr.sh_size);
    memset(wrap, 0, sizeof(wrap));
    memset(&dec_state, 0, sizeof(dec_state));
    memset(bitcode, 0, shdr.sh_size);
    free(bitcode);
    wipe_k_wrap_slot();
    __builtin___clear_cache(reinterpret_cast<char*>(target),
                            reinterpret_cast<char*>(target + shdr.sh_size));

    if (page_mprotect(target, target + shdr.sh_size, target_prot) != 0) {
        abort();
    }
    PLOGI("decrypted section %s size=%u", section_name, static_cast<unsigned>(shdr.sh_size));
}

void decrypt_bitcode() {
    static std::atomic_bool done{false};
    bool expected = false;
    if (!done.compare_exchange_strong(expected, true)) {
        return;
    }
    decrypt_section(SECTION_NAME_BITCODE,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    PROT_READ | PROT_EXEC);
}

static void seed_rng() {
    unsigned seed = 0;
    FILE* ur = fopen("/dev/urandom", "rb");
    if (ur != nullptr) {
        if (fread(&seed, 1, sizeof(seed), ur) != sizeof(seed)) {
            seed = 0;
        }
        fclose(ur);
    }
    if (seed == 0) {
        seed = static_cast<unsigned>(time(nullptr))
                ^ static_cast<unsigned>(getpid())
                ^ static_cast<unsigned>(reinterpret_cast<uintptr_t>(&seed));
    }
    srand(seed);
}

void init_protector() {
    static std::atomic_bool done{false};
    bool expected = false;
    if (!done.compare_exchange_strong(expected, true)) {
        return;
    }

    seed_rng();
#ifdef DECRYPT_BITCODE
    decrypt_bitcode();
#endif
    protector::risk::so_guard_init();
#ifndef NDEBUG
    if (!crypto::aes_self_test()) {
        __android_log_print(ANDROID_LOG_ERROR, "protector", "AES self-test failed");
        abort();
    }
    if (!crypto::hkdf_self_test()) {
        __android_log_print(ANDROID_LOG_ERROR, "protector", "HKDF self-test failed");
        abort();
    }
    if (!crypto::apk_sign_self_test()) {
        __android_log_print(ANDROID_LOG_ERROR, "protector", "APK v2/v3 cert parse self-test failed");
        abort();
    }
    if (!crypto::key_ladder_self_test()) {
        __android_log_print(ANDROID_LOG_ERROR, "protector", "key ladder self-test failed");
        abort();
    }
#endif
    runtime_state().sdk_level = android_get_device_api_level();
    // Install after JNI_OnLoad — never from .init_array (linker-hook + bh_cfi
    // dlopen deadlock on some OEMs). ART class hooks remain deferred to init_app.
    //
    // Do NOT install business SO dlopen/openat hooks here. bytehook_hook_all on
    // dlopen makes the linker attribute subsequent loads (e.g. vendor
    // mapper.*.so for HWUI) to libprotector.so's app namespace (clns-*),
    // which cannot open /vendor/lib64/hw/* and aborts RenderThread /
    // GraphicBufferAllocator on OEM Android 12+ (MTK / Xiaomi / …).
    // Install those hooks only after sokeys are loaded (see engine.cpp) when
    // --protect-so actually needs them.
    protector::hook::ensure_bytehook();
    protector::risk::risk_checker().start();
    PLOGI("init_protector done (bytehook ready; SO dlopen hooks deferred)");
}

} // namespace protector

// .init_array: decrypt .bitcode only. JNI_OnLoad / so_guard / hooks live in
// that section — ART calls JNI_OnLoad after constructors, so plaintext must
// exist first. Never install linker hooks here (OEM dlopen deadlock).
INIT_ARRAY_SECTION void protector_early_init() {
#ifdef DECRYPT_BITCODE
    protector::decrypt_bitcode();
#endif
}
