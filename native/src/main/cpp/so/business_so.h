#pragma once

#include "common/runtime_state.h"

#include <string>

namespace protector::so {

/**
 * Load assets/protector/sokeys.bin (PSOK) using {@code K_so}.
 * @return false on corrupt/decrypt failure; true if absent (no protect-so) or loaded OK.
 */
bool load_sokeys(const std::string& path, const uint8_t* so_wrap_key);

/** Protector cache dir + optional ApplicationInfo.nativeLibraryDir for pre-decrypt. */
void set_runtime_dirs(const std::string& protector_dir, const std::string& native_lib_dir);

/**
 * From config.json {@code so_decrypt_mode}. Default Eager.
 * Lazy: skip full cold-start materialize; dlopen path decrypts keyed DT_NEEDED closure.
 */
void set_so_decrypt_mode(protector::SoDecryptMode mode);

/** Current mode (default Eager until config is applied). */
protector::SoDecryptMode so_decrypt_mode();

/**
 * From config.json {@code so_diag} or {@code debug.protector.so_diag=1}.
 * When enabled, emits [XOP-SO] materialize/dlopen status even in Release builds.
 * Debug (!NDEBUG) builds always enable diagnostics.
 */
void set_so_diag(bool on);

/** True when [XOP-SO] diagnostics should be emitted. */
bool so_diag_enabled();

/**
 * Mkdir so_plain only. Does not RC4/hash/pin the keyed set at Application attach.
 * Extract-inode hooks map keyed SOs from packaged extract and RC4 .text in RAM.
 * Falls back to a full table if those hooks failed.
 */
void materialize_decrypted_sos();

/**
 * Skip full keyed pin when dlopen/linker hooks work; schedule background fill
 * of remaining so_plain mirrors (writes so_plain_ready for the next launch).
 * Idempotent per process. Call after NativeLibDirRedirect (so_plain fallback).
 */
void preload_so_plain();

/** Install dlopen / android_dlopen_ext hooks to decrypt .text on first load. */
void install_business_so_hooks();

/** True if any business SO keys were loaded. */
bool has_sokeys();

/**
 * Load assets/protector {@code so_text_diag.json} from the code-cache protector dir
 * (copied by ProxyApplication). Missing file is OK (older packs). Used to gate
 * materialize / warm reuse / dlopen on .text offset/size/sha256 mismatch.
 */
void load_so_text_diag(const std::string& protector_dir);

/**
 * Optional AES-128 key for legacy so_warm/ PSW1 (unused when plaintext warm is on).
 */
void set_so_warm_key(const uint8_t key[16]);

/**
 * Decrypt .text of business SOs already mapped into this process.
 * Prefer calling after ClassLoader merge (or on a background thread) so cold
 * start is not blocked; dlopen hooks still cover subsequent loads.
 */
void decrypt_already_loaded_async();

/**
 * Explicit decrypt for a basename (e.g. "libdemo_biz.so") after System.loadLibrary.
 * Needed when linker symbols bypass hooked dlopen/android_dlopen_ext.
 * @return true if the SO is not in the key table, or .text is decrypted successfully;
 *         false if a key exists but decrypt failed / still encrypted.
 */
bool ensure_decrypted(const char* so_basename);

} // namespace protector::so
