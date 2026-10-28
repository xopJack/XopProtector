#pragma once

#include <jni.h>

namespace protector::hook {

/**
 * Redirect DexFile.openDexFileNative(sourceDir) → scan facade zip for
 * class-name scanners (XPage / ARouter-style). Fail-open.
 *
 * @param facade_path absolute path to scan_facade.zip (business classes*.dex)
 * @return true when hook installed
 */
bool install_dex_scan_compat(JNIEnv* env, const char* facade_path);

/** From config.json; default true when field missing. */
bool dex_scan_compat_enabled();

} // namespace protector::hook
