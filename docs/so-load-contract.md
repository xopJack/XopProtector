# SO load contract (protect-so)

Commercial runtime contract for encrypted business SOs. Strategies are
**mechanism-based**, not customer SO basenames.

## Load strategies

| Id | Name | When | Linker `filename` / `dladdr` | File content |
|----|------|------|------------------------------|--------------|
| **L1m** | lib_mirror publish | Writable extract-equivalent under `code_cache/protector/lib_mirror/` | `.../lib_mirror/libX.so` | Hardlink/copy from `so_plain` (same inode as warm cache) |
| **L1** | Extract plain | Packaged extract dir is writable; plaintext published there after archiving cipher to `so_cipher/` | `/data/app/.../lib/<abi>/libX.so` | Same path (plaintext) |
| **L2e** | Extract inode + in-memory `.text` decrypt | Every keyed SO whose packaged extract file exists, after L1 misses. Not gated on packer `l2e`. `l2e=true` still means eager-skip disk RC4 and hide that SO from ClassLoader helper dirs. | Linker filename = packaged extract path | Ciphertext on disk; RC4 `.text` inside the linker `mmap` hook before it returns (before relocation and constructors). Kernel maps path is the stock `/data/app/.../lib/<abi>/libX.so`. If the recorded spans already cover `.text` and decrypt fails, that `mmap` is unmapped and returns `MAP_FAILED`. Missing linker `mmap` hook, or a failed file-backed execmod probe, refuses the load (FATAL). `call_constructors` is never hooked. No memfd fallback: `/memfd:libX.so (deleted)` breaks JNI that trusts the kernel path. |
| **L2** | FD, no extract inode | Packaged extract file is absent. Plaintext from `so_plain` (or memfd copy) | Linker filename is the plaintext path. Userspace `dladdr`/maps/`readlink` spoof to extract when a path is known | `android_dlopen_ext` + `ANDROID_DLEXT_USE_LIBRARY_FD` → **memfd** when `memfd_create` works and the SO is ≤ 16 MiB; else `so_plain` fd. Maps spoof strips a leading `memfd:` so the keyed basename still matches. |
| **L2b** | `dladdr` rewrite | After L2/L3 maps still show `so_plain` or `/memfd:` | Hooked `dladdr` returns extract/`lib_mirror` path for keyed SOs | Unchanged |
| **L3** | so_plain path | Fallback when memfd / `android_dlopen_ext` fail | `.../code_cache/protector/so_plain/libX.so` | Same |
| **Skip** | Do not encrypt | Class S / path-sensitive / industry (mode-dependent) | N/A | — |

`lib_mirror` also symlinks non-keyed deps, **Class S stubs** (`libGLESv*`,
`libcrypto.so`, … → extract only; never into `so_plain`), and **subdirectories**
from the packaged extract (e.g. `osgPlugins-*`) so path-sensitive engines that
`dirname()` the mapped SO path still find sibling plugins/models.
`ApplicationInfo.nativeLibraryDir` **stays on the packaged extract** (required for
Hi-MC / Teigha / OSG). ClassLoader still searches `lib_mirror` / `so_plain`
**first** so `loadLibrary` never maps packaged ciphertext (ART
`LoadNativeLibrary` of extract ciphertext SIGILLs in `JNI_OnLoad` /
`.init_array`, e.g. `libxcrash` / `libcpbase`). This must patch
`DexPathList.nativeLibraryPathElements` (`findLibrary` ignores the
`nativeLibraryDirectories` list). ART still calls linker
`__loader_android_dlopen_ext` (apex `libnativeloader`); that export is
Dobby-hooked. When the packaged extract file exists the rewrite is L2e
(that inode, in-memory `.text` decrypt), including when `so_plain` is already
warm. `so_plain` is the rewrite target only when that extract file is absent.
The linker resolves `DT_NEEDED` with its own
`open`/`openat` (often a relative name + extract `dirfd`); those imports
are hooked (bytehook-single on linker GOT, Dobby if defined, GOT patch
fallback). Keyed DT_NEEDED that still have a packaged extract file are pinned
with L2e before the linker searches. Opens with no extract file materialize
a `so_plain` closure instead of mapping leftover ciphertext. Packaged extract
is the fallback directory only.
`so_plain` also gets extract **sidecars** (non-`.so` files and subdirs such as
`.tx`, `osgPlugins-*`) as symlinks so Teigha/OSG `dirname()` of a mapped
`so_plain` path still finds modules.
Keyed loads use L1 when the extract dir is writable. Otherwise, if the packaged
extract file exists, the load is L2e for every keyed basename (not only
`l2e=true`): `use_library_fd` stays false. A warm `so_plain` mirror is kept
for the next launch and is not the mapping. Missing hooks or a failed execmod
probe fails the load closed. `LIBRARY_FD` / memfd remains only when the
extract file is absent. If that fd cannot be opened and the app targets below
API 29, the fallback path-load uses `so_plain`. On Android 10+ with
`targetSdk` 29 or newer that path-load is refused.

**Maps spoof (L2c):** libc `fopen`/`open`/`openat`/`__openat` of `/proc/self/maps`
rewrite keyed `so_plain` / `lib_mirror` / `memfd` paths to the packaged extract
path so OSG/Teigha `dirname()` matches stock. `dladdr` / `__loader_dladdr` /
`dl_iterate_phdr` / `readlink` / `readlinkat` / `realpath` do the same rewrite
(kernel maps still show the FD inode). Protector internals read maps via raw
`openat` syscall. Keyed opens of extract ciphertext redirect to plaintext.

After a successful **L1** or **L2** map, the keyed `so_plain/libX.so` file is
**kept on disk** so the next process can warm-reuse via `so_plain_ready`
(product chose cross-launch speed over in-process unlink). **L3** also keeps
the file. Class S is never planted in `so_plain/`.

### L1 plaintext probing (so_text_diag)

Extract-path `.text` checks are **probes**, not integrity verdicts: on many
Android 10+ devices the packaged extract dir is `system`-owned and not
app-writable, so L1 publish is impossible and the extract legitimately keeps
packaged ciphertext. The runtime therefore:

- skips all extract hashing once the extract dir is known not writable
  (probe memoized per basename + mtime/size — no multi-MB SHA-256 per dlopen);
- logs probe misses at INFO (never `[XOP-SO] FATAL`), falls through to L2;
- reserves FATAL for must-be-plaintext files only: `so_plain` mirrors after
  RC4 / warm reuse and freshly published extract copies.
- records the published extract inode (`st_dev`+`st_ino`). An in-memory RC4 of
  that inode is skipped — RC4 is an involution, so a second pass would turn
  L1 plaintext back into ciphertext before constructors. A different inode for
  the same basename is still treated as packaged ciphertext. The decrypt runs
  only after the lowest `PT_LOAD` is the mapped file offset and every `.text`
  page is executable; a partial `mmap` does not mark the basename done.
  The hooked symbol is the linker's own wrapper: `mmap` or `__dl_mmap`
  (64-bit also `mmap64` / `__dl_mmap64` when that address differs). 32-bit
  ABIs do not hook linker `mmap64` (`off64_t` vs `off_t`). When that hook
  is missing and `so_plain` is not executable, preload does not `dlopen`
  (a plaintext dep would pull packaged ciphertext through `DT_NEEDED`).
- maps records are read in 4KB chunks and stitched to a newline. The pathname
  is the field after the inode, up to `PATH_MAX`, not a 255-byte `%s`. A long
  applicationId extract path still matches its basename.

### RC4 identity gate (basename ≠ mapping)

A sokey entry is keyed by **basename** only. The same name can appear under a
foreign plugin tree (e.g. CSJ `pangle_p/.../libmaparmor.so`) while the
packaged extract also ships that basename. Before any in-memory or on-disk
RC4 of `.text`, the runtime requires either:

1. **Trusted path** — shell-controlled mapping (`nativeLibraryDir` extract,
   `so_plain` / `lib_mirror` / `memfd`, `so_cipher`, or `code_cache/protector/…`); or
2. **Diag meta match** — on-disk `file_size` + `.text` offset/size/`sh_addr`
   match packer `so_text_diag` (layout only; not plaintext SHA-256, so
   ciphertext extract still qualifies).

Fail closed: log `identity_gate=…`, skip RC4, and do **not** mark the basename
decrypted. Maps path selection prefers shell-controlled hits over foreign
same-basename rows. Packer **SO Industry Compatibility Policy** (SAFE/MAX only)
is complementary: basename → lowercase → EXACT then PREFIX → `decision=SKIP`
`reason=industry/{category}` and **no sokey**. Covers ads (`libpangle*`,
`libmaparmor*`), OEM/cloud push, analytics, and sample-confirmed EXACTs
(`libcrashsdk.so`, `libxgVipSecurity.so`, `libjutils.so`, …). Wide `libxg` /
`libj` prefixes stay out of policy. AGGRESSIVE does not apply industry skips.
The runtime gate remains mandatory and is not replaced by the packer policy.

## Plaintext warm cache (`so_plain_ready` + DEX `.prepatched`)

Cross-launch speed by reusing decrypted mirrors (accepts plaintext-at-rest):

| Path | Role |
|------|------|
| `code_cache/protector/so_plain/*` | Decrypted keyed ELF mirrors kept across launches |
| `so_plain/so_plain_ready` | Present when all on-ABI keyed SOs are mirrored |
| `.prepatched` + `classes*.dex` | DEX warm — skip PDX1 re-extract / re-prepatch |

Cold start: RC4 into `so_plain` → write `so_plain_ready` (+ DEX `.prepatched`).  
Next launch: reuse mirrors / prepatched dexes (skip RC4 and dex re-decrypt).  
APK update deletes `so_plain/`, `.prepatched`, and extracted dexes via `invalidateIfApkChanged`.

Legacy `so_warm/` PSW1 helpers may remain in the tree but are not used on this path.

### Hi-MC / HiBoat verification (2026-08)

- **SAFE/MAX + `path_sensitive` skip** (`libd3` / `libzhd3d`): MainMap / DeepSurvey stable.
- **AGGRESSIVE encrypt d3/zhd3d + L2e**: map packaged extract inode and decrypt `.text` in RAM before constructors (kernel maps path matches stock). Do not path-load `so_plain` for these megacores.
- **AGGRESSIVE encrypt `libcrypto*`**: Conscrypt SIGILL (Class S). Packer+runtime
  now refuse Class S in **all** modes including AGGRESSIVE.

Default product modes:

- **SAFE / MAX:** skip Class S (`system_soname`), industry SDKs, and path-sensitive.
- **AGGRESSIVE:** still **hard-skips Class S**; may encrypt path-sensitive / some industry SDKs.

## Class S — system / reserved soname collision

APK-bundled OpenSSL (etc.) must **never** live under `so_plain` or be RC4-encrypted:
`nativeLibraryDir` → `so_plain` would hijack `libcrypto.so` / `libssl.so` and break
Apex Conscrypt (`RSA_new` SIGILL). Same class: Bionic/NDK exact names, GLES/EGL/Vulkan.

| Layer | Behavior |
|-------|----------|
| Packer (all modes) | Skip encrypt; report reason `system_soname` |
| Runtime materialize | Refuse copy/RC4 into `so_plain`; unlink if present |
| Runtime `lib_mirror` | Symlink Class S → extract (path-sensitive dirname); never copy into `so_plain` |
| Runtime `copy_plain_deps` | Never symlink/plant Class S beside `so_plain` mirrors |
| Runtime dlopen path | Never rewrite Class S to `so_plain`; scrub on sight |

Re-pack old “encrypt everything” APKs; dirty `so_plain/libcrypto*` is scrubbed on next launch.

## Class A — dependency dual-mapping

- Non-keyed deps beside keyed mirrors: **symlink** to packaged extract (same inode).
- Never plant Class S / GLES stubs in `so_plain` (use `/system` / Apex).
- Refresh dep links **before** keyed preload / dlopen.
- `ApplicationInfo.nativeLibraryDir` → `so_plain` when mirrors exist; ClassLoader prepends `so_plain`, packaged extract as fallback for excluded/unkeyed libs.

## Class B — path-sensitive engines

Heuristic (packer), not hard-coded app SO names:

- `.text` size ≥ 4 MiB **or** file size ≥ 16 MiB, and
- `.dynstr` / small `.rodata` scan hits graphics NEEDED stubs (`libGLESv*`, `libEGL`) **or** engine markers (`osg`, `osgDB`, `Unity`, `UE4`, `cocos2d`, …).

Runtime: **L2e** for every keyed SO that still has a packaged extract file,
after L1 misses. Packer `so_text_diag` `l2e` is not the gate. That flag still
selects eager-skip of disk RC4 and hiding the SO from ClassLoader helper
dirs. Size-only runtime classification is not used on v2 diags — it treated
`libproj` as a megacore and skipped its eager mirror.
Application attach loads sokeys and installs hooks only: no full-table
RC4, SHA-256, `lib_mirror` scan, or keyed pin. L2e maps the packaged inode
and RC4s `.text` in the linker `mmap` hook before that call returns, so
relocation and constructors see plaintext. The hook records each `PT_LOAD`
span and decrypts once those spans cover `.text`; it does not wait for
`/proc/self/maps` to catch up. `soinfo::call_constructors` is not hooked
on any device. Dobby on that function zeroes `.init_array` on some OEM
linkers (Meizu 20 Pro, vivo X200 / PD2405), so even plaintext `libmmkv`
jumps to `pc=0`. A span set that already covers `.text` and still fails
decrypt unmaps that mapping and returns `MAP_FAILED`, so the linker does
not run constructors on ciphertext. If the linker `mmap` hook is missing
and `so_plain` is not executable (`targetSdk >= 29` on Android 10+), the
load is refused (FATAL). When `so_plain` is executable and mmap is not
hooked, the load is L3. No memfd.
The execmod probe is unchanged:
`mmap` one page of a packaged extract `.so` `PROT_READ|PROT_EXEC`, then
`mprotect` it writable. The probe uses a real extract file
(`apk_data_file`), not an anonymous mapping and not a file created under
`code_cache`. If the execmod probe fails, the load is refused
(FATAL) for every keyed SO that has an extract file. Constructors are not
run on ciphertext, and the load does not fall through to memfd. A successful
write restores
per-page protection from the pre-write snapshot: pages that hold only
`.text` go back to RX; a page whose original protection included
`PROT_WRITE` and that also extends outside `.text` keeps that protection.
If that restore fails after the bytes were written, the basename is latched
as already-plaintext so a later decrypt does not RC4 it again. The
failed mapping is dropped. When `USE_LIBRARY_FD` fails
and the app targets API 29 or newer on Android 10+, the load fails closed
instead of path-loading `so_plain`. Older targets still path-load `so_plain`.
Packer `l2e=true` megacores always stay on that extract inode
(CAD-OSG). Background fill of `so_plain` is delayed so it does not starve
first-frame IO; `so_plain_ready` is for later launches. If dlopen/linker
hooks fail, fall back to full materialize + pin so `DT_NEEDED` cannot
map ciphertext.

## Hooks failure

If dlopen-family hooks fail (e.g. bytehook): force full materialize + eager-style preload; never execute packaged ciphertext for keyed SOs.

## Operator overrides

- `--protect-so-exclude` — force skip encrypt (highest priority).
- `--protect-so-mode aggressive` — allow encrypting path-sensitive (not Class S).
