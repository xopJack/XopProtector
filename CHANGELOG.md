# Changelog

## 0.7.1

- SO protect runtime: Application attach no longer RC4/pins the full keyed table.
  Keyed SOs map packaged extract and decrypt `.text` in RAM (opportunistic L2e);
  packer `so_text_diag` v2 `l2e` marks true Class B megacores. Background
  `so_plain` fill is delayed past first frame.
- Desktop / installer / packer jar / native version **0.7.1**.

## 0.6.30

- Desktop / installer / packer jar / native version **0.6.30**.

## 0.6.28

- Desktop / installer / packer jar version **0.6.28**.

## 0.6.44

- Packer SO protect: basename all-or-none across ABIs — if any ABI is skipped for
  `path_sensitive` / text-reloc / no `.text`, sibling ABIs are not encrypted
  (`*_abi`). Fixes arm64 plaintext + v7a cipher for the same soname (e.g.
  `liblibpag.so`) where sokeys is basename-keyed → RC4 corrupt → SIGILL.
- SAFE/MAX industry skip: `libpag` / `liblibpag` prefixes (PAG GLES megacore).
- Desktop / installer / packer jar / native version **0.6.44**.

## 0.6.43

- PVM2 `dispatch_exception` JNI correctness:
  - `ExceptionClear` before `dup_owned_ref` (NewLocalRef/NewGlobalRef illegal
    while an exception is pending).
  - `global_to_local` deletes the Global only after a successful `NewLocalRef`;
    on OOM, rethrow via Global so the throwable is not dropped.
- Desktop / installer / packer jar / native version **0.6.43**.

## 0.6.42

- PVM2 nested-frame JNI Local scrub + exception OEM safety (Honor/Huawei Alipay
  nested `PayTask.payV2` → `Call*` → inner VMP):
  - `scrub_ref_aliases` walks the full `InterpFrame` prev chain so inner
    `DeleteLocalRef` cannot leave outer regs holding a freed cookie.
  - `clear_regs` scrub before delete covers outer frames; stash teardown uses
    `release_stash`.
  - `dispatch_exception`: `dup_owned_ref` / transfer ownership into stash (no
    `NewLocalRef`+`DeleteLocalRef` alias); Throw path uses `release_ref`.
- Desktop / installer / packer jar / native version **0.6.42**.

## 0.6.41

- PVM2 JNI Local alias hardening (Honor/Huawei `attempt to remove stale Local` on
  Alipay `PayTask.payV2` / `m.p.e.a` after 0.6.40):
  - Frame-scoped scrub: every owned `DeleteLocalRef`/`DeleteGlobalRef` clears the
    same jobject cookie from all regs / pending / stash first.
  - `dup_owned_ref`: when OEM `NewLocalRef` returns the same cookie, fall back to
    `NewGlobalRef` for move-object / args / const-class copies.
  - `return-object` promotes via GlobalRef across `clear_regs`; move-exception
    transfers stash ownership (no NewLocalRef+Delete alias).
- Desktop / installer / packer jar / native version **0.6.41**.

## 0.6.40

- PVM2 JNI Local ownership: `iget`/`sget`/`aget` KIND_L use `reg_take_o`
  (skip `DeleteLocalRef` when `old == got`); `clear_regs` dedupes aliased
  jobject cookies before delete. Fixes ART abort
  `attempt to remove stale Local` on Alipay `PayTask.payV2` / `m.p.e.a`
  under full payment True-VMP (Honor/Huawei). Keep Alipay VMP open.
- Desktop / installer / packer jar / native version **0.6.40**.

## 0.6.39

- Payment Auto True-VMP: clear Alipay pay hot-path denylist — reopen
  `Lcom/alipay/android/app/` (`IAlixPay$Stub` / Binder surface). Full Alipay +
  `/wxapi/` coverage under payment auto-VMP.
- Desktop / installer / packer jar version **0.6.39**.

## 0.6.38

- Payment Auto True-VMP: reopen Alipay `sdk/app` (incl. `PayTask`). Hot-path
  denylist now only `Lcom/alipay/android/app/` (Binder `IAlixPay$Stub`).

## 0.6.37

- PVM2 `iget` / `instance-of`: same register-alias fix as `aget` — do not
  `reg_as_i/j(dst)` before `Get*Field` / `IsInstanceOf`. `iget v0, v0, Field`
  deleted the object local then `GetIntField` SIGSEGV (fault `0xb1`) on Alipay
  `m.u.n.f`.

## 0.6.36

- PVM2 `aget`: do not `reg_as_i/j(dst)` before reading the array — when `dst`
  aliases the array register (`aget v0, v0, v1`), early drop deletes the live
  array local and `IsInstanceOf` SIGSEGV (fault `0x31`) on Alipay `m.u.j`→`m.n.a`.
  Read array first, then overwrite `dst`. Type-check before `Get*ArrayRegion`
  for Z/B/S/C remains. `sdk/m/u` stays True-VMP'd.

## 0.6.35

- PVM2 semantics: register kind tag (`RK_I`/`RK_J`/`RK_L`) so `if-eqz`/`if-nez`/
  `if-eq`/`if-ne` on objects use nullness / `IsSameObject` instead of leftover
  `.i`. `invoke-direct` uses `CallNonvirtual*`. `sdk/m/u` still crashes
  (`SIGSEGV` in `GetCharArrayRegion` / aget via `m.u.j`→`m.n.*`); keep denylisted.

## 0.6.34

- PVM2: fix `DeleteLocalRef` across `PushLocalFrame` in `invoke_method` (ART
  "index outside index area" when clearing outer `pending` / throwing NPE inside
  the frame). Clear pending + null-receiver checks happen before Push; frame only
  wraps `Call*`. `sdk/m/u` True-VMP still returns Alipay `4000` (no JNI warn);
  keep `m/u` on denylist until interpret semantics fixed.

## 0.6.33

- PVM2 interpreter JNI Local hardening (fixes Alipay `PayTask.payV2` stale Local /
  `GetObjectField` abort under payment Auto True-VMP):
  - L1: take ownership of `Call*Object` / `Get*ObjectField` / `aget` returns (no
    double `NewLocalRef` leak).
  - L2: `PushLocalFrame` RAII around `invoke_method`; object results promoted via
    `PopLocalFrame`.
  - L3: `EnsureLocalCapacity(regs+256)`; GlobalRef cache for classes / exceptions /
    box types; no `FindClass` leak on hot paths.
  - Fix register-alias stale Local: `iget`/`sget`/`aget` object must Get-then-Delete
    (supports `iget-object vX, vX, field`); `move-object vX, vX` is a no-op.
  - Null receiver/object: throw NPE before `Call*MethodA` / `iget`/`iput`/`aget`/`aput`/
    `array-length` (CheckJNI aborts on null `obj` otherwise).
- **Payment Auto True-VMP + Alipay (phased):** denylist `sdk/app`, `android/app`
  (AIDL). Full `sdk/m/*` + `android/phone` + `apmobilesecuritysdk` + `/wxapi/`.

## 0.6.32

- Desktop / installer / packer jar / native version string **0.6.32**.
- After Proxy→real Application reattach, transfer `ActivityLifecycleCallbacks`
  (fixes `ProcessLifecycleOwner` stuck after `androidx.startup` init on Proxy).
- Also transfer `ComponentCallbacks` / Assist via public APIs on
  `ProxyApplication` (API 34+ blocks reflecting `mCallbacksController`).
- Reflection migrate kept as fallback; best-effort `HiddenApiBypass` for older paths.
- Extra protect (assets / res-protect / NetGuard / pin-certs) stays **off** in
  Desktop + `protectDemo` (ExtraProtectPanel collapsed; CLI-only). `--encrypt-assets`
  requires the app to use `ProtectorAssets` — no transparent `AssetManager` hook.

## 0.6.31

- Fix Android 16 / 卓易通 SIGSEGV: ART `DefineClass` gained `descriptor_length`
  before `hash`; Dobby now uses V36 ABI + mangling (`EPKcmm` / `EPKcjj`) so
  `DexFile`/`ClassDef` args are not shifted into poison pointers.
- DefineClass ABI selection is mangling-first: `EPKcmm`/`EPKcjj` → V36;
  clear `EPKcm`/`EPKcj` → V22; do not force V36 solely because `sdk>=36`.

## 0.6.30

- Desktop / installer / packer jar / native version string **0.6.30**
  (current shipping line; versions unified).
- API 36 / OEM ART: safe `DexFile` probe (`process_vm_readv` + memcpy fallback),
  system-class DefineClass bypass, exact mangling + RX check; junk verify off ART callback.
- No separate `V36::DexFile` (sdk≥35 keeps V35 layout).
- Extra protect (assets / res-protect / NetGuard / pin-certs) stays **off** in
  Desktop + `protectDemo` (ExtraProtectPanel collapsed; CLI-only). `--encrypt-assets`
  requires the app to use `ProtectorAssets` — no transparent `AssetManager` hook.

## 0.6.27

- Desktop / installer / packer jar version **0.6.27**.
- Native shell ABIs: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64` (x86 skips shadowhook).
- Fix Android 10 (API 29): prefer ART `LoadClass` hook; skip broken Dobby `DefineClass`
  replace on i386 (was SIGABRT in `GetIndexForClassDef`). Demo includes x86 ABIs for
  emulator smoke.
- Fix Android 6 (API 23) DEX load: `write_all` used `pubsetbuf` with a buffer that was
  destroyed before `ofstream` flush (UAF). Last 256KiB of `classes.dex` became zeros
  (`map_list` / `class_data`) → ART `Map is missing header entry`. Buffer now outlives
  the stream; close/flush while it is still valid.
- Fix Android 6 business SO: strip `DT_VERNEEDNUM` on `so_plain` (API≤24 only) so L3
  dlopen is not rejected; `ensure_decrypted` still RC4s packaged ciphertext when the
  linker mapped extract instead of `so_plain`.
- Fix Android 7 (API 24) x86: do not pass an oat dir into `DexPathList.makePathElements`
  for protector secondary dex (dex2oat caused ART `AllocObject` SIGSEGV). Skip Dobby
  ART class hooks on x86 API≤24; defer `finishBusinessSoDecrypt` until first load.
- Fix Android 10 arm64: `libc_export_hooked` / `verify_libc_text_crc` read libc
  `.text` under execute-only memory (SEGV_ACCERR); use `process_vm_readv` instead.

## Unreleased

### Runtime — restore plaintext warm reuse (startup)
- Cross-launch reuse of **`so_plain/` + `so_plain_ready`** and DEX **`.prepatched`**
  (product chose speed over encrypted `so_warm` / in-process unlink).
- Do not drop keyed mirrors or ready marks each launch; APK stamp still
  invalidates the whole protector cache on update.
- `maybe_drop_so_plain_mirror` is a no-op so L2/memfd loads keep disk mirrors
  for the next process. Encrypted PSW1 hydrate/persist is unused on this path.

### Runtime — shorten in-process SO plaintext (PR12)
- L2 prefers an optional **memfd** (`memfd_create`, SOs ≤ 16 MiB) as
  `ANDROID_DLEXT_USE_LIBRARY_FD` content; falls back to the `so_plain` fd, then L3
  `dlopen(so_plain/...)`.
- L2b `dladdr` also rewrites `/memfd:` names; in-memory RC4 is skipped for SOs
  already mapped from plaintext.
- *(Superseded for cross-launch disk policy by plaintext warm above.)*

### Packer / Runtime — Integrity v2 (PR13)
- Config HMAC now also covers `code_methods_hmac`: HMAC-SHA256 of the canonical
  hollow/VMP method set (LE count + sorted `dex, method_idx, flags`), matching
  parsed `code.bin`.
- After extract, every `code.bin` method must exist as a concrete (`code_off != 0`)
  method in the matching `classes*.dex`. Fail closed. Not a Java↔Native↔VM mesh.

### Runtime — syscall read of protector assets (PR14)
- `config.json`, `code.bin`, `dexes.zip`, and the APK signing block are read via
  `openat`/`read`/`lseek`/`fstat`/`close` syscalls, not libc `fopen`/`ifstream`/`pread`.
- Does **not** convert process-wide I/O (`/proc/maps`, SO materialize, DEX write).

### Runtime — small shell self-protect (PR15)
- `JNI_OnLoad` pins `JniBridge` and `ProxyApplication` class global refs.
- Heartbeat is `heartbeat(Application shell)`: native records a ping only when
  the caller class is the pinned `JniBridge` and `shell` is a `ProxyApplication`.
  Forged pings abort (`java_shell`).
- Ping immediately, then every 5 s. Capture `this` from `attachBaseContext`
  (still `ProxyApplication` after replace). Do **not** check
  `ActivityThread.currentApplication()`.
- `init_app` arms the window. First legal ping must arrive within **90 s**
  (covers DexMerger / SO decrypt after arm, especially ACF `FileBootstrap`).
  After that, a gap &gt; **15 s** aborts. Never pinging after init is a timeout,
  not a skip. Does **not** randomize shell package names or specialize
  `RegisterNatives`.
- Heartbeat thread starts immediately after `init_app` (Application path) or
  when ACF instantiates `ProxyApplication`, then pings every 5 s.

### Runtime — PR12–PR15 review fixes
- L1/L2 mark keyed SO as already-plain **before** `dlopen` / `android_dlopen_ext`
  so `.init_array` cannot RC4 a plaintext memfd/extract mapping.
- PVM2 `fill-array-data` scratch scan walks real Dalvik insns (a `const/16 0x26`
  no longer inflates scratch and rejects 30–31-reg methods).
- Protector asset `read`/`openat` retry `EINTR`.
- `libprotector.so` `.bitcode` is RX at load (K_master slot is `const`). A
  writable object in that section made LLD emit a WX `PT_LOAD`; Android 10+
  then refused `dlopen` (`W+E load segments are not allowed`).
- Bitcode HMAC bind: wipe the `const` K_master slot with volatile stores
  (Release `memset` through `const_cast` was UB and could be deleted). HMAC
  itself matches packer `hmacBitcodePostWipe` (slot treated as zeros) so a
  failed in-place wipe is not a false integrity fail.

- Temporarily disable assets encrypt / res-protect / NetGuard in desktop + `protectDemo`
  (code kept; ExtraProtectPanel stays collapsed). Demo smoke no longer requires them.
- Packer: probe SDK `zipalign` for `-P` before trying 16 KB page align, so older
  build-tools (e.g. 34.0.0) no longer spam `ERROR: unknown flag` in desktop logs.

### Packer / Runtime — Class S system soname guard
- Docs: Class S in `docs/so-load-contract.md` (system/OpenSSL/GLES collision).
- Packer: **all modes** (incl. AGGRESSIVE) skip Class S with reason
  `system_soname` (`libcrypto*` / `libssl*` / Bionic exact / GLES…).
- Industry SDK skips remain SAFE/MAX-only (`industry/runtime`).
- Runtime: never materialize Class S into `so_plain`; scrub leftovers; deps
  blacklist extended beyond GLES; dlopen path never rewrites Class S to `so_plain`.

### Packer / Runtime — path-sensitive SO contract (L1/L2 + heuristic)
- Docs: `docs/so-load-contract.md` (mechanism-based; no customer SO hardcodes).
- Packer SAFE/MAX: skip encrypt when (`.text` ≥ 4MiB **or** file ≥ 16MiB) and
  GLES/engine markers hit (`path_sensitive`). AGGRESSIVE may still encrypt those SOs.
- Runtime keyed load prefers **L1 → L2 → L3**:
  - **L1** publish plaintext onto packaged extract (archives cipher under
    `so_cipher/` first so rematerialize stays correct).
  - **L2** `android_dlopen_ext` + `ANDROID_DLEXT_USE_LIBRARY_FD` (linker name =
    extract path; content = `so_plain` fd). Clears caller zip FD-offset flags.
  - **L2b** hook `dladdr` so keyed `so_plain` mappings report extract `dli_fname`.
  - **L3** `dlopen(so_plain/...)`.
- **Known limit (Hi-MC):** AGGRESSIVE encrypt of OSG megacores (`libd3` /
  `libzhd3d`) still hits TTIN `SIGSEGV @ 0x30` after L2/L2b — `/proc/maps`
  remains `so_plain`. SAFE/MAX `path_sensitive` skip stays the ship default.
- Class A: never plant Class S stubs in `so_plain`; `nativeLibraryDir` → `so_plain`.

### Packer — `--protect-so-exclude`
- Skip exact SO basenames from encryption (e.g. `libd3.so,libzhd3d.so`).
- Reported as `so_skipped_policy` reason `exclude`. Repeatable / comma-separated.

### Runtime — lazy SO decrypt: no SIGILL when dlopen hooks fail
- Track whether any of `dlopen` / `android_dlopen_ext` / `__loader_*` hooks
  actually installed (`g_dlopen_hooks_ok`).
- **Lazy + hooks missing** (e.g. bytehook `INITERR_SIG`): force full
  `materialize_all_keyed_sos` + eager-style preload so ClassLoader never maps
  packaged ciphertext (fixes Hi-MC first-install `libcpbase` SIGILL).
- `path_for_dlopen` never returns packaged path for keyed SOs; hooked loaders
  return `nullptr` instead of executing encrypted `.text`.
- Full materialize is **idempotent**: skip already-decrypted same-sized mirrors
  (avoid force-copy + `AlreadyDone` leaving ciphertext).

### Runtime — SO decrypt-mode hardening (post Phase 0–3 review)
- Background fill: `setpriority` uses **thread tid** (not process who=0).
- `copy_plain_deps` skips keyed basenames (no raw ciphertext planted in `so_plain`).
- `materialize_one_keyed`: serialize via `claim_key`; copy only on missing/size
  mismatch (no force-clobber of same-sized mirrors); RC4 under the same claim.
- Pending/`ensure_decrypted` closure materialize runs only in **lazy** mode.

### Packer / Runtime — `--so-decrypt-mode` background fill (Phase 3)
- **Lazy** after preload: low-priority thread materializes remaining keyed SOs
  into `so_plain` (up to 2 workers + one retry). Full success → write
  `so_plain_ready` so the next process hits warm reuse like eager.
- Incomplete fill leaves no ready mark; next launch stays on-demand.
- Already-ready warm starts skip the background job.

### Packer / Runtime — `--so-decrypt-mode` lazy preload (Phase 2)
- **Lazy** `preload_so_plain`: only `dlopen` keyed mirrors **already** in `so_plain`
  (warm / prior on-demand); skip missing (no full keyed pin at bootstrap).
- Cold-start decrypt still on first hooked `dlopen` via Phase 1 keyed DT_NEEDED
  closure. `decrypt_already_loaded_async` unchanged as fallback.
- **Eager** still preloads every keyed SO from `so_plain`.

### Packer / Runtime — `--so-decrypt-mode` lazy materialize (Phase 1)
- **Lazy** cold start skips full keyed RC4 materialize (no `so_plain_ready` written).
- On `dlopen` / `ensure_decrypted`: materialize the SO (if keyed) plus keyed
  `DT_NEEDED` closure into `so_plain`, then `copy_plain_deps` — avoids SIGILL when
  a plaintext parent resolves an encrypted dep.
- Warm reuse still applies when `so_plain_ready` is already valid (prior eager run
  or future Phase 3 background fill).
- **Eager** (default) unchanged. Phase 2 will narrow lazy preload.

### Packer / Runtime — `--so-decrypt-mode` (Phase 0)
- CLI: `--so-decrypt-mode eager|lazy` (default **eager**).
- Written to `config.json` as `so_decrypt_mode` (HMAC-covered).
- Runtime parses and applies the mode. Missing field → eager (old APKs).

### Branding — XopProtector
- Product / display name, `AssemblyName` (`XopProtector.exe`), portable `dist/XopProtector/`,
  and installer Setup title aligned to **XopProtector**.
- AppData root: `%AppData%\XopProtector` (migrates from `XOP Protector` / `AppShield`).
- Gradle `rootProject.name` set to `XopProtector`.

### Desktop — security reports: one entry per protect job
- Job ids include milliseconds + random suffix (second-only stamps collided).
- Report list uses history `Id` as the stable key (no `R-` collapse).
- `size_report.json` is snapshotted under `%AppData%\XopProtector\reports\`
  so re-protecting the same output path no longer overwrites older reports.

### Docs / open-source readiness
- English README: Quick start, disclaimer, security contact, link to Chinese docs.
- Added [README.zh-CN.md](README.zh-CN.md), hardened `.gitignore`, [SECURITY.md](SECURITY.md)
  contact (`xopJack@163.com`).
- GitHub: [.github/RELEASE_TEMPLATE.md](.github/RELEASE_TEMPLATE.md) + issue contact links
  (replace `OWNER/REPO` before going public).
- Open-source cleanup: `.gitignore` keeps `packer/libs/*.jar`; ignores `.claude/`,
  `.gradle-tmp-home/`, local list leftovers; drop local build/customer artifacts.

### Desktop — i18n P1 (overseas readiness)
- Neutral payment Auto-VMP copy (no alipay|wxapi in UI); ZH nav subtitles localized.
- EN polish: App protection / Select app; clearer language-restart messaging.
- Desktop + installer version aligned to **0.6.26**; sidebar version from assembly.
- AppData root: `%AppData%\XOP Protector` (one-time migrate from legacy `AppShield`).

### Packer 0.6.26 — Sparse progress logs + Desktop log UI
- Milestone progress (every 10%) for `unzip`, `assets encrypt`, `res-protect`
  move/arsc, and `repack`; plus `zipalign: starting` before align.
- Assets encrypt no longer prints one line per file (avoids 3k+ line floods).
- Desktop: queue + batch `AppendText` for engine stdout; `BeginInvoke` for
  progress (no per-line `Dispatcher.Invoke` blocking the Java pipe).

### Packer 0.6.25 — Industry auto True-VMP app-package scope
- `IndustryVmpRules` production match requires Manifest `package` prefix
  (`ProtectPolicy.appPackagePrefix`); third-party crypto-named types (zip4j,
  LitePal, XStream, …) are skipped without a library denylist.
- Log: `True-VMP policy: … industry_scope=<Lcom/…/|none>`; WARN when industry
  auto is on but package is missing.
- Payment auto-VMP and `--true-vmp-prefix` remain unscoped (escape hatch for
  sibling packages outside applicationId).

### Desktop — protect log persist + selectable console
- Harden log is a read-only selectable TextBox (Ctrl+C / Copy / Select all).
- Each job writes UTF-8 log to `%AppData%\XOP Protector\logs\yyyyMMdd-HHmmss_<apk>.log`.
- On finish, also mirrors `<output>-protect.log` beside the APK when possible.
- History stores `protectLog` path.

### Desktop — security report score (stable + higher)
- Score is **feature-additive** (profile / SO / assets / res / auto-VMP / proxy /
  channel / signed); no longer subtracts `warn×3` from reloc/budget skips.
- Higher baseline (80+); typical industry+SO+signed lands near ceiling.
- SO skip penalty: −1 per up-to-5 skipped (budget+reloc, ceil), max −5; policy skips ignored.
- SO off: −5 (in addition to missing the +8 on-bonus).

### Phase 3 — Desktop Advanced extras
- Advanced: `--encrypt-assets` / `--enable-res-protect` / `--detect-proxy` /
  `--pin-certs` / `--channel`, plus hollow & VMP1 prefix boxes.
- Channel requires custom signing (UI validate); pin-certs path checked before run.
- History shows assets/res/proxy/channel flags when set.

### Phase 2 — Desktop Advanced (auto True-VMP + SO budget)
- Harden Step2 **Advanced** expander: payment/industry auto True-VMP checkboxes,
  True-VMP prefixes (moved from Step3), SO budget/max-file fields.
- Profile `industry` presets industry auto ☑; user overrides sticky; reset button.
- `EngineRunner` always forwards `--payment-auto-vmp`/`--no-…` and industry pair;
  optional `--protect-so-budget-mb` / `--protect-so-max-file-mb`.
- History records auto-VMP + budget fields.

### Phase 1 — Auto True-VMP CLI (packer 0.6.24)
- `ProtectOptions.AutoVmpMode` + `--payment-auto-vmp` / `--no-payment-auto-vmp`,
  `--industry-auto-vmp` / `--no-industry-auto-vmp`, optional `--auto-true-vmp`.
- Resolution per `doc/auto-true-vmp-contract.md` (UNSET keeps 0.6.23 defaults).
- Log `True-VMP policy:`; Industry banner shows effective `IndustryVmpRules=on|off`.
- Conflicting paired flags → fail; unit tests for policy / rules / CLI parse.

### Phase 0 — Auto True-VMP contract (docs only)
- Freeze CLI / defaults / log / compat matrix: `doc/auto-true-vmp-contract.md`.
- Planned flags (Phase 1): `--payment-auto-vmp` / `--no-payment-auto-vmp`,
  `--industry-auto-vmp` / `--no-industry-auto-vmp` (UNSET keeps 0.6.23 defaults).
- Update `doc/industry-profile.md`: industry defaults auto VMP on; `--no-industry-auto-vmp` allowed.
- Roadmap note in `doc/roadmap-hardening.md`.
- No packer/Desktop code in this phase.

## 0.6.23 — SO protect runtime correctness
- Atomic stream-copy for `so_plain` mirrors (no truncated large deps like `libd3.so`).
- Refresh plain DT_NEEDED deps on warm reuse; rewrite incomplete size-mismatched deps.
- `find_so_path` prefers `/so_plain/`; force in-memory RC4 if packaged ciphertext still mapped.
- DT_NEEDED parse no longer slurps entire multi-100MB ELF into RAM.
- Materialize always force-copies ciphertext from packaged lib before disk decrypt.
- `--profile industry`: encrypt-first (no package-wide hollow) + `IndustryVmpRules` auto True-VMP.
- Industry SO budget defaults **48 / 24 MB** unless `--protect-so-budget-mb` / `--protect-so-max-file-mb` set.
- Narrow industry tokens (no broad `auth`/`protocol`); path-segment hits license-only;
  crypto tokens only on simple names; skip `Lcom/amazonaws/` + `Lorg/spongycastle/`.
- TRUE_VMP trampoline uses 32-bit `const` for dex/method indices (fixes large-DEX `const/16` overflow).
- Desktop Harden page adds `industry` profile option.
- Doc: `doc/industry-profile.md`.

## 0.6.21 — PVM2 / res-protect correctness fixes
- PVM2: `shl/shr/ushr-long` read 32-bit shift count from `Reg.i` (was always 0 via `.j`).
- PVM2: float/double→int/long follow ART (NaN→0, clamp min/max).
- Res protect: string-pool slot end uses next greater offset / `stylesStart` (no style wipe);
  move files before rewriting `resources.arsc`; abort if any move fails.
- Fix: revert CFF on `unpad_unknown_key` (broke RC4 .bitcode decrypt → SIGILL on load).

## 0.6.20 — Phase 2B res path obfuscation
- Opt-in `--enable-res-protect`: shorten `res/` → `r/…` and rewrite `resources.arsc` string pool.
- Mapping written to `assets/protector/res_mapping.txt`; arsc stays STORED (not encrypted).
- Default whitelist keeps `res/mipmap*/**`.

## 0.6.19 — Phase 7 native CFF/BCF
- Source-level CFF/BCF/MBA (`common/obfuscate.h`) on `handle_risk`, `detect_frida`, `unpad_unknown_key`.
- Opt-in OLLVM/Hikari via `-Pprotector.llvmObf=true` (sensitive TUs only).
- Probe script: `scripts/probe-llvm-obf.ps1`; doc: `doc/llvm-obfuscation.md`.

## 0.6.18 — Phase 6 multi-channel (signing-block)
- Walle-compatible channel ID `0x71777777` via `ApkChannel` / `ChannelReader`.
- CLI: `--channel` / `--channels`; standalone `channel get|put|batch`.
- `protectDemo` signs with debug keystore and stamps channel `demo`.

## 0.6.17 — Phase 4 string OBSC + Phase 5 threat telemetry
- Rolling XOR string obfuscation (`OBSC_ROLL` / `StrEnc`); tool `scripts/obsc_encode.py`.
- Re-encoded risk detectors + shell path literals.
- Threat JSON adds `pid`/`sdk`; Block paths write `crash_reason.txt`.
- `CrashGuard` chains uncaught handler (soft threat report).

## 0.6.16 — Phase 3 NetGuard (proxy detect + cert pins)
- Opt-in `--detect-proxy` / `--pin-certs <file>` → `assets/protector/netguard.json`.
- Runtime `NetGuard` + soft `JniBridge.reportThreat` (no Block-crash for proxy/VPN).
- Pin helper: `NetGuard.wrappingTrustManager` (leaf SHA-256). Distinct from APK signing check.
- Demo enables detect-proxy + placeholder pins; MainActivity asserts NetGuard installed.

## 0.6.15 — Phase 2A assets encryption
- Opt-in `--encrypt-assets`: AES-GCM (`PAS1`) for `assets/**` → `protector/aenc/`.
- Runtime: `ProtectorAssets` + `JniBridge.decryptAssetBlob`; key `PROTECTOR_ASSETS_KEY`.
- Demo `assets/secret.txt` smoke via `ProtectorAssets.readString`.
- Media extensions skipped (openFd-friendly); `enableResProtect` still reserved for 2B.

## 0.6.14 — PVM2 Phase 5 (float/double/monitor ISA)
- PVM2 image **v4**: morph `OP_COUNT=50` — float/double/long ALU, conversions,
  cmp, `monitor-enter/exit`, `const-wide` / `const-wide/high16`, int div/rem.
- Runtime accepts v1–v4; v3 morph tables (`op_count=40`) still parse.
- Demo probes: `floatProbe` / `doubleProbe` / `floatCmpProbe` / `syncProbe`.
- Roadmap + reserved `ProtectOptions` flags for later phases
  (`enableResProtect` / `enableNetGuard` / `enableChannelMark`).

## 0.6.13 — Packer library API + desktop UI progress
- Public library entry: `Protector` / `ProtectOptions` / `ProtectResult` /
  `ProtectProgressListener` (CLI remains `PackerMain`).
- New `--json-progress`: NDJSON phase/log/done/error events on stdout for the
  Windows desktop UI (subprocess protocol).
- WPF desktop app under `desktop/` (see README).

## 0.6.12 — SO protect size budget (production default)
- Default `--protect-so-mode safe` now applies a **size budget** (in addition to
  industry/reloc skips): greedy select small/low-Δ SOs until budget is exhausted.
- New flags: `--protect-so-budget-mb` (default 12), `--protect-so-max-file-mb`
  (default 8), `--protect-so-abi <abi>|all` (default all).
- `--protect-so-mode max`: same industry skips, **no** size budget (prior full encrypt).
- `--protect-so-mode aggressive`: shell+reloc only + soft budget truncate + WARN.
- Emits `size_report` (stdout + `<out>-size_report.json` + assets placeholder).
- Runtime unchanged: unlisted SO basenames in `sokeys.bin` are not decrypted.

## 0.6.11 — Startup perf (SO warm reuse + critical preload)
- Warm: reuse `so_plain` via `.so_plain_ready` (skip rematerialize/RC4); skip re-extract
  of `code.bin`/`config.json` when present; APK update clears `so_plain`.
- Cold: parallel materialize (up to 4 workers); copy only DT_NEEDED plaintext deps into
  `so_plain` (no full `lib/` mirror from Java).
- Preload all keyed (encrypted) SOs from `so_plain` in DT_NEEDED order so plaintext
  parents loaded from `/data/app/lib` cannot pull ciphertext deps; idempotent.
- Application bootstrap skips heavy init when AppComponentFactory already ran.

## 0.6.10 — Universal SAFE SO filter (APK-agnostic)
- Default `--protect-so-mode safe`: skip shell libs, text-reloc SOs, and industry/
  runtime basenames (OpenSSL, Flutter/`libapp.so`, RN/Hermes, Sophix, crash SDKs,
  carrier/push SDKs like `libcmcc*`, system-collision names like `liblog.so`…).
  **No customer package names.**
- `--protect-so-mode aggressive`: previous wide behavior (shell + text-reloc only).
- SO protect remains default ON; `--no-protect-so` still disables entirely.
- Runtime: if packaged `.so` is read-only, copy+decrypt under protector cache before
  `dlopen` so `JNI_OnLoad` never runs on ciphertext.
- DEX extract: sequential inflate + ZIP CRC check; fall back to Java unzip on failure.

## 0.6.9 — Startup perf (P0–P2), same protection surface
- **P0**: Cold start decrypts PDX1 in memory and extracts `classes*.dex` in parallel
  (zlib); no plaintext `dexes.zip` on disk; larger I/O buffers (256 KiB).
- **P1**: Skip Java re-unzip when native already extracted; avoid double zip write.
- **P2**: Keep `code.bin` on disk for warm starts (no APK re-copy every launch);
  load `sokeys` on warm; defer `decrypt_already_loaded` to a background thread.
- Protection unchanged: PDX1 DEX encrypt + default SO `.text` RC4. APK payload size
  unchanged (shell/native only).

## 0.6.8 — SO .text protect on by default
- Business `lib/*.so` `.text` RC4 (`--protect-so`) is **default ON**.
- Pass `--no-protect-so` when SO encryption is not wanted.
- `--protect-so` kept as an explicit enable (compatible with older scripts).
- SOs with text relocs are still skipped (would break after encrypt).

## 0.6.7 — Production default: encrypt DEX + auto payment True-VMP
- Default `balanced`/`perf`: **no package-wide hollow**; all business DEX still encrypted in `dexes.zip`.
- Auto True-VMP for types containing `alipay` or package segment `/wxapi/`
  (not OpenSDK names like `WXApiImpl`; skip Activity/Service/… components so DexPool
  rewrite cannot corrupt the rest of that multidex).
- Optional `--true-vmp-prefix` / `--hollow-prefix` / `--profile aggressive|max` still available.
- TRUE_VMP compile failure on auto-only types leaves the method intact (no hollow fallback).

## 0.6.6 — No plaintext business DEX in APK
- All business `classes*.dex` go into encrypted `assets/protector/dexes.zip` (PDX1).
- Base APK only keeps shell `classes.dex` + junk multidex — static APK has no plaintext business DEX.
- Method hollow/VMP scope unchanged (`balanced` still few methods); empty `code.bin` allowed when zero hollow.
- Warm start: skip re-extract **and** PDX1 decrypt of `dexes.zip` when `.prepatched` + dexes exist
  (was re-decrypting ~18MB every process start). `makePathElements` still ~2s for multidex on device.

## 0.6.5 — Keep non-hollowed DEX in base.apk (install AOT)
- Only DEXes with hollowed methods go into `assets/protector/dexes.zip`.
- Untouched `classesN.dex` stay in the APK so ART can AOT them at install (release-like feel).
- Vacate `classes.dex` for the shell; compact remaining APK multidex to contiguous `classes2..N`
  (ART stops at the first gap).
- **Superseded for product default by 0.6.6** (plaintext-in-APK traded for install AOT).

## 0.6.4 — Speed-first default hollow scope
- Default `--profile balanced|perf`: hollow only manifest `applicationId` package (skip Activities etc.).
- `--profile aggressive` = previous wide non-SDK hollow; `--profile max` = near hollow-all.
- Warm start: reuse `.prepatched` dexes (skip re-extract / re-prepatch).

## 0.6.3 — Engine P1: file prepatch before ART map
- After extract, parallel-restore hollow methods into `classes*.dex` before `makePathElements`.
- Rewrite DEX checksum/signature after prepatch; DefineClass path mostly no-op.

## 0.6.2 — Engine P0: faster hollow restore
- Class-batch patch: decrypt then one `mprotect` RW window per class (not per method).
- Startup DEX RW hold (~25s) + deferred RO flush to cut RW↔RO thrash.

## 0.6.1 — Production hollow policy
- Default hollow mode is no longer “all methods”: `--profile balanced|aggressive|perf` (default **balanced**).
- Unified skip lists (framework / major SDKs / Android components / generated `R`/`BuildConfig`) — same rules for every APK.
- `--hollow-prefix` is an allowlist; empty = auto include under the selected profile.

## 0.6.0 — PVM2 Phase 4
- Cache parsed PVM2 images across `interpret()` calls; hoist box-class FindClass.
- Demo `libdemo_biz.so` + `Business.soProbe` for `--protect-so` smoke.
- `protectDemo` enables `--protect-so`; `scripts/release-demo.ps1` pack/sign/install/logcat.
- Version strings: native `0.6.0-pvm2`, packer jar `0.6.0`.

## 0.5.0 — PVM2 Phase 3
- PVM2 v3 opcode morph + `isa_id` multi-entry (`pvm2_run_a/b/c`).
- RASP gate: `vmp_allowed()` + SO integrity on prepare / periodic pulse.

## 0.4.0 — PVM2 Phase 2
- Invoke / field / array / filled-new-array / throw+try-catch / lit* scratch fix.

## 0.3.0 — PVM2 Phase 1 (MVP)
- True VMP: never restore selected methods; JNI trampoline + native interpret.
