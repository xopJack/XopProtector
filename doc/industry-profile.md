# Industry profile (`--profile industry`)

Step A preset for **tools / surveying / industrial** Android apps (e.g. `com.zhd.*`).

Auto True-VMP toggles are specified in [`auto-true-vmp-contract.md`](auto-true-vmp-contract.md) (**Phase 0 frozen**; Phase 1 implements CLI).

## What it does

| Area | Behavior |
|------|----------|
| DEX encrypt | Same as `balanced` (full `dexes.zip` PDX1) |
| Package hollow | **Off** (no package-wide hollow) |
| Auto True-VMP | **Defaults:** `PaymentVmpRules` **on** + [`IndustryVmpRules`](../packer/src/main/java/com/yqsh/protector/packer/IndustryVmpRules.java) **on** (license / activate / encrypt / … tokens), **scoped to Manifest `package` only** (0.6.25+). Override with CLI below. |
| SO protect | On by default; budget **48 MB**, max file **24 MB** unless CLI overrides |
| Root / emulator / libc CRC RASP | Disabled by default (`risk_flags=50`) — OEM false positives |

### Auto True-VMP overrides (Phase 1+)

| Flag | Meaning |
|------|---------|
| `--no-industry-auto-vmp` | Keep industry profile (DEX / SO 48/24 / no hollow) but **do not** apply `IndustryVmpRules` |
| `--industry-auto-vmp` | Force industry rules **on** even if profile is not `industry` |
| `--no-payment-auto-vmp` / `--payment-auto-vmp` | Force payment markers off/on (default remains **on** when unset) |
| `--true-vmp-prefix` | Manual prefixes (repeatable); always additive |

Omitting the auto-VMP flags preserves **0.6.23** behavior for `--profile industry`.

Explicit `--hollow-prefix` still works. Explicit SO budget flags set `protectSoBudgetExplicit` / `protectSoMaxFileExplicit` so industry SO defaults are not applied. Turning industry auto-VMP off **does not** reset SO budget.

## Example

```bat
java -jar protector-packer-0.6.25.jar app.apk -o out.apk ^
  --shell-dir executable\shell-files ^
  --profile industry ^
  --keystore release.jks --alias KEY --storepass *** --keypass *** ^
  --channel customer-a
```

Disable industry auto True-VMP (faster pack; weaker coverage) while keeping industry SO budget:

```bat
  --profile industry --no-industry-auto-vmp
```

Optional: pin sensitive packages **outside** the Manifest package (sibling modules), or when token rules miss:

```bat
  --true-vmp-prefix Lcom/zhd/ts/license/ ^
  --true-vmp-prefix Lcom/zhd/common/crypto/
```

## Acceptance

- Log contains `True-VMP policy:` with `industry_scope=L…/` (Phase 1+ / 0.6.25+) and/or `Industry defaults:` with effective `IndustryVmpRules=on|off`.
- Prefer `Auto True-VMP (IndustryVmpRules): types=` &gt; 0 when industry auto is effective **and** sensitive types live under applicationId (or use `--true-vmp-prefix`).
- Third-party libs under other packages (e.g. zip4j / LitePal) must not inflate Industry counts.
- `SO protect` `skipped_budget` lower than with 12 MB budget on large apps (when using industry SO defaults).
- Cold start reaches main UI; resign with wrong cert must fail closed.

## Desktop (Phase 2 — done)

Industry profile remains a **preset**. Auto True-VMP checkboxes, True-VMP prefixes, and SO budget live under Harden **Advanced options**; Desktop always forwards paired `--payment-auto-vmp` / `--industry-auto-vmp` flags (see contract § Desktop forwarding).

## Not in Step A

Quota hollow under `Lcom/zhd/…`, Frida↔key binding, Flutter — see roadmap / later steps.
