#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <memory>

namespace protector {

namespace vm {
struct Pvm2Image;
}

struct CodeItem {
    uint32_t method_idx = 0;
    /** Plaintext insn byte length (written into DEX), or PVM2 image size for TRUE_VMP. */
    uint32_t plain_insns_size = 0;
    /** Encrypted blob length (nonce||ct||tag) while still in code_blob. */
    uint32_t insns_size = 0;
    /** bit0 = PVM1; bit1 = TRUE_VMP (PVM2). */
    uint32_t flags = 0;
    /** Points into RuntimeState::code_blob (TRUE_VMP ciphertext stays for LRU re-decrypt). */
    uint8_t* insns = nullptr;
    /** Decrypted PVM2 image for TRUE_VMP methods (LRU plaintext; never written to DEX). */
    std::vector<uint8_t> vm_image;
    /** Parsed + demorph-ready image (filled on first interpret / LRU hit). */
    std::unique_ptr<vm::Pvm2Image> parsed_vm;
    /** Serializes decrypt + first-parse of {@link #parsed_vm}. */
    std::mutex parse_mu;
    /** In-flight interpret() pins; LRU will not wipe while > 0. */
    std::atomic<int> vmp_in_use{0};
    std::atomic_bool patched{false};

    CodeItem();
    ~CodeItem();
    CodeItem(const CodeItem&) = delete;
    CodeItem& operator=(const CodeItem&) = delete;
};

/** RASP response when a detector fires (config.json rasp_action). */
enum class RaspAction : int {
    /** Log only — never crash (demo / low false-positive). */
    Alert = 0,
    /** Mark degraded + schedule delayed crash (softer than immediate kill). */
    Degrade = 1,
    /** Immediate process termination via crash_* paths. */
    Block = 2,
};

/** When to decrypt protected business SOs at process start. */
enum class SoDecryptMode : int {
    /** Full materialize + preload at cold start (default, compatible). */
    Eager = 0,
    /** On-demand / deferred decrypt (skip full cold-start materialize). */
    Lazy = 1,
};

struct ShellConfig {
    std::string application_name;
    /** Legacy field retained in config.json; unused for crypto. */
    uint32_t insns_xor_key = 0;
    /** 16-byte AES-128 key for code.bin GCM payloads. */
    std::vector<uint8_t> insns_aes_key;
    /** 16-byte AES-128 key for assets/protector/dexes.zip (PDX1 wrapper). */
    std::vector<uint8_t> dex_aes_key;
    /** 16-byte AES-128 key wrapping sokeys.bin (PSOK). */
    std::vector<uint8_t> so_aes_key;
    /**
     * 16-byte AES-128 key for encrypted so_warm/ cache (PSW1).
     * Kept for process lifetime (hydrate + write); not wiped with so_aes_key.
     */
    std::vector<uint8_t> so_warm_key;
    /** 16-byte AES-128 key for PAS1 encrypted app assets (protector/aenc). */
    std::vector<uint8_t> assets_aes_key;
    /** 32-byte HMAC-SHA256 key for config.json. */
    std::vector<uint8_t> hmac_key;
    /** Manifest package from config.json (HKDF info); must match JNI package. */
    std::string package_name;
    /**
     * Bitmask of FLAG_DISABLE_* from risk.h.
     * Default 48 = disable Root(16)+Emulator(32) until config.json loads.
     */
    std::atomic<int> risk_flags{48};
    /** How to react when a detector fires. Default Block. */
    std::atomic<int> rasp_action{static_cast<int>(RaspAction::Block)};
    /** Lowercase hex SHA-256 of APK signing cert; empty = fail closed. */
    std::string app_sign_sha256;
    /** Packer wrote sokeys.bin (--protect-so); missing keys at init is fatal. */
    bool protect_so = false;
    /** Packer encrypted business assets (--encrypt-assets). */
    bool encrypt_assets = false;
    /**
     * From config.json {@code so_decrypt_mode}; missing field → Eager.
     * Lazy skips full cold-start materialize (on-demand keyed DT_NEEDED closure).
     */
    SoDecryptMode so_decrypt_mode = SoDecryptMode::Eager;
    /**
     * From config.json {@code so_diag}; missing → false.
     * Enables [XOP-SO] load/materialize diagnostics in Release.
     */
    bool so_diag = false;
    /**
     * Max decrypted TRUE_VMP images kept in memory (config.json {@code vmp_lru}).
     * Default 32. Missing field → 32.
     */
    int vmp_lru = 32;
    /** HMAC-SHA256 hex of APK PDX1 {@code dexes.zip} bytes ({@code config.dex_hmac}). */
    std::string dex_hmac;
    /** HMAC-SHA256 hex of {@code code.bin} file bytes ({@code config.code_hmac}). */
    std::string code_hmac;
    /**
     * HMAC-SHA256 hex of the canonical hollow/VMP method set
     * ({@code config.code_methods_hmac}): LE count + sorted (dex, method_idx, flags).
     */
    std::string code_methods_hmac;
    /** ABI → HMAC-SHA256 hex of post-wipe in-memory {@code .bitcode}. */
    std::unordered_map<std::string, std::string> bitcode_hmac;
};

struct RuntimeState {
    ShellConfig config;
    // dex_index -> method_idx -> CodeItem*
    std::unordered_map<int, std::unordered_map<uint32_t, CodeItem*>> code_map;
    std::vector<uint8_t> code_blob; // owns CodeItem::insns memory
    std::string dexes_zip_path;
    std::string code_bin_path;
    std::mutex mutex;
    std::atomic_bool inited{false};
    /** Set when rasp_action=Degrade and a detector fired. */
    std::atomic_bool environment_degraded{false};
    int sdk_level = 0;
    /** ApplicationInfo.sourceDir (base APK) for native signing-block parse. */
    std::string apk_path;
    /** Context package name; used by later key derivation. */
    std::string app_package;
};

RuntimeState& runtime_state();

} // namespace protector
