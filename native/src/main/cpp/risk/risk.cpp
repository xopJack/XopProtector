#include "risk/risk.h"
#include "risk/so_guard.h"
#include "report/threat_report.h"
#include "common/crc32.h"
#include "common/elf_util.h"
#include "common/log.h"
#include "common/obfuscate.h"
#include "common/runtime_state.h"
#include "common/protector_macro.h"
#include "common/va_tag.h"
#include "vm/pvm2_interp.h"

#include <atomic>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <android/api-level.h>
#endif

namespace protector::risk {

static std::atomic_bool g_started{false};
static std::atomic_int g_delayed_crash{0};
static std::atomic_int g_delayed_integrity_exit{0};
static std::atomic_int64_t g_last_heartbeat_ms{0};
static std::atomic_int64_t g_heartbeat_armed_ms{0};
// Set immediately before crash_* so logcat shows which detector fired.
static const char* g_crash_reason = "unknown";

void mark_environment_degraded() {
    runtime_state().environment_degraded.store(true, std::memory_order_release);
    protector::vm::clear_true_vmp_lru();
}

PROTECTOR_ENCRYPT void handle_risk(const char* reason, CrashKind kind) {
#if PROTECTOR_SRC_OBF
    volatile int st = 0;
    const char* r = nullptr;
    int action = 0;
    const char* kind_s = "block";
    PROTECTOR_CFF_BEGIN(st)
    PROTECTOR_CFF_CASE(0) {
        PROTECTOR_BCF_SINK();
        r = reason != nullptr ? reason : "unknown";
        g_crash_reason = r;
        PROTECTOR_CFF_GOTO(st, 1);
    }
    PROTECTOR_CFF_CASE(1) {
        action = runtime_state().config.rasp_action.load(std::memory_order_relaxed);
        protector::report::report_threat(r, action);
        if (action == static_cast<int>(protector::RaspAction::Alert)) {
            PLOGE("rasp alert: %s (no crash)", r);
            PROTECTOR_CFF_FINISH(st);
        } else {
            PROTECTOR_CFF_GOTO(st, 2);
        }
    }
    PROTECTOR_CFF_CASE(2) {
        if (action == static_cast<int>(protector::RaspAction::Degrade)) {
            PLOGE("rasp degrade: %s", r);
            mark_environment_degraded();
            PROTECTOR_CFF_FINISH(st);
        } else {
            PROTECTOR_CFF_GOTO(st, 3);
        }
    }
    PROTECTOR_CFF_CASE(3) {
        switch (kind) {
            case CrashKind::SigIll: kind_s = "sigill"; break;
            case CrashKind::SigSegv: kind_s = "sigsegv"; break;
            case CrashKind::Abort: kind_s = "abort"; break;
            case CrashKind::Hang: kind_s = "hang"; break;
            case CrashKind::Exit: kind_s = "exit"; break;
        }
        protector::report::write_crash_reason(r, kind_s);
        PLOGE("rasp block: %s", r);
        PROTECTOR_CFF_GOTO(st, 4);
    }
    PROTECTOR_CFF_CASE(4) {
        PROTECTOR_BCF_SINK();
        switch (kind) {
            case CrashKind::SigIll: crash_sigill(); break;
            case CrashKind::SigSegv: crash_sigsegv(); break;
            case CrashKind::Abort: crash_abort(); break;
            case CrashKind::Hang: crash_hang(); break;
            case CrashKind::Exit: crash_exit(); break;
        }
        PROTECTOR_CFF_FINISH(st);
    }
    PROTECTOR_CFF_END(st);
#else
    const char* r = reason != nullptr ? reason : "unknown";
    g_crash_reason = r;
    int action = runtime_state().config.rasp_action.load(std::memory_order_relaxed);
    protector::report::report_threat(r, action);
    if (action == static_cast<int>(protector::RaspAction::Alert)) {
        PLOGE("rasp alert: %s (no crash)", r);
        return;
    }
    if (action == static_cast<int>(protector::RaspAction::Degrade)) {
        PLOGE("rasp degrade: %s", r);
        mark_environment_degraded();
        return;
    }
    const char* kind_s = "block";
    switch (kind) {
        case CrashKind::SigIll: kind_s = "sigill"; break;
        case CrashKind::SigSegv: kind_s = "sigsegv"; break;
        case CrashKind::Abort: kind_s = "abort"; break;
        case CrashKind::Hang: kind_s = "hang"; break;
        case CrashKind::Exit: kind_s = "exit"; break;
    }
    protector::report::write_crash_reason(r, kind_s);
    PLOGE("rasp block: %s", r);
    switch (kind) {
        case CrashKind::SigIll: crash_sigill(); break;
        case CrashKind::SigSegv: crash_sigsegv(); break;
        case CrashKind::Abort: crash_abort(); break;
        case CrashKind::Hang: crash_hang(); break;
        case CrashKind::Exit: crash_exit(); break;
    }
#endif
}

#define CRASH_SEGV(reason) handle_risk((reason), CrashKind::SigSegv)
#define CRASH_ILL(reason) handle_risk((reason), CrashKind::SigIll)

static int64_t now_ms() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

// ═══════════════════════════════════════════════════════════════════
// Diverse crash paths — each in .bitcode, each uses a different
// mechanism so no single NOP can disarm all protections.
// ═══════════════════════════════════════════════════════════════════

PROTECTOR_ENCRYPT void crash_sigill() {
#ifdef DEBUG
    PLOGE("risk: sigill reason=%s", g_crash_reason);
    abort();
#else
    __android_log_print(ANDROID_LOG_ERROR, "protector.risk", "sigill reason=%s", g_crash_reason);
    // udf/#0 on arm64 → SIGILL; attacker can catch but not easily resume
    __builtin_trap();
#endif
}

PROTECTOR_ENCRYPT void crash_sigsegv() {
#ifdef DEBUG
    PLOGE("risk: sigsegv reason=%s", g_crash_reason);
    abort();
#else
    __android_log_print(ANDROID_LOG_ERROR, "protector.risk", "sigsegv reason=%s", g_crash_reason);
    // Null deref → SIGSEGV. Different signal, different handler bypass.
    volatile int* p = nullptr;
    *p = 0xDEAD;
    // If we somehow survive, force a trap
    __builtin_trap();
#endif
}

PROTECTOR_ENCRYPT void crash_abort() {
    // Always use real abort() — generates SIGABRT with a distinct
    // tombstone backtrace that doesn't point back to detection code.
    PLOGE("risk: abort");
    abort();
}

PROTECTOR_ENCRYPT void crash_hang() {
    PLOGE("risk: hang");
    // Busy-loop → ANR / watchdog kill. Avoid libc sleep/usleep — easily hooked.
    // Yield via sched_yield only periodically so we do not trip thermal kill as fast.
    while (true) {
        volatile int sink = 0;
        for (int i = 0; i < 2000000; ++i) {
            sink = sink + i;
        }
        (void)sink;
        sched_yield();
    }
}

PROTECTOR_ENCRYPT void crash_exit() {
    // Clean _exit: no tombstone, no crash log, process just disappears.
    // Much harder to diagnose than a signal.
    _exit(1);
}

PROTECTOR_ENCRYPT void schedule_delayed_crash() {
    g_delayed_crash.store(1, std::memory_order_release);
}

void schedule_integrity_exit() {
    g_delayed_integrity_exit.store(1, std::memory_order_release);
}

PROTECTOR_ENCRYPT void check_delayed_crash() {
    if (g_delayed_integrity_exit.load(std::memory_order_acquire)) {
        PLOGE("integrity: delayed crash_exit");
        crash_exit();
        return;
    }
    if (!g_delayed_crash.load(std::memory_order_acquire)) return;
    // Honour Alert: never crash from a previously scheduled delay either.
    int action = runtime_state().config.rasp_action.load(std::memory_order_relaxed);
    if (action == static_cast<int>(protector::RaspAction::Alert)) {
        g_delayed_crash.store(0, std::memory_order_release);
        PLOGE("rasp alert: delayed crash suppressed");
        return;
    }
    if (action == static_cast<int>(protector::RaspAction::Degrade)) {
        g_delayed_crash.store(0, std::memory_order_release);
        mark_environment_degraded();
        PLOGE("rasp degrade: delayed crash → degraded flag");
        return;
    }
    g_crash_reason = "delayed";
    crash_sigill();
}

PROTECTOR_ENCRYPT void crash_on_risk() {
    crash_sigill();
}

void record_java_heartbeat() {
    g_last_heartbeat_ms.store(now_ms(), std::memory_order_release);
}

void arm_java_heartbeat() {
    int64_t now = now_ms();
    int64_t expected = 0;
    g_heartbeat_armed_ms.compare_exchange_strong(expected, now, std::memory_order_acq_rel);
}

/** After the first valid ping, Java must keep pinging. */
static constexpr int64_t kHeartbeatKeepaliveMs = 15000;
/**
 * init_app arms before DexMerger / SO decrypt (ACF FileBootstrap especially).
 * That work can exceed 15 s on a cold protect-so launch; 15 s still applies
 * after the first legal ping.
 */
static constexpr int64_t kHeartbeatFirstPingMs = 90000;

/** Check if Java-layer heartbeat is still arriving. */
static void check_heartbeat() {
    int64_t armed = g_heartbeat_armed_ms.load(std::memory_order_acquire);
    if (armed == 0) return;  // init_app not reached (no protect assets)
    int64_t last = g_last_heartbeat_ms.load(std::memory_order_acquire);
    int64_t now = now_ms();
    if (last == 0) {
        int64_t elapsed = now - armed;
        if (elapsed > kHeartbeatFirstPingMs) {
            PLOGE("Java heartbeat never arrived (%lld ms after init_app)", (long long)elapsed);
            handle_risk("java_heartbeat", CrashKind::Abort);
        }
        return;
    }
    int64_t elapsed = now - last;
    if (elapsed > kHeartbeatKeepaliveMs) {
        PLOGE("Java heartbeat lost (%lld ms)", (long long)elapsed);
        handle_risk("java_heartbeat", CrashKind::Abort);
    }
}

// ── Enhanced Frida detection ───────────────────────────────────────

/** Check if Frida's default TCP ports are reachable. */
static bool frida_port_open() {
    static const uint16_t kPorts[] = {27042, 27043, 0};
    for (int i = 0; kPorts[i] != 0; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(kPorts[i]);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        struct timeval tv{0, 100000};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int rc = connect(sock, reinterpret_cast<const struct sockaddr*>(&addr), sizeof(addr));
        close(sock);
        if (rc == 0) return true;
    }
    return false;
}

/** Scan /proc/self/fd for Frida-related open file descriptors. */
static bool frida_fd_hits() {
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return false;
    bool found = false;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/fd/%s", ent->d_name);
        char link[256] = {0};
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if (n > 0) {
            link[n] = 0;
            if (strstr(link, OBSC_DECODE("\x3c\x33\x05\x6f\x57")) ||
                strstr(link, OBSC_DECODE("\x36\x28\x02\x61\x53\xbe\x8c\x88\xf0")) ||
                strstr(link, OBSC_DECODE("\x3d\x34\x01\x26\x5c\xae"))) {
                found = true;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

// ── Enhanced anti-debugging ────────────────────────────────────────

/** ptrace(PTRACE_TRACEME) self-attach.  If it fails we are already
 *  being traced.  On success our own process becomes the tracer,
 *  blocking other debuggers from attaching. */
static void detect_ptrace_self() {
    // PTRACE_TRACEME is unreliable on modern Android (SELinux / YAMA often
    // return EPERM with no debugger attached, and some OEMs leave a
    // non-parent TracerPid). Rely on TracerPid + /proc/self/stat instead.
    (void)0;
}

/**
 * State character from /proc/self/stat.
 * comm is "(name)" and may contain spaces, so scan to the last ')' —
 * fields after comm are numeric and do not contain ')'.
 * Returns 0 when the file cannot be read.
 */
static char read_self_stat_state() {
    FILE* fp = fopen("/proc/self/stat", "r");
    if (!fp) return 0;
    char buf[512];
    if (fgets(buf, sizeof(buf), fp) == nullptr) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    char* end = strrchr(buf, ')');
    if (end == nullptr || end[1] == '\0') return 0;
    char* p = end + 1;
    while (*p == ' ') ++p;
    return *p;
}

/** Real uid of pid from /proc/pid/status. False when unreadable. */
static bool read_proc_uid(int pid, int* uid_out) {
    if (pid <= 0 || uid_out == nullptr) return false;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE* fp = fopen(path, "r");
    if (!fp) return false;
    char line[256];
    bool ok = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strncmp(line, "Uid:", 4) == 0) {
            int uid = -1;
            if (sscanf(line + 4, "%d", &uid) == 1 && uid >= 0) {
                *uid_out = uid;
                ok = true;
            }
            break;
        }
    }
    fclose(fp);
    return ok;
}

/**
 * OEM security scanners (any vendor) attach briefly as a system uid.
 * AID_SHELL (2000) is adb/gdb and stays hostile.
 */
static bool is_system_tracer(int pid) {
    int uid = -1;
    if (!read_proc_uid(pid, &uid)) return false;
    if (uid == 2000) return false;
    return uid < 10000;
}

/** TracerPid that is not self or parent. 0 when absent or ignored. */
static int read_foreign_tracer_pid() {
    FILE* fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    int tracer_pid = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            sscanf(line + 10, "%d", &tracer_pid);
            break;
        }
    }
    fclose(fp);
    if (tracer_pid == 0 || tracer_pid == getpid() || tracer_pid == getppid()) {
        return 0;
    }
    return tracer_pid;
}

/** Timing anomaly: a debugger single-stepping causes large delays in
 *  trivial loops.  Schedules a delayed crash rather than crashing now
 *  (the delay itself is evidence, so crashing immediately would give
 *   the attacker a precise location to patch). */
static void detect_timing_anomaly() {
    struct timespec t1{}, t2{};
    clock_gettime(CLOCK_MONOTONIC, &t1);
    volatile int x = 0;
    for (int i = 0; i < 2000; ++i) x += i;
    (void)x;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);
    // 30 ms for 2000 iterations is already generous.
    if (ns > 30000000L) {
        PLOGD("timing anomaly: %ld ns (expected < 1 ms)", ns);
        handle_risk("timing_anomaly", CrashKind::SigIll);
    }
}

// ── Original detection (retained & enhanced) ────────────────────────

static bool maps_has_frida() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, OBSC_DECODE("\x3c\x33\x05\x6f\x57")) != nullptr // frida
            || strstr(line, OBSC_DECODE("\x3d\x34\x01\x26\x5c\xae")) != nullptr // gum-js
            || strstr(line, OBSC_DECODE("\x36\x28\x02\x61\x53\xbe\x8c\x88\xf0")) != nullptr // linjector
            || strstr(line, OBSC_DECODE("\x3c\x33\x05\x6f\x57\xf0\x99\x80\xe7\xc7\x20")) != nullptr // frida-agent
            || strstr(line, "frida-gadget") != nullptr
            || strstr(line, "re.frida.server") != nullptr) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

/** Common native hook frameworks (maps basename hits). */
static bool maps_has_hook_framework() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, "libsubstrate")
            || strstr(line, "libsandhook")
            || strstr(line, "libepic.so")
            || strstr(line, "libyahfa")
            || strstr(line, "libwhale.")
            || strstr(line, "liband64inlinehook")
            || strstr(line, "libhookzz")
            || strstr(line, "libxhook.so")) {
            found = true;
            break;
        }
        // Standalone libbhook.so is suspicious (ours is static-linked).
        if (strstr(line, "libbhook.so") != nullptr) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

/** Frida often exposes abstract unix sockets; scan /proc/net/unix. */
static bool frida_unix_socket_hits() {
    FILE* fp = fopen("/proc/net/unix", "r");
    if (!fp) return false;
    char line[512];
    bool found = false;
    (void)fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "frida") || strstr(line, "gum-js")) {
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static bool frida_tmp_files() {
    return access("/data/local/tmp/frida-server", F_OK) == 0
           || access("/data/local/tmp/re.frida.server", F_OK) == 0;
}

/**
 * Inline-hook fingerprint: ARM64 B/BL at the start of critical libc exports.
 * Android 10+ may map libc .text execute-only (XOM); a plain load faults with
 * SEGV_ACCERR. Read via process_vm_readv which is allowed for XOM pages.
 */
static bool safe_read_u32(const void* addr, uint32_t* out) {
    if (addr == nullptr || out == nullptr) return false;
    addr = untag_ptr(addr);
#if defined(__ANDROID__)
    struct iovec local{out, sizeof(uint32_t)};
    struct iovec remote{const_cast<void*>(addr), sizeof(uint32_t)};
    ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (n == static_cast<ssize_t>(sizeof(uint32_t))) {
        return true;
    }
#endif
    // Pre-XOM / non-Android fallback — may SIGSEGV on API≥29 aarch64 if used.
#if defined(__aarch64__) && defined(__ANDROID__)
    if (android_get_device_api_level() >= 29) {
        return false;
    }
#endif
    *out = *reinterpret_cast<const uint32_t*>(addr);
    return true;
}

static bool libc_export_hooked(void* fn) {
    if (fn == nullptr) return false;
    uint32_t w = 0;
    if (!safe_read_u32(fn, &w)) return false;
#ifdef __aarch64__
    if ((w & 0xFC000000u) == 0x14000000u) return true; // B
    if ((w & 0xFC000000u) == 0x94000000u) return true; // BL
    if ((w & 0xFFE0001Fu) == 0xD4200000u) return true; // BRK #imm
#elif defined(__arm__)
    if ((w & 0xFF000000u) == 0xEA000000u) return true; // B
#endif
    return false;
}

static void* libc_sym(const char* name) {
    // Prefer already-loaded libc; RTLD_DEFAULT is fine for these exports.
    return dlsym(RTLD_DEFAULT, name);
}

static int libc_hook_score() {
    int score = 0;
    if (libc_export_hooked(libc_sym("fopen"))) score++;
    if (libc_export_hooked(libc_sym("open"))) score++;
    if (libc_export_hooked(libc_sym("connect"))) score++;
    if (libc_export_hooked(libc_sym("read"))) score++;
    return score;
}

static int frida_thread_hits() {
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return 0;
    int hits = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", ent->d_name);
        FILE* fp = fopen(path, "r");
        if (!fp) continue;
        char comm[64] = {0};
        if (fgets(comm, sizeof(comm), fp) != nullptr) {
            size_t n = strlen(comm);
            if (n > 0 && comm[n - 1] == '\n') comm[n - 1] = 0;
            // Do NOT match generic GLib names (gmain/gdbus) — common on MIUI/OEM
            // processes and cause false positives. Keep Frida-specific markers only.
            if (strcmp(comm, OBSC_DECODE("\x3d\x34\x01\x26\x5c\xae\xd5\x8b\xed\xc6\x24")) == 0 // gum-js-loop
                || strstr(comm, OBSC_DECODE("\x3c\x33\x05\x6f\x57")) != nullptr // frida
                || strcmp(comm, OBSC_DECODE("\x2a\x2e\x03\x67\x1b\xbb\x8a\x8e\xe6\xc8")) == 0) { // pool-frida
                hits++;
            }
        }
        fclose(fp);
    }
    closedir(dir);
    return hits;
}

static void detect_frida() {
    PROTECTOR_BCF_SINK();
    int score = 0;
    if (PROTECTOR_BCF_ALWAYS() && frida_port_open()) {
        PLOGD("frida port open");
        CRASH_SEGV("frida_port");
        return;
    }
    if (maps_has_frida()) {
        PLOGD("frida so/maps hit");
        CRASH_SEGV("frida_maps");
        return;
    }
    if (PROTECTOR_BCF_NEVER()) {
        score = 99;
    }
    if (frida_unix_socket_hits()) score += 2;
    if (frida_tmp_files()) score += 1;
    int thr = frida_thread_hits();
    if (thr >= 1) score += thr;
    if (frida_fd_hits()) score += 2;
    if (maps_has_hook_framework()) {
        PLOGD("hook framework in maps");
        CRASH_SEGV("hook_framework");
        return;
    }
    int hook_score = libc_hook_score();
    if (hook_score >= 2) {
        PLOGD("libc inline-hook score=%d", hook_score);
        CRASH_ILL("libc_inline_hook");
        return;
    }
    score += hook_score;
    // Cross-source: weak signals alone are ignored; combined → risk.
    if (score >= 3) {
        PLOGD("frida composite score=%d", score);
        CRASH_SEGV("frida_composite");
    }
}

void scan_hooks_and_frida_now() {
    int flags = runtime_state().config.risk_flags.load(std::memory_order_relaxed);
    if ((flags & FLAG_DISABLE_FRIDA_DETECT) == 0) {
        detect_frida();
    }
    if ((flags & FLAG_DISABLE_CRC_DETECT) == 0) {
        // libc .text CRC defined below — call via forward; verify later in thread if not ready
    }
    so_guard_check();
}

bool vmp_allowed() {
    auto& state = runtime_state();
    if (so_guard_integrity_failed()) {
        return false;
    }
    if (state.environment_degraded.load(std::memory_order_acquire)) {
        return false;
    }
    // Periodic SO pulse (every 64th TRUE_VMP call): HMAC + maps live here, not
    // on every interpret (full .bitcode HMAC is too expensive for the UI thread).
    static std::atomic<uint32_t> tick{0};
    uint32_t n = tick.fetch_add(1, std::memory_order_relaxed);
    if ((n & 63u) == 0u) {
        int flags = state.config.risk_flags.load(std::memory_order_relaxed);
        if ((flags & FLAG_DISABLE_SO_INTEGRITY) == 0) {
            so_guard_check();
        }
        if (so_guard_integrity_failed()
                || state.environment_degraded.load(std::memory_order_acquire)) {
            return false;
        }
    }
    return true;
}

static void detect_debugger() {
    // Multi-source: TracerPid, stat, ptrace self-attach, timing.
    // System-uid tracers (phone security scan on any OEM) are ignored.
    // A non-system attach must still be present on the next loop (~2–5 s)
    // before we crash, so a one-shot scan does not kill the process.
    int tracer_pid = read_foreign_tracer_pid();
    bool system_tracer = tracer_pid > 0 && is_system_tracer(tracer_pid);
    if (system_tracer) {
        PLOGD("ignore system tracer pid=%d", tracer_pid);
        tracer_pid = 0;
    }

    char state = read_self_stat_state();
    bool stat_traced = (state == 't' || state == 'T');
    // 't' from a system scanner is the same short attach — not a debugger.
    if (system_tracer) stat_traced = false;

    const char* reason = nullptr;
    int hit_key = 0;
    if (tracer_pid > 0) {
        reason = "tracer_pid";
        hit_key = tracer_pid;
    } else if (stat_traced) {
        reason = "stat_traced";
        hit_key = -1;
    }

    static int s_streak = 0;
    static int s_last_key = 0;
    if (reason == nullptr) {
        s_streak = 0;
        s_last_key = 0;
    } else if (hit_key == s_last_key) {
        s_streak++;
    } else {
        s_streak = 1;
        s_last_key = hit_key;
    }

    if (reason != nullptr && s_streak >= 2) {
        PLOGD("debugger persist reason=%s tracer=%d state='%c' streak=%d",
              reason, tracer_pid, state != 0 ? state : '?', s_streak);
        CRASH_SEGV(reason);
    }

    detect_ptrace_self();
    detect_timing_anomaly();
}

/** Compare on-disk libc .text CRC with in-memory mapping (anti-hook). */
static void verify_libc_text_crc() {
    Dl_info info{};
    if (dladdr(reinterpret_cast<const void*>(&fopen), &info) == 0
        || info.dli_fbase == nullptr) {
        PLOGW("dladdr libc failed, skip text crc");
        return;
    }

    std::string libc_path;
    if (info.dli_fname != nullptr) {
        if (info.dli_fname[0] == '/') {
            libc_path.assign(info.dli_fname);
        } else {
            libc_path = find_so_path(info.dli_fname);
        }
    }
    if (libc_path.empty()) {
        libc_path = find_so_path("libc.so");
    }
    if (libc_path.empty()) {
        PLOGW("cannot resolve libc path, skip text crc");
        return;
    }

    Elf_Shdr shdr{};
    get_elf_section(&shdr, libc_path.c_str(), ".text");
    if (shdr.sh_size == 0) {
        PLOGW("libc .text missing, skip text crc");
        return;
    }

    FILE* fp = fopen(libc_path.c_str(), "rb");
    if (!fp) {
        PLOGW("cannot open libc: %s", libc_path.c_str());
        return;
    }
    if (fseek(fp, static_cast<long>(shdr.sh_offset), SEEK_SET) != 0) {
        fclose(fp);
        return;
    }

    auto* file_buf = static_cast<uint8_t*>(malloc(shdr.sh_size));
    if (!file_buf) {
        fclose(fp);
        return;
    }
    size_t nread = fread(file_buf, 1, shdr.sh_size, fp);
    fclose(fp);
    if (nread != shdr.sh_size) {
        free(file_buf);
        PLOGW("fread libc .text incomplete");
        return;
    }

    uint32_t crc_file = 0;
    uint32_t crc_mem = 0;
    size_t remaining = shdr.sh_size;
    size_t offset = 0;
    const auto* mem_base = untag_ptr(
            reinterpret_cast<const uint8_t*>(info.dli_fbase) + shdr.sh_addr);
    // Android 10+ XOM: cannot load from .text; process_vm_readv into a scratch page.
    constexpr size_t kChunk = 4096;
    uint8_t scratch[kChunk];
    while (remaining > 0) {
        size_t chunk = remaining > kChunk ? kChunk : remaining;
        crc_file = crc32_update(crc_file, file_buf + offset, chunk);
#if defined(__ANDROID__)
        struct iovec local{scratch, chunk};
        struct iovec remote{const_cast<uint8_t*>(mem_base + offset), chunk};
        ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (n != static_cast<ssize_t>(chunk)) {
            free(file_buf);
            PLOGW("libc .text XOM read failed at off=%zu errno=%d — skip crc",
                  offset, errno);
            return;
        }
        crc_mem = crc32_update(crc_mem, scratch, chunk);
#else
        crc_mem = crc32_update(crc_mem, mem_base + offset, chunk);
#endif
        offset += chunk;
        remaining -= chunk;
    }
    free(file_buf);

    PLOGD("libc .text crc file=%08x mem=%08x size=%u", crc_file, crc_mem,
          static_cast<unsigned>(shdr.sh_size));
    if (crc_file != crc_mem) {
        // OEM (HyperOS/ColorOS/…) often remap or patch libc .text; file≠mem is
        // a weak signal alone. Do not Block — rely on libc_export_hooked /
        // Frida composite. Log for telemetry when CRC detect is explicitly on.
        PLOGW("libc .text crc mismatch file=%08x mem=%08x (fail-open, no crash)",
              crc_file, crc_mem);
    }
}

// ── Xposed / LSPosed detection ─────────────────────────────────────

static bool maps_has_xposed() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, OBSC_DECODE("\x22\x31\x03\x78\x53\xb9")) || // xposed
            strstr(line, OBSC_DECODE("\x02\x31\x03\x78\x53\xb9\xba\x95\xeb\xcd\x33\x16")) || // XposedBridge
            strstr(line, OBSC_DECODE("\x36\x32\x1c\x64\x45\xb8\x9c")) || // lsposed
            strstr(line, OBSC_DECODE("\x16\x12\x3c\x64\x45\xb8\x9c")) || // LSPosed
            strstr(line, OBSC_DECODE("\x3f\x25\x14\x7b\x59\xae\x9d\x83")) || // edxposed
            strstr(line, OBSC_DECODE("\x1f\x25\x34\x7b\x59\xae\x9d\x83"))) { // EdXposed
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

static bool xposed_class_present() {
    // Check for XposedBridge class being loaded — only if we have a JVM.
    // We use a weak check via dlsym to avoid hard dependency on JNI here.
    // The class check happens via the risk thread which may not have JNI env.
    // Fallback: check common Xposed JAR paths on disk.
    static const char* kPaths[] = {
        "/system/framework/XposedBridge.jar",
        "/system/framework/lsposed",
        "/data/local/tmp/xposed",
        nullptr
    };
    for (int i = 0; kPaths[i]; i++) {
        if (access(kPaths[i], F_OK) == 0) {
            return true;
        }
    }
    return false;
}

static void detect_xposed() {
    if (maps_has_xposed()) {
        PLOGD("xposed in maps");
        CRASH_SEGV("xposed_maps");
    }
    if (xposed_class_present()) {
        PLOGD("xposed files present");
        CRASH_SEGV("xposed_files");
    }
}

// ── Root / Magisk detection ────────────────────────────────────────

static bool root_binaries_found() {
    // Paths decoded via OBSC so `strings` on the SO does not list them plainly.
    if (access(OBSC_DECODE("\x75\x32\x15\x78\x42\xb8\x95\xc8\xe0\xc0\x3a\x5c\x6d\x70"), F_OK) == 0 // /system/bin/su
        || access(OBSC_DECODE("\x75\x32\x0e\x62\x58\xf2\x95\x86\xe5\xc0\x27\x18"), F_OK) == 0 // /sbin/magisk
        || access(OBSC_DECODE("\x75\x25\x0d\x7f\x57\xf2\x99\x83\xe0\x86\x39\x12\x79\x6c\x53\xa4"), F_OK) == 0 // /data/adb/magisk
        || access(OBSC_DECODE("\x75\x25\x0d\x7f\x57\xf2\x99\x83\xe0\x86\x39\x1c\x7a\x70\x4c\xaa\x99"), F_OK) == 0) { // /data/adb/modules
        return true;
    }
    static const char* kSuPaths[] = {
        "/system/xbin/su",
        "/sbin/su",
        "/system/sbin/su",
        "/vendor/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/app/SuperSU",
        "/system/app/Superuser",
        "/system/app/Superuser.apk",
        "/cache/.disable_magisk",
        nullptr
    };
    for (int i = 0; kSuPaths[i]; i++) {
        if (access(kSuPaths[i], F_OK) == 0) {
            PLOGD("root binary hit");
            return true;
        }
    }
    return false;
}

static void detect_root() {
    if (root_binaries_found()) {
        CRASH_SEGV("root");
    }
}

// ── Emulator detection ─────────────────────────────────────────────

static bool is_emulator() {
    int hits = 0;
    if (access(OBSC_DECODE("\x75\x25\x09\x7d\x19\xae\x97\x84\xe9\xcc\x20\x5c\x6f\x60\x4d\xba\x8e"), F_OK) == 0) hits++; // /dev/socket/qemud
    if (access(OBSC_DECODE("\x75\x25\x09\x7d\x19\xac\x9d\x8a\xf7\xf6\x24\x1a\x6e\x60"), F_OK) == 0) hits++; // /dev/qemu_pipe
    static const char* kEmuMarkers[] = {
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        nullptr
    };
    for (int i = 0; kEmuMarkers[i]; i++) {
        if (access(kEmuMarkers[i], F_OK) == 0) hits++;
    }
    // One hit might be coincidence; two is likely an emulator.
    if (hits >= 2) {
        PLOGD("emulator markers: %d", hits);
        return true;
    }
    return false;
}

static void detect_emulator() {
    if (is_emulator()) {
        CRASH_SEGV("emulator");
    }
}

// ── Background thread ──────────────────────────────────────────────

static void* risk_thread_main(void*) {
    // Run Xposed / root / emulator checks only once on first iteration —
    // these can't appear mid-process.
    bool ran_one_shot = false;
    while (true) {
        int flags = runtime_state().config.risk_flags.load(std::memory_order_relaxed);
        bool need_frida = (flags & FLAG_DISABLE_FRIDA_DETECT) == 0;
        bool need_crc = (flags & FLAG_DISABLE_CRC_DETECT) == 0;
        bool need_dbg = (flags & FLAG_DISABLE_ANTI_DEBUG) == 0;
        bool need_xposed = (flags & FLAG_DISABLE_XPOSED_DETECT) == 0;
        bool need_root = (flags & FLAG_DISABLE_ROOT_DETECT) == 0;
        bool need_emu = (flags & FLAG_DISABLE_EMULATOR_DETECT) == 0;
        bool need_so = (flags & FLAG_DISABLE_SO_INTEGRITY) == 0;

        // One-shot environmental checks
        if (!ran_one_shot) {
            ran_one_shot = true;
            if (need_xposed) detect_xposed();
            if (need_root) detect_root();
            if (need_emu) detect_emulator();
        }

        if (need_frida) {
            detect_frida();
        }
        if (need_crc) {
            verify_libc_text_crc();
        }
        if (need_dbg) {
            detect_debugger();
        }
        if (need_so) {
            so_guard_check();
        }
        // Cross-layer integrity: Java shell must heartbeat periodically.
        check_heartbeat();
        // Honours delayed-crash requests from other protection layers.
        check_delayed_crash();
        // 2‒5 s with jitter — tighter than the original 10 s window.
        sleep(2 + (rand() % 3));
    }
    return nullptr;
}

void DefaultRiskChecker::start() {
    bool expected = false;
    if (!g_started.compare_exchange_strong(expected, true)) {
        return;
    }
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, risk_thread_main, nullptr) != 0) {
        g_started.store(false);
        PLOGW("risk thread create failed");
    } else {
        PLOGI("risk checker started");
    }
    pthread_attr_destroy(&attr);
}

RiskChecker& risk_checker() {
    static DefaultRiskChecker checker;
    return checker;
}

} // namespace protector::risk
