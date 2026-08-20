// =============================================================================
//  hwbp_internal.hpp - in-process hardware breakpoint hook engine (x64 Windows)
//
//  * Uses the four CPU debug address registers (DR0-DR3 + DR7) as "hooks".
//    No bytes of target code are modified, so nothing is visible to integrity
//    checks that scan for inline hooks or int3 (0xCC) patches.
//  * A first-order vectored exception handler catches the #DB single-step
//    faults and dispatches them to user callbacks with full read/write access
//    to the faulting thread's register state (CONTEXT).
//  * Debug registers are per-thread: a background sweeper keeps every thread
//    (including threads created after install) carrying the breakpoints.
//  * Optional stealth helpers:
//      - stealth::hide_debug_registers()  re-routes ntdll!NtGetContextThread
//        through a rebuilt syscall stub so CONTEXT_DEBUG_REGISTERS probes in
//        this process observe zeroed DR registers while the real ones stay
//        armed and functional.
//      - stealth::hide_self_module()      unlinks this module from the PEB
//        loader lists so module enumeration (CreateToolhelp32Snapshot,
//        GetModuleHandle, ...) no longer sees it.
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY. See README.md for the
//  (honest) list of what the stealth features do and do not conceal.
//
//  x64 Windows only. Do not call install() from DllMain (thread creation and
//  cross-thread suspension are not loader-lock safe).
// =============================================================================
#pragma once

#ifndef _WIN64
#error "hwbp_internal.hpp supports x64 only"
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>

#include <array>
#include <cstring>
#include <functional>
#include <mutex>
#include <utility>
#include <vector>

#include "hwbp_common.hpp"

namespace hwbp {

using Callback = std::function<void(CONTEXT*)>;

namespace detail {

inline LONG NTAPI veh_dispatch(PEXCEPTION_POINTERS ep);

constexpr DWORD kSweepPeriodMs = 200;

struct Slot {
    void* address = nullptr;
    BreakType type = BreakType::Execute;
    uint8_t length = 1;
    Callback callback;
    bool active = false;
};

// The complete debug-register image the engine wants on every thread.
struct DrState {
    uint64_t addr[kMaxBreakpoints] = {};
    uint64_t dr7 = 0;
};

inline std::vector<DWORD> current_process_thread_ids() {
    std::vector<DWORD> ids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return ids;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId())
                ids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ids;
}

// Push a debug-register image into a (suspended) thread. Note that once
// stealth::hide_debug_registers() is active the GetThreadContext read inside
// comes back masked - that is fine, every field we care about is overwritten
// from `st` before SetThreadContext.
inline void write_state(HANDLE thread, const DrState& st) {
    CONTEXT c{};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &c)) return;
    c.Dr0 = st.addr[0];
    c.Dr1 = st.addr[1];
    c.Dr2 = st.addr[2];
    c.Dr3 = st.addr[3];
    c.Dr6 = 0;
    c.Dr7 = st.dr7;
    SetThreadContext(thread, &c);
}

// Suspend every thread of the current process except the calling one and
// apply the state. SetThreadContext requires a suspended target.
inline void apply_state_to_other_threads(const DrState& st) {
    const DWORD self = GetCurrentThreadId();
    for (DWORD tid : current_process_thread_ids()) {
        if (tid == self) continue;
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                              FALSE, tid);
        if (!h) continue;
        if (SuspendThread(h) != static_cast<DWORD>(-1)) {
            write_state(h, st);
            ResumeThread(h);
        }
        CloseHandle(h);
    }
}

// A thread cannot suspend itself, so for the current thread we hand the
// desired debug registers to the kernel directly; the values materialise in
// hardware on the next context switch in/out (which happens constantly).
inline void apply_state_to_current_thread_best_effort(const DrState& st) {
    write_state(GetCurrentThread(), st);
}

class Manager {
public:
    static Manager& instance() {
        static Manager* inst = new Manager();  // intentionally leaked: avoids
        return *inst;                          // teardown-order surprises
    }

    int install(const void* address, BreakType type, uint8_t length, const Callback& cb) {
        if (!address || !length_supported(type, length)) return -1;
        if (!address_aligned(reinterpret_cast<uint64_t>(address), type, length)) return -1;

        int slot = -1;
        {
            std::lock_guard<std::recursive_mutex> lk(mtx_);
            for (uint32_t i = 0; i < kMaxBreakpoints; ++i)
                if (!slots_[i].active) { slot = static_cast<int>(i); break; }
            if (slot < 0) return -1;
            slots_[slot].address = const_cast<void*>(address);
            slots_[slot].type = type;
            slots_[slot].length = length;
            slots_[slot].callback = cb;
            slots_[slot].active = true;
        }
        ensure_engine();   // VEH must be in place before any thread gets DRs armed
        refresh_threads();
        return slot;
    }

    bool uninstall(int slot) {
        if (slot < 0 || slot >= static_cast<int>(kMaxBreakpoints)) return false;
        {
            std::lock_guard<std::recursive_mutex> lk(mtx_);
            if (!slots_[slot].active) return false;
            slots_[slot] = Slot{};
        }
        refresh_threads();
        return true;
    }

    DrState compute_state() {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        DrState st;
        for (uint32_t i = 0; i < kMaxBreakpoints; ++i) {
            if (!slots_[i].active) continue;
            st.addr[i] = reinterpret_cast<uint64_t>(slots_[i].address);
            st.dr7 = dr7_enable_slot(st.dr7, i, slots_[i].type, slots_[i].length);
        }
        return st;
    }

    // Deterministic refresh: a short-lived helper thread performs the apply,
    // which suspends *this* thread too, so the caller itself walks away with
    // the registers armed instead of waiting for the next sweeper pass.
    void refresh_threads() {
        DrState st = compute_state();
        HANDLE done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!done) {
            apply_state_to_other_threads(st);
            apply_state_to_current_thread_best_effort(st);
            return;
        }
        RefreshCtx ctx{st, done};
        HANDLE h = CreateThread(nullptr, 0, refresh_thread_proc, &ctx, 0, nullptr);
        if (h) {
            WaitForSingleObject(done, INFINITE);
            CloseHandle(h);
        } else {
            apply_state_to_other_threads(st);
            apply_state_to_current_thread_best_effort(st);
        }
        CloseHandle(done);
    }

    void set_sweeper(bool enabled) {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        if (enabled) {
            ensure_engine();
            return;
        }
        if (sweeper_) {
            SetEvent(sweeper_wake_);
            CloseHandle(sweeper_);
            sweeper_ = nullptr;
        }
    }

    // public: the VEH reads slots_ under mtx_ (kept simple rather than friend-
    // decorating a dozen members)
    std::recursive_mutex mtx_;
    std::array<Slot, kMaxBreakpoints> slots_{};

private:
    struct RefreshCtx {
        DrState st;
        HANDLE done;
    };

    static DWORD WINAPI refresh_thread_proc(void* p) {
        RefreshCtx* c = static_cast<RefreshCtx*>(p);
        apply_state_to_other_threads(c->st);
        SetEvent(c->done);
        return 0;
    }

    void ensure_engine() {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        if (!veh_)
            veh_ = AddVectoredExceptionHandler(1, veh_dispatch);
        if (!sweeper_) {
            ResetEvent(sweeper_wake_);
            sweeper_ = CreateThread(nullptr, 0, sweep_proc, this, 0, nullptr);
        }
    }

    static DWORD WINAPI sweep_proc(void* p) {
        Manager* m = static_cast<Manager*>(p);
        for (;;) {
            DrState st = m->compute_state();
            apply_state_to_other_threads(st);                  // everyone but the sweeper
            apply_state_to_current_thread_best_effort(st);     // the sweeper itself
            if (WaitForSingleObject(m->sweeper_wake_, kSweepPeriodMs) == WAIT_OBJECT_0)
                break;
        }
        return 0;
    }

    void* veh_ = nullptr;
    HANDLE sweeper_ = nullptr;
    HANDLE sweeper_wake_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
};

// The heart of the engine. #DB faults surface here as EXCEPTION_SINGLE_STEP
// with the faulting thread's register state in the exception CONTEXT.
inline LONG NTAPI veh_dispatch(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    Manager& m = Manager::instance();
    CONTEXT* ctx = ep->ContextRecord;

    // Copy the callbacks out under the lock, then run them unlocked so user
    // code may freely call set()/remove() from inside a callback.
    Callback hits[kMaxBreakpoints];
    uint32_t count = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(m.mtx_);
        for (uint32_t i = 0; i < kMaxBreakpoints; ++i) {
            const Slot& s = m.slots_[i];
            if (!s.active) continue;
            const bool hit = (s.type == BreakType::Execute)
                                 ? (reinterpret_cast<uint64_t>(s.address) == ctx->Rip)
                                 : ((ctx->Dr6 & (1ull << i)) != 0);
            if (hit && count < kMaxBreakpoints) hits[count++] = s.callback;
        }
    }
    if (count == 0)
        return EXCEPTION_CONTINUE_SEARCH;  // not ours (e.g. trap-flag stepping)

    for (uint32_t i = 0; i < count; ++i) {
        try {
            hits[i](ctx);  // user callback: full read/write access to registers
        } catch (...) {    // a throw unwinding through the VEH would be fatal
        }
    }

    ctx->Dr6 = 0;              // clear the B0-B3 condition-hit status bits
    ctx->EFlags |= 0x10000;    // RF: bypass instruction breakpoints once on resume
    return EXCEPTION_CONTINUE_EXECUTION;
}

}  // namespace detail

// =============================================================================
//  Public API - internal (in-process) hook
// =============================================================================
class HwBpHook {
public:
    // `address`  target of the breakpoint (function entry for Execute).
    // `length`   watch window in bytes for Write/Access (1/2/4/8, aligned).
    // The callback receives the faulting thread's CONTEXT; mutate it freely
    // (Rcx/Rdx/R8/R9 hold the first four x64 arguments at function entry,
    // stack arguments start at [Rsp+0x28]).
    bool set(const void* address, BreakType type, uint8_t length, const Callback& cb) {
        slot_ = detail::Manager::instance().install(address, type, length, cb);
        return slot_ >= 0;
    }

    bool remove() {
        if (slot_ < 0) return false;
        const bool ok = detail::Manager::instance().uninstall(slot_);
        slot_ = -1;
        return ok;
    }

    int slot() const { return slot_; }

    // Manually push the current breakpoint set onto all threads (the engine
    // also does this automatically via the background sweeper).
    static void refresh_threads() { detail::Manager::instance().refresh_threads(); }

    // The sweeper re-arms breakpoints on threads created after install.
    // Disable it if the 200 ms periodic thread suspension is unwanted.
    static void set_auto_thread_watch(bool enabled) {
        detail::Manager::instance().set_sweeper(enabled);
    }

    HwBpHook() = default;
    ~HwBpHook() { remove(); }
    HwBpHook(const HwBpHook&) = delete;
    HwBpHook& operator=(const HwBpHook&) = delete;

private:
    int slot_ = -1;
};

// =============================================================================
//  Stealth helpers
// =============================================================================
namespace stealth {

bool hide_debug_registers();
bool restore_debug_registers();
void hide_self_module();

// ---------------------------------------------------------------------------
//  Register hiding: hook ntdll!NtGetContextThread.
//
//  ntdll syscall stubs start with   mov r10, rcx        4C 8B D1
//                                  mov eax, <ssn>       B8 xx xx xx xx
//                                  syscall              0F 05
//  so the service number can be lifted out and a *clean* stub rebuilt in
//  private memory. The detour calls that rebuilt stub (never re-entering the
//  patched bytes), and zeroes DR0-DR7 in any returned CONTEXT that asked for
//  debug registers. The real registers stay armed and the hooks keep firing.
// ---------------------------------------------------------------------------
namespace reg_hide {

using NtGetContextThreadFn = LONG(NTAPI*)(HANDLE, PCONTEXT);

struct RegHookState {
    uint8_t* target = nullptr;
    uint8_t* view_rw = nullptr;  // same section, writable view (build)
    uint8_t* view_rx = nullptr;  // same section, executable view (run)
    uint8_t saved[14] = {};
    NtGetContextThreadFn original = nullptr;
    bool active = false;
};
inline RegHookState g_reg_hook;

inline LONG NTAPI nt_get_context_thread_detour(HANDLE thread, PCONTEXT context) {
    const LONG status = g_reg_hook.original(thread, context);
    if (status >= 0 && context &&
        (context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS) {
        context->Dr0 = 0;
        context->Dr1 = 0;
        context->Dr2 = 0;
        context->Dr3 = 0;
        context->Dr6 = 0;
        context->Dr7 = 0;
    }
    return status;
}

inline bool build_relocated_syscall_stub(uint8_t* fn) {
    // Layout A (direct):            4C 8B D1  B8 <ssn>  0F 05  C3
    // Layout B (KPTI-gated):        4C 8B D1  B8 <ssn>  F6 04 25 <abs32> 01
    //   test byte [0x7FFE0308], 1 / jne -> int 2E path / syscall / ret
    // Layout B consults KUSER_SHARED_DATA.SystemCall (0x7FFE0308) to decide
    // between `syscall` and `int 2E`; the rebuilt stub reads the same flag
    // once at build time and emits the matching transfer.
    if (fn[0] != 0x4C || fn[1] != 0x8B || fn[2] != 0xD1 || fn[3] != 0xB8) return false;
    const bool direct = (fn[8] == 0x0F && fn[9] == 0x05);
    const bool gated = (fn[8] == 0xF6 && fn[9] == 0x04 && fn[10] == 0x25);
    if (!direct && !gated) return false;
    const uint32_t ssn = *reinterpret_cast<const uint32_t*>(fn + 4);
    const uint8_t transfer[2] = {0x0F, 0x05};                 // syscall
    const uint8_t transfer_int[2] = {0xCD, 0x2E};             // int 2Eh
    const bool use_int2e =
        gated && (*reinterpret_cast<const uint8_t*>(0x7FFE0308ull) & 1) != 0;
    const uint8_t* xfer = use_int2e ? transfer_int : transfer;

    // One section mapped twice: write through view_rw, execute view_rx, so no
    // page is ever simultaneously writable and executable. The section itself
    // must be created with execute permission (a plain PAGE_READWRITE section
    // refuses FILE_MAP_EXECUTE views). Under HVCI this creation may fail; the
    // caller then reports register hiding as unavailable.
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                                        PAGE_EXECUTE_READWRITE, 0, 0x1000, nullptr);
    if (!section) return false;
    g_reg_hook.view_rw =
        static_cast<uint8_t*>(MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0));
    g_reg_hook.view_rx =
        static_cast<uint8_t*>(MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_EXECUTE, 0, 0, 0));
    CloseHandle(section);
    if (!g_reg_hook.view_rw || !g_reg_hook.view_rx) return false;

    const uint8_t stub[] = {0x4C, 0x8B, 0xD1,
                            0xB8,
                            static_cast<uint8_t>(ssn & 0xFF),
                            static_cast<uint8_t>((ssn >> 8) & 0xFF),
                            static_cast<uint8_t>((ssn >> 16) & 0xFF),
                            static_cast<uint8_t>((ssn >> 24) & 0xFF),
                            xfer[0], xfer[1],
                            0xC3};
    memcpy(g_reg_hook.view_rw, stub, sizeof(stub));
    g_reg_hook.original = reinterpret_cast<NtGetContextThreadFn>(g_reg_hook.view_rx);
    return true;
}

inline void freeze_other_threads(std::vector<HANDLE>& out) {
    const DWORD self = GetCurrentThreadId();
    for (DWORD tid : detail::current_process_thread_ids()) {
        if (tid == self) continue;
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!h) continue;
        if (SuspendThread(h) != static_cast<DWORD>(-1))
            out.push_back(h);
        else
            CloseHandle(h);
    }
}

inline void thaw_threads(std::vector<HANDLE>& threads) {
    for (HANDLE h : threads) {
        ResumeThread(h);
        CloseHandle(h);
    }
}

inline bool write_jump14(uint8_t* dst, const void* destination) {
    // ntdll syscall stubs live in 32-byte slots, so a 14-byte jmp stays inside
    // the slot; bail out only if bytes 11..13 look like a neighbouring packed
    // stub already beginning there (defensive - no known build does this).
    if (dst[11] == 0x4C && dst[12] == 0x8B && dst[13] == 0xD1) return false;

    uint8_t code[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};  // jmp [rip+0]
    const uint64_t dest = reinterpret_cast<uint64_t>(destination);
    memcpy(code + 6, &dest, 8);
    DWORD old = 0;
    // Fails on systems with HVCI / memory integrity enabled - by design.
    if (!VirtualProtect(dst, 14, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(dst, code, 14);
    VirtualProtect(dst, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), dst, 14);
    return true;
}

}  // namespace reg_hide

inline bool hide_debug_registers() {
    using namespace reg_hide;
    if (g_reg_hook.active) return true;

    uint8_t* fn = reinterpret_cast<uint8_t*>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtGetContextThread"));
    if (!fn) return false;
    if (!build_relocated_syscall_stub(fn)) return false;
    memcpy(g_reg_hook.saved, fn, sizeof(g_reg_hook.saved));

    // Freeze every other thread so nobody is mid-instruction inside the bytes
    // we are about to overwrite.
    std::vector<HANDLE> frozen;
    freeze_other_threads(frozen);
    const bool ok =
        write_jump14(fn, reinterpret_cast<const void*>(&nt_get_context_thread_detour));
    thaw_threads(frozen);

    if (!ok) {
        UnmapViewOfFile(g_reg_hook.view_rw);
        UnmapViewOfFile(g_reg_hook.view_rx);
        g_reg_hook = RegHookState{};
        return false;
    }
    g_reg_hook.target = fn;
    g_reg_hook.active = true;
    return true;
}

inline bool restore_debug_registers() {
    using namespace reg_hide;
    if (!g_reg_hook.active) return false;
    std::vector<HANDLE> frozen;
    freeze_other_threads(frozen);
    DWORD old = 0;
    VirtualProtect(g_reg_hook.target, 14, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_reg_hook.target, g_reg_hook.saved, 14);
    VirtualProtect(g_reg_hook.target, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_reg_hook.target, 14);
    thaw_threads(frozen);
    UnmapViewOfFile(g_reg_hook.view_rw);
    UnmapViewOfFile(g_reg_hook.view_rx);
    g_reg_hook = RegHookState{};
    return true;
}

// ---------------------------------------------------------------------------
//  Module hiding: unlink this DLL from the PEB loader lists.
//
//  Walks InLoadOrder / InMemoryOrder / InInitializationOrder (offsets 0x00 /
//  0x10 / 0x20 in LDR_DATA_TABLE_ENTRY are stable across versions) and also
//  locates the HashLinks field dynamically: its offset is NOT stable, but the
//  two pointers always land inside loaded-module memory (bucket heads live in
//  ntdll's data section, other nodes inside peer entries), which identifies
//  it. The name strings are wiped as well so hash-bucket lookups by name fail
//  even on builds where the scan misses.
// ---------------------------------------------------------------------------
namespace peb_hide {

struct ListEntry {
    ListEntry* Flink;
    ListEntry* Blink;
};
struct UnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PVOID Buffer;
};
struct LdrData {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    ListEntry InLoadOrderModuleList;
    ListEntry InMemoryOrderModuleList;
    ListEntry InInitializationOrderModuleList;
};
struct LdrEntry {  // x64 offsets via standard layout rules
    ListEntry InLoadOrderLinks;            // +0x00
    ListEntry InMemoryOrderLinks;          // +0x10
    ListEntry InInitializationOrderLinks;  // +0x20
    PVOID DllBase;                         // +0x30
    PVOID EntryPoint;                      // +0x38
    ULONG SizeOfImage;                     // +0x40
    UnicodeString FullDllName;             // +0x48
    UnicodeString BaseDllName;             // +0x58
};

inline void* current_peb() {
#if defined(_MSC_VER) || defined(__clang__)
    return reinterpret_cast<void*>(__readgsqword(0x60));
#else
    void* peb;
    asm volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
#endif
}

}  // namespace peb_hide

inline void hide_self_module() {
    using namespace peb_hide;

    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&hide_self_module), &self))
        return;

    uint8_t* peb = static_cast<uint8_t*>(current_peb());
    if (!peb) return;
    LdrData* ldr = *reinterpret_cast<LdrData**>(peb + 0x18);  // PEB->Ldr
    if (!ldr) return;

    struct Range {
        uint8_t* lo;
        uint8_t* hi;
    };
    std::vector<Range> ranges;
    LdrEntry* self_entry = nullptr;
    for (ListEntry* p = ldr->InLoadOrderModuleList.Flink;
         p != &ldr->InLoadOrderModuleList; p = p->Flink) {
        auto* e = reinterpret_cast<LdrEntry*>(p);  // InLoadOrderLinks is at +0
        ranges.push_back({static_cast<uint8_t*>(e->DllBase),
                          static_cast<uint8_t*>(e->DllBase) + e->SizeOfImage});
        if (reinterpret_cast<HMODULE>(e->DllBase) == self) self_entry = e;
    }
    if (!self_entry) return;

    auto unlink = [](ListEntry* e) {
        if (e->Blink) e->Blink->Flink = e->Flink;
        if (e->Flink) e->Flink->Blink = e->Blink;
        e->Flink = e->Blink = e;
    };
    unlink(&self_entry->InLoadOrderLinks);
    unlink(&self_entry->InMemoryOrderLinks);
    unlink(&self_entry->InInitializationOrderLinks);

    // HashLinks offset varies by Windows version: probe 0x60..0xB8 for a
    // pointer pair that stays inside loaded-module memory.
    const auto in_any_module = [&](void* p) {
        uint8_t* q = static_cast<uint8_t*>(p);
        for (const Range& r : ranges)
            if (q >= r.lo && q < r.hi) return true;
        return false;
    };
    const uint8_t* self_lo = reinterpret_cast<uint8_t*>(self_entry);
    const uint8_t* self_hi = self_lo + 0xC0;
    for (uintptr_t off = 0x60; off + 16 <= 0xC0; off += 8) {
        auto* candidate = reinterpret_cast<ListEntry*>(const_cast<uint8_t*>(self_lo) + off);
        if (!candidate->Flink || !candidate->Blink) continue;
        if (!in_any_module(candidate->Flink) || !in_any_module(candidate->Blink)) continue;
        // skip lists already unlinked (they now point back into this entry)
        const bool flink_self = reinterpret_cast<uint8_t*>(candidate->Flink) >= self_lo &&
                                reinterpret_cast<uint8_t*>(candidate->Flink) < self_hi;
        const bool blink_self = reinterpret_cast<uint8_t*>(candidate->Blink) >= self_lo &&
                                reinterpret_cast<uint8_t*>(candidate->Blink) < self_hi;
        if (flink_self && blink_self) continue;
        unlink(candidate);
        break;
    }

    // Wipe the names so hash-bucket lookups comparing BaseDllName fail too.
    self_entry->BaseDllName.Length = 0;
    self_entry->BaseDllName.Buffer = nullptr;
    self_entry->FullDllName.Length = 0;
    self_entry->FullDllName.Buffer = nullptr;
}

}  // namespace stealth

}  // namespace hwbp
