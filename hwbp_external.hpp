// =============================================================================
//  hwbp_external.hpp - out-of-process hardware breakpoint hooker (x64 Windows)
//
//  Hardware breakpoint #DB faults are consumed by an attached debugger before
//  anything in the target runs, so an external engine must be the debugger:
//  this class attaches via DebugActiveProcess, arms DR0-DR3/DR7 on every
//  debug event that yields a thread handle, and dispatches the resulting
//  EXCEPTION_SINGLE_STEP events to user callbacks with full read/write access
//  to the thread's CONTEXT (registers can be inspected and rewritten).
//
//  Compared to int3 patching there is no modified byte in the target, but note
//  the process IS being debugged while attached: BeingDebugged /
//  NtQueryInformationProcess(ProcessDebugPort) still reveal the debugger.
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY. See README.md.
//
//  x64 Windows only; the target must not already be debugged and must not be
//  a WOW64 process (Wow64GetThreadContext is not wired up).
// =============================================================================
#pragma once

#ifndef _WIN64
#error "hwbp_external.hpp supports x64 only"
#endif

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <thread>

#include "hwbp_common.hpp"

namespace hwbp {
namespace external {

class Debugger {
public:
    using Callback = std::function<void(CONTEXT&)>;

    ~Debugger() { detach(); }

    // Attach to a running process and start the debug-event loop. Blocks until
    // the loop is up (existing threads get the breakpoints armed through the
    // synthetic CREATE_PROCESS/CREATE_THREAD events).
    bool attach(DWORD pid) {
        if (running_.load()) return false;
        pid_ = pid;
        stop_ = false;
        threads_.clear();

        std::promise<bool> ready;
        auto future = ready.get_future();
        // DebugActiveProcess must be called from the thread that owns the
        // debug loop, so the whole setup happens inside it.
        thread_ = std::thread([this, pid, pr = std::move(ready)]() mutable {
            if (!DebugActiveProcess(pid)) {
                pr.set_value(false);
                return;
            }
            DebugSetProcessKillOnExit(FALSE);  // survive our detach
            running_ = true;  // before set_value: attach() must never observe
                              // a loop that is running but not marked as such
            pr.set_value(true);
            loop();
        });

        if (!future.get()) {
            if (thread_.joinable()) thread_.join();
            return false;
        }
        return true;
    }

    // Restore clean debug registers on every thread and detach the debugger.
    bool detach() {
        if (!running_.load() || !thread_.joinable()) return false;
        stop_ = true;
        thread_.join();
        return true;
    }

    bool attached() const { return running_.load(); }

    // Same semantics as the internal engine's set(). If already attached, the
    // breakpoints are pushed onto all known threads immediately.
    int add(const void* address, BreakType type, uint8_t length, const Callback& cb) {
        if (!address || !length_supported(type, length)) return -1;
        if (!address_aligned(reinterpret_cast<uint64_t>(address), type, length)) return -1;

        int slot = -1;
        {
            std::lock_guard<std::recursive_mutex> lk(mtx_);
            for (uint32_t i = 0; i < kMaxBreakpoints; ++i)
                if (!slots_[i].active) { slot = static_cast<int>(i); break; }
            if (slot < 0) return -1;
            slots_[slot] = Slot{address, type, length, cb, true};
        }
        if (running_.load(std::memory_order_relaxed)) push_state_to_debuggee();
        return slot;
    }

    bool remove(int slot) {
        if (slot < 0 || slot >= static_cast<int>(kMaxBreakpoints)) return false;
        {
            std::lock_guard<std::recursive_mutex> lk(mtx_);
            if (!slots_[slot].active) return false;
            slots_[slot] = Slot{};
        }
        if (running_.load(std::memory_order_relaxed)) push_state_to_debuggee();
        return true;
    }

    Debugger() = default;
    Debugger(const Debugger&) = delete;
    Debugger& operator=(const Debugger&) = delete;

private:
    struct Slot {
        const void* address = nullptr;
        BreakType type = BreakType::Execute;
        uint8_t length = 1;
        Callback cb;
        bool active = false;
    };

    void loop() {
        DEBUG_EVENT ev{};
        bool exited = false;
        while (!stop_ && !exited) {
            if (!WaitForDebugEvent(&ev, 100)) continue;  // timeout lets us poll stop_
            DWORD cont = DBG_CONTINUE;

            switch (ev.dwDebugEventCode) {
                case CREATE_PROCESS_DEBUG_EVENT: {
                    auto& info = ev.u.CreateProcessInfo;
                    hProcess_ = info.hProcess;
                    if (info.hFile) CloseHandle(info.hFile);
                    threads_[ev.dwThreadId] = info.hThread;
                    apply_slots(info.hThread);
                    break;
                }
                case CREATE_THREAD_DEBUG_EVENT:
                    threads_[ev.dwThreadId] = ev.u.CreateThread.hThread;
                    apply_slots(ev.u.CreateThread.hThread);
                    break;
                case EXIT_THREAD_DEBUG_EVENT: {
                    auto it = threads_.find(ev.dwThreadId);
                    if (it != threads_.end()) {
                        CloseHandle(it->second);
                        threads_.erase(it);
                    }
                    break;
                }
                case EXIT_PROCESS_DEBUG_EVENT:
                    exited = true;
                    break;
                case LOAD_DLL_DEBUG_EVENT:
                    if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
                    break;
                case EXCEPTION_DEBUG_EVENT:
                    if (!handle_exception(ev, &cont)) cont = DBG_EXCEPTION_NOT_HANDLED;
                    break;
                default:
                    break;
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
        }

        if (stop_ && !exited) {
            // Put every thread back onto clean debug registers, then detach.
            for (auto& kv : threads_) {
                SuspendThread(kv.second);
                clear_slots(kv.second);
                ResumeThread(kv.second);
            }
            DebugActiveProcessStop(pid_);
        }
        for (auto& kv : threads_) CloseHandle(kv.second);
        threads_.clear();
        if (hProcess_) {
            CloseHandle(hProcess_);
            hProcess_ = nullptr;
        }
        running_ = false;
    }

    bool handle_exception(const DEBUG_EVENT& ev, DWORD* cont) {
        const EXCEPTION_RECORD& rec = ev.u.Exception.ExceptionRecord;

        // The initial attach breakpoint (and any int3 the app itself uses) is
        // simply swallowed so the debuggee keeps running normally.
        if (rec.ExceptionCode == EXCEPTION_BREAKPOINT) {
            *cont = DBG_CONTINUE;
            return true;
        }
        if (rec.ExceptionCode != EXCEPTION_SINGLE_STEP) return false;

        auto it = threads_.find(ev.dwThreadId);
        if (it == threads_.end()) return false;
        CONTEXT c{};
        c.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(it->second, &c)) return false;

        Callback cbs[kMaxBreakpoints];
        uint32_t n = 0;
        {
            std::lock_guard<std::recursive_mutex> lk(mtx_);
            for (uint32_t i = 0; i < kMaxBreakpoints; ++i) {
                const Slot& s = slots_[i];
                if (!s.active) continue;
                const bool hit = (s.type == BreakType::Execute)
                                     ? (reinterpret_cast<uint64_t>(s.address) == c.Rip)
                                     : ((c.Dr6 & (1ull << i)) != 0);
                if (hit && n < kMaxBreakpoints) cbs[n++] = s.cb;
            }
        }
        if (n == 0) {
            // A single-step we did not request (e.g. the app trap-flag stepping
            // itself): swallow it so the target is not killed by second chance.
            *cont = DBG_CONTINUE;
            return true;
        }
        for (uint32_t i = 0; i < n; ++i) cbs[i](c);
        c.Dr6 = 0;            // clear B0-B3 condition-hit bits
        c.EFlags |= 0x10000;  // RF: resume past an execute breakpoint
        SetThreadContext(it->second, &c);
        *cont = DBG_CONTINUE;
        return true;
    }

    void apply_slots(HANDLE hThread) {
        // The thread is stopped at a debug event while this runs.
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        CONTEXT c{};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(hThread, &c)) return;
        c.Dr0 = slots_[0].active ? reinterpret_cast<uint64_t>(slots_[0].address) : 0;
        c.Dr1 = slots_[1].active ? reinterpret_cast<uint64_t>(slots_[1].address) : 0;
        c.Dr2 = slots_[2].active ? reinterpret_cast<uint64_t>(slots_[2].address) : 0;
        c.Dr3 = slots_[3].active ? reinterpret_cast<uint64_t>(slots_[3].address) : 0;
        uint64_t dr7 = 0;
        for (uint32_t i = 0; i < kMaxBreakpoints; ++i)
            if (slots_[i].active)
                dr7 = dr7_enable_slot(dr7, i, slots_[i].type, slots_[i].length);
        c.Dr6 = 0;
        c.Dr7 = dr7;
        SetThreadContext(hThread, &c);
    }

    void clear_slots(HANDLE hThread) {
        CONTEXT c{};
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(hThread, &c)) return;
        c.Dr0 = c.Dr1 = c.Dr2 = c.Dr3 = 0;
        c.Dr6 = 0;
        c.Dr7 = 0;
        SetThreadContext(hThread, &c);
    }

    // Re-apply the slot image to all live threads (after add()/remove()).
    void push_state_to_debuggee() {
        for (auto& kv : threads_) {
            SuspendThread(kv.second);
            apply_slots(kv.second);
            ResumeThread(kv.second);
        }
    }

    mutable std::recursive_mutex mtx_;
    Slot slots_[kMaxBreakpoints];
    std::map<DWORD, HANDLE> threads_;  // tid -> debug-event thread handle
    HANDLE hProcess_ = nullptr;
    DWORD pid_ = 0;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_{false};
};

}  // namespace external
}  // namespace hwbp
