// =============================================================================
//  test_smoke.cpp - non-interactive functional test of hwbp_internal.hpp
//  Exercises: execute bp + argument rewrite, data write watchpoint, register
//  hiding (probe masked while hooks still fire), module hiding.
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>

#include "hwbp_internal.hpp"

static int g_failures = 0;
#define CHECK(cond, msg)                                            \
    do {                                                            \
        if (cond)                                                   \
            printf("[PASS] %s\n", msg);                             \
        else {                                                      \
            printf("[FAIL] %s\n", msg);                             \
            ++g_failures;                                           \
        }                                                           \
    } while (0)

static volatile unsigned long long g_watch_me = 0;
static int g_write_hits = 0;
static unsigned long long g_seen_a = 0, g_seen_b = 0;
static int g_exec_hits = 0;

static int g_multiply_calls = 0;

// the counter is an observable side effect: it stops the Release optimizer
// from dead-call-eliminating pure demo calls whose results go unused
__declspec(noinline) unsigned long long Multiply(unsigned long long a, unsigned long long b) {
    ++g_multiply_calls;
    return a * b;
}

int main() {
    // ---- 1. execute breakpoint + argument rewrite --------------------------
    hwbp::HwBpHook exec_hook;
    bool ok = exec_hook.set(&Multiply, hwbp::BreakType::Execute, 1, [](CONTEXT* c) {
        ++g_exec_hits;
        g_seen_a = c->Rcx;
        g_seen_b = c->Rdx;
        c->Rcx = 7;  // rewrite first argument before the body runs
    });
    CHECK(ok, "exec breakpoint installed");

    // volatile arguments stop the Release optimizer from folding / CSE-ing /
    // dead-call-eliminating these pure demo calls - the hooks live at real
    // runtime call sites.
    static volatile unsigned long long v_a = 100, v_b = 3;
    const unsigned long long r = Multiply(v_a, v_b);
    CHECK(g_exec_hits == 1, "exec breakpoint fired");
    CHECK(g_seen_a == 100 && g_seen_b == 3, "callback read arguments");
    CHECK(r == 21, "argument rewrite took effect (100*3 -> 7*3)");

    // ---- 1b. redirect: jump to our own function via Rip --------------------
    struct Path {
        static unsigned long long __declspec(noinline) Original(unsigned long long x) {
            return x + 1;
        }
        static unsigned long long Detour(unsigned long long x) { return x * 100 + 5; }
    };
    hwbp::HwBpHook redirect_hook;
    ok = redirect_hook.set(&Path::Original, hwbp::BreakType::Execute, 1, [](CONTEXT* c) {
        c->Rip = reinterpret_cast<unsigned long long>(&Path::Detour);
    });
    CHECK(ok, "redirect hook installed");
    static volatile unsigned long long v_x3 = 3;
    CHECK(Path::Original(v_x3) == 305, "call redirected to our function");
    redirect_hook.remove();
    CHECK(Path::Original(v_x3) == 4, "original restored after remove()");

    // ---- 2. data write watchpoint ------------------------------------------
    hwbp::HwBpHook data_hook;
    ok = data_hook.set(const_cast<unsigned long long*>(&g_watch_me), hwbp::BreakType::Write,
                       sizeof(unsigned long long), [](CONTEXT*) { ++g_write_hits; });
    CHECK(ok, "write watchpoint installed");
    g_watch_me = 42;  // triggers #DB after the store retires
    g_watch_me = 43;
    CHECK(g_write_hits == 2, "write watchpoint fired twice");

    // ---- 3. hide debug registers from GetThreadContext ---------------------
    CONTEXT probe{};
    probe.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &probe);
    CHECK(probe.Dr0 != 0 || probe.Dr7 != 0, "probe sees real DRs before hiding");

    const bool hidden = hwbp::stealth::hide_debug_registers();
    printf("       hide_debug_registers() -> %d\n", hidden ? 1 : 0);
    if (hidden) {
        CONTEXT masked{};
        masked.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &masked);
        CHECK(masked.Dr0 == 0 && masked.Dr7 == 0, "probe masked after hiding");

        g_exec_hits = 0;
        static volatile unsigned long long v_five = 5;
        Multiply(v_five, v_five);
        CHECK(g_exec_hits == 1, "hooks still fire while DRs are masked");
    }

    // ---- 4. module hiding ---------------------------------------------------
    HMODULE before = GetModuleHandleW(L"test_smoke.exe");
    hwbp::stealth::hide_self_module();
    HMODULE after = GetModuleHandleW(L"test_smoke.exe");
    CHECK(before != nullptr && after == nullptr, "module vanished from loader lists");

    // hooks keep working after everything is hidden
    g_exec_hits = 0;
    static volatile unsigned long long v_five_b = 5;
    Multiply(v_five_b, v_five_b);
    g_watch_me = 44;
    CHECK(g_exec_hits == 1 && g_write_hits == 3, "hooks alive after full stealth");

    printf("\n%s (%d failure(s))\n", g_failures ? "SMOKE TEST FAILED" : "ALL TESTS PASSED",
           g_failures);
    return g_failures ? 1 : 0;
}
