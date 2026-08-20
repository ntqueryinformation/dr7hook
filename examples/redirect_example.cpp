// =============================================================================
//  redirect_example.cpp - "jump to my own function" demo for hwbp_internal.hpp
//
//  A hardware breakpoint at a function's entry fires BEFORE the first
//  instruction runs, with the caller's stack and argument registers exactly as
//  they were at the call. Rewriting CONTEXT.Rip to your own function with the
//  same signature therefore makes YOUR code execute instead of the original -
//  a detour with zero patched bytes. Your function's `ret` goes straight back
//  to the original caller.
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY.
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdint>

#include "../hwbp_internal.hpp"

// --- the "victim" functions we are going to take over -----------------------
__declspec(noinline) unsigned long long ComputeScore(unsigned long long x) {
    return x + 1;  // trivial on purpose - real targets can be arbitrary
}

__declspec(noinline) const char* GetGreeting(const char* name) {
    (void)name;  // trivial on purpose - real targets can be arbitrary
    return "hello from the ORIGINAL GetGreeting";
}

// --- our replacements: SAME signature / calling convention as the victim ----
static unsigned long long g_detour_hits = 0;

static unsigned long long ComputeScoreDetour(unsigned long long x) {
    ++g_detour_hits;
    printf("  [detour] ComputeScoreDetour(%llu) running INSTEAD of ComputeScore\n", x);
    return x * 100 + 5;  // whatever we want - the caller receives this
}

static const char* GetGreetingDetour(const char* name) {
    ++g_detour_hits;
    printf("  [detour] GetGreetingDetour(\"%s\") running INSTEAD of GetGreeting\n", name);
    return "hello from MY function";
}

// --- the hook callbacks: one line performs the jump -------------------------
static void redirect_compute(CONTEXT* c) {
    // Everything except Rip stays untouched: RCX already holds `x`, Rsp
    // already points at the caller's return address. The detour therefore
    // behaves exactly as if the caller had called it directly.
    c->Rip = reinterpret_cast<uint64_t>(&ComputeScoreDetour);
    // You can still touch the arguments before the jump, e.g.:
    // c->Rcx += 10;   // detour sees x+10
}

static void redirect_greeting(CONTEXT* c) {
    c->Rip = reinterpret_cast<uint64_t>(&GetGreetingDetour);
}

int main() {
    // volatile call arguments keep the Release optimizer from folding, CSE-ing
    // or dead-call-eliminating these pure demo calls - breakpoints only fire
    // for calls that actually happen at runtime.
    static volatile unsigned long long v_x = 3;
    static const char* volatile v_name = "kyle";

    printf("== 1. before hooking ==\n");
    printf("ComputeScore(3)          = %llu\n", ComputeScore(v_x));
    printf("GetGreeting(\"kyle\")      = %s\n", GetGreeting(v_name));

    hwbp::HwBpHook score_hook, greet_hook;
    const bool a = score_hook.set(&ComputeScore, hwbp::BreakType::Execute, 1, redirect_compute);
    const bool b = greet_hook.set(&GetGreeting, hwbp::BreakType::Execute, 1, redirect_greeting);
    if (!a || !b) {
        printf("hook install failed\n");
        return 1;
    }

    printf("\n== 2. while hooked: calls are redirected to our functions ==\n");
    const unsigned long long ra = ComputeScore(v_x);  // sequenced before reading the counter
    printf("ComputeScore(3)          = %llu   (detour answered, %llu hits)\n", ra,
           g_detour_hits);
    printf("GetGreeting(\"kyle\")      = %s\n", GetGreeting(v_name));

    printf("\n== 3. after remove(): originals run again ==\n");
    score_hook.remove();
    greet_hook.remove();
    printf("ComputeScore(3)          = %llu\n", ComputeScore(v_x));
    printf("GetGreeting(\"kyle\")      = %s\n", GetGreeting(v_name));

    // notes:
    //  * a detour must NOT call its own victim function - the breakpoint is
    //    still armed at the entry, so it would re-trigger forever. Chain to
    //    the original by unhooking first (remove() is cheap) or duplicate the
    //    original's logic.
    //  * the same works for external hooks (hwbp_external.hpp): rewrite
    //    CONTEXT.Rip in the callback before the thread resumes.
    return 0;
}
