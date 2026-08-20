// =============================================================================
//  internal_example.cpp - inject-and-forget demo DLL for hwbp_internal.hpp
//
//  No host exe needed: on DLL_PROCESS_ATTACH a bootstrap thread installs the
//  configured hook, hides this module from the loader lists and masks the
//  debug registers, then records what it did in
//  %TEMP%\hwbp_internal_demo.log (headless verification).
//
//  The exports (Install / GoStealth / Demo / Probe) remain available for
//  manual control from a host, injector or debugger - they are optional.
//
//  To use this as your own internal hook DLL: edit the CONFIGURATION section
//  below (hook target + callback) and rebuild.
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY.
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <utility>

#include "../hwbp_internal.hpp"

// ======================= CONFIGURATION (edit me) ============================
// Hook target: MessageBoxW - fires in any process that shows a message box.
//
// This config demonstrates the REDIRECT pattern: instead of letting the
// original run, the callback rewrites CONTEXT.Rip so the call "jumps" to our
// own function (detour_messageboxw below) with identical arguments. The
// detour has the same signature, so its `ret` returns straight to the
// original caller with whatever WE choose to return.
static int detour_messageboxw(HWND hwnd, const wchar_t* text, const wchar_t* caption,
                              unsigned type) {
    (void)hwnd;  // signature must match MessageBoxW even if unused
    printf("[detour] MessageBoxW redirected: text='%ls' caption='%ls' type=0x%x\n", text,
           caption, type);
    return IDYES;  // the caller believes the user clicked Yes
}

static void on_hooked_call(CONTEXT* c) {
    // Arguments are already in place (RCX=hWnd, RDX=text, R8=caption, R9=uType)
    // and [Rsp] is the caller's return address; only the instruction pointer
    // changes, so the detour behaves as if it were called directly.
    c->Rip = reinterpret_cast<unsigned long long>(&detour_messageboxw);
}
// ===========================================================================

static hwbp::HwBpHook g_hook;
static bool g_stealth = false;

// Every step is mirrored into %TEMP%\hwbp_internal_demo.log so the DLL can be
// verified headlessly after injection (the process may not own a console).
static void log_line(const char* fmt, ...) {
    char path[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, path)) return;
    strcat_s(path, "hwbp_internal_demo.log");
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fprintf(f, "\n");
    fclose(f);
}

static void install_hooks() {
    if (g_hook.slot() >= 0) return;
    HMODULE user32 = LoadLibraryW(L"user32.dll");
    if (!user32) {
        log_line("[dll] LoadLibrary(user32) failed");
        return;
    }
    void* target = reinterpret_cast<void*>(GetProcAddress(user32, "MessageBoxW"));
    if (g_hook.set(target, hwbp::BreakType::Execute, 1, on_hooked_call)) {
        log_line("[dll] pid=%lu hook armed: MessageBoxW @ %p (slot %d)",
                 GetCurrentProcessId(), target, g_hook.slot());
    } else {
        log_line("[dll] pid=%lu hook install FAILED", GetCurrentProcessId());
    }
}

static void enable_stealth() {
    if (g_stealth) return;
    g_stealth = true;
    hwbp::stealth::hide_self_module();
    const bool regs_hidden = hwbp::stealth::hide_debug_registers();
    const HMODULE still = GetModuleHandleW(L"internal_example.dll");
    log_line("[dll] stealth: module hidden (GetModuleHandle -> %p), DR masking=%d",
             static_cast<void*>(still), regs_hidden ? 1 : 0);
}

static void log_probe(const char* tag) {
    CONTEXT c{};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &c);
    log_line("[probe:%s] GetThreadContext DR0=%p DR7=0x%llx", tag,
             reinterpret_cast<void*>(static_cast<uintptr_t>(c.Dr0)),
             static_cast<unsigned long long>(c.Dr7));
}

// DllMain cannot do the work itself (thread creation + cross-thread
// suspension are not loader-lock safe), so it only launches this thread; the
// loader lock is released the moment DllMain returns.
static DWORD WINAPI bootstrap(void*) {
    log_line("[dll] bootstrap start, pid=%lu", GetCurrentProcessId());
    install_hooks();
    log_probe("armed");  // real debug registers visible before masking
    enable_stealth();
    log_probe("stealthed");  // GetThreadContext now reports zeros
    log_line("[dll] bootstrap done - engine running");
    return 0;
}

// ---------------- optional manual-control exports ---------------------------
extern "C" __declspec(dllexport) void __stdcall Install() { install_hooks(); }
extern "C" __declspec(dllexport) void __stdcall GoStealth() { enable_stealth(); }
extern "C" __declspec(dllexport) void __stdcall Demo() {
    MessageBoxW(nullptr, L"body text", L"hooked caption", MB_OK);
}
extern "C" __declspec(dllexport) void __stdcall Probe() {
    log_probe(g_stealth ? "manual:stealthed" : "manual:armed");
    CONTEXT c{};
    c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &c);
    printf("[probe] GetThreadContext -> DR0=%p DR7=0x%llx\n",
           reinterpret_cast<void*>(static_cast<uintptr_t>(c.Dr0)),
           static_cast<unsigned long long>(c.Dr7));
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        CreateThread(nullptr, 0, bootstrap, nullptr, 0, nullptr);
    }
    return TRUE;
}
