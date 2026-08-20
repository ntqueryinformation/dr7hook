// =============================================================================
//  internal_host.cpp - console host for the internal_example demo DLL
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY.
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>

using Fn = void(__stdcall*)();

int main() {
    const HMODULE dll = LoadLibraryW(L"internal_example.dll");
    if (!dll) {
        printf("LoadLibrary failed: %lu\n", GetLastError());
        return 1;
    }
    const auto install = reinterpret_cast<Fn>(GetProcAddress(dll, "Install"));
    const auto demo = reinterpret_cast<Fn>(GetProcAddress(dll, "Demo"));
    const auto probe = reinterpret_cast<Fn>(GetProcAddress(dll, "Probe"));
    const auto go_stealth = reinterpret_cast<Fn>(GetProcAddress(dll, "GoStealth"));
    if (!install || !demo || !probe || !go_stealth) {
        printf("GetProcAddress failed\n");
        return 1;
    }

    printf("pid=%lu\n", GetCurrentProcessId());

    printf("\n-- 1. install hook (exec bp on MessageBoxW) --\n");
    install();
    probe();  // DR0 should hold the MessageBoxW address
    printf("calling MessageBoxW - the call is redirected to the DLL's own\n");
    printf("detour function (logged, returns IDYES, no dialog appears):\n");
    demo();
	MessageBoxW(nullptr, L"body text", L"hooked caption", MB_OK);
    printf("\n-- 2. go stealth --\n");
    go_stealth();
    probe();  // GetThreadContext now reports zeroed DR registers
    printf("GetModuleHandleW(internal_example.dll) -> %p (NULL once hidden)\n",
           static_cast<void*>(GetModuleHandleW(L"internal_example.dll")));

    printf("\n-- 3. hook still fires while hidden --\n");
    demo();
    return 0;
}
