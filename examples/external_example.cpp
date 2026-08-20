// =============================================================================
//  external_example.cpp - demo driver for hwbp_external.hpp
//
//  Attaches to a running target, arms an execute breakpoint on a function and
//  prints/rewrites its arguments every time it is called.
//
//  usage: external_example <pid> <hex address of function>
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY.
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdlib>

#include "../hwbp_external.hpp"

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 3) {
        printf("usage: external_example <pid> <hex address>\n");
        return 1;
    }
    const DWORD pid = static_cast<DWORD>(strtoul(argv[1], nullptr, 0));
    void* address = reinterpret_cast<void*>(strtoull(argv[2], nullptr, 16));

    hwbp::external::Debugger dbg;
    if (!dbg.attach(pid)) {
        printf("attach failed: %lu\n", GetLastError());
        return 1;
    }

    const int slot = dbg.add(address, hwbp::BreakType::Execute, 1, [](CONTEXT& c) {
        // x64 calling convention at function entry: RCX=1st, RDX=2nd arg.
        printf("[hook] entry: a=%llu b=%llu\n", static_cast<unsigned long long>(c.Rcx),
               static_cast<unsigned long long>(c.Rdx));
        c.Rcx = 111;		// rewrite the first argument before the body runs
    });
    if (slot < 0) {
        printf("no free breakpoint slot\n");
        return 1;
    }

    printf("breakpoint armed in slot %d at %p - press Enter to detach\n", slot, address);
    getchar();
    dbg.detach();
    printf("detached, target continues clean\n");
    return 0;
}
