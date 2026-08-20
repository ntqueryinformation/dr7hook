// =============================================================================
//  target.cpp - victim process for the external demo. Prints the address of
//  CombineValues, then calls it in a loop so a breakpoint can be placed on it.
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY.
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>

__declspec(noinline) unsigned long long CombineValues(unsigned long long a,
                                                      unsigned long long b) {
    const unsigned long long r = (a * 31) + b;
    printf("[target] CombineValues(%llu, %llu) -> %llu\n", a, b, r);
    return r;
}

int main() {
    printf("[target] pid=%lu CombineValues=%p\n", GetCurrentProcessId(),
           reinterpret_cast<void*>(&CombineValues));
    fflush(stdout);
    for (unsigned long long i = 0;; ++i) {
        Sleep(1500);
        CombineValues(i, i * 3);
        fflush(stdout);
    }
}
