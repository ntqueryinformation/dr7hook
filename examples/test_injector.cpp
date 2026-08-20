// =============================================================================
//  test_injector.cpp - TEST TOOL: injects the internal demo DLL into a
//  process to verify inject-and-forget operation. Use your own injector in
//  real setups; this one exists so the library can be validated headlessly.
//
//  usage: test_injector <pid> <path-to-dll>
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY.
// =============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 3) {
        printf("usage: test_injector <pid> <path-to-dll>\n");
        return 1;
    }
    const DWORD pid = static_cast<DWORD>(strtoul(argv[1], nullptr, 0));

    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                                     PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                     PROCESS_VM_READ,
                                 FALSE, pid);
    if (!process) {
        printf("OpenProcess(%lu) failed: %lu\n", pid, GetLastError());
        return 1;
    }

    wchar_t wpath[1024] = {};
    MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, wpath, 1024);
    const SIZE_T bytes = (wcslen(wpath) + 1) * sizeof(wchar_t);

    void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (!remote) {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(process);
        return 1;
    }
    if (!WriteProcessMemory(process, remote, wpath, bytes, nullptr)) {
        printf("WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }

    // Classic CreateRemoteThread(LoadLibraryW). The exit code is the HMODULE
    // truncated to 32 bits - non-zero means the DLL loaded and DllMain ran.
    auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    HANDLE thread =
        CreateRemoteThread(process, nullptr, 0, load_library, remote, 0, nullptr);
    if (!thread) {
        printf("CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        CloseHandle(process);
        return 1;
    }
    WaitForSingleObject(thread, INFINITE);
    DWORD module_low = 0;
    GetExitCodeThread(thread, &module_low);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    CloseHandle(process);

    printf("remote LoadLibraryW exit code: 0x%lx -> %s\n", module_low,
           module_low ? "loaded" : "FAILED");
    if (module_low)
        printf("check %%TEMP%%\\hwbp_internal_demo.log for the engine report\n");
    return module_low ? 0 : 1;
}
