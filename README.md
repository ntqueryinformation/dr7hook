# dr7hook

![platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6)
![language](https://img.shields.io/badge/C%2B%2B-17-00599C)
![toolset](https://img.shields.io/badge/MSVC-v143-5C2D91)
![status](https://img.shields.io/badge/tests-passing-brightgreen)

**Invisible function hooking for x64 Windows using CPU hardware breakpoints (DR0–DR7) — internal *and* external, with optional stealth that hides the debug registers and unlinks your module.**

No bytes are patched: no inline jmp, no `int3` (0xCC). Integrity checks that hash or scan `.text` see pristine code.

> ⚠️ **For authorized security research and education only.** Use this library on software you own or are explicitly permitted to test. Check the laws that apply to you before using it.

---

## Contents

- [Why hardware breakpoints](#why-hardware-breakpoints)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Internal usage (in-process)](#internal-usage-in-process)
- [Redirecting calls to your own function](#redirecting-calls-to-your-own-function)
- [External usage (out-of-process)](#external-usage-out-of-process)
- [Stealth — what it does and does not hide](#stealth--what-it-does-and-does-not-hide)
- [Limitations](#limitations)
- [Project layout](#project-layout)
- [Test results](#test-results)

## Why hardware breakpoints

| | inline / int3 hook | **dr7hook** |
|---|---|---|
| Modified bytes in target | yes | **none** |
| Visible to integrity scans | yes | **no** |
| Resume mechanism | instruction skipping / re-write | `EFLAGS.RF` (faultless) |
| Register access in callback | manual | full `CONTEXT`, read/write |
| Slots | unlimited | 4 (architectural) |

Callbacks receive the faulting thread's full `CONTEXT` — inspect and rewrite registers (arguments, return address, `Rip`, …) live, or [redirect the entire call to your own function](#redirecting-calls-to-your-own-function).

## Quick start

Requirements: Visual Studio 2022 (v143 toolset), Windows x64.

```bat
git clone https://github.com/<you>/dr7hook.git
cd dr7hook
build.bat          :: or open hwbp.sln in Visual Studio
```

Try the demos (binaries land in the repo root via `build.bat`, or in `build\Release\` via the solution):

```bat
redirect_example.exe      :: watch two functions get hijacked, then restored
test_smoke.exe            :: full engine self-test (14 checks)

:: external demo
target.exe                :: prints its pid + a function address
external_example.exe <pid> <address>

:: inject-and-forget demo (any process you own)
test_injector.exe <pid> <path\to\internal_example.dll>
type %TEMP%\hwbp_internal_demo.log
```

Example — the self-test:

```text
[PASS] exec breakpoint installed
[PASS] exec breakpoint fired
[PASS] callback read arguments
[PASS] argument rewrite took effect (100*3 -> 7*3)
[PASS] redirect hook installed
[PASS] call redirected to our function
[PASS] original restored after remove()
[PASS] write watchpoint installed
[PASS] write watchpoint fired twice
[PASS] probe sees real DRs before hiding
[PASS] probe masked after hiding
[PASS] hooks still fire while DRs are masked
[PASS] module vanished from loader lists
[PASS] hooks alive after full stealth

ALL TESTS PASSED (0 failure(s))
```

Example — the injected DLL's report:

```text
[dll] bootstrap start, pid=24664
[dll] pid=24664 hook armed: MessageBoxW @ 00007FFC5781C760 (slot 0)
[probe:armed] GetThreadContext DR0=00007FFC5781C760 DR7=0x401
[dll] stealth: module hidden (GetModuleHandle -> 0000000000000000), DR masking=1
[probe:stealthed] GetThreadContext DR0=0000000000000000 DR7=0x0
[dll] bootstrap done - engine running
```

## How it works

1. The target address is loaded into a free debug address register (`DR0`–`DR3`) and enabled in `DR7` with a condition (execute / write / access) and length (1/2/4/8 bytes).
2. When the condition hits, the CPU raises `#DB`. **Internal engine:** a first-order vectored exception handler catches it and dispatches to your callback. **External engine:** the library is attached as the target's debugger and dispatches the debug event.
3. After your callback, `DR6` is cleared and `EFLAGS.RF` is set, so execution resumes past the breakpoint without re-triggering — no instruction skipping, no re-patching.
4. Debug registers are per-thread, so a background sweeper keeps every thread (including threads created later) carrying the breakpoints.

## Internal usage (in-process)

### Ready-to-go DLL (no host needed)

`examples/internal_example.cpp` builds `internal_example.dll`, which is
**inject-and-forget**: on `DLL_PROCESS_ATTACH` it spawns a bootstrap thread
(DllMain itself must not create/suspend threads — loader lock) that

1. arms the configured hook (demo: execute breakpoint on `MessageBoxW`),
2. unlinks the DLL from the PEB loader lists,
3. masks the debug registers from `GetThreadContext`,
4. appends what it did to `%TEMP%\hwbp_internal_demo.log` for headless
   verification (strip the `log_line` calls if you want zero artifacts).

To make it yours, edit the `CONFIGURATION` section at the top of the file
(hook target + callback) and rebuild. Its exports (`Install`, `GoStealth`,
`Demo`, `Probe`) remain for optional manual control from a host or debugger;
`internal_host.exe` is just such an optional driver.

### Using the engine directly (header-only)

```cpp
#include "hwbp_internal.hpp"

hwbp::HwBpHook hook;

hook.set(&TargetFunc, hwbp::BreakType::Execute, /*length=*/1, [](CONTEXT* c) {
    // x64 MSVC ABI at entry: RCX, RDX, R8, R9 = args 1-4,
    // stack args start at [Rsp+0x28] ([Rsp] = return address).
    printf("TargetFunc(a=%llu)\n", (unsigned long long)c->Rcx);
    c->Rcx = 42;                      // rewrite an argument
});

// data watchpoints work too (aligned, 1/2/4/8 bytes):
// hook.set(&g_config, hwbp::BreakType::Write, 8, on_config_write);

hook.remove();

// optional stealth (call AFTER installing; DLL must stay loaded forever):
hwbp::stealth::hide_self_module();      // vanish from module enumeration
hwbp::stealth::hide_debug_registers();  // GetThreadContext sees DR0-DR7 = 0
```

What the engine does for you:

- installs a **first-order VEH** that catches `EXCEPTION_SINGLE_STEP`,
  matches the faulting `Rip` (execute bps) or the `DR6` condition bits (data
  bps) against the registered slots and invokes your callback;
- **arms DR0–DR3/DR7 on every thread** — synchronously on install (a helper
  thread suspends everyone, including you) and on any thread created later
  via a 200 ms background sweeper (`HwBpHook::set_auto_thread_watch(false)`
  to disable);
- clears `DR6` and sets `RF` on return so execution resumes past the bp.

## Redirecting calls to your own function

Because the breakpoint fires at function entry — before the first instruction,
with argument registers and the return address exactly as the caller left
them — rewriting `CONTEXT.Rip` makes *your* function run instead of the
original, like a detour with zero patched bytes:

```cpp
static int MyMessageBoxW(HWND hwnd, const wchar_t* text, const wchar_t* caption,
                         unsigned type) {          // SAME signature as victim
    log("MessageBoxW(%ls)", text);
    return IDYES;                                  // caller gets OUR result
}

hook.set(&MessageBoxW, hwbp::BreakType::Execute, 1, [](CONTEXT* c) {
    c->Rip = (uint64_t)&MyMessageBoxW;             // the entire "jump"
});
```

Your function's `ret` returns straight to the original caller. Run
`redirect_example.exe` to see it live: two functions get hijacked
mid-program and restored by `remove()`. The inject-and-forget DLL uses the
same pattern on `MessageBoxW`.

Two rules of thumb:

- a detour must not call its own victim — the breakpoint is still armed at
  the entry and would re-trigger forever; chain to the original by
  unhooking first or duplicating its logic;
- in **Release builds** the optimizer can fold / CSE / dead-call-eliminate
  calls to small pure functions *at compile time* — such calls never happen,
  so no breakpoint fires. Give the victim an observable side effect or pass
  volatile arguments (both demos do this).

## External usage (out-of-process)

```cpp
#include "hwbp_external.hpp"

hwbp::external::Debugger dbg;
dbg.attach(pid);
dbg.add((void*)0x7FF6ABCD1234, hwbp::BreakType::Execute, 1, [](CONTEXT& c) {
    printf("called: rcx=%llx rdx=%llx\n", (long long)c.Rcx, (long long)c.Rdx);
});
// ...
dbg.detach();   // restores clean debug registers, detaches debugger
```

Hardware bp exceptions are delivered to an attached debugger before anything
in the target runs, so the external engine *is* the debugger: it attaches with
`DebugActiveProcess`, arms the registers on every create-thread/debug event and
dispatches `EXCEPTION_SINGLE_STEP` events to your callbacks, then resumes with
`DBG_CONTINUE` (and `RF`) so the target never notices the trap.

## Stealth — what it does and does not hide

`stealth::hide_debug_registers()` rebuilds the `NtGetContextThread` syscall
stub in a W^X dual-mapped page, redirects `ntdll!NtGetContextThread` with a
14-byte jump, and zeroes DR0–DR7 in any returned `CONTEXT_DEBUG_REGISTERS`
view, while the real registers stay armed and the hooks keep firing.
`stealth::hide_self_module()` unlinks the DLL from the PEB
`InLoadOrder/InMemoryOrder/InInitializationOrder` lists (locating the
version-dependent `HashLinks` field dynamically) and wipes the name strings.

Honest limits:

- masking affects **in-process API probes only** (`GetThreadContext` /
  `NtGetContextThread`); an attached debugger, a kernel driver, or another
  VEH reading its own exception `CONTEXT` still sees the real values;
- the register hook needs writable `ntdll .text` — **HVCI / memory integrity
  rejects it** (the function then returns `false`);
- module hiding removes list entries, not memory: page scans still find the
  code, and the DLL must never be unloaded;
- the internal VEH itself remains visible to anyone walking ntdll's
  undocumented VEH list; the external engine, while attached, is revealed by
  `NtQueryInformationProcess(ProcessDebugPort)` / `BeingDebugged`;
- what you gain regardless: **no modified bytes anywhere**, which is the point
  of hardware breakpoints.

## Limitations

- 4 slots total (architectural), process-wide (internal) / all-threads
  (external); per-thread filtering is not implemented.
- Data watchpoints must be aligned to their length (1/2/4/8 bytes).
- The internal engine takes full ownership of all four debug registers on
  every thread; anything else using them gets clobbered — don't combine it
  with the external engine on the same process.
- x64 only; WOW64 targets are not supported by the external engine
  (`Wow64GetThreadContext` not wired up).
- Don't call `set()` from `DllMain` (thread creation + cross-thread
  suspension are not loader-lock safe).
- Each hit costs an exception round-trip (~µs); fine for API/function-level
  hooking, not for tight-loop data watchpoints.

## Project layout

| File | Purpose |
|---|---|
| `hwbp.sln` + `vs\*.vcxproj` | Visual Studio 2022 solution (7 projects, x64 Debug/Release) |
| `hwbp_common.hpp` | DR7 encoding shared by both engines |
| `hwbp_internal.hpp` | In-process engine (VEH dispatch) + stealth helpers |
| `hwbp_external.hpp` | Out-of-process engine (debug-event loop) |
| `examples/redirect_example.cpp` | **"Jump to my own function"** redirect demo |
| `examples/internal_example.cpp` | **Inject-and-forget** internal demo DLL (self-starts, hooks, goes stealth) |
| `examples/internal_host.cpp` | *Optional* manual driver for the demo DLL |
| `examples/target.cpp` | Victim process for the external demo |
| `examples/external_example.cpp` | External driver for `target.cpp` |
| `examples/test_injector.cpp` | Test-only injector (`CreateRemoteThread`) to verify inject-and-forget |
| `test_smoke.cpp` | Non-interactive self-test (exec bp, watchpoint, redirect, stealth) |
| `build.bat` | CLI build (x64 Native Tools prompt) |
| `sln_build.bat` | CLI build of the whole solution (MSBuild, Debug + Release) |

## Test results

Windows 10 22H2 (x64), VS 2022 (v143), `/W4` clean, Debug **and** Release:

- `test_smoke.exe` — exec bp fires with argument read/rewrite, write
  watchpoint fires, `Rip` redirect jumps to our function and `remove()`
  restores the original, `GetThreadContext` masked while hooks keep firing,
  module vanishes from loader lists (14/14 checks).
- `redirect_example.exe` — live redirect of two functions, restore on
  remove.
- External demo — bp fires per call, args rewritten from the debugger,
  clean detach restores registers, target survives.
- Injection — `internal_example.dll` injected into a running process with no
  host: engine armed (redirect hook on `MessageBoxW`), stealth active
  (module hidden, DRs masked), target unaffected (see
  `%TEMP%\hwbp_internal_demo.log`).
