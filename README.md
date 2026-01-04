# DbgNexum - Shellcode Injection

**DbgNexum** is a Proof-of-Concept for injecting shellcode using the Windows Debugging API and Shared Memory (File Mapping). It avoids writing and reading remote memory directly, instead using context manipulation to force the target process to load and execute the payload itself.

## Overview
The injector attaches to a target process and creates a suspended thread. Through a debug loop, it sets a Hardware Breakpoint to trap execution at a specific return address. At each trap, the injector modifies the CPU registers to mimic function calls, orchestrating a sequence of Windows API function calls inside of the target process. 

> At the time of writing this README, I tested the technique against MDE and Elastic, neither of which detected it.

### Key Features
- **No `WriteProcessMemory` / `VirtualAllocEx`:** The payload is transferred via `CreateFileMapping` and `MapViewOfFile`.
- **No `ReadProcessMemory`:** The approach gets all the key information from the thread context.

## Usage
> The PoC uses an XORed msfvenom shellcode that spawns "calc.exe". But please use your own shellcode!

1. Include your shellcode (and XOR key) in `shellcode.h`
2. Find the Process ID of the target.
3. Run the injector:

```cmd
DbgNexum.exe <PID>
```

**Example Output:**

```text
[i] Section 'MZ' created and shellcode copied
[+] Bait thread created. Setting HWBP on FileTimeToSystemTime
[i] Execution Redirected:
|-> [0] Preparation & anchoring stack
|-> [1] Setting HWBP & buffer alloc
|-> [2] Copying File-Mapping name
|-> [3] Zeroing stack slot
|-> [4] Opening handle to named file mapping
|-> [5] Mapping payload into mem. with exec. perm.
|-> [6] Cleanup & shellcode execution
[+] Successfully detached from process 19256
[i] Orchestration complete.
```

## How It Works
The execution flow is a constant back and forth between the injector's Debug Loop and the target process.

**Injection Stages**

The `DebugLoop` function contains the main injection logic and orchestrates the "state machine":

**0. Preparation:**
- The injector saves the current stack pointer to reuse for each stage
- To get the return address of the anchored stack, we set a trap flag and set execution to an instant `ret` call.

**1. Allocation:**
- Set HWBP on the return address of the anchored stack, to get notified when a called function returns.
- Prepare and force thread to call `LocalAlloc` to (obviously) allocate a small buffer.

**2. Data Setup:**
- Prepare and force thread to call `memcpy` to copy the string `MZ` into the previously allocated buffer.

**3. Stack Prep:**
- Force thread to call `memset` to zero out a stack slot. This is in preparation of stage 5, which will call `MapViewOfFile`. Since the function will use >4 arguments, the 5th arg is passed via the stack (which we set here).

**4. Open Mapping:**
- Force thread to call `OpenFileMappingA` using the `MZ` name, "created" in stage 2 & 3.

**5. Map Payload:**
- Forces the target to call `MapViewOfFile`. This maps the shared memory section (containing the shellcode) into the target's address space with `EXECUTE` permissions.

**6. Execution:**
- Redirects `RIP` to the address returned by `MapViewOfFile`.
- Clears debug registers and detaches.