/*
 * Direct Syscalls - Implementation (x64)
 *
 * Provides direct syscall execution without Win32 API shims.
 * Syscall numbers are resolved dynamically at runtime, and
 * per-call stubs are emitted in executable memory:
 *   mov r10, rcx; mov eax, <num>; syscall; ret
 */

#include "syscalls.h"
#include <stdio.h>

// ================================================================
// Syscall Number Resolution
// ================================================================

typedef struct _SYSCALL_ENTRY
{
    DWORD hash;
    DWORD syscallNumber;
    PVOID stub;            // Executable stub for this syscall
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

static SYSCALL_ENTRY g_Syscalls[16] = {0};
static BOOL g_SyscallsInitialized = FALSE;

// Simple hash function for function names
DWORD HashFunctionName(const char* name)
{
    DWORD hash = 0;
    while (*name)
    {
        hash = ((hash << 5) + hash) + (DWORD)(*name);
        name++;
    }
    return hash;
}

// Extract syscall number from ntdll.dll export
DWORD GetSyscallNumber(HMODULE hNtdll, const char* functionName)
{
    BYTE* pFunction = (BYTE*)GetProcAddress(hNtdll, functionName);
    if (!pFunction)
    {
        return 0xFFFFFFFF;
    }

    // x64 syscall stub pattern:
    // mov r10, rcx (4C 8B D1)
    // mov eax, <syscall_number> (B8 XX XX XX XX)
    // syscall (0F 05)

    if (pFunction[0] == 0x4C && pFunction[1] == 0x8B && pFunction[2] == 0xD1)
    {
        if (pFunction[3] == 0xB8)
        {
            // Extract syscall number from bytes 4-7
            return *(DWORD*)(pFunction + 4);
        }
    }

    return 0xFFFFFFFF;
}

// Emit an x64 syscall stub for the given number
static PVOID BuildSyscallStub(DWORD num)
{
    // mov r10, rcx; mov eax, imm32; syscall; ret
    // 4C 8B D1    B8 XX XX XX XX    0F 05    C3
    const SIZE_T kSize = 3 + 5 + 2 + 1; // 11 bytes
    BYTE code[16] = {0};
    SIZE_T i = 0;
    code[i++] = 0x4C; code[i++] = 0x8B; code[i++] = 0xD1;      // mov r10, rcx
    code[i++] = 0xB8;                                           // mov eax, imm32
    *(DWORD*)(code + i) = num; i += 4;
    code[i++] = 0x0F; code[i++] = 0x05;                         // syscall
    code[i++] = 0xC3;                                           // ret

    void* mem = VirtualAlloc(NULL, kSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, code, kSize);
    DWORD oldProt = 0;
    if (!VirtualProtect(mem, kSize, PAGE_EXECUTE_READ, &oldProt)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return NULL;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, kSize);
    return mem;
}

BOOL Syscalls_Initialize(void)
{
    if (g_SyscallsInitialized)
    {
        return TRUE;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        return FALSE;
    }

    // Resolve syscall numbers for critical functions
    const char* functions[] = {
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtClose",
        "NtReadVirtualMemory",
        "NtQuerySystemInformation",
        "NtFreeVirtualMemory",
        NULL
    };

    for (int i = 0; functions[i] != NULL && i < 16; i++)
    {
        DWORD num = GetSyscallNumber(hNtdll, functions[i]);
        if (num == 0xFFFFFFFF) { continue; }
        g_Syscalls[i].hash = HashFunctionName(functions[i]);
        g_Syscalls[i].syscallNumber = num;
        g_Syscalls[i].stub = BuildSyscallStub(num);
    }

    g_SyscallsInitialized = TRUE;
    return TRUE;
}

BOOL Syscalls_IsAvailable(void)
{
    return g_SyscallsInitialized;
}

// Get syscall entry by hash
PSYSCALL_ENTRY GetSyscallEntry(DWORD hash)
{
    for (int i = 0; i < 16; i++)
    {
        if (g_Syscalls[i].hash == hash)
        {
            return &g_Syscalls[i];
        }
    }
    return NULL;
}

// ================================================================
// Syscall Execution Helpers
// ================================================================

// Assembly is not required; stubs are emitted at runtime

// ================================================================
// Syscall Wrappers
// ================================================================

NTSTATUS Syscall_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        // Fallback to VirtualAllocEx
        LPVOID addr = VirtualAllocEx(ProcessHandle, *BaseAddress, (RegionSize ? *RegionSize : 0), AllocationType, Protect);
        if (addr)
        {
            if (BaseAddress) { *BaseAddress = addr; }
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtAllocateVirtualMemory"));
    if (!entry || !entry->stub)
    {
        // Fallback to VirtualAllocEx
        LPVOID addr = VirtualAllocEx(ProcessHandle, *BaseAddress, (RegionSize ? *RegionSize : 0), AllocationType, Protect);
        if (addr)
        {
            if (BaseAddress) { *BaseAddress = addr; }
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG))
            (entry->stub))(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS Syscall_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        // Fallback to WriteProcessMemory
        SIZE_T written = 0;
        BOOL ok = WriteProcessMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, &written);
        if (NumberOfBytesWritten) { *NumberOfBytesWritten = written; }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtWriteVirtualMemory"));
    if (!entry || !entry->stub)
    {
        SIZE_T written = 0;
        BOOL ok = WriteProcessMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, &written);
        if (NumberOfBytesWritten) { *NumberOfBytesWritten = written; }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))
            (entry->stub))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS Syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        // Fallback to VirtualProtectEx
        DWORD oldp = 0;
        BOOL ok = VirtualProtectEx(ProcessHandle,
                                   (BaseAddress ? *BaseAddress : NULL),
                                   (RegionSize ? *RegionSize : 0),
                                   NewProtect,
                                   &oldp);
        if (OldProtect) { *OldProtect = oldp; }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtProtectVirtualMemory"));
    if (!entry || !entry->stub)
    {
        DWORD oldp = 0;
        BOOL ok = VirtualProtectEx(ProcessHandle,
                                   (BaseAddress ? *BaseAddress : NULL),
                                   (RegionSize ? *RegionSize : 0),
                                   NewProtect,
                                   &oldp);
        if (OldProtect) { *OldProtect = oldp; }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG))
            (entry->stub))(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS Syscall_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        // Fallback to CreateRemoteThreadEx/CreateRemoteThread
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        typedef HANDLE (WINAPI *CRTEX)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
        CRTEX pCreateRemoteThreadEx = (CRTEX)(k32 ? GetProcAddress(k32, "CreateRemoteThreadEx") : NULL);
        HANDLE th = NULL;
        if (pCreateRemoteThreadEx)
        {
            th = pCreateRemoteThreadEx(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)StartRoutine, Argument, 0, NULL, NULL);
        }
        else
        {
            th = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)StartRoutine, Argument, 0, NULL);
        }
        if (th)
        {
            if (ThreadHandle) { *ThreadHandle = th; }
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtCreateThreadEx"));
    if (!entry || !entry->stub)
    {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        typedef HANDLE (WINAPI *CRTEX)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
        CRTEX pCreateRemoteThreadEx = (CRTEX)(k32 ? GetProcAddress(k32, "CreateRemoteThreadEx") : NULL);
        HANDLE th = NULL;
        if (pCreateRemoteThreadEx)
        {
            th = pCreateRemoteThreadEx(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)StartRoutine, Argument, 0, NULL, NULL);
        }
        else
        {
            th = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)StartRoutine, Argument, 0, NULL);
        }
        if (th)
        {
            if (ThreadHandle) { *ThreadHandle = th; }
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PPS_ATTRIBUTE_LIST))
            (entry->stub))(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS Syscall_NtClose(HANDLE Handle)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        return CloseHandle(Handle) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtClose"));
    if (!entry || !entry->stub)
    {
        return CloseHandle(Handle) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(HANDLE))(entry->stub))(Handle);
}

NTSTATUS Syscall_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        SIZE_T read = 0;
        BOOL ok = ReadProcessMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, &read);
        if (NumberOfBytesRead) { *NumberOfBytesRead = read; }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtReadVirtualMemory"));
    if (!entry || !entry->stub)
    {
        SIZE_T read = 0;
        BOOL ok = ReadProcessMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, &read);
        if (NumberOfBytesRead) { *NumberOfBytesRead = read; }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))
            (entry->stub))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS Syscall_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        // Fallback to ntdll!NtQuerySystemInformation via import
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        typedef NTSTATUS (NTAPI *PFN)(ULONG,PVOID,ULONG,PULONG);
        PFN p = (PFN)(ntdll ? GetProcAddress(ntdll, "NtQuerySystemInformation") : NULL);
        if (p)
        {
            return p(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        }
        return STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtQuerySystemInformation"));
    if (!entry || !entry->stub)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        typedef NTSTATUS (NTAPI *PFN)(ULONG,PVOID,ULONG,PULONG);
        PFN p = (PFN)(ntdll ? GetProcAddress(ntdll, "NtQuerySystemInformation") : NULL);
        if (p)
        {
            return p(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        }
        return STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(ULONG,PVOID,ULONG,PULONG))
            (entry->stub))(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS Syscall_NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType)
{
    if (!g_SyscallsInitialized && !Syscalls_Initialize())
    {
        BOOL ok = FALSE;
        if (FreeType & MEM_RELEASE)
        {
            ok = VirtualFreeEx(ProcessHandle, (BaseAddress ? *BaseAddress : NULL), 0, MEM_RELEASE);
        }
        else
        {
            ok = VirtualFreeEx(ProcessHandle, (BaseAddress ? *BaseAddress : NULL), (RegionSize ? *RegionSize : 0), MEM_DECOMMIT);
        }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    PSYSCALL_ENTRY entry = GetSyscallEntry(HashFunctionName("NtFreeVirtualMemory"));
    if (!entry || !entry->stub)
    {
        BOOL ok = FALSE;
        if (FreeType & MEM_RELEASE)
        {
            ok = VirtualFreeEx(ProcessHandle, (BaseAddress ? *BaseAddress : NULL), 0, MEM_RELEASE);
        }
        else
        {
            ok = VirtualFreeEx(ProcessHandle, (BaseAddress ? *BaseAddress : NULL), (RegionSize ? *RegionSize : 0), MEM_DECOMMIT);
        }
        return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    return ((NTSTATUS (NTAPI*)(HANDLE,PVOID*,PSIZE_T,ULONG))
            (entry->stub))(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

#ifdef __cplusplus
}
#endif
