/*
 * Direct Syscalls - SysWhispers3 Style Implementation
 *
 * This provides direct syscall stubs to bypass EDR userland hooks.
 * Based on SysWhispers3 by @klezVirus
 *
 * These syscalls bypass ALL userland API hooks including:
 * - VirtualAllocEx → NtAllocateVirtualMemory
 * - WriteProcessMemory → NtWriteVirtualMemory
 * - CreateRemoteThread → NtCreateThreadEx
 * - VirtualProtectEx → NtProtectVirtualMemory
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" {
#endif

// ================================================================
// NTSTATUS Return Codes
// ================================================================

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ================================================================
// NT Structures
// ================================================================

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// CLIENT_ID is already defined in winternl.h, no need to redefine

// ================================================================
// Direct Syscall Function Prototypes
// ================================================================

/**
 * NtAllocateVirtualMemory - Allocate memory in target process
 * Bypasses VirtualAllocEx hooks
 */
EXTERN_C NTSTATUS Syscall_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

/**
 * NtWriteVirtualMemory - Write to target process memory
 * Bypasses WriteProcessMemory hooks
 */
EXTERN_C NTSTATUS Syscall_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

/**
 * NtProtectVirtualMemory - Change memory protection
 * Bypasses VirtualProtectEx hooks
 */
EXTERN_C NTSTATUS Syscall_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

/**
 * NtCreateThreadEx - Create thread in target process
 * Bypasses CreateRemoteThread hooks
 */
EXTERN_C NTSTATUS Syscall_NtCreateThreadEx(
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
    PPS_ATTRIBUTE_LIST AttributeList
);

/**
 * NtClose - Close handle
 * Bypasses CloseHandle hooks
 */
EXTERN_C NTSTATUS Syscall_NtClose(
    HANDLE Handle
);

/**
 * NtReadVirtualMemory - Read target process memory
 * Bypasses ReadProcessMemory hooks
 */
EXTERN_C NTSTATUS Syscall_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

/**
 * NtQuerySystemInformation - Query system information
 * Bypasses standard API hooks
 */
EXTERN_C NTSTATUS Syscall_NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

/**
 * NtFreeVirtualMemory - Free memory in target process
 * Bypasses VirtualFreeEx hooks
 */
EXTERN_C NTSTATUS Syscall_NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

// ================================================================
// Helper Functions
// ================================================================

/**
 * Initialize syscall subsystem
 * Resolves syscall numbers and prepares stubs
 */
BOOL Syscalls_Initialize(void);

/**
 * Check if syscalls are available
 */
BOOL Syscalls_IsAvailable(void);

#ifdef __cplusplus
}
#endif

#endif // SYSCALLS_H
