extern SW2_GetSyscallNumber:PROC

.code

NtOpenProcessToken proc
	mov [rsp+8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 33AD0704h
	call SW2_GetSyscallNumber
	add rsp, 28h
	mov rcx, [rsp +8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall
	ret
NtOpenProcessToken endp

NtAdjustPrivilegesToken proc
    mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 04997D6BAh
	call SW2_GetSyscallNumber
	add rsp, 28h
	mov rcx, [rsp +8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall
	ret
NtAdjustPrivilegesToken endp

NtOpenProcess proc
    mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 2613078Ch
	call SW2_GetSyscallNumber
	add rsp, 28h
	mov rcx, [rsp +8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall
	ret
NtOpenProcess endp

NtWriteVirtualMemory proc
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00F9114F3h
	call SW2_GetSyscallNumber
	add rsp, 28h
	mov rcx, [rsp +8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall
	ret
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
	mov [rsp+8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 04FDD415Bh
	call SW2_GetSyscallNumber
	add rsp, 28h
	mov rcx, [rsp+8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall
	ret
NtProtectVirtualMemory endp

NtCreateFile proc
	mov [rsp +8], rcx
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0187AEB6Dh
	call SW2_GetSyscallNumber
	add rsp, 28h
	mov rcx, [rsp +8]
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall
	ret
NtCreateFile endp

end
