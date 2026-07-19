from pwn import *

libc = ELF("./libc.so.6")
context.arch = 'amd64'

for addr in libc.search(asm('mov rax, 0xf;syscall')):
    print(hex(addr))
