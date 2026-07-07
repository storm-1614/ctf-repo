from pwn import *

context(os="linux", arch="amd64", log_level="debug")
io = process("./ezheap")
#io = remote('node5.anna.nssctf.cn', 23338)
#context.gdb_binary = "/bin/pwndbg"

libc = ELF("./libc.so.6")


def edit(index: int, size: int, content: bytes):
    io.recvuntil(b"Choice:")
    io.sendline(b"4")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.send(content)


def add(index: int, size: int, name: bytes, content: bytes):
    io.recvuntil(b"Choice:")
    io.sendline(b"1")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.recvuntil(b"Name:")
    io.sendline(name)
    io.recvuntil(b"Content:")
    io.sendline(content)


def show(index: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"3")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())


def delete(index: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"2")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())


gdb.attach(io)
add(0, 0x10, b"A", b"A")
add(1, 0x10, b"B", b"B")
add(2, 0x10, b"C", b"C")

pause()
io.interactive()
