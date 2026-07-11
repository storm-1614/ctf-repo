from pwn import *

io = process("./ez_uaf")
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


add(0x20, b"a", b"a")
print("add(0)")

gdb_debug()
io.interactive()
