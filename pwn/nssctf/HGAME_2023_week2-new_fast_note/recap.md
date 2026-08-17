# new_fast_note(HGAME 2023 week2)全链路复盘

## 0. 题目与环境

- 二进制:`vuln`,64 位 PIE,符号未剥离
- libc:**glibc 2.31**(`libc-2.31.so`,stripped,但 `.dynsym` 保留,偏移可用 `readelf` 离线算)
- 漏洞:**UAF** —— `delete_note` free 后不清 `notes[i]`,导致已 free 的 chunk 仍被引用

## 1. 程序功能(逆向结果)

| 函数 | 行为 | 限制 |
|------|------|------|
| `add_note(index, size, content)` | `malloc(size)` + `read(0, ptr, size)`,指针存 `notes[index]` | `index ≤ 0x13`,`size ≤ 0xff` |
| `delete_note(index)` | `free(notes[index])`,**不清指针(UAF)** | `index ≤ 0xf` |
| `show_note(index)` | `puts(notes[index])` | `index ≤ 0xf` |

菜单:1=add, 2=delete, 3=show, 4=exit。全局数组 `notes[20]`。

## 2. 攻击链总览

```
unsortedbin 泄漏 libc base
  → 灌满 tcache 0x30,溢出进 fastbin
  → fastbin 内 double-free 成环(绕过 fasttop)
  → 掏空 tcache → 第 8 次 malloc 触发 stash 把环搬进 tcache
  → read 在 stash 之后写 → 把返回 chunk 的 fd 改成 __free_hook
  → 连续 malloc 走链,第 3 次返回 __free_hook → 写入 system
  → free("/bin/sh") → system("/bin/sh") → shell
```

## 3. 关键偏移(libc-2.31,readelf 离线可查,无需 debug info)

| 符号/对象 | 偏移 |
|-----------|------|
| `system` | `0x52290` |
| `__free_hook` | `0x1eee48` |
| `__malloc_hook` | `0x1ecb70` |
| `main_arena`(unsortedbin 链头 = main_arena+0x60) | `0x1ebb80`(=0x1ecbe0-0x60) |
| 泄漏值换算 | `libc_base = leak - 0x1ecbe0` |

## 4. 详细步骤

### 4.1 泄漏 libc base

`add` 8 个 `0xff` 请求(实际 chunk `0x110`),`free(9); free(0..6)`:
- 前 7 个填满 tcache 0x110 桶(上限 7)
- 第 8 个(free(6))**溢出进 unsortedbin**,其 `fd`/`bk` 写入 `main_arena+0x60`
- `show(6)`(UAF,notes[6] 还指着它)→ `puts` 打出 `0x7f...` 地址
- `libc_base = u64(leak) - 0x1ecbe0`

### 4.2 制造 double-free 场地(fastbin 成环)

`add`/`free` 一批 `0x20` 请求(实际 chunk `0x30`):
- `free(0..6)` → 填满 tcache 0x30(7 个)
- `free(7)` → tcache 满 → **溢出进 fastbin 0x30**
- `free(8)`(备用块)→ fastbin:`[8' → 7']`
- `free(7)`(**UAF 双 free**)→ fasttop 检查(表头=8'≠7')通过 → fastbin:`[7' ↔ 8']` 成环

**为什么能双 free**:fastbin 无 key 检查,只有 fasttop(不能 free 表头)。两次 free 时表头都是对方,放行。

### 4.3 把环搬进 tcache + 污染 fd(stash 时序)

- 7 次 `add(0x20)` → **掏空** tcache 0x30
- 第 8 次 `add(7, 0x20, p64(free_hook))`:
  1. malloc 从 fastbin 取 `7'` 返回
  2. glibc **stash**:tcache 有空位 → 把 fastbin 剩余环逐个搬进 tcache(塞满 7 个)
  3. `read` 在 **stash 之后** 才写 → 把 `7'` 的 fd 覆盖成 `__free_hook`,**幸存**
- 此时 tcache 链:`8' → 7' → __free_hook → ...`

**关键机制**:stash = malloc 从 fastbin 取 chunk 时,若 tcache 对应桶有空位,把 fastbin 剩余链表搬进 tcache。发生在 malloc 内部、read 之前。

### 4.4 走链 → 写 __free_hook → 触发

- `add(8, 0x20, "aaa")` → 返回 `8'`
- `add(9, 0x20, "aaa")` → 返回 `7'`
- `add(10, 0x20, p64(system_addr))` → **直接返回 `__free_hook`** → 写入 `system`
- `free(0)`(notes[0]=`/bin/sh`)→ 调用 `__free_hook` → `system("/bin/sh")` → **shell**

## 5. 用到的核心知识点

| 知识点 | 一句话 |
|--------|--------|
| chunk 结构 | `malloc(n)` 返回指针在 chunk 头后 0x10,size 字段含 P 位 |
| fd 复用 | free 后用户数据区开头 8 字节被改写为链表 next |
| tcache | 单向链表,头插法,**后进先出 LIFO**,每桶上限 7 |
| tcache key 检查 | free 时检查 chunk 的 key(=tcache 地址)是否已在桶里,是则报 double free |
| 绕过 key | 让 chunk 在第二次 free 前离开 tcache(被 malloc 走/溢出进 fastbin) |
| fastbin | 单向链表 LIFO,无 key,只有 fasttop(不能 free 表头) |
| 绕过 fasttop | `free(A); free(B); free(A)`,两次 free 时表头都不是 A → 成环 |
| stash | malloc 从 fastbin 取时,tcache 有空位则把 fastbin 剩余链搬进 tcache |
| 时序 | stash 在 malloc 内部、read 之前 → read 写的 fd 会覆盖 stash 写的 next,幸存 |
