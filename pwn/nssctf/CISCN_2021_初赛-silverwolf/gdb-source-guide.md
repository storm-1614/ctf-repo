# GDB 源码调试：为什么 `directory` 不生效？

## 问题

`.gdbinit` 中设置了 `directory /data/project/read_sc/glibc-2.27`，但 `l malloc` 仍然报错找不到源文件：

```
file: "dl-minimal.c", line number: 50, symbol: "malloc"
⚠️ warning: 45    dl-minimal.c: No such file or directory
file: "malloc.c", line number: 3038, symbol: "__GI___libc_malloc"
⚠️ warning: 3033    malloc.c: No such file or directory
```

## 根本原因

### `directory` 做了什么

`directory` 将指定目录加入 **源文件搜索路径**（source path）。当 GDB 查找源文件时，在搜索路径的每个目录下按 **basename**（文件名）查找，**不做路径前缀替换，也不递归搜索子目录**。

```
directory /data/project/read_sc/glibc-2.27

GDB 实际搜索：
  /data/project/read_sc/glibc-2.27/dl-minimal.c   ← 找不到，因为文件在 elf/ 下
  /data/project/read_sc/glibc-2.27/malloc.c        ← 找不到，因为文件在 malloc/ 下
```

### 编译路径 vs 本地路径

glibc 是 Ubuntu 维护者在构建服务器上编译的。DWARF 调试信息中硬编码了**构建服务器上的原始路径**：

```
DW_AT_comp_dir: /build/glibc-CVJwZb/glibc-2.27/elf/
DW_AT_name:     dl-minimal.c
→ 完整路径:      /build/glibc-CVJwZb/glibc-2.27/elf/dl-minimal.c
```

这个路径在你的机器上不存在。你的源码在 `/data/project/read_sc/glibc-2.27/`。

## 解决方案：`set substitute-path`

```
set substitute-path /build/glibc-CVJwZb/glibc-2.27 /data/project/read_sc/glibc-2.27
```

`substitute-path` 做**路径前缀替换**——GDB 从 debug info 读到路径后，将匹配的前缀替换为本地路径，**保留子目录结构**：

```
/build/glibc-CVJwZb/glibc-2.27/elf/dl-minimal.c
         ↓ 前缀替换
/data/project/read_sc/glibc-2.27/elf/dl-minimal.c   ← 文件存在 ✓

/build/glibc-CVJwZb/glibc-2.27/malloc/malloc.c
         ↓ 前缀替换
/data/project/read_sc/glibc-2.27/malloc/malloc.c    ← 文件存在 ✓
```

## 如何找到正确的编译路径

用 `readelf` 查看 libc 中的 `DW_AT_comp_dir`：

```bash
readelf --debug-dump=info ./libc-2.27.so 2>/dev/null \
  | grep "DW_AT_comp_dir" \
  | sed 's/.*: //' \
  | sed 's|/[^/]*$||' \
  | sort -u
```

找到共同的根路径（例如 `/build/glibc-CVJwZb/glibc-2.27`），然后映射到你本地的 glibc 源码目录。

## 两个命令的对比

| | `directory` | `set substitute-path` |
|---|---|---|
| 机制 | 加入搜索目录列表 | 路径前缀替换 |
| 子目录 | 不搜索 | 自动保留 |
| 适用场景 | 源码在单个目录 | 源码有多级子目录（如 glibc） |
| 查找方式 | 按 basename 匹配 | 按完整路径匹配 |

## 参考

- 当前 `.gdbinit` 配置已使用 `set substitute-path` 替代 `directory`
- 源码目录：`/data/project/read_sc/glibc-2.27/`
- 编译根路径：`/build/glibc-CVJwZb/glibc-2.27/`
