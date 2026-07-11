# CTF libc debug info 配置

## 通用流程

### 1. 确认 libc 版本

```bash
strings libc.so.6 | grep "GNU C Library"
# 例: GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1.6) stable release version 2.27.
```

### 2. 下载 debug 包

```bash
VER="2.27-3ubuntu1.6"
wget "http://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc6-dbg_${VER}_amd64.deb"
mkdir libc_dbg && cd libc_dbg
ar x ../libc6-dbg_${VER}_amd64.deb && tar xf data.tar.xz
mv ./usr/lib/debug ./ && rm -rf usr *.tar.xz debian-binary control md5sums post*
```

### 3. 创建 build-id 符号链接

```bash
# 取 build-id 前 2 字符为目录名，剩余为文件名 + .debug
readelf -n libc.so.6   | grep -oP 'Build ID: \K(\w+)'  # → f7307432a8b1...
readelf -n ld.so        | grep -oP 'Build ID: \K(\w+)'  # → 9ea8014cf020...

# 前 2 字符 / 剩余.debug
# f7307432... → .build-id/f7/307432a8b162377e77a182b6cc2e53d771ec4b.debug
# 9ea8014c... → .build-id/9e/a8014cf02021a29e57aa3e0512e9bb6e30541d.debug

mkdir -p libc_dbg/debug/.build-id/{f7,9e}
ln -sf ../../lib/x86_64-linux-gnu/libc-2.27.so  libc_dbg/debug/.build-id/f7/307432a8b162377e77a182b6cc2e53d771ec4b.debug
ln -sf ../../lib/x86_64-linux-gnu/ld-2.27.so    libc_dbg/debug/.build-id/9e/a8014cf02021a29e57aa3e0512e9bb6e30541d.debug
```

> **常见错误**: build-id 文件名手动输入极易抄错，建议从 `readelf` 输出直接复制。

### 4. 配置

**`.gdbinit`（手动调试）**：
```
set debug-file-directory /absolute/path/to/libc_dbg/debug
```

**pwntools `gdb.attach()`（脚本调试）**：
```python
gdb.attach(io, gdbscript=f'''
set debug-file-directory {os.path.abspath("libc_dbg/debug")}
nosharedlibrary
sharedlibrary
''')
```

> **关键**: `gdb.attach()` 的 gdbscript 在 attach **之后**执行，此时共享库已加载完毕。仅设 `debug-file-directory` 不够，必须 `nosharedlibrary` 丢弃 → `sharedlibrary` 重建才能触发 debug info 重新查找。

### 5. 验证

```
(gdb) start / attach 后
(gdb) info functions malloc
# 应看到 __libc_malloc、File malloc.c: 等源文件信息
```

## 原理

- GDB 通过 **build-id**（非文件路径）匹配 detached debug info
- 查找路径：`$debug-file-directory/.build-id/XX/XXXX...XXXX.debug`
- `.gnu_debuglink` 跨发行版路径不匹配，不可靠
- `sharedlibrary` 不会重载已加载库的 debug info；必须 `nosharedlibrary` 清空再重建
