---
title: "GhostPatch"
ctf: "未知"
date: 2026-09-13
category: pwn
difficulty: hard
points: "未知"
flag_format: "题目未给出"
author: "team"
---

# GhostPatch

## Summary

本题先从 fw-gw 镜像口的 pcap 中恢复 FGT/1.0 自定义加密信道，再把历史会话中传输的调试版 ELF、libc 和动态加载器作为动态靶机的攻击面。

当前已验证：协议解密、文件提取、堆元数据覆盖、伪造 unlink、blob 表项重定向、libc 泄漏、栈泄漏和保存 RIP 覆盖。普通 ret-ROP 被 CET 的 SHSTK 阻断，最后读取 /flag 的 CET 兼容链尚未闭合，因此本文不伪造最终 flag。

动态服务地址以题目重新下发的地址为准：

~~~text
47.95.120.71:24839
~~~

## 一、附件和流量定位

压缩包中只有 capture.pcap。按 TCP 端口筛选后，关键控制台流为：

~~~text
192.168.16.128:46124 -> 192.168.16.9:9999
约 3503 个数据包，TCP 数据约 2,408,291 字节
~~~

TCP/8888 流是明文协议说明，TCP/9999 流是实际维护会话。历史会话中传输了：

~~~text
notes.txt
checksum.txt
fw_v2.bin
libc.so.6
ld-linux-x86-64.so.2
~~~

## 二、解密 FGT/1.0

### 2.1 DH 握手

9999 端口的明文握手：

~~~text
FGT/1.0 READY p=8348d41a7225 g=5
FGT/1.0 HELLO 3709a1d52d1d
FGT/1.0 OK d90673c26b
~~~

参数为：

~~~text
p = 144348819386917
g = 5
A = 0x3709a1d52d1d
B = 0xd90673c26b
~~~

p 只有 48 bit，可以离线求解离散对数。恢复出的值：

~~~text
a      = 8357903120266
b      = 144059249333483
shared = 129261817995543
~~~

共享秘密满足：

~~~text
shared = B^a mod p = A^b mod p
~~~

### 2.2 密钥和帧

shared 按大端整数编码后取 SHA-256 前 16 字节：

~~~text
K = SHA256(I2OSP(shared, big-endian))[:16]
  = b75ad015fa6436b6dd6479dcb9c660b4
~~~

两个方向使用独立 RC4 状态。每帧格式：

~~~text
[2 字节大端长度][RC4(ciphertext)]
~~~

长度字段不加密。8888 明文说明流恢复出的帧类型如下：

| 类型 | 名称 | 数据格式 |
| --- | --- | --- |
| 01 | GET | [u16 name_len][name] |
| 02 | META | [u64 size][32B sha256][u16 name_len][name] |
| 03 | DATA | [u32 seq][u32 len][data] |
| 04 | END | [32B sha256] |
| 05 | ERR | [u8 code] |
| 06 | LIST | [u16 count] 加多个文件名 |
| 07 | SHELL | 打开维护 shell |
| 08 | OKSH | shell 确认 |
| 09 | CIN | [u32 len][stdin_data] |
| 0a | COUT | [u32 len][stdout_data] |

文件按 0x400 字节分块传输。解密循环的核心形式：

~~~python
while True:
    n = read_be16(sock)
    ciphertext = read_exact(sock, n)
    plaintext = rc4.decrypt(ciphertext)
    parse_frame(plaintext)
~~~

### 2.3 历史会话中的实际内容

解密后的客户端操作顺序：

~~~text
SHELL
GET notes.txt
GET checksum.txt
GET fw_v2.bin
GET libc.so.6
GET ld-linux-x86-64.so.2
SHELL
CIN "5\n"
CIN "nightshift\n"
~~~

这解释了题目中的提示：调试版二进制没有普通入库记录，而是在该维护会话中被取出。

## 三、调试版 ELF 审计

fw_v2.bin 是 64 位 PIE ELF，启用了：

~~~text
IBT
SHSTK
stack canary
~~~

关键地址：

~~~text
main     = 0x1180
menu     = 0x1520
readn    = 0x1420
getnum   = 0x1470
tag_buf  = 0x4040
blobs    = 0x4140
~~~

初始化时：

~~~c
table = calloc(7, 0x10);
slot0 = calloc(1, 0x88);
~~~

表项逻辑上是：

~~~c
struct blob {
    uint64_t size;
    uint8_t *ptr;
};
~~~

slot 0 的自报信息：

~~~text
GhostPatch 2.4.1-debug selftest ok
build=%p table=%p slots=%d
~~~

verify 会原样 write blob，因此可以泄漏 PIE 和 table 地址。

菜单功能：

| 选项 | 功能 |
| --- | --- |
| 1 | stage：申请 blob 并读入数据 |
| 2 | verify：write(1, ptr, size) |
| 3 | hotfix：按偏移写入数据 |
| 4 | rollback：释放 blob |
| 5 | dispatch：读取 operator tag 后退出 |

stage 允许的大小范围为：

~~~text
0x88 <= size <= 0x418
~~~

hotfix 的边界检查近似为：

~~~c
if (offset > size || size - offset < length)
    reject();
readn(ptr + offset, length);
*(ptr + offset + length) = '\0';
~~~

当 offset 加 length 等于 size 时，第二个 NUL 写会越过 blob 末尾，覆盖下一个 chunk 的第一个字节。

seccomp 只允许：

~~~text
read, write, close, brk, exit, exit_group, openat
~~~

所以最终系统调用目标是：

~~~text
openat(AT_FDCWD, "/flag", O_RDONLY, 0)
read(fd, buf, n)
write(1, buf, n)
~~~

## 四、堆利用

### 4.1 构造 Q/B 相邻 chunk

根据 table 泄漏地址，利用脚本构造两个相邻的大 chunk：

~~~text
Q 请求大小 0x408
B 请求大小 0x418
q = table + 0x110 + 7 * 0x400
~~~

用户区中的关键可控值：

~~~text
Q + 0x08 = 0x400
Q + 0x10 = table
Q + 0x18 = table + 8
B + 0x3f8 = 0x21
~~~

对 Q 尾部执行：

~~~text
hotfix(slot_Q, offset=0x400, length=8, data=p64(0x400))
~~~

hotfix 自带的 NUL 终止字节会把 B 的 size 低字节从类似 0x421 改成 0x400。随后 rollback B，触发向前合并和伪造 unlink。

### 4.2 表项重定向

伪造 unlink 的实际效果是：

~~~text
slot_1.ptr = table
~~~

此时对 slot 1 的 hotfix 会改写 blob 表。继续写入：

~~~text
table + 0x20 = 0x408
table + 0x28 = q
~~~

即可令 slot 2 指向 Q。之后可以重复把其他 slot 指向任意已知地址。

### 4.3 libc 泄漏

Q 进入 unsorted bin 后，用户区出现 libc 链表指针。令 slot 2 指向 Q 并 verify：

~~~text
libc_base = unsorted_leak - 0x203b20
~~~

一次远端运行的示例：

~~~text
unsorted = 0x7f7e19403b20
libc     = 0x7f7e19200000
~~~

绝对地址会随 ASLR 变化，但偏移关系稳定。

## 五、栈泄漏和保存 RIP

拿到 libc 基址后，将表项指向：

~~~text
__environ = libc + 0x20ad58
~~~

verify 读出栈地址，再扫描 environ 附近的栈内存，搜索：

~~~text
pie + 0x1303
~~~

设扫描命中的地址单元为 A。根据 main 调用 menu 前后留下的两个 snprintf 参数：

~~~text
main 保存 RIP = A + 0xa0
伪造链起点   = A + 0xa8
~~~

远端验证结果表明，libc 泄漏、environ 泄漏、栈扫描和保存 RIP 覆盖均成功。

## 六、普通 ROP 为什么失败

已找到的常规 gadget：

~~~text
pop rax ; ret       = libc + 0xdd337
pop rdi ; ret       = libc + 0x10c08d
pop rsi ; ret       = libc + 0x110b7d
pop rdx ; ret       = libc + 0x8d6a
syscall ; ret       = libc + 0x99096
xchg edi, eax ; ret = libc + 0x11b145
~~~

先测试最短链 write(1, buf, 4)，buf 内容为 PWN!。verify 可以确认 ROP 数据和保存 RIP 已经写入，但服务没有输出 PWN!。

原因是 ELF 启用了 SHSTK。普通 ret-ROP 只能修改普通栈上的返回地址，不能同步修改 shadow stack；函数返回时校验失败，控制流无法按照伪造 ret 链继续执行。IBT 又要求间接 call/jmp 目标具有合法 ENDBR。

因此这里不能直接套用无 CET 程序的 ret2libc。

## 七、当前 CET 兼容攻击面

### 7.1 exit handler

libc 中可利用的退出处理器对象：

~~~text
__exit_funcs        = libc + 0x203680
__new_exitfn_called = libc + 0x204fa0
initial exit list   = libc + 0x204fc0
__run_exit_handlers = libc + 0x47910
~~~

exit list 中的函数指针采用指针混淆。已确认公式：

~~~text
mangled = rol(actual ^ fs:0x30, 17)
guard   = ror(mangled, 17) ^ actual
~~~

如果通过已有表项读写原语伪造 exit list，程序退出时可以通过真实 call 调用合法 ENDBR 函数，从而绕开直接伪造 ret 的 SHSTK 问题。

### 7.2 longjmp 上下文切换

关键函数：

~~~text
__longjmp_cancel = libc + 0x45140
~~~

它从 rdi 指向的上下文恢复 rbx、r12-r15、rsp、rbp、rdx，并跳转到经过指针混淆的目标地址。入口带 ENDBR，适合作为 exit handler 的间接调用目标。

当前难点是它不直接设置 rdi/rsi，而 read 和 write 需要正确的参数寄存器。

### 7.3 参数整理和 openat 方向

libc 加偏移 0x4b510 处存在一个带 ENDBR 的短函数：

~~~asm
xor eax, eax
xor edx, edx
tzcnt rax, rdi
add eax, 1
test rdi, rdi
cmove eax, edx
ret
~~~

当 rdi 为 0 时，它能保持 rdi 为 0 并清零 rdx。一个可能的多 exit-handler 链是：

~~~text
1. 令某个 handler 的参数为 "/flag"；
2. 用 flavor 2 调用 0x4b510，整理出 rdi=0、rdx=0；
3. 用另一个 handler 调用 openat；
4. 处理 openat 返回的 fd，再调用 read 和 write。
~~~

这条链还需要解决 fd 从 rax 到 read 的 rdi 传递，以及 read/write 的缓冲区参数。截至本文整理时，尚未成功读出 /flag。

## 八、关键偏移汇总

### fw_v2.bin

~~~text
main       0x1180
menu       0x1520
readn      0x1420
getnum     0x1470
tag_buf    0x4040
blobs      0x4140
~~~

### libc.so.6

~~~text
main_arena             0x203ac0
unsorted leak          0x203b20
__environ              0x20ad58
__exit_funcs           0x203680
__new_exitfn_called    0x204fa0
__exit_funcs_lock      0x204fa8
initial exit list      0x204fc0
__run_exit_handlers    0x47910
__longjmp_cancel       0x45140
parameter helper       0x4b510
setcontext             0x4a960
__start_context        0x5ef80
openat                 0x11b3d0
read                   0x11bb80
write                  0x11c690
close                  0x11c730
rtld-global pointer    0x202f88
~~~

### ld-linux-x86-64.so.2

~~~text
_rtld_global           0x38000
_rtld_global_ro        0x37aa0
_dl_fini               0x5380
~~~

## 九、当前结论

当前攻击链已经闭合到：

~~~text
pcap
  -> 破解 48 bit DH
  -> 解出双向 RC4
  -> 提取调试版 ELF/libc/ld
  -> banner 泄漏 PIE/table
  -> hotfix 末尾 NUL 覆盖
  -> 伪造 unlink
  -> blob 表项重定向
  -> unsorted bin 泄漏 libc
  -> environ 泄漏栈
  -> 定位并覆盖 main 保存 RIP
  -> SHSTK 阻断普通 ret-ROP
  -> 转向 exit-handler / longjmp CET 链
~~~

稳定地址关系：

~~~text
libc_base  = unsorted_leak - 0x203b20
environ    = libc_base + 0x20ad58
loader_base = rtld_global - 0x38000
保存 RIP    = 栈扫描命中位置 + 0xa0
伪造栈起点  = 保存 RIP + 8
~~~

最终的 openat、read、write 链还没有完成，所以本文是当前阶段 WP，最终 flag 尚未获得。

