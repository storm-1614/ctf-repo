from pwn import *

elf = ELF("./service")
elf.got["read"]
