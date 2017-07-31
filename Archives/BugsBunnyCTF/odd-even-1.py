#!/usr/bin/python
from pwn import *
import random
import os
import sys

def lol(t):
	random.seed(t)

	i = 0
	big_list = []
	for i in range(0,101):
		big_list.append(random.randrange(0,100))
	return big_list
p = 0

#for p in range(0,10000):
#	x = lol(p)
#	if(x == 1):
#		print big_list
#
finale = []
big_list = lol(1005)
for i in range(len(big_list)):
	if big_list[i]%2 == 0:
		finale.append('0')
	else:
		finale.append('1')
print finale
print str(len(finale))
r = remote("34.253.165.46",1995)
r.recvuntil("2)even")
r.sendline("2")
win = 0
for i in range(len(finale) - 1):
	print r.recvuntil("number:")
	r.sendline(finale[i])
	win = win + 1
	log.info("Count: " + str(win))
r.interactive()
