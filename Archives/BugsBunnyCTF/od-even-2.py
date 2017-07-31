#!/usr/bin/python
from pwn import *
import random
import os
import sys

r = remote("34.253.165.46",1994)
pp = 0
r.recvuntil("2)even")
r.sendline("2")
r.recvuntil("number:")
r.sendline("0")
r.recvuntil("is: ")
arg1 = int(r.recv(2))
log.info("ARG1: " + str(arg1))
test = r.recv()
print test
if "good Keep going" in test:
	pp = pp + 1
#r.recvuntil("number:")
r.sendline("0")
r.recvuntil("is: ")
arg2 = int(r.recv(2))
log.info("ARG2: " + str(arg2))
test = r.recv()
print test
if "good Keep going" in test:
	pp = pp + 1
r.sendline("0")
r.recvuntil("is: ")
arg3 = int(r.recv(2))
log.info("ARG3: " + str(arg3))
test = r.recv()
print test
if "good Keep going" in test:
	pp = pp + 1

win = pp


def lol(t,a1,a2,a3):
	random.seed(t)

	i = 0
	big_list = []
	for i in range(0,101):
		big_list.append(random.randrange(0,100))
	if(big_list[0] == a1 and big_list[1] == a2 and big_list[2] == a3):
		print t
		return big_list
	else:
		return 0
#	return big_list
p = 0

for p in range(0,10000000):
	x = lol(p,arg1,arg2,arg3)
	if(x == 0):
		continue
	else:
		break

finale = []

#big_list = lol(1005)
print x
for i in range(len(x)):
	if x[i]%2 == 0:
		finale.append('0')
	else:
		finale.append('1')
print finale
print str(len(finale))
for i in range(len(finale) - 1-3):
	#print r.recvuntil("number:")
	r.sendline(finale[i+3])
#	print r.recvuntil("number:")
	print r.recv()
	win = win + 1
	log.info("Count: " + str(win))
#	if(win == 48):
#		r.interactive()
r.interactive()
