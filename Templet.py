#!/usr/bin/python

from Pwn import *
# when binary doesn't have nx eable or mprotect/nmap is on got table
# from Shellcode import *

p = Pwn(host='example.com',port=8888)
# if you want to pwn local
p = Pwn(isconnect=False)

def ploit():
	# some ploit code
	p.pack(0xcafebabe)
	p.write('A'*4)

	write_addr = p.unpack(p.recv(4))
	system_addr = write_addr - offset

	print '[+] write() :',hex(write_addr)
	print '[+] system() :',hex(system_addr)

	p.io()

exploit()