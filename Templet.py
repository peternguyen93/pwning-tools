#!/usr/bin/python

from Pwn import *
# when binary doesn't have nx eable or mprotect/nmap is on got table
# from Shellcode import *

p = Pwn(host='example.com',port=8888)

def exploit():
	p.connect()
	# some ploit code
	p.pack(0xcafebabe)
	p.write('A'*4)

	write_addr = p.unpack(p.recv(4))
	system_addr = write_addr - offset

	print '[+] write() :',hex(write_addr)
	print '[+] system() :',hex(system_addr)

	p.io() # interact with socket

exploit()