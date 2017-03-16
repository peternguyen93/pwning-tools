#!/usr/bin/python

# - This is Pwn module that helps you to build faster and easier payloads.
# - Pwn module works like a Interface (Abstract Class) that create a templet
# that you can base on it and create your payload.
# - Pwn module also support you create format string exploit easily, support x86 and x86-64
# - This module includes collection of shellcode, you can easily use it for your
# payload, supports Linux x86 and x86-64, arm will support later.
# - To install this module, you just copy this module to /usr/lib/python2.7 or python 3.1

# Requires: pyelftools,capstone,keystone

# Author : Peternguyen
# Version : 2.0

# /bin/sh -c "echo shell >&4; sh <&4 >&4"

from __future__ import print_function
from subprocess import Popen,PIPE,STDOUT
from ctypes import *
from struct import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from Shellcode import *
import telnetlib
import fcntl
import urllib2
import urllib
import string
import select
import pty,tty
import json
import os
import re
import sys

LIBC_REPO = 'http://libc.babyphd.net/' # own libc repo

# use this key to authen with libc.babyphd.net
def load_auth_key():
	default_path = os.path.expanduser('~/.libc_collection_authkey')
	try:
		if os.path.exists(default_path):
			'''
				{'authkey':'1234567890abcbef'}
			'''
			file_handle = open(default_path,'r')
			key = json.load(file_handle)['authkey']
			file_handle.close()
			return key
	except KeyError :
		print('"authkey" doesn\'t exists')
	return None

class ELFTable(dict):
	def __init__(self,*arg,**kw):
		super(ELFTable, self).__init__(*arg, **kw)

	def __getitem__(self,key):
		# override this method to perform new search method act like this example:
		# >>> got = ELFTable({
		# ...             '__gmon_start__': 6294744,
		# ...             '_IO_getc': 6294752,
		# ...             'puts': 6294704,
		# ...             '__printf_chk': 6294760,
		# ...             'memset': 6294728
		# ... })
		# >>> got['getc'] # will return '_IO_getc' value
		# 6294752
		res = {}
		for _key in self.keys():
			if key in _key: # find item has there key look like my key
				res[key] = dict.__getitem__(self,_key)
		# one result
		if len(res) == 1:
			return res.values()[0]
		# more than one result
		else:
			for _key in res:
				if key == _key: # find item has there key is matched my key
					return res[_key]
			# raise exception when i couldn't find any matched key
			raise Exception("There are many result has returned",res)

		raise KeyError('%s is\'t found' % key)
	
	def __call__(self,arg):
		# istead using key lookup, user can lookup value as a function
		# >>> got = ELFTable({
		# ...             '__gmon_start__': 6294744,
		# ...             '_IO_getc': 6294752,
		# ...             'puts': 6294704,
		# ...             '__printf_chk': 6294760,
		# ...             'memset': 6294728
		# ... })
		# >>> got('getc') # will return '_IO_getc' value
		return self.__getitem__(arg)

class ELF(object):
	def __init__(self,elf_file):
		real_path = os.path.realpath(elf_file)
		if not os.path.exists(real_path):
			raise Exception('File Not Found')

		self.got = ELFTable()
		self.plt = ELFTable()
		# parsing symtab if it present in ELF file (-ggdb is enable)
		# symbol is dict that store all function of program
		self.symbol = ELFTable()
		self.__elfparsing(real_path)

	def __dump_plt_section(self,elf,plt_sec_name):
		plt_section = elf.get_section_by_name(plt_sec_name)
		if not plt_section:
			raise Exception('Binary doesn\'t have %s section' % plt_sec_name)
		plt_address = plt_section.header['sh_addr'] # get plt base address
		entry_align = plt_section.header['sh_addralign'] # plt entry size
		plt_offset = plt_section.header['sh_offset'] # get plt offset
		return plt_address,plt_offset,entry_align

	def __get_symtab(self,elf):
		# p = Pwn(elf='./bin')
		# p.elf.symbol['main'] => address of main function
		# all object like global variable and function
		# will stored in this symbol table
		symtab = elf.get_section_by_name('.symtab')
		if not isinstance(symtab, SymbolTableSection):
			# raise Exception('Can\'t dump .symtab')
			print('[LOG] .symtab isn\'t loaded')
			return None

		for symbol in symtab.iter_symbols():
			if symbol.entry['st_info']['bind'] == 'STB_GLOBAL' and \
				(
					symbol.entry['st_info']['type'] == 'STT_FUNC' or  \
					symbol.entry['st_info']['type'] == 'STT_OBJECT'
				) and symbol.entry['st_value']:

				self.symbol[symbol.name] = symbol.entry['st_value']

	def __dynamic_tags(self, elf, key="DT_RPATH"):
		for section in elf.iter_sections():
			if not isinstance(section, DynamicSection):
				continue
			for tag in section.iter_tags():
				if tag.entry.d_tag == key:
					return True
		return False

	def __is_pie(self,elf):
		if self.__dynamic_tags(elf,"EXEC") == "Enabled":
			return True
		if "ET_DYN" in elf.header['e_type']:
			if self.__dynamic_tags(elf,"DT_DEBUG") == "Enabled":
				return True
		return False

	def __elfparsing(self,path):
		# parsing elf file to dump got and plt table
		with open(path,'r') as pfile:
			elf = ELFFile(pfile)
			if not elf:
				raise Exception('File %s is not elf file' % path)

			# get rellocation section 
			# auto set self.mode base on arch of elf binary
			self.mode = 0 if elf.elfclass == 32 else 1

			plt_address,plt_offset,entry_align = self.__dump_plt_section(elf,'.plt')

			# dump symbol table
			symbol_sec = elf.get_section_by_name(b'.dynsym')
			# can dump ?
			if not isinstance(symbol_sec, SymbolTableSection):
				raise Exception('Can dump .dynsym')

			# get reallocation section to dump got table
			# for RERLO is enabled with option FULL
			# .rel.plt or rela.plt is not exist
			reladyn_name = b'.rel.plt' if self.mode == 0 else b'.rela.plt'
			reladyn = elf.get_section_by_name(reladyn_name)
			# can dump ?
			if not isinstance(reladyn, RelocationSection):
				print('[!] RERLO : enable')
				reladyn_name = b'.rel.dyn' if self.mode == 0 else b'.rela.dyn'
				# getting info again
				reladyn = elf.get_section_by_name(reladyn_name)
				if not isinstance(reladyn, RelocationSection):
					raise Exception('Can\'t dump RelocationSection')
				# getting plt_address again when RELRO FULL is enable
				plt_address,plt_offset,entry_align = self.__dump_plt_section(elf,'.plt.got')

				# dumping GOT (Global Offset Table) first
				for reloc in reladyn.iter_relocations():
					got_func_name = symbol_sec.get_symbol(reloc['r_info_sym']).name
					self.got[got_func_name] = reloc['r_offset']

				# get arch info
				elf_arch = elf.get_machine_arch()
				arch = 'x86_64' if elf_arch == 'x64' else elf_arch
				# when PIE is enable
				if self.__is_pie(elf):
					print('[!] PIE : enable')
					# save current offset of elf file
					old_file_offset = pfile.tell()
					# see to .plt.got offset
					pfile.seek(plt_offset,0)
					# read code from .plt.got
					code = pfile.read(entry_align)
					code = Shellcode(code,arch)
					# disassembly and extract offset
					asm_code = str(code.disas())
					_m = re.findall(r'(0x[0-9a-f]+)',asm_code)
					if len(_m) < 3:
						raise Exception("Can't extract .plt.got from binary")
					# from PLT to GOT
					got_offset = int(_m[1],16)
					step = int(_m[2],16) - int(_m[0],16)

					for i in xrange(len(self.got)):
						got_addr = plt_address + got_offset + step
						for k in self.got:
							if self.got[k] == got_addr:
								# found correct symbol of PLT
								self.plt[k] = plt_address
								break
						plt_address += entry_align
				# when PIE is disable
				else:
					print('[!] PIE : disable')
					# save current offset of elf file
					old_file_offset = pfile.tell()
					# see to .plt.got offset
					pfile.seek(plt_offset,0)
					for i in xrange(len(self.got)):
						# read code from .plt.got
						code = pfile.read(entry_align)
						code = Shellcode(code,arch)
						# disassembly and extract offset
						asm_code = str(code.disas())
						_m = re.findall(r'(0x[0-9a-f]+)',asm_code)
						if len(_m) < 3:
							raise Exception("Can't extract .plt.got from binary")
						# from PLT to GOT
						got_addr = int(_m[1],16)
						for k in self.got:
							if self.got[k] == got_addr:
								# found correct symbol of PLT
								self.plt[k] = plt_address
								break
						plt_address += entry_align
				# restore old offset
				pfile.seek(old_file_offset,0)			
			else:
				print('[!] RERLO : disable')
				# dumping got and plt table
				# for RELRO FULL is disable
				for reloc in reladyn.iter_relocations():
					plt_address += entry_align
					got_func_name = symbol_sec.get_symbol(reloc['r_info_sym']).name
					# dumping SymbolTableSection
					self.got[got_func_name] = reloc['r_offset']
					# mapping plt base address with SymbolTableSection
					self.plt[got_func_name] = plt_address
			# getting symbol of binary if it present
			self.__get_symtab(elf)


class Telnet(telnetlib.Telnet):
	def __init__(self,host,port):
		telnetlib.Telnet.__init__(self,host,port)

	# make easier when you want to send raw data to server
	def send(self,data):
		return self.get_socket().send(data)

	def recv(self,size):
		return self.get_socket().recv(size)

# for remote Pwning
class Pwn(object):
	def __init__(self,**kwargs):
		# setting default values
		self.mode = 0 # for x86 mode is default mode
		self.host = 'localhost'
		self.port = 8888
		self.con = None
		self.elf = None
		self.debug = False
		self.elf_path = ''

		# load authkey
		self.authkey = load_auth_key()

		# user inputs values
		for key,value in kwargs.iteritems():
			# setting some instances
			if key.lower() == 'mode':
				if type(value) is int:
					self.mode = value
				else:
					raise Exception('Unexpected value of self.mode')
			elif key.lower() == 'host':
				if type(value) is str:
					self.host = value
				else:
					raise Exception('Unexpected value of self.host')
			elif key.lower() == 'port':
				if type(value) is int:
					self.port = value
				else:
					raise Exception('Unexpected value of self.port')
			elif key.lower() == 'elf':
				# parsing ELFFile and extract some usefull information
				# such as GOT, PLT also doing checksec of binary
				if type(value) is str:
					self.elf_path = value
					self.elf = ELF(value)
					self.mode = self.elf.mode
				else:
					raise Exception('`elf` only accept string object')
			elif key.lower() == 'proc':
				if not os.path.exists(value):
					raise Exception('"%s" is not exists' % value)
				self.elf_path = value
			elif key.lower() == 'sock':
				# overwrite self-connection with other connection
				if value.__class__.__name__ == '_socketobject':
					# no need to call connect() method
					self.con = Telnet()
					self.con.sock = value
			elif key.lower() == 'lazy':
				host = ''
				port = 0
				# for copy host,port of target only
				# just put hole "(?nc) xxx.xxx.xxx.xxx yyyy" to `lazy`
				# matching ip
				_res = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s*](\d*)',value)
				if len(_res) > 0:
					host = _res[0][0]
					port = int(_res[0][1])
				# matching host
				_res = re.findall(r'(\w*\.\w*\.\w*)[:\s]*(\d*)',value)
				if len(_res) > 0:
					host = _res[0][0]
					port = int(_res[0][1])

				if not host and not port:
					raise Exception('Invalid syntax, syntax must be "nc <host/ip> <port>"')

				self.host = host
				self.port = port

			elif key.lower() == 'debug':
				if type(value) is not bool:
					raise Exception('debug variable only accept bool type')
				self.debug = value

	def connect(self):
		if self.con:
			raise Exception('You had connected.')
		self.con = Telnet(self.host,self.port)

	def read_until(self,value):
		# wrapper popular send/recive function
		if not self.con:
			raise Exception('You must connect() first')
		return self.con.read_until(value)

	def read_untils(self,*args):
		# read_untils many sign of text
		# read_untils('AAAAAA','BBBBBB'), if in buffer recv has
		# text 'AAAAAA' or 'BBBBBB' it will stop recv byte from server
		recv = ''
		is_found = False
		while not is_found:
			recv += self.recv(1)
			for arg in args:
				if arg in recv:
					is_found = True
					break
		return recv

	def readlines(self,timeout = 0.1):
		# make easier when writing exploit code, read until stdin is available to send data.
		# timeout default value is 0.1 sec
		if not self.con:
			raise Exception('You must connect() first')
		s = self.con.get_socket()
		s.setblocking(0)
		recv_data = ''
		while 1:
			ready = select.select([s], [], [], timeout) # waiting reading list is available
			if not ready[0]: # reach server input
				break
			recv_data += self.recv(1024)

		if self.debug:
			print('[DEBUG] readlines() : ' + repr(recv_data))

		return recv_data

	def send(self,value):
		if not self.con:
			raise Exception('You must connect() first')
		return self.con.send(value)

	def sendline(self,value):
		# send string with new line
		if not self.con:
			raise Exception('You must connect() first')
		return self.send(value + '\n')

	def sendint(self,value):
		# rename sendnum to sendint
		if not self.con:
			raise Exception('You must connect() first')
		if type(value) is not int and type(value) is not float:
			raise Exception('1st argument must be integer or float')
		return self.sendline(str(value))

	def recv(self,size):
		if not self.con:
			raise Exception('You must connect() first')
		recv_data = self.con.recv(size)
		if self.debug:
			print('[DEBUG] recv(%d) : %s' % (size,repr(recv_data)))
		return recv_data

	def write(self,value):
		if not self.con:
			raise Exception('You must connect() first')
		return self.con.write(value)

	def close(self):
		if not self.con:
			raise Exception('You must connect() first')
		self.con.close()

	def io(self):
		print('[+] Pwned Shell.')
		self.con.interact()

	def get_libc_offset(self,func2_addr,func2_name,func1_name='system',**kargs):
		# get offset between to function if you can leak one of them
		# >>> from Pwn import *
		# >>> p = Pwn()
		# >>> offset,offset2 = p.get_libc_offset(0x7ffff7a84e30,'puts',is_get_base=True)
		# >>> print hex(offset)
		# 0x297f0
		# >>> base_address = 0x7ffff7a84e30 - offset2
		# >>> print hex(base_address)
		# 0x7ffff7a15000
		# >>> offset = p.get_libc_offset(0x7ffff7a84e30,'puts')
		# >>> print hex(offset)
		# 0x297f0
		
		if kargs.has_key('is_get_base'): # if flag is_get_base is setted
			is_get_base = kargs['is_get_base']
			if type(is_get_base) != bool:
				raise Exception('is_get_base argument must be bool type')
		else: # if is_get_base is not set
			is_get_base = False 

		# get offset on own collection
		offset = offset2 = 0
		if not self.authkey:
			raise Exception('You must set your authkey in ~/.libc_collection_authkey \
				to use this method')

		try:
			form = { # own post request
				'func_addr' : hex(func2_addr),
				'func_name' : func2_name,
				'func2_name' : func1_name,
				'auth' : self.authkey
			}
			headers = {'User-Agent':'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
			# getting result
			req = urllib2.Request(LIBC_REPO + 'libc_find',urllib.urlencode(form),headers)
			res = urllib2.urlopen(req)
			result = json.loads(res.read())
			res.close()

			offset = result['offset']
			offset2 = result['offset2'] # store offset between your func1_name and libc_base_address
		except: # handle every exception
			pass

		if is_get_base: # if user want to calc libc base address
			# return both offset between 2 function and base address of libc
			return offset,offset2
		else: # otherwise return offset between func1 and func2
			return offset

	def calc_libc_offset(self,libc_path,func2,func1='system'):
		# this method helps you calc local libc.so offset
		# >>> offset = p.calc_libc_offset('/lib/x86_64-linux-gnu/libc.so.6','puts')
		# >>> print hex(offset)
		# 0x297f0
		offset = 0
		if os.path.exists(libc_path):
			with open(libc_path,'r') as pfile:
				# can't find any thing calculate it
				elffile = ELFFile(pfile)

				# dump symbol table
				symbol_sec = elffile.get_section_by_name(b'.dynsym')
				# can dump ?
				if not isinstance(symbol_sec, SymbolTableSection):
					return None

				func1_addr = 0
				func2_addr = 0
				for symbol in symbol_sec.iter_symbols():
					if symbol.name == func1:
						func1_addr = symbol.entry['st_value'] # get offset of func1
					if symbol.name == func2:
						func2_addr = symbol.entry['st_value'] # get offset of func2
					# collect all neccessary function
					if func1_addr and func2_addr:
						break

				offset = func1_addr - func2_addr

		return offset

	# utilities method that support you make your payload easier
	# c_uint32,c_uint64 that heap p32/p64 can pack in signed integer
	# for example:
	#  - p.pack(-1) # will return "\xff\xff\xff\xff"

	def p32(self,value):
		return pack('<I',c_uint32(value).value)

	def up32(self,value):
		if len(value) < 4:
			value = value.ljust(4,'\x00')
		return unpack('<I',value)[0]

	def p64(self,value):
		return pack('<Q',c_uint64(value).value)

	def up64(self,value):
		if len(value) < 8:
			value = value.ljust(8,'\x00')
		return unpack('<Q',value)[0]

	def p16(self,value):
		return pack('<H',c_uint16(value).value)

	def up16(self,value):
		if len(value) < 2:
			value = value.ljust(2,'\x00')
		return unpack('<H',value)

	def p8(self,value):
		return pack('<B',value)

	def up8(self,value):
		return unpack('<B',value)

	# using pack,unpack simplier by defining mode value

	def pack(self,value):
		return self.p32(value) if self.mode == 0 else self.p64(value)

	def unpack(self,value):
		return self.up32(value) if self.mode == 0 else self.up64(value)

	def pA(self,*args):
		# >>> self.pA([1,2,3])
		# '\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'
		# >>> self.pA(1,2,3)
		# '\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'

		ropchain = []
		if isinstance(args[0],list):
			ropchain = args[0]
		else:
			ropchain = args
		return ''.join([self.pack(rop) for rop in ropchain])

	# ror,rol operator
	def _rol(self,val,r_bits,max_bits):
		# @max_bits present max size of integer
		# for example int32 -> max_bits = 32 bits
		# @var is number you want to ror/rol
		# @r_bits is number of bit you want to ror/rol 
		res = (val << r_bits%max_bits) & (2**max_bits-1) | \
			((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
		return res

	def _ror(self,val,r_bits,max_bits):
		res = ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
			(val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
		return res

	def rol32(self,val,r_bits):
		return self._rol(val,r_bits,32)

	def ror32(self,val,r_bits):
		return self._ror(val,r_bits,32)

	def rol64(self,val,r_bits):
		return self._rol(val,r_bits,64)

	def ror64(self,val,r_bits):
		return self._ror(val,r_bits,64)

	def rol(self,val,r_bits):
		return self.rol32(val,r_bits) if self.mode == 0 else self.rol64(va,r_bits)

	def ror(self,val,r_bits):
		return self.ror32(val,r_bits) if self.mode == 0 else self.ror64(va,r_bits)

	def build32FormatStringBug(self,address,write_address,offset,pad = ''):
		# building format string payload support 32 and 64 bit :)
		# you can ovewrite this method and make it better

		fmt = pad
		for i in xrange(4):
			fmt += pack('<I',address + i)

		length_pad = len(fmt)
		start = 0
		if c_byte(write_address & 0xff).value < length_pad:
			start += 0x100

		# generate write string
		for i in xrange(0,4):
			byte = (write_address >> (8*i)) & 0xff
			byte += start
			fmt += '%{0}x'.format((byte - length_pad)) + '%{0}$n'.format(offset + i)
			length_pad = byte
			start += 0x100
		
		return fmt

	def build64FormatStringBug(self,address,write_address,offset,pad = ''):
		# this method require you must find a stable format string and offset
		# that make stack offset doesn't change.

		fmt = ''
		next = 0
		last = len(fmt) # length pad
		for i in xrange(8):
			byte = (write_address >> (8*i)) & 0xff
			byte += next
			fmt+= '%{0}x%{1}$n'.format(byte - last,offset + i)
			last = byte
			next += 0x100
		# fmt+= 'A'*20 # you may custom here
		fmt+= pad # stable pad must be appended here
		for i in xrange(8):
			fmt+= self.p64(address + i)

		return fmt

	def genFormatString(self,address,write_address,offset,pad = ''):
		# dynamic buildFormatStringBug
		if self.mode: # for 64 bits mode
			return self.build64FormatStringBug(address,write_address,offset,pad)
		else: # for 32 bits mode
			return self.build32FormatStringBug(address,write_address,offset,pad)

	def rand_buf(self,size,except_bytes=['\x00','\x0a','\x0b','\x0c']):
		# randomize my buffer :v
		buf = ''
		for i in xrange(size):
			b = os.urandom(1)
			while b in except_bytes:
				b = os.urandom(1)
			buf += b
		return buf

	def de_bruijn(self, alphabet = string.ascii_lowercase, n = 4):
		# string cyclic function
		# this code base on https://github.com/Gallopsled/pwntools/blob/master/pwnlib/util/cyclic.py
		# Taken from https://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
		"""de_bruijn(alphabet = string.ascii_lowercase, n = 4) -> generator

		Generator for a sequence of unique substrings of length `n`. This is implemented using a
		De Bruijn Sequence over the given `alphabet`.

		The returned generator will yield up to ``len(alphabet)**n`` elements.

		Arguments:
		  alphabet: List or string to generate the sequence over.
		  n(int): The length of subsequences that should be unique.
		"""
		k = len(alphabet)
		a = [0] * k * n
		def db(t, p):
			if t > n:
				if n % p == 0:
					for j in range(1, p + 1):
						yield alphabet[a[j]]
			else:
				a[t] = a[t - p]
				for c in db(t + 1, p):
					yield c

				for j in range(a[t - p] + 1, k):
					a[t] = j
					for c in db(t + 1, t):
						yield c

		return db(1,1)

	# generate a cyclic string
	def cyclic(self, length = None, n = 4):
		alphabet = string.printable[:-6]# default charset

		out = []
		for ndx, c in enumerate(self.de_bruijn(alphabet, n)):
			if length != None and ndx >= length:
				break
			else:
				out.append(c)

		if isinstance(alphabet, str):
			return ''.join(out)
		else:
			return out

	def cyclic_find(self, subseq, length = 0x10000):
		# finding subseq in generator then return pos of this subseq
		# if it doens't find then return -1
		generator = self.cyclic(length)

		if isinstance(subseq, (int, long)): # subseq might be a number or hex value
			try:
				subseq = self.p32(subseq)
			except error: # struct.error
				try:
					subseq = self.p64(subseq)
				except error: # struct.error
					return -1
		
		if not isinstance(subseq,str):
			return -1
		# finding position of subseq
		subseq = list(subseq)
		saved = []
		pos = 0

		for c in generator:
			saved.append(c)
			if len(saved) > len(subseq):
				saved.pop(0)
				pos += 1
			if saved == subseq: # if subseq equal saved then return pos of subseq
				return pos
		return -1

# use for local Pwning
# this class only work on Linux
class PwnProc(Pwn):
	def __init__(self,**kargs):
		super(PwnProc, self).__init__(**kargs)
		self.__start_proc()

	def __start_proc(self):
		# for more information, pls refer :
		# http://rachid.koucha.free.fr/tech_corner/pty_pdip.html
		# open new pty 
		master,slave = pty.openpty()
		# set to raw mode
		tty.setraw(master)
		tty.setraw(slave)

		# binding slave in to subprocess
		self.proc = Popen(self.elf_path,
			stdin=slave,
			stdout=slave,
			stderr=slave,
			close_fds=True,
			preexec_fn=self.preexec_fn,
			shell=True
		)
		self.pid = self.proc.pid
		print('[+] Start pid : %d' % self.pid)
		# binding master to own controlled file descriptors
		self.proc.stdin = os.fdopen(os.dup(master),"r+")
		self.proc.stdout = os.fdopen(os.dup(master),"r+")
		self.proc.stderr = os.fdopen(os.dup(master),"r+")
		# close unnessesary file descriptor
		os.close(slave)
		os.close(master)

		# set non-blocking mode
		fd = self.proc.stdout.fileno()
		fl = fcntl.fcntl(fd, fcntl.F_GETFL)
		fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

	def pty_make_controlling_tty(self,tty_fd):
		# borrow this code from pwntools
		child_name = os.ttyname(tty_fd)
		# Disconnect from controlling tty. Harmless if not already connected.
		try:
			fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
			if fd >= 0:
				os.close(fd)
			# which exception, shouldnt' we catch explicitly .. ?
		except OSError:
			# Already disconnected. This happens if running inside cron.
			pass

		os.setsid()

		# Verify we are disconnected from controlling tty
		# by attempting to open it again.
		try:
			fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
			if fd >= 0:
				os.close(fd)
				raise Exception('Failed to disconnect from ' +
						'controlling tty. It is still possible to open /dev/tty.')
		# which exception, shouldnt' we catch explicitly .. ?
		except OSError:
			# Good! We are disconnected from a controlling tty.
			pass
		
		# Verify we can open child pty.
		fd = os.open(child_name, os.O_RDWR)
		if fd < 0:
			raise Exception("Could not open child pty, " + child_name)
		else:
			os.close(fd)

		# Verify we now have a controlling tty.
		fd = os.open("/dev/tty", os.O_WRONLY)
		if fd < 0:
			raise Exception("Could not open controlling tty, /dev/tty")
		else:
			os.close(fd)

	def preexec_fn(self):
		self.pty_make_controlling_tty(1)

	def can_recv(self,timeout = 0):
		# is process die ?
		if self.poll() != None:
			return -1
		# can we read output from pty ?
		# base on situlation we can change timeout to read output.
		child_stdout = self.proc.stdout
		if timeout > 0:
			return select.select([child_stdout], [], [], timeout) == ([child_stdout], [], [])
		else:
			return select.select([child_stdout], [], []) == ([child_stdout], [], [])

	def poll(self):
		# keep tracking child process is still alive
		# or die, output status
		self.proc.poll() # check child process
		returncode = self.proc.returncode

		if returncode != None:
			print('Process %d is stopped with exit code %d' % (self.pid,returncode))
		return returncode

	def close(self):
		# kill() child process
		self.proc.close()

	def recv(self,numb,timeout = 0.1):
		recv_data = ''
		if not self.can_recv(timeout):
			return recv_data

		recv_data = self.proc.stdout.read(numb)
		return recv_data

	def read(self,numb,timeout = 0.1):
		return self.recv(numb,timeout)

	def send(self,data):
		if self.poll() >= 0:
			return -1
		nbytes = self.proc.stdin.write(data)
		self.proc.stdin.flush()
		return nbytes

	def write(self,data):
		return self.send(data) 

	def read_until(self,until,timeout = 0.1):
		out = ''
		while until not in out:
			# c = 
			# if c == '':
			# 	break
			out += self.recv(1024,timeout)
		return out

	def read_untils(self,until_array,timeout = 0.1):
		out = ''
		is_found = False
		while not is_found:
			out += self.recv(1024,timeout)
			for until in until_array:
				if out in until:
					is_found = True
					break
		return out

	def sendline(self,data,timeout = 0.1):
		return self.send(data + '\n')

	def sendint(self,num,timeout = 0.1):
		return self.send(str(num) + '\n')

	def io(self,timeout = 0.1):
		try:
			while 1:
				x = self.can_recv(timeout)
				if x > 0:
					# get output from child process
					out = self.recv(1024,timeout)
					sys.stdout.write(out)
					sys.stdout.flush()
				elif x == 0: # current tty interact
					_in = sys.stdin.readline()
					self.send(_in) # send to child process
				else:
					# process is die
					break
		except IOError:
			pass

	# export PwnProc exploit code to standalone py file
	# that py file can run standalone without installed pwning-tools
	def export(self):
		pass