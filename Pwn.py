#!/usr/bin/python

# - This is Pwn module that helps you to build faster and easier payloads.
# - Pwn module works like a Interface (Abstract Class) that create a templet
# that you can base on it and create your payload.
# - Pwn module also support you create format string exploit easily, support x86 and x86-64
# - This module includes collection of shellcode, you can easily use it for your
# payload, supports Linux x86 and x86-64, arm will support later.
# - To install this module, you just copy this module to /usr/lib/python2.7 or python 3.1

# On this version 0.3 , i will add new feature
# method that help calc offset between 2 libc function (system and other func)
# method that help automatic find got address and write value to it

# Requires: pyelftools

# Author : Peternguyen
# Version : 0.5

# /bin/sh -c "echo shell >&4; sh <&4 >&4"

from __future__ import print_function
from ctypes import *
from struct import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
import telnetlib
import os
import json
import urllib2
import urllib
import string

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
	def __getitem__(self,key):
		for _key in self.keys():
			if key in _key:
				return dict.__getitem__(self,_key)
		raise KeyError('%s is\'t found' % key)
	
	# istead using key lookup, user can lookup value as a function
	# >>> got = ELFTable({
	# ...             '__gmon_start__': 6294744,
	# ...             '_IO_getc': 6294752,
	# ...             'puts': 6294704,
	# ...             '__printf_chk': 6294760,
	# ...             'memset': 6294728
	# ... })
	# >>> got('getc') # will return '_IO_getc' value
	def __call__(self,arg):
		return self.__getitem__(arg)


class Telnet(telnetlib.Telnet):
	def __init__(self,host,port):
		telnetlib.Telnet.__init__(self,host,port)
	# make easier when you want to send raw data to server
	def send(self,data):
		return self.get_socket().send(data)

	def recv(self,size):
		return self.get_socket().recv(size)

class Pwn():
	def __init__(self,**kwargs):
		# setting default values
		self.mode = 0 # for x86 mode is default mode
		self.host = 'localhost'
		self.port = 8888
		self.con = None
		self.sock_file = None
		self.got = ELFTable({})
		self.plt = ELFTable({})

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
				# define new input to dump got and plt table in elf file
				# >>> p = Pwn(elf='pwn.elf')
				# >>> p.got('puts')
				# 0x60008
				# >>> p.plt('puts')
				# 0x400640
				# >>> p.got['puts']
				# 0x60008
				# >>> p.plt['puts']
				# 0x400640
				if type(value) is str:
					path = os.path.expanduser(value) # ~/
					# is elf file exists
					if not os.path.exists(path):
						raise Exception('File %s not found' % path)	
					self.__elfparsing(path)

	def __elfparsing(self,path):
		# parsing elf file to dump got and plt table
		with open(path,'r') as pfile:
			elf = ELFFile(pfile)
			if not elf:
				raise Exception('File %s is not elf file' % path)

			# get rellocation section 
			arch = elf.get_machine_arch() # get arch
			# auto set self.mode base on arch of elf binary
			self.mode = 0 if arch == 'x86' else 1

			plt_section = elf.get_section_by_name('.plt')
			plt_address = plt_section.header['sh_addr'] # get plt base address
			entry_align = plt_section.header['sh_addralign'] # plt entry size

			# dump symbol table
			symbol_sec = elf.get_section_by_name(b'.dynsym')
			# can dump ?
			if not isinstance(symbol_sec, SymbolTableSection):
				raise Exception('Can dump SymbolTableSection')

			# get reallocation section to dump got table
			reladyn_name = b'.rel.plt' if arch == 'x86' else b'.rela.plt'
			reladyn = elf.get_section_by_name(reladyn_name)
			# can dump ?
			if not isinstance(reladyn, RelocationSection):
				raise Exception('Can dump SymbolTableSection')

			# dumping got and plt table
			for reloc in reladyn.iter_relocations():
				plt_address += entry_align
				got_func_name = symbol_sec.get_symbol(reloc['r_info_sym']).name
				# dumping SymbolTableSection
				self.got[got_func_name] = reloc['r_offset']
				# mapping plt base address with SymbolTableSection
				self.plt[got_func_name] = plt_address

	def connect(self):
		if self.con:
			raise Exception('You had connected.')
		self.con = Telnet(self.host,self.port)

	# make socket as file, use with libncurse in service
	def makefile(self,mode,bufsize=0): # default bufsize = 0 unbuffered
		if not self.con:
			raise Exception('You must connect() first')
		s = self.con.get_socket()
		self.sock_file = s.makefile(mode,bufsize)
		return self.sock_file

	# some function work with sock_file
	def read_file_until(self,end):
		buf = ''
		if not self.sock_file:
			raise Exception('You must makefile() first')

		while not buf.endswith(end):
			buf += self.sock_file.read(1)
		return buf

	# wrapper popular send/recive function
	def read_until(self,value):
		if not self.con:
			raise Exception('You must connect() first')
		return self.con.read_until(value)

	def read_all(self):
		rc = self.con.recv(1024)
		while 1:
			t = self.con.recv(1024)
			if t == '':
				break
			rc += t
		return rc 

	def write(self,value):
		if not self.con:
			raise Exception('You must connect() first')
		return self.con.write(value)

	def send(self,value):
		if not self.con:
			raise Exception('You must connect() first')
		return self.con.send(value)

	def recv(self,size):
		if not self.con:
			raise Exception('You must connect() first')
		return self.con.recv(size)

	def close(self):
		if not self.con:
			raise Exception('You must connect() first')
		self.con.close()

	def io(self):
		print('[+] Pwned Shell.')
		self.con.interact()

	# get offset between to function if you can leak one of them
	# >>> from Pwn import *
	# >>> p = Pwn()
	# >>> offset,base_address = p.get_libc_offset(0x7ffff7a84e30,'puts')
	# >>> print hex(offset)
	# 0x297f0
	# >>> print hex(base_address)
	# 0x7ffff7a15000
	def get_libc_offset(self,func2_addr,func2_name,func1_name='system'):
		# get offset on own collection
		offset = base_addr = 0
		if not self.authkey:
			raise Exception('You must set your authkey in ~/.libc_collection_authkey to use this method')

		try:
			form = { # own post request
				'func_addr' : hex(func2_addr),
				'func_name' : func2_name,
				'func2_name' : func1_name,
				'auth' : self.authkey
			}
			headers = {'User-Agent':'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
			req = urllib2.Request(LIBC_REPO + 'libc_find',urllib.urlencode(form),headers) # getting result
			res = urllib2.urlopen(req)
			result = json.loads(res.read())
			res.close()

			offset = result['offset']
			base_addr = result['base_addr']
		except: # handle every exception
			pass
		# return both offset between 2 function and base address of libc
		return offset,base_addr

	# this method helps you calc local libc.so offset
	# >>> offset = p.calc_libc_offset('/lib/x86_64-linux-gnu/libc.so.6','puts')
	# >>> print hex(offset)
	# 0x297f0
	def calc_libc_offset(self,libc_path,func2,func1='system'):
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
	def p32(self,value):
		return pack('<I',value)

	def up32(self,value):
		return unpack('<I',value)[0]

	def p64(self,value):
		return pack('<Q',value)

	def up64(self,value):
		return unpack('<Q',value)[0]

	# using pack,unpack simplier by defining mode value
	def pack(self,value):
		return self.p32(value) if self.mode == 0 else self.p64(value)

	def unpack(self,value):
		return self.up32(value) if self.mode == 0 else self.up64(value)

	# >>> self.pA([1,2,3])
	# '\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'
	# >>> self.pA(1,2,3)
	# '\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00'
	def pA(self,*args):
		ropchain = []
		if isinstance(args[0],list):
			ropchain = args[0]
		else:
			ropchain = args
		return ''.join([self.pack(rop) for rop in ropchain])

	# building format string payload support 32 and 64 bit :)
	# you can ovewrite this method and make it better
	def build32FormatStringBug(self,address,write_address,offset,pad = ''):
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

	# this method require you must find a stable format string and offset that make stack offset doesn't change.
	def build64FormatStringBug(self,address,write_address,offset,pad = ''):
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

	# dynamic buildFormatStringBug
	def genFormatString(self,address,write_address,offset,pad = ''):
		if self.mode: # for 64 bits mode
			return self.build64FormatStringBug(address,write_address,offset,pad)
		else: # for 32 bits mode
			return self.build32FormatStringBug(address,write_address,offset,pad)

	# randomize my buffer :v
	def rand_buf(self,size,except_bytes=['\x00','\x0a','\x0b','\x0c']):
		buf = ''
		for i in xrange(size):
			b = os.urandom(1)
			while b in except_bytes:
				b = os.urandom(1)
			buf += b
		return buf

	# string cyclic function
	# this code base on https://github.com/Gallopsled/pwntools/blob/master/pwnlib/util/cyclic.py
	# Taken from https://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
	def de_bruijn(self, alphabet = string.ascii_lowercase, n = 4):
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

	# finding subseq in generator then return pos of this subseq
	# if it doens't find then return -1
	def cyclic_find(self, subseq, length = 0x10000):
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