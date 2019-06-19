#!/usr/bin/python

# - This is Pwn module that helps you to build faster and easier payloads.
# - Pwn module works like a Interface (Abstract Class) that create a templet
# that you can base on it and create your payload.
# - Pwn module also support you create format string exploit easily, support x86 and x86-64
# - This module includes collection of shellcode, you can easily use it for your
# payload, supports Linux x86 and x86-64, arm will support later.
# - To install this module, you just copy this module to /usr/lib/python2.7 or python 3.1

# Requires: pyelftools, capstone, keystone

# Author : Peternguyen

# /bin/sh -c "echo shell >&4; sh <&4 >&4"

from ctypes import *
from struct import *
from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from urllib import parse, request
import telnetlib
import string
import select
import socket
import json
import os
import re
import sys

LIBC_REPO = 'http://libc.meepwn.team/' # own libc repo
web_headers = {
	'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
	'content-type': 'application/json'
}

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
	def __init__(self, mode = 0, host='localhost', port=8888, constr='', debug = False):
		# setting default values
		self.mode = mode # for x86 mode is default mode
		self.host = host
		self.port = port
		self.con = None
		self.debug = debug

		# load authkey
		self.authkey = load_auth_key()

		if constr:
			m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{2,5})', constr)
			if m:
				self.host = m[1].strip(' \n')
				try:
					self.port = int(m[2].strip(' \n'))
				except IndexError:
					pass

	def connect(self):
		if self.con:
			raise Exception('You had connected.')
		self.con = Telnet(self.host,self.port)

	'''
		Wrapper for read data from socket.
		if argument is str convert it to bytes (python3)
	'''

	def recv(self, size):
		if not self.con:
			raise Exception('You must connect() first')
		recv_data = self.con.recv(size)
		if self.debug:
			print('[DEBUG] recv(%d) : %s' % (size,repr(recv_data)))
		return recv_data

	def read_until(self, pattern):
		if type(pattern) is str:
			pattern = pattern.encode('utf-8')

		if not self.con:
			raise Exception('You must connect() first')
		return self.con.read_until(pattern)

	def read_untils(self, *patterns):
		# read_untils many sign of text
		# read_untils('AAAAAA','BBBBBB'), if in buffer recv has
		# text 'AAAAAA' or 'BBBBBB' it will stop recv byte from server
		npatterns = []

		for pattern in patterns:
			if type(pattern) is str:
				npatterns.append(pattern.encode('utf-8'))
			else:
				npatterns.append(pattern)

		recv = b''
		is_found = False
		while not is_found:
			recv += self.recv(1)
			for pattern in npatterns:
				if pattern in recv:
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

		recv_data = b''

		while 1:
			try:
				ready = select.select([s], [], [], timeout) # waiting reading list is available
				if not ready[0]: # reach server input
					break
				recv_data += s.recv(1024)
			except socket.error:
				break

		if self.debug:
			print('[DEBUG] readlines() : ' + repr(recv_data))

		return recv_data

	'''
		Wrapper for write data to socket.
		if argument is str convert it to bytes (python3)
	'''

	def write(self, data):
		if type(data) is str:
			data = data.encode('utf-8')

		if not self.con:
			raise Exception('You must connect() first')
		return self.con.write(data)

	def send(self, data):
		if type(data) is str:
			# convert to bytes
			data = data.encode('utf-8')

		if not self.con:
			raise Exception('You must connect() first')
		return self.con.send(data)

	def sendline(self, line):
		# send string with new line
		if type(line) is str:
			line = line.encode('utf-8')

		if not self.con:
			raise Exception('You must connect() first')
		return self.send(line + b'\n')

	def sendint(self, value):
		# rename sendnum to sendint
		if not self.con:
			raise Exception('You must connect() first')
		if type(value) is not int and type(value) is not float:
			raise Exception('1st argument must be integer or float')
		return self.sendline(str(value))

	def close(self):
		if not self.con:
			raise Exception('You must connect() first')
		self.con.close()
		self.con = None

	def io(self):
		print('[+] Pwned Shell.')
		self.con.interact()

	def get_libc_offset(self, known_fn_addr, known_fn_name, target_fn_name='system', is_get_base = False):
		'''
			get offset between to function if you can leak one of them
			>>> from Pwn import *
			>>> p = Pwn()
			>>> offset,offset2 = p.get_libc_offset(0x7ffff7a84e30,'puts',is_get_base=True)
			>>> print(hex(offset))
			0x297f0
			>>> base_address = 0x7ffff7a84e30 - offset2
			>>> print(hex(base_address))
			0x7ffff7a15000
			>>> offset = p.get_libc_offset(0x7ffff7a84e30,'puts')
			>>> print(hex(offset))
			0x297f0
		'''
		
		# get offset on own collection
		offset = offset2 = 0
		if not self.authkey:
			raise Exception('You must set your authkey in ~/.libc_collection_authkey \
				to use this method')

		try:
			formdata = { # own post request
				'func_addr' : hex(known_fn_addr),
				'func_name' : known_fn_name,
				'func2_name' : target_fn_name,
				'auth' : self.authkey
			}
			
			form_encode = json.dumps(formdata).encode('utf8')
			req = request.Request(LIBC_REPO + 'libc_find', data=form_encode, headers=web_headers)
			resp = request.urlopen(req)
			resp_data = resp.read()
			print(repr(resp_data))
			result = json.loads(resp_data)
			resp.close()

			offset = result['offset']
			offset2 = result['offset2'] # store offset between your target_fn_name and libc_base_address
		except: # handle every exception
			pass

		if is_get_base: # if user want to calc libc base address
			# return both offset between 2 function and base address of libc
			return offset, offset2
		else: # otherwise return offset between func1 and func2
			return offset

	def calc_libc_offset(self, libc_path, known_func, target_func='system'):
		# this method helps you calc local libc.so offset
		# >>> offset = p.calc_libc_offset('/lib/x86_64-linux-gnu/libc.so.6','puts')
		# >>> print(hex(offset))
		# 0x297f0

		offset = 0
		if not os.path.exists(libc_path):
			print('[ERROR] libc "{0}" is not exists.'.format(libc_path))
			return offset

		with open(libc_path,'rb') as pfile:
			# can't find any thing calculate it
			elffile = ELFFile(pfile)

			# dump symbol table
			symbol_sec = elffile.get_section_by_name('.dynsym')
			# can dump ?

			if not isinstance(symbol_sec, SymbolTableSection):
				print('[ERROR] libc "{0}" doesn\'t have SymbolTableSection')
				return 0

			know_func_addr = 0
			target_func_addr = 0
			for symbol in symbol_sec.iter_symbols():
				if symbol.name == known_func:
					know_func_addr = symbol.entry['st_value'] # get offset of func1
				if symbol.name == target_func:
					target_func_addr = symbol.entry['st_value'] # get offset of func2
				# collect all neccessary function
				if know_func_addr and target_func_addr:
					break

			offset = know_func_addr - target_func_addr

		return offset

	'''
		Utilities methods, support turn int to byte array to send over socket
	'''

	def p32(self, value):
		return pack('<I',c_uint32(value).value)

	def up32(self, value):
		if len(value) < 4:
			value = value.ljust(4, b'\x00')
		return unpack('<I',value)[0]

	def p64(self, value):
		return pack('<Q',c_uint64(value).value)

	def up64(self, value):
		if len(value) < 8:
			value = value.ljust(8, b'\x00')
		return unpack('<Q',value)[0]

	def p16(self, value):
		return pack('<H',c_uint16(value).value)

	def up16(self, value):
		if len(value) < 2:
			value = value.ljust(2, b'\x00')
		return unpack('<H',value)

	def p8(self, value):
		return pack('<B',value)

	def up8(self, value):
		return unpack('<B',value)

	# using pack,unpack simplier by defining mode value

	def pack(self, value):
		return self.p32(value) if self.mode == 0 else self.p64(value)

	def unpack(self, value):
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
		return b''.join([self.pack(rop) for rop in ropchain])

	'''
		Support special operator like rotate left, rotate right
	'''

	def _rol(self, value, r_bits, max_bits):
		# @max_bits present max size of integer
		# for example int32 -> max_bits = 32 bits
		# @var is number you want to ror/rol
		# @r_bits is number of bit you want to ror/rol 
		res = (value << r_bits % max_bits) & (2**max_bits - 1) | \
			((value & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
		return res

	def _ror(self, value, r_bits, max_bits):
		res = ((value & (2**max_bits-1)) >> r_bits%max_bits) | \
			(value << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
		return res

	def rol32(self, value, r_bits):
		return self._rol(value,r_bits,32)

	def ror32(self, value, r_bits):
		return self._ror(value,r_bits,32)

	def rol64(self, value, r_bits):
		return self._rol(value,r_bits,64)

	def ror64(self, value, r_bits):
		return self._ror(value,r_bits,64)

	def rol(self, value, r_bits):
		return self.rol32(value,r_bits) if self.mode == 0 else self.rol64(va,r_bits)

	def ror(self, value, r_bits):
		return self.ror32(value,r_bits) if self.mode == 0 else self.ror64(va,r_bits)

	'''
		These methods allow I can quickly build format string to exploit format string bug
	'''

	def build32FormatStringBug(self, address, write_value, offset, pad = ''):
		# building format string payload support 32 and 64 bit :)
		# you can ovewrite this method and make it better

		fmt = pad
		for i in range(4):
			fmt += pack('<I',address + i)

		length_pad = len(fmt)
		start = 0
		if c_byte(write_value & 0xff).value < length_pad:
			start += 0x100

		# generate write string
		for i in range(0,4):
			byte = (write_value >> (8*i)) & 0xff
			byte += start
			fmt += '%{0}x'.format((byte - length_pad)) + '%{0}$n'.format(offset + i)
			length_pad = byte
			start += 0x100
		
		return fmt

	def build64FormatStringBug(self, address, write_value, offset, pad = ''):
		# this method require you must find a stable format string and offset
		# that make stack offset doesn't change.

		fmt = ''
		next = 0
		last = len(fmt) # length pad
		for i in range(8):
			byte = (write_value >> (8*i)) & 0xff
			byte += next
			fmt+= '%{0}x%{1}$n'.format(byte - last,offset + i)
			last = byte
			next += 0x100
		# fmt+= 'A'*20 # you may custom here
		fmt+= pad # stable pad must be appended here
		for i in range(8):
			fmt+= self.p64(address + i)

		return fmt

	def genFormatString(self, address, write_value, offset, pad = ''):
		# dynamic buildFormatStringBug
		if self.mode: # for 64 bits mode
			return self.build64FormatStringBug(address,write_value,offset,pad)
		else: # for 32 bits mode
			return self.build32FormatStringBug(address,write_value,offset,pad)

	def rand_buf(self,size,except_bytes=[b'\x00',b'\x0a',b'\x0b',b'\x0c']):
		# randomize my buffer :v
		buf = ''
		for i in range(size):
			b = os.urandom(1)
			while b in except_bytes:
				b = os.urandom(1)
			buf += b
		return buf

	'''
		These method support generate De Bruijn Sequence to detect offset of crashed
	'''

	def de_bruijn(self, charset , n = 4, maxlen = 0x10000):
		# string cyclic function
		# this code base on https://github.com/Gallopsled/pwntools/blob/master/pwnlib/util/cyclic.py
		# Taken from https://en.wikipedia.org/wiki/De_Bruijn_sequence but changed to a generator
		"""de_bruijn(charset = string.ascii_lowercase, n = 4) -> generator

		Generator for a sequence of unique substrings of length `n`. This is implemented using a
		De Bruijn Sequence over the given `charset`.

		The returned generator will yield up to ``len(charset)**n`` elements.

		Arguments:
		  charset: List or string to generate the sequence over.
		  n(int): The length of subsequences that should be unique.
		"""
		k = len(charset)
		a = [0] * k * n
		sequence = []
		def db(t, p):
			if len(sequence) == maxlen:
				return
			if t > n:
				if n % p == 0:
					for j in range(1	, p + 1):
						sequence.append(charset[a[j]])
						if len(sequence) == maxlen:
							return
			else:
				a[t] = a[t - p]
				db(t + 1, p)

				for j in range(a[t - p] + 1, k):
					a[t] = j
					db(t + 1, t)
		db(1,1)
		return ''.join(sequence)

	# generate a cyclic string
	def cyclic(self, length = None, n = 4):
		charset = []
		charset += ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"] # string.uppercase
		charset += ["abcdefghijklmnopqrstuvwxyz"] # string.lowercase
		charset += ["0123456789"] # string.digits
		charset[1] = "%$-;" + re.sub("[sn]", "", charset[1])
		charset[2] = "sn()" + charset[2]
		mixed_charset = mixed = ''
		k = 0
		while True:
			for i in range(0, len(charset)): mixed += charset[i][k:k+1]
			if not mixed: break
			mixed_charset += mixed
			mixed = ''
			k+=1

		pattern = self.de_bruijn(mixed_charset, 3, length)
		return pattern

	def cyclic_find(self, subseq, length = 0x10000):
		# finding subseq in generator then return pos of this subseq
		# if it doens't find then return -1
		generator = self.cyclic(length)

		if isinstance(subseq, int): # subseq might be a number or hex value
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