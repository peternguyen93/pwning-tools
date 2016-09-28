import os

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