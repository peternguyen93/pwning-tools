from elftools.common.py3compat import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
import json
import hashlib
import sys
import os

DEFAULT_LIBC_COLLECTION = os.path.expanduser('~/.libc_collection.json')

def md5(pfile):
	if os.path.exists(pfile):
		pfile = open(pfile,'r')
		content = pfile.read()
		pfile.close()
		return hashlib.md5(content).hexdigest()
	return None

def add_libc_symbol_to_collection(collection,libc_path):
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
	libc_symbol = {
		'libc_md5sum' : md5(libc_path),
		'libc_symbol' : {}
	}
	for symbol in symbol_sec.iter_symbols():
		libc_symbol['libc_symbol'][symbol.name] = symbol.entry['st_value']
	collection.append(libc_symbol)
	pfile.close()
	return collection

def dump_collection(collection):
	fp = open(DEFAULT_LIBC_COLLECTION,'w')
	text = json.dumps(collection)
	fp.write(text)
	fp.close()

def load_collection():
	fp = open(DEFAULT_LIBC_COLLECTION,'r')
	text = fp.read()
	return json.loads(text)

# generate symbol collection
if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Usage {0} <libc>'.format(sys.argv[0])
	else:
		collection = []
		# load my collection
		if os.path.exists(DEFAULT_LIBC_COLLECTION):
			collection = load_collection()

		collection = add_libc_symbol_to_collection(collection,sys.argv[1])
		dump_collection(collection)