import struct
import binascii

import binaryninja

RED = '\x1B[31m'
GREEN = '\x1B[32m'
BROWN = '\x1B[33m'
NORMAL = '\x1B[0m'

def hex_dump(data, addr=0, grouping=1, endian='little'):
	result = ''

	while(data):
		ascii = ''
		buff16 = data[0:16]
		data = data[16:]
		result += "%s%016X%s: " % (GREEN, addr, NORMAL)

		i = 0
		while i < 16:
			if(i < len(buff16)):
				f0 = { \
					'big':	{1:'>B', 2:'>H', 4:'>I', 8:'>Q'}, \
					'little': {1:'<B', 2:'<H', 4:'<I', 8:'<Q'} \
				}

				f1 = { \
					1:'%02X ', 2:'%04X ', 4:'%08X ', 8:'%016X ' \
				}

				temp = struct.unpack(f0[endian][grouping], buff16[i:i+grouping])[0]

				result += f1[grouping] % temp

				for j in range(grouping):
					u8 = buff16[i+j]

					if(u8 >= ord(' ') and u8 <= ord('~')):
						ascii += chr(u8)
					else:
						ascii += '.'
			else:
				if grouping == 1:
					result += ' '*3
				elif grouping == 2:
					result += ' '*5
				elif grouping == 4:
					result += ' '*9
				elif grouping == 8:
					result += ' '*17

			i += grouping

		result += ' %s\n' % ascii

		addr += 16

	return result

def disasm1(data, addr, arch='x86_64'):
	arch = binaryninja.Architecture[arch]
	toksAndLen = arch.get_instruction_text(data, addr)
	if not toksAndLen or toksAndLen[1]==0:
		return (None, 0)
	toks = toksAndLen[0]
	strs = ''.join(list(map(lambda x: x.text, toks)))
	return [strs, toksAndLen[1]]

def disasm(data, addr, arch='x86_64'):
	if not data:
		return
	lines = []
	offs = 0
	while offs < len(data):
		addrstr = '%016X' % addr
		(asmstr, length) = disasm1(data[offs:], addr+offs, arch)
		if length == 0: break
		bytestr = binascii.hexlify(data[offs:offs+length]).decode('utf-8').ljust(16)
		lines.append('%s%s%s: %s %s' % (GREEN, addrstr, NORMAL, bytestr, asmstr))
		offs += length
	return '\n'.join(lines)

