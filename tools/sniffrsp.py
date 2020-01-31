#!/usr/bin/env python3
#
# usage:
# sudo ./sniffrsp.py

import sys
import pyshark

sys.path.append('.')
sys.path.append('..')
import rsp

RED = '\x1B[31m'
GREEN = '\x1B[32m'
NORMAL = '\x1B[0m'

port = 31337
if sys.argv[1:]:
	port = int(sys.argv[1])

cap = pyshark.LiveCapture(interface='lo', bpf_filter='port %d'%port)

for pkt in cap.sniff_continuously():
	if not hasattr(pkt.tcp, 'payload'):
		continue

	srcport = int(str(pkt.tcp.srcport), 10)
	if srcport == port:
		print(RED + '<- ', end='')
	else:
		print(GREEN + '-> ', end='')

	result = ''
	for hex2 in str(pkt.tcp.payload).split(':'):
		byte = int(hex2, 16)
		if byte >= 32 and byte <= 126:
			result += chr(byte)
		else:
			result += '\\x%02X' % byte

	print(result, end='')
	if '*' in result:
		result = rsp.un_rle(result)
		print('\nrle-decoded: ' + result, end='')

	print(NORMAL)

cap.close()
