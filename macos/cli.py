#!/usr/bin/env python3

# notes:
# tcpdump -i lo0 -A -s0 'port 31337'
# typical GDB RSP files
# https://sourceware.org/gdb/onlinedocs/gdb/Packets.html
# lldb-gdb-remote.txt

import os
import re
import sys
from struct import pack, unpack
import socket
import string
import capstone
from binascii import hexlify, unhexlify

import colorama
RED = '\x1B[31m'
GREEN = '\x1B[32m'
BROWN = '\x1B[33m'
NORMAL = '\x1B[0m'

sock = None

context_last = {}

reg_id_to_name = {}

sig_num_to_name = {
	1: 'SIGHUP', 2: 'SIGINT', 3: 'SIGQUIT', 4: 'SIGILL', 5: 'SIGTRAP', 6:
	'SIGABRT', 7: 'SIGEMT', 8: 'SIGFPE', 9: 'SIGKILL', 10: 'SIGBUS', 11: 'SIGSEGV',
	12: 'SIGSYS', 13: 'SIGPIPE', 14: 'SIGALRM', 15: 'SIGTERM', 16: 'SIGURG', 17:
	'SIGSTOP', 18: 'SIGTSTP', 19:  'SIGCONT', 20: 'SIGCHLD', 21: 'SIGTTIN', 22:
	'SIGTTOU', 23: 'SIGIO', 24:    'SIGXCPU', 25: 'SIGXFSZ', 26: 'SIGVTALRM', 27:
	'SIGPROF', 28: 'SIGWINCH', 29: 'SIGINFO', 30: 'SIGUSR1', 31: 'SIGUSR2'}

#--------------------------------------------------------------------------
# GDB RSP FUNCTIONS (LOW LEVEL)
#--------------------------------------------------------------------------
def send_raw(data):
	global sock
	sock.send(data.encode('utf-8'))

def send_packet_data(data):
	global sock
	# packet is exactly "$<data>#<checksum>"
	checksum = sum(map(ord, data))
	packet = '$' + data + '#' + ("%02x" % (checksum % 256))
	send_raw(packet)

def recv_packet_data():
	global sock

	hexes = b'abcdefABCDEF0123456789'

	# consume ack's
	tmp = b'+'
	while tmp == b'+':
		tmp = sock.recv(1)

	# start packet
	pkt = tmp
	assert pkt == b'$'

	# consume until '#' and checksum bytes
	while not (len(pkt)>=3 and pkt[-3] == ord('#') and pkt[-2] in hexes and pkt[-1] in hexes):
		pkt = pkt + sock.recv(1)

	# acknowledge
	send_raw('+')

	return pkt[1:-3].decode('utf-8')

def tx_rx(data):
	send_packet_data(data)

	# require no acknowledgement
	if data[0] in 'fiIkRt':
		pass
	# require simple ack
	elif data[0] in '!ADGHMPQTXzZ' or data.startswith('vFlashErase') or data.startswith('vFlashWrite'):
		pass
	# return result data or error code
	elif data[0] in '?cCgmpsSqv':
		return recv_packet_data()

def send_ack():
	packet = '+'
	self.sock.send(packet)
	print(packet.decode('utf-8'), '->')

#--------------------------------------------------------------------------
# GDB RSP FUNCTIONS (HIGHER LEVEL)
#--------------------------------------------------------------------------

def register_info_learn():
	for i in range(256):
		reply = tx_rx('qRegisterInfo%02X' % i)
		if not reply.startswith('name:'):
			break
		name = re.match(r'^name:(.*?);', reply).group(1)
		#print('reg %d is %s' % (i, name))
		reg_id_to_name[i] = name

def packet_T_to_dict(data):
	if not reg_id_to_name:
		register_info_learn()

	# map the info to a context dictionary
	context = {}
	context['signal'] = int(data[1:3], 16)

	for key_vals in data[3:].split(';'):
		if not key_vals:
			continue
		(key, val) = key_vals.split(':')

		if key == 'thread':
			context['thread'] = int(val, 16)
		elif re.match(r'^[0-9a-fA-F]+$', key):
			rid = int(key, 16)
			reg_name = reg_id_to_name[rid]
			val = int(''.join(reversed([val[i:i+2] for i in range(0,len(val),2)])), 16)
			context[reg_name] = val
		else:
			# 'metype', 'mecount', 'medata', 'memory', etc.
			context[key] = val

	return context

def packet_display(data):
	# stdout
	if data[0] == 'O':
		message = unhexlify(data[1:])
		print('stdout message: %s' % message)

	# thread info
	elif data[0] == 'T':
		if data[-1] == ';':
			data = data[0:-1]
		for (key,val) in [x.split(':') for x in data[3:].split(';')]:
			print('%s: %s' % (key, val))

	# exit status
	elif data[0] == 'W':
		exit_status = int(data[1:], 16)
		print('inferior exited with status: %d' % exit_status)
	else:
		print(data)

#--------------------------------------------------------------------------
# COMMON DEBUGGER TASKS
#--------------------------------------------------------------------------

def break_into():
	send_draw(b'\x03')
	pass

def mem_read(addr, amt=None):
	packed = b''

	while(amt):
		chunk = min(amt, 256)

		data = 'm' + ( "%x" % addr ) + ',' + ( "%x" % chunk )
		reply = tx_rx(data)

		while(reply):
			packed += pack('B', int(reply[0:2],16))
			reply = reply[2:]

		amt -= chunk

	return packed

def context_show(pkt_T=None):
	global context_last

	# get a new context
	if not pkt_T:
		pkt_T = tx_rx('?')
	context_last = packet_T_to_dict(pkt_T)

	# show it
	sig = context_last['signal']
	if 'thread' in context_last:
		print('thread %d stopped due to signal %d (%s)' % \
			(context_last['thread'], sig, sig_num_to_name[sig]))
	else:
		print('thread ? stopped due to signal %d (%s)' % \
			(sig, sig_num_to_name[sig]))

	rax = context_last['rax']
	rbx = context_last['rbx']
	rcx = context_last['rcx']
	rdx = context_last['rdx']
	rsi = context_last['rsi']
	rdi = context_last['rdi']
	rip = context_last['rip']
	rsp = context_last['rsp']
	rbp = context_last['rbp']
	r8 = context_last['r8']
	r9 = context_last['r9']
	r10 = context_last['r10']
	r11 = context_last['r11']
	r12 = context_last['r12']
	r13 = context_last['r13']
	r14 = context_last['r14']
	r15 = context_last['r15']

	print("%srax%s=%016X %srbx%s=%016X %srcx%s=%016X" % \
		(BROWN, NORMAL, rax, BROWN, NORMAL, rbx, BROWN, NORMAL, rcx))
	print("%srdx%s=%016X %srsi%s=%016X %srdi%s=%016X" %
		(BROWN, NORMAL, rdx, BROWN, NORMAL, rsi, BROWN, NORMAL, rdi))
	print("%srip%s=%016X %srsp%s=%016X %srbp%s=%016X" % \
		(BROWN, NORMAL, rip, BROWN, NORMAL, rsp, BROWN, NORMAL, rbp))
	print(" %sr8%s=%016X  %sr9%s=%016X %sr10%s=%016X" % \
		(BROWN, NORMAL, r8, BROWN, NORMAL, r9, BROWN, NORMAL, r10))
	print("%sr11%s=%016X %sr12%s=%016X %sr13%s=%016X" % \
		(BROWN, NORMAL, r11, BROWN, NORMAL, r12, BROWN, NORMAL, r13))
	print("%sr14%s=%016X %sr15%s=%016X" % \
		(BROWN, NORMAL, r14, BROWN, NORMAL, r15))

	data = mem_read(rip, 16)
	if data:
		(asmstr, asmlen) = disasm1(data, rip)
		print('%s%016X%s: %s\t%s' % \
			(GREEN, rip, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

def debug_status():
	return

#--------------------------------------------------------------------------
# UTILITIES
#--------------------------------------------------------------------------

def disasm1(data, addr):
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	gen = md.disasm(data, addr)
	insn = next(gen)
	return ('%s %s' % (insn.mnemonic, insn.op_str), insn.size)

def disasm(data, addr):
	if not data:
		return
	lines = []
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	offset = 0
	for i in md.disasm(data, addr):
		addrstr = '%s%016X%s' % (GREEN, i.address, NORMAL)
		bytestr = hexlify(data[offset:offset+i.size]).decode('utf-8').ljust(16)
		asmstr = i.mnemonic + ' ' + i.op_str
		line = '%s: %s %s' % (addrstr, bytestr, asmstr)
		lines.append(line)
		offset += i.size
	return '\n'.join(lines)

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

				temp = unpack(f0[endian][grouping], buff16[i:i+grouping])[0]

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

#--------------------------------------------------------------------------
# MAIN
#--------------------------------------------------------------------------

adapter_blocking = False

if __name__ == '__main__':
	colorama.init()

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(('localhost', 31337))

	user_still_wants_to_debug = True
	while user_still_wants_to_debug:
		try:
			prompt = 'RUNNING>' if adapter_blocking else 'FAKEDBG>'
			text = input(prompt)
			if not text:
				continue

			if adapter_blocking and not text in ['break', 'breakinto']:
				print('target running, break into it first')
				continue

			# testing stuff
			if text == 'hello':
				send_packet_data('?')
			elif text in ['?', 'state']:
				debug_status()

			# thread list, thread switch
			elif text in ['~', 'threads']:
				threads_list()
			elif text[0:] and text[0]=='~' and text[-1]=='s':
				tid = int(text[1:-1])
				set_current_thread(tid)

			# breakpoint set/clear
			elif text.startswith('bp '):
				addr = int(text[3:], 16)
				bpid = breakpoint_set(addr)
				if bpid == None:
					print('ERROR')
				else:
					print('breakpoint %d set at 0x%X' % (bpid, addr))

			elif text.startswith('bc '):
				bpid = int(text[3:])
				if breakpoint_clear(bpid) == None:
					print('ERROR')

			# context, read regs, write regs
			elif text in ['r']:
				context_show()
			elif re.match(r'r .* .*$', text):
				(_, reg, val) = text.split(' ')
				reg_write(reg, int(val, 16))

			# read/write mem, disasm mem
			elif text.startswith('db '):
				addr = int(text[3:], 16)
				data = mem_read(addr, 128)
				print(hex_dump(data, addr))
			elif text.startswith('eb '):
				m = re.match(r'^eb (\w+) (.*)$', text)
				addr = int(m.group(1), 16)
				bytes_ = bytes(map(lambda x: int(x,16), m.group(2).split()))
				mem_write(addr, bytes_)
			elif text.startswith('u '):
				addr = int(text[2:],16)
				data = mem_read(addr, 32)
				print(disasm(data, addr))

			# break into, go, step, step into
			elif text in ['break', 'breakinto']:
				break_into()

			elif text == 'g':
				reply = tx_rx('c') # rsp continue packet
				packet_display(reply)

			elif text == 't':
				pkt_T = tx_rx('vCont;s') # rsp step packet
				context_show(pkt_T)

			elif text == 'p':
				print('no step over')
				pass

			# quit, detach, quit+detach
			elif text in ['q', 'quit', 'exit']:
				user_still_wants_to_debug = False
			elif text in ['qd', 'detach']:
				process_detach()
				user_still_wants_to_debug = False

			# pass-thru packet
			elif text.startswith('packet '):
				reply = tx_rx(text[7:])
				packet_display(reply)

			# else
			else:
				print('unrecognized: %s' % text)

		except KeyboardInterrupt as e:
			print("ctrl+c detected! quiting!\n")
			user_still_wants_to_debug = False

	print("telling server to disconnect")
	send_raw('D')
	print("socket shutdown() and close()")
	sock.shutdown(socket.SHUT_RDWR)
	sock.close()
