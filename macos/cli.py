#!/usr/bin/env python3

# notes:
# tcpdump -i lo0 -A -s0 'port 31337'
# typical GDB RSP files
# https://sourceware.org/gdb/onlinedocs/gdb/Packets.html
# lldb-gdb-remote.txt

import os
import re
import sys
import struct
import socket
import string
import binascii
import colorama

sock = None

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

def packet_display(data):
	# stdout
	if reply[0] == 'O':
		message = binascii.unhexlify(reply[1:])
		print('stdout message: %s' % message)

	# thread info
	elif reply[0] == 'T':
		if not reg_id_to_name:
			register_info_learn()

		signal = int(reply[1:3], 16)
		print('thread stopped due to signal %d (%s)' % (signal, sig_num_to_name[signal]))
		for key_vals in reply[3:].split(';'):
			if not key_vals:
				continue
			(key, val) = key_vals.split(':')
			if key == 'thread':
				tid = int(val, 16)
				print('thread: %s' % tid)
			elif re.match(r'^[0-9a-fA-F]+$', key):
				rid = int(key, 16)
				reg_name = reg_id_to_name[rid] if rid in reg_id_to_name else 'reg%02d' % rid;
				print('%s: %s' % (reg_name, val))
			else:
				print('%s: %s' % (key, val))

	# exit status
	elif reply[0] == 'W':
		exit_status = int(reply[1:], 16)
		print('inferior exited with status: %d' % exit_status)
	else:
		print(reply)	

#--------------------------------------------------------------------------
# COMMON DEBUGGER TASKS
#--------------------------------------------------------------------------

def break_into():
	send_draw(b'\x03')
	pass

def mem_read(addr, amt=None):
	packed = ''

	while(amt):
		chunk = min(amt, 256)

		data = 'm' + ( "%x" % addr ) + ',' + ( "%x" % chunk )
		send_packet_data(data)
		resp = recv_packet_data()

		while(resp):
			packed += pack('B', int(resp[0:2],16))
			resp = resp[2:]

		amt -= chunk

	return packed

def debug_status():
	return

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
				reply = tx_rx('?')
				packet_display(reply)
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
				reply = tx_rx('vCont;s') # rsp step packet
				packet_display(reply)

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
