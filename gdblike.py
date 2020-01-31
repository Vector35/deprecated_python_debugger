#!/usr/bin/env python3

import re
import socket
from struct import pack, unpack
from binascii import hexlify, unhexlify

from . import rsp
from . import DebugAdapter

# asynchronously called when inside a "go" to inform us of stdout (and
# possibly other stuff)
def handler_async_pkt(pkt):
	if pkt.startswith('O'):
		msg = pkt[1:]
		print(''.join([chr(int(msg[2*x:2*x+2], 16)) for x in range(int(len(msg)/2))]), end='')
	else:
		print('handler_async_pkt() got unknown packet: %s' % repr(pkt))

class DebugAdapterGdbLike(DebugAdapter.DebugAdapter):
	def __init__(self, **kwargs):
		host = kwargs.get('host', 'localhost')
		port = kwargs.get('port', 31337)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((host, port))

		# register info
		self.reg_info = {}

		# address -> True
		self.breakpoints = {}

		# thread state
		self.thread_idx_selected = None

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, path):
		# TODO: find/launch gdb/debugserver
		pass

	def attach(self, pid):
		# TODO: find/launch gdb/debugserver
		pass

	def detach(self):
		try:
			rsp.send_packet_data(self.sock, 'D')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass

	def quit(self):
		try:
			rsp.send_packet_data(self.sock, 'k')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass

	# threads
	def thread_list(self):
		raise NotImplementedError("subclass should implement this")

	def thread_selected(self):
		reply = rsp.tx_rx(self.sock, '?', 'ack_then_reply')
		context = rsp.packet_T_to_dict(reply)
		if not 'thread' in context:
			raise DebugAdapter.GeneralError("setting thread on server after '?' packet")
		return context.get('thread')

	def thread_select(self, tid):
		if not tid in self.thread_list():
			raise DebugAdapter.GeneralError("tid 0x%X is not in threads list" % tid)

		# set thread for step and continue operations
		payload = 'Hc%x' % tid
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

		# set thread for other operations
		payload = 'Hg%x' % tid
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

	# breakpoints
	def breakpoint_set(self, addr):
		if addr in self.breakpoints:
			raise DebugAdapter.BreakpointSetError("breakpoint set at 0x%X already exists" % addr)

		data = 'Z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')
		if reply != 'OK':
			raise DebugAdapter.BreakpointSetError('rsp replied: %s' % reply)
		self.breakpoints[addr] = True
		return 0

	def breakpoint_clear(self, addr):
		if not addr in self.breakpoints:
			raise DebugAdapter.BreakpointClearError("breakpoint clear at 0x%X doesn't exist" % addr)

		data = 'z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')
		if reply != 'OK':
			raise DebugAdapter.BreakpointClearError("rsp replied: %s" % reply)

		del self.breakpoints[addr]
		return 0

	def breakpoint_list(self):
		return self.breakpoints

	# register
	def reg_read(self, name):
		self.reg_info_load()
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		id_ = self.reg_info[name]['id']
		reply = rsp.tx_rx(self.sock, 'p%02x' % id_, 'ack_then_reply')
		return int(''.join(reversed([reply[i:i+2] for i in range(0,len(reply),2)])), 16)

	def reg_write(self, name, value):
		self.reg_info_load()

		if not name in self.reg_name_to_id:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)

		id_ = self.reg_name_to_id[name]

		valstr = '%016x'%value
		valstr = [valstr[i:i+2] for i in range(0,len(valstr),2)]
		valstr = ''.join(reversed(valstr))
		payload = 'P %d=%s' % (id_, valstr)
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

	def reg_list(self):
		self.reg_info_load()
		return self.reg_info.keys()

	def reg_bits(self, name):
		self.reg_info_load()
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		return int(self.reg_info[name]['width'])

	# mem
	def mem_read(self, address, length):
		packed = b''

		while(length):
			chunk = min(length, 256)

			data = 'm' + ("%x" % address) + ',' + ("%x" % chunk)
			reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')
			if reply.startswith('E'): # error 'E' differentiated from hex 'e' by case
				# and len(reply)==3:
				raise DebugAdapter.GeneralError('reading from address 0x%X' % address)

			while(reply):
				packed += pack('B', int(reply[0:2],16))
				reply = reply[2:]

			length -= chunk

		return packed

	def mem_write(self, address, data):
		payload = 'M%X,%X:%s' % (address, len(data), ''.join(['%02X'%b for b in data]))
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_reply')
		if reply != 'OK':
			raise DebugAdapter.GeneralError('writing to address 0x%X' % address)
			return 0

	def mem_modules(self):
		module2addr = {}
		reply = rsp.tx_rx(self.sock, 'jGetLoadedDynamicLibrariesInfos:{"fetch_all_solibs":true}')
		for (addr, path) in re.findall(r'"load_address":(\d+).*?"pathname":"([^"]+)"', reply):
			addr = int(addr, 10)
			module2addr[path] = addr
		return module2addr

	# break
	def break_into(self):
		rsp.send_raw(self.sock, '\x03')
		# TODO: detect error
		return True

	def break_reason(self):
		pkt_T = rsp.tx_rx(self.sock, '?', 'ack_then_reply')
		print(pkt_T)

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		return self.go_generic('c', handler_async_pkt)

	def step_into(self):
		return self.go_generic('vCont;s', handler_async_pkt)

	def step_over(self):
		# gdb, lldb just doesn't have this, you must synthesize it yourself
		raise NotImplementedError('step over')

	#--------------------------------------------------------------------------
	# helpers, NOT part of the API
	#--------------------------------------------------------------------------
	def reg_info_load(self):
		raise NotImplementedError('subclass needs to populate self.reg_info ' + \
			'where key is reg name and value is a dict with id and width ' + \
			'keys')
