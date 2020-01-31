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
		self.reg_info = {} # eg: 'rip' -> {'id':8, 'width':64}
		self.reg_cache = {} # eg: 'rip' -> 0x400400

		# address -> True
		self.breakpoints = {}

		# thread state
		self.thread_idx_selected = None

		#
		self.last_api_call = ''

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, path):
		# TODO: find/launch gdb/debugserver
		self.last_api_call = 'exec'
		pass

	def attach(self, pid):
		# TODO: find/launch gdb/debugserver
		self.last_api_call = 'attach'
		pass

	def detach(self):
		self.last_api_call = 'detach'
		try:
			rsp.send_packet_data(self.sock, 'D')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass

	def quit(self):
		self.last_api_call = 'quit'
		try:
			rsp.send_packet_data(self.sock, 'k')
			self.sock.shutdown(socket.SHUT_RDWR)
			self.sock.close()
			self.sock = None
		except rsp.RspDisconnected:
			pass

	# threads
	def thread_list(self):
		self.last_api_call = 'thread_list'
		raise NotImplementedError("subclass should implement this")

	def thread_selected(self):
		self.last_api_call = 'thread_selected'
		reply = rsp.tx_rx(self.sock, '?', 'ack_then_reply')
		context = rsp.packet_T_to_dict(reply)
		if not 'thread' in context:
			raise DebugAdapter.GeneralError("setting thread on server after '?' packet")
		return context.get('thread')

	def thread_select(self, tid):
		self.last_api_call = 'thread_select'
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
		self.last_api_call = 'breakpoint_set'
		if addr in self.breakpoints:
			raise DebugAdapter.BreakpointSetError("breakpoint set at 0x%X already exists" % addr)

		data = 'Z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')
		if reply != 'OK':
			raise DebugAdapter.BreakpointSetError('rsp replied: %s' % reply)
		self.breakpoints[addr] = True
		return 0

	def breakpoint_clear(self, addr):
		self.last_api_call = 'breakpoint_clear'
		if not addr in self.breakpoints:
			raise DebugAdapter.BreakpointClearError("breakpoint clear at 0x%X doesn't exist" % addr)

		data = 'z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')
		if reply != 'OK':
			raise DebugAdapter.BreakpointClearError("rsp replied: %s" % reply)

		del self.breakpoints[addr]
		return 0

	def breakpoint_list(self):
		self.last_api_call = 'breakpoint_list'
		return self.breakpoints

	# register
	def reg_read(self, name):
		cache_clean = (self.last_api_call == 'reg_read')

		self.last_api_call = 'reg_read'

		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)

		if name in self.reg_cache and cache_clean:
			return self.reg_cache[name]

		# see if gdb will respond to a single register query
		id_ = self.reg_info[name]['id']
		reply = rsp.tx_rx(self.sock, 'p%02x' % id_, 'ack_then_reply')
		if reply != '':
			val = int(''.join(reversed([reply[i:i+2] for i in range(0,len(reply),2)])), 16)
			self.reg_cache[name] = val # cache result
			return val

		# otherwise, do a general purpose register query
		tmp = self.general_read_registers()
		if not name in tmp:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		for (k,v) in tmp.items():
			self.reg_cache[k] = v # cache update
		return self.reg_cache[name]

	def reg_write(self, name, value):
		self.last_api_call = 'reg_write'
		if not name in self.reg_name_to_id:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)

		id_ = self.reg_name_to_id[name]

		valstr = '%016x'%value
		valstr = [valstr[i:i+2] for i in range(0,len(valstr),2)]
		valstr = ''.join(reversed(valstr))
		payload = 'P %d=%s' % (id_, valstr)
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

	def reg_list(self):
		self.last_api_call = 'reg_list'
		return self.reg_info.keys()

	def reg_bits(self, name):
		self.last_api_call = 'reg_bits'
		if not name in self.reg_info:
			raise DebugAdapter.GeneralError("requested register %s doesnt exist" % name)
		return int(self.reg_info[name]['width'])

	# mem
	def mem_read(self, address, length):
		self.last_api_call = 'mem_read'
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
		self.last_api_call = 'mem_write'
		payload = 'M%X,%X:%s' % (address, len(data), ''.join(['%02X'%b for b in data]))
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_reply')
		if reply != 'OK':
			raise DebugAdapter.GeneralError('writing to address 0x%X' % address)
			return 0

	def mem_modules(self):
		self.last_api_call = 'mem_modules'
		module2addr = {}
		reply = rsp.tx_rx(self.sock, 'jGetLoadedDynamicLibrariesInfos:{"fetch_all_solibs":true}')
		for (addr, path) in re.findall(r'"load_address":(\d+).*?"pathname":"([^"]+)"', reply):
			addr = int(addr, 10)
			module2addr[path] = addr
		return module2addr

	# break
	def break_into(self):
		self.last_api_call = 'break_into'
		rsp.send_raw(self.sock, '\x03')
		# TODO: detect error
		return True

	def break_reason(self):
		self.last_api_call = 'break_reason'
		pkt_T = rsp.tx_rx(self.sock, '?', 'ack_then_reply')
		#print(pkt_T)

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		self.last_api_call = 'go'
		return self.go_generic('c', handler_async_pkt)

	def step_into(self):
		self.last_api_call = 'step_into'
		return self.go_generic('vCont;s', handler_async_pkt)

	def step_over(self):
		# gdb, lldb just doesn't have this, you must synthesize it yourself
		self.last_api_call = 'step_over'
		raise NotImplementedError('step over')

	#--------------------------------------------------------------------------
	# helpers, NOT part of the API
	#--------------------------------------------------------------------------
	def general_read_registers(self):
		reply = rsp.tx_rx(self.sock, 'g')

		# map register id to bit width
		id2width = {v['id']: v['width'] for v in self.reg_info.values()}
		id_max = max(id2width.keys())

		# build map register id -> bit offset within registers blob
		id2offs = {}
		offset = 0
		for i in range(id_max):
			if not i in id2width: # non-sequential id, can't know offset
				break
			id2offs[i] = offset
			offset += id2width[i]

		#
		result = {}
		id2name = {self.reg_info[k]['id']: k for k in self.reg_info.keys()}
		id_max = max(id2offs.keys())
		for i in range(id_max):
			slice_lo = 2*(id2offs[i]//8)
			slice_hi = 2*((id2offs[i] + id2width[i])//8)
			# TODO: exception if bits aren't multiple of 8
			# TODO: exception if slice not within
			valstr = reply[slice_lo:slice_hi]
			assert len(valstr) % 2 == 0
			# TODO: is gdb response always little end?
			valstr = ''.join(reversed([valstr[2*i]+valstr[2*i+1] for i in range(len(valstr)//2)]))
			result[id2name[i]] = int(valstr, 16)

		return result
