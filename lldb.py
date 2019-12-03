#!/usr/bin/env python3

import rsp
import socket
from struct import pack, unpack

class DebugAdapterLLDB:
	def __init__(self, cfg={}):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(('localhost', 31337))

		self.context_last = {}
		self.reg_id_to_name = {}
		self.reg_name_to_id = {}
		self.breakpoint_id_to_addr = {}

	# session start/stop
	def exec(self, path):
		# TODO: find/launch debugserver
		pass

	def attach(self, pid):
		# TODO: find/launch debugserver
		pass

	def detach(self):
		rsp.send_packet_data(self.sock, 'D')
		self.sock.shutdown(socket.SHUT_RDWR)
		self.sock.close()
		self.sock = None
		pass

	def quit(self):
		rsp.send_packet_data(self.sock, 'k')
		self.sock.shutdown(socket.SHUT_RDWR)
		self.sock.close()
		self.sock = None

	# threads
	def thread_get_ids(self):
		reply = rsp.tx_rx(self.sock, 'qfThreadInfo', 'ack_then_reply')
		assert reply[0] == 'm'
		lldb_tids = reply[1:].split(',')
		lldb_tids = list(map(lambda x: int(x,16), lldb_tids))

		if display:
			lldb_tid_cur = None

			if context_last and 'thread' in context_last:
				lldb_tid_cur = context_last['thread']
			for (i, lldb_tid) in enumerate(lldb_tids):
				marker = '-->' if lldb_tid == lldb_tid_cur else '   '
				print('%s %d: %x' % (marker, i, lldb_tid))

		return lldb_tids

	def thread_get_active(self):
		pass

	def thread_switch(self, tid):
		global context_last

		thread_ids = self.thread_list()

		# set thread for step and continue operations
		payload = 'Hc%x' % thread_ids[thread_idx]
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

		# set thread for other operations
		payload = 'Hg%x' % thread_ids[thread_idx]
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

		# capture new thread context
		pkt_T = rsp.tx_rx(self.sock, '?', 'ack_then_reply')
		context_last = packet_T_to_dict(pkt_T)

	# breakpoints
	def breakpoint_set(self, address):
		if addr in self.breakpoint_id_to_addr.values():
			return None

		data = 'Z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data)
		if reply != 'OK':
			return None

		ids = self.breakpoint_id_to_addr.keys()
		for bpid in range(999999999):
			if not bpid in ids:
				self.breakpoint_id_to_addr[bpid] = addr
				return bpid

	def breakpoint_clear(self, bpid):
		if not bpid in self.breakpoint_id_to_addr:
			return None

		data = 'z0,%x,1' % self.breakpoint_id_to_addr[bpid]
		reply = rsp.tx_rx(self.sock, data)
		if reply != 'OK':
			print('reply was: -%s-' % reply)
			return None

		del self.breakpoint_id_to_addr[bpid]

	def breakpoint_list(self):
		return self.breakpoint_id_to_addr

	# register
	def register_read(self, name):
		self.register_sense()
		id_ = self.reg_name_to_id[name]
		reply = rsp.tx_rx(self.sock, 'p%02x' % id_, 'ack_then_reply')
		return int(''.join(reversed([reply[i:i+2] for i in range(0,len(reply),2)])), 16)

	def register_write(self, name, value):
		self.register_sense()

		if not name in self.reg_name_to_id:
			print('ERROR: unknown register %s' % name)
			return None

		id_ = self.reg_name_to_id[name]

		valstr = '%016x'%value
		valstr = [valstr[i:i+2] for i in range(0,len(valstr),2)]
		valstr = ''.join(reversed(valstr))
		payload = 'P %d=%s' % (id_, valstr)
		reply = rsp.tx_rx(self.sock, payload)
		if reply == 'OK':
			return 0

	def register_list(self):
		self.register_sense()
		return self.reg_name_to_id.keys()

	# mem
	def mem_read(self, address, length):
		packed = b''

		while(length):
			chunk = min(length, 256)

			data = 'm' + ("%x" % address) + ',' + ("%x" % chunk)
			reply = rsp.tx_rx(self.sock, data)

			while(reply):
				packed += pack('B', int(reply[0:2],16))
				reply = reply[2:]

			length -= chunk

		return packed

	def mem_write(self, address, data):
		payload = 'M%X,%X:%s' % (addr, len(data), ''.join(['%02X'%b for b in data]))
		reply = rsp.tx_rx(self.sock, payload)
		if reply == 'OK':
			return 0

	# break
	def break_into(self):
		rsp.send_raw(sock, '\x03')

	# execution control
	def go(self):
		while 1:
			reply = rsp.tx_rx(self.sock, 'c')
			if reply[0] == 'T':
				break
			# TODO: process reply as pkt_T

	def step_into(self):
		while 1:
			reply = rsp.tx_rx(self.sock, 'vCont;s')
			if reply[0] == 'T':
				break
		pass

	def step_over(self):
		pass

	# other stuff
	def register_sense(self, force=False):
		if not force and self.reg_id_to_name:
			return

		self.reg_id_to_name = {}
		self.reg_name_to_id = {}

		reg_array = rsp.register_scan(self.sock)

		for (i, name) in enumerate(reg_array):
			if name == None:
				continue

			self.reg_id_to_name[i] = name
			self.reg_name_to_id[name] = i
