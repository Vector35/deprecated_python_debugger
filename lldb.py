#!/usr/bin/env python3

import re
import socket
from struct import pack, unpack
from binascii import hexlify, unhexlify

from . import rsp
from . import DebugAdapter

macos_signal_to_name = {
	1: 'SIGHUP',
	2: 'SIGINT',
	3: 'SIGQUIT',
	4: 'SIGILL',
	5: 'SIGTRAP',
	6: 'SIGABRT',
	7: 'SIGEMT',
	8: 'SIGFPE',
	9: 'SIGKILL',
	10: 'SIGBUS',
	11: 'SIGSEGV',
	12: 'SIGSYS',
	13: 'SIGPIPE',
	14: 'SIGALRM',
	15: 'SIGTERM',
	16: 'SIGURG',
	17: 'SIGSTOP',
	18: 'SIGTSTP',
	19:  'SIGCONT',
	20: 'SIGCHLD',
	21: 'SIGTTIN',
	22: 'SIGTTOU',
	23: 'SIGIO',
	24: 'SIGXCPU',
	25: 'SIGXFSZ',
	26: 'SIGVTALRM',
	27: 'SIGPROF',
	28: 'SIGWINCH',
	29: 'SIGINFO',
	30: 'SIGUSR1',
	31: 'SIGUSR2'
}

macos_signal_to_debugadapter_reason = {
	1: DebugAdapter.STOP_REASON.SIGNAL_HUP,
	2: DebugAdapter.STOP_REASON.SIGNAL_INT,
	3: DebugAdapter.STOP_REASON.SIGNAL_QUIT,
	4: DebugAdapter.STOP_REASON.SIGNAL_ILL,
	5: DebugAdapter.STOP_REASON.SIGNAL_TRAP,
	6: DebugAdapter.STOP_REASON.SIGNAL_ABRT,
	7: DebugAdapter.STOP_REASON.SIGNAL_EMT,
	8: DebugAdapter.STOP_REASON.SIGNAL_FPE,
	9: DebugAdapter.STOP_REASON.SIGNAL_KILL,
	10: DebugAdapter.STOP_REASON.SIGNAL_BUS,
	11: DebugAdapter.STOP_REASON.SIGNAL_SEGV,
	12: DebugAdapter.STOP_REASON.SIGNAL_SYS,
	13: DebugAdapter.STOP_REASON.SIGNAL_PIPE,
	14: DebugAdapter.STOP_REASON.SIGNAL_ALRM,
	15: DebugAdapter.STOP_REASON.SIGNAL_TERM,
	16: DebugAdapter.STOP_REASON.SIGNAL_URG,
	17: DebugAdapter.STOP_REASON.SIGNAL_STOP,
	18: DebugAdapter.STOP_REASON.SIGNAL_TSTP,
	19: DebugAdapter.STOP_REASON.SIGNAL_CONT,
	20: DebugAdapter.STOP_REASON.SIGNAL_CHLD,
	21: DebugAdapter.STOP_REASON.SIGNAL_TTIN,
	22: DebugAdapter.STOP_REASON.SIGNAL_TTOU,
	23: DebugAdapter.STOP_REASON.SIGNAL_IO,
	24: DebugAdapter.STOP_REASON.SIGNAL_XCPU,
	25: DebugAdapter.STOP_REASON.SIGNAL_XFSZ,
	26: DebugAdapter.STOP_REASON.SIGNAL_VTALRM,
	27: DebugAdapter.STOP_REASON.SIGNAL_PROF,
	28: DebugAdapter.STOP_REASON.SIGNAL_WINCH,
	29: DebugAdapter.STOP_REASON.SIGNAL_INFO,
	30: DebugAdapter.STOP_REASON.SIGNAL_USR1,
	31: DebugAdapter.STOP_REASON.SIGNAL_USR2,
}

class DebugAdapterLLDB(DebugAdapter.DebugAdapter):
	def __init__(self, cfg={}):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect(('localhost', 31337))

		# register state
		self.reg_id_to_name = {}
		self.reg_name_to_id = {}
		self.register_sense()

		# address -> True
		self.breakpoints = {}

		# thread state
		self.thread_idx_selected = None

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, path):
		# TODO: find/launch debugserver
		pass

	def attach(self, pid):
		# TODO: find/launch debugserver
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
		except RspDisconnected:
			pass

	# threads
	def thread_list(self):
		reply = rsp.tx_rx(self.sock, 'qfThreadInfo', 'ack_then_reply')
		assert reply.startswith('m')
		tids = reply[1:].split(',')
		tids = list(map(lambda x: int(x,16), tids))
		return tids

	def thread_selected(self):
		reply = rsp.tx_rx(self.sock, '?', 'ack_then_reply')
		context = rsp.packet_T_to_dict(reply)
		assert 'thread' in context
		return context.get('thread')

	def thread_select(self, tid):
		# set thread for step and continue operations
		payload = 'Hc%x' % tid
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

		# set thread for other operations
		payload = 'Hg%x' % tid
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

	# breakpoints
	def breakpoint_set(self, addr):
		if addr in self.breakpoints:
			return None

		data = 'Z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')
		if reply != 'OK':
			return None

		self.breakpoints[addr] = True
		return 0

	def breakpoint_clear(self, addr):
		if not addr in self.breakpoints:
			return None

		data = 'z0,%x,1' % addr
		reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')
		if reply != 'OK':
			print('reply was: -%s-' % reply)
			return None

		del self.breakpoints[addr]
		return 0

	def breakpoint_list(self):
		return self.breakpoints

	# register
	def reg_read(self, name):
		self.register_sense()
		id_ = self.reg_name_to_id[name]
		reply = rsp.tx_rx(self.sock, 'p%02x' % id_, 'ack_then_reply')
		return int(''.join(reversed([reply[i:i+2] for i in range(0,len(reply),2)])), 16)

	def reg_write(self, name, value):
		self.register_sense()

		if not name in self.reg_name_to_id:
			print('ERROR: unknown register %s' % name)
			return None

		id_ = self.reg_name_to_id[name]

		valstr = '%016x'%value
		valstr = [valstr[i:i+2] for i in range(0,len(valstr),2)]
		valstr = ''.join(reversed(valstr))
		payload = 'P %d=%s' % (id_, valstr)
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

	def register_list(self):
		self.register_sense()
		return self.reg_name_to_id.keys()

	# mem
	def mem_read(self, address, length):
		packed = b''

		while(length):
			chunk = min(length, 256)

			data = 'm' + ("%x" % address) + ',' + ("%x" % chunk)
			reply = rsp.tx_rx(self.sock, data, 'ack_then_reply')

			while(reply):
				packed += pack('B', int(reply[0:2],16))
				reply = reply[2:]

			length -= chunk

		return packed

	def mem_write(self, address, data):
		payload = 'M%X,%X:%s' % (address, len(data), ''.join(['%02X'%b for b in data]))
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_reply')
		if reply == 'OK':
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

	# execution control
	def go(self):
		return self.go_generic('c')

	def step_into(self):
		return self.go_generic('vCont;s')

	def step_over(self):
		# gdb, lldb just doesn't have this, you must synthesize it yourself
		raise NotImplementedError('step over')

	# testing
	def test(self):
		reply = rsp.tx_rx(self.sock, 'jGetLoadedDynamicLibrariesInfos:{"fetch_all_solibs":true}')
		for (addr, path) in re.findall(r'"load_address":(\d+).*?"pathname":"([^"]+)"', reply):
			addr = int(addr, 10)
			print('%s: 0x%X' % (path, addr))

		#self.break_reason()

	#--------------------------------------------------------------------------
	# helpers, NOT part of the API
	#--------------------------------------------------------------------------

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

	def go_generic(self, gotype, handler_async_pkt=None):
		try:
			reply = rsp.tx_rx(self.sock, gotype, 'mixed_output_ack_then_reply', handler_async_pkt)
			(reason, reason_data) = (None, None)

			# thread info
			if reply[0] == 'T':
				tdict = rsp.packet_T_to_dict(reply)
				self.active_thread_tid = tdict['thread']
				signum = tdict.get('signal', 0)
				(reason, reason_data) = \
					(macos_signal_to_debugadapter_reason.get(signum, DebugAdapter.STOP_REASON.UNKNOWN), signum)

			# exit status
			elif reply[0] == 'W':
				exit_status = int(reply[1:], 16)
				#print('inferior exited with status: %d' % exit_status)
				(reason, reason_data) = (DebugAdapter.STOP_REASON.PROCESS_EXITED, exit_status)

			else:
				print(reply)
				(reason, reason_data) = (DebugAdapter.STOP_REASON.UNKNOWN, None)

			return (reason, reason_data)

		except rsp.RspDisconnected:
			return (DebugAdapter.BACKEND_DISCONNECTED, None)
