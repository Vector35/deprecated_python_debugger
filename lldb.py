#!/usr/bin/env python3

import os
import re
import shutil
import socket
import subprocess

from . import rsp
from . import gdblike
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

class DebugAdapterLLDB(gdblike.DebugAdapterGdbLike):
	def __init__(self, **kwargs):
		gdblike.DebugAdapterGdbLike.__init__(self, **kwargs)

		self.os_sig_to_reason = macos_signal_to_debugadapter_reason

		# register state
		self.reg_info = {}

		# address -> True
		self.breakpoints = {}

		# thread state
		self.thread_idx_selected = None

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, path, args):
		# resolve path to debugserver
		path_debugserver = shutil.which('debugserver')
		if not path_debugserver:
			path_debugserver = '/Library/Developer/CommandLineTools/Library/' + \
			'PrivateFrameworks/LLDB.framework/Versions/A/Resources/debugserver'
		if not os.path.exists(path_debugserver):
			raise Exception('cannot locate debugserver')

		# get available port
		port = gdblike.get_available_port()
		if port == None:
			raise Exception('no available ports')

		# invoke debugserver
		dbg_args = [path_debugserver, 'localhost:%d'%port, path, '--']
		dbg_args.extend(args)
		#print('args are: ', ' '.join(dbg_args))
		try:
			subprocess.Popen(dbg_args, stdin=None, stdout=None, stderr=None, preexec_fn=gdblike.preexec)
		except Exception:
			raise Exception('invoking debugserver (used path: %s)' % path_debugserver)

		# connect to it
		self.sock = gdblike.connect('localhost', port)

		# learn initial registers
		self.reg_info_load()

	# threads
	def thread_list(self):
		reply = rsp.tx_rx(self.sock, 'qfThreadInfo', 'ack_then_reply')
		if not reply.startswith('m'):
			raise DebugAdapter.GeneralError("retrieving thread list from server after qfThreadInfo packet")
		tids = reply[1:].split(',')
		tids = list(map(lambda x: int(x,16), tids))
		return tids

	def thread_selected(self):
		reply = rsp.tx_rx(self.sock, '?', 'ack_then_reply')
		context = rsp.packet_T_to_dict(reply)
		if not 'thread' in context:
			raise DebugAdapter.GeneralError("setting thread on server after '?' packet")
		return context.get('thread')

	def thread_select(self, tid):
		if not tid in self.thread_list():
			raise DebugAdapter.GeneralError("tid 0x%X is not in threads list" % tid)

		# changing threads? new regs
		self.reg_cache = {}

		# set thread for step and continue operations
		payload = 'Hc%x' % tid
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

		# set thread for other operations
		payload = 'Hg%x' % tid
		reply = rsp.tx_rx(self.sock, payload, 'ack_then_ok')

	# breakpoints
	#def breakpoint_set(self, addr):
	#def breakpoint_clear(self, addr):
	#def breakpoint_list(self):

	# register
	#def reg_read(self, name):
	#def reg_write(self, name, value):
	#def reg_list(self):
	#def reg_bits(self, name):

	# mem
	#def mem_read(self, address, length):
	#def mem_write(self, address, data):

	def mem_modules(self):
		module2addr = {}
		reply = rsp.tx_rx(self.sock, 'jGetLoadedDynamicLibrariesInfos:{"fetch_all_solibs":true}')
		for (addr, path) in re.findall(r'"load_address":(\d+).*?"pathname":"([^"]+)"', reply):
			addr = int(addr, 10)
			module2addr[path] = addr
		return module2addr

	# break
	#def break_into(self):
	#def break_reason(self):

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		self.reg_cache = {}
		return self.go_generic('c', self.handler_async_pkt)

	def step_into(self):
		self.reg_cache = {}
		return self.go_generic('vCont;s', self.handler_async_pkt)

	def step_over(self):
		# gdb, lldb just doesn't have this, you must synthesize it yourself
		self.reg_cache = {}
		raise NotImplementedError('step over')

	# asynchronously called when inside a "go" to inform us of stdout (and
	# possibly other stuff)
	def handler_async_pkt(self, pkt):
		if pkt.startswith('O'):
			msg = pkt[1:]
			data = ''.join([chr(int(msg[2*x:2*x+2], 16)) for x in range(int(len(msg)/2))])
			if self.cb_stdout is not None:
				self.cb_stdout(data)
			else:
				print(data, end='')
		else:
			print('handler_async_pkt() got unknown packet: %s' % repr(pkt))
