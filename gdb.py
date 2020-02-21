#!/usr/bin/env python3

import os
import re
import shutil
import socket
import subprocess
from struct import pack, unpack

from . import rsp
from . import utils
from . import gdblike
from . import DebugAdapter

linux_signal_to_name = {
	# ISO C99
	2: 'SIGINT',
	4: 'SIGILL',
	6: 'SIGABRT',
	8: 'SIGFPE',
	11: 'SIGSEGV',
	15: 'SIGTERM',

	# historical POSIX
	1: 'SIGHUP',
	3: 'SIGQUIT',
	5: 'SIGTRAP',
	9: 'SIGKILL',
	10: 'SIGUSR1',	# differs from macos
	12: 'SIGUSR2',	# differs from macos
	13: 'SIGPIPE',
	14: 'SIGALRM',

	# newer POSIX
	16: 'SIGSTKFLT',
	17: 'SIGCHLD',	# differs from macos
	18: 'SIGCONT',	# differs from macos
	19: 'SIGSTOP',	# differs
	20: 'SIGTSTP',	# differs
	21: 'SIGTTIN',
	22: 'SIGTTOU',
	23: 'SIGURG', # differs from macos
	24: 'SIGXCPU',
	25: 'SIGXFSZ',
	26: 'SIGVTALRM',
	27: 'SIGPROF',
	30: 'SIGUSR1',
	31: 'SIGUSR2',

	# nonstandard POSIX
	28: 'SIGWINCH',

	# unallocated posix
	7: 'SIGBUX',	# differs from macos
	29: 'SIGPOLL',

	30: 'SIGSTKFLT',
	31: 'SIGSYS'
}

linux_signal_to_debugadapter_reason = {
	1: DebugAdapter.STOP_REASON.SIGNAL_HUP,
	2: DebugAdapter.STOP_REASON.SIGNAL_INT,
	4: DebugAdapter.STOP_REASON.SIGNAL_ILL,
	6: DebugAdapter.STOP_REASON.SIGNAL_ABRT,
	8: DebugAdapter.STOP_REASON.SIGNAL_FPE,
	11: DebugAdapter.STOP_REASON.SIGNAL_SEGV,
	15: DebugAdapter.STOP_REASON.SIGNAL_TERM,
	3: DebugAdapter.STOP_REASON.SIGNAL_QUIT,
	5: DebugAdapter.STOP_REASON.SIGNAL_TRAP,
	9: DebugAdapter.STOP_REASON.SIGNAL_KILL,
	10: DebugAdapter.STOP_REASON.SIGNAL_USR1,
	12: DebugAdapter.STOP_REASON.SIGNAL_USR2,
	13: DebugAdapter.STOP_REASON.SIGNAL_PIPE,
	14: DebugAdapter.STOP_REASON.SIGNAL_ALRM,
	16: DebugAdapter.STOP_REASON.SIGNAL_STKFLT,
	17: DebugAdapter.STOP_REASON.SIGNAL_CHLD,
	18: DebugAdapter.STOP_REASON.SIGNAL_CONT,
	19: DebugAdapter.STOP_REASON.SIGNAL_STOP,
	20: DebugAdapter.STOP_REASON.SIGNAL_TSTP,
	21: DebugAdapter.STOP_REASON.SIGNAL_TTIN,
	22: DebugAdapter.STOP_REASON.SIGNAL_TTOU,
	23: DebugAdapter.STOP_REASON.SIGNAL_URG,
	24: DebugAdapter.STOP_REASON.SIGNAL_XCPU,
	25: DebugAdapter.STOP_REASON.SIGNAL_XFSZ,
	26: DebugAdapter.STOP_REASON.SIGNAL_VTALRM,
	27: DebugAdapter.STOP_REASON.SIGNAL_PROF,
	30: DebugAdapter.STOP_REASON.SIGNAL_USR1,
	31: DebugAdapter.STOP_REASON.SIGNAL_USR2,
	28: DebugAdapter.STOP_REASON.SIGNAL_WINCH,
	7: DebugAdapter.STOP_REASON.SIGNAL_BUX,
	29: DebugAdapter.STOP_REASON.SIGNAL_POLL,
	30: DebugAdapter.STOP_REASON.SIGNAL_STKFLT,
	31: DebugAdapter.STOP_REASON.SIGNAL_SYS
}

class DebugAdapterGdb(gdblike.DebugAdapterGdbLike):
	def __init__(self, **kwargs):
		gdblike.DebugAdapterGdbLike.__init__(self, **kwargs)
		self.os_sig_to_reason = linux_signal_to_debugadapter_reason

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	def exec(self, path, args=[]):
		# resolve path to gdbserver
		path_gdbserver = shutil.which('gdbserver')
		if not os.path.exists(path_gdbserver):
			raise Exception('cannot locate gdbserver')

		# get available port
		port = gdblike.get_available_port()
		if port == None:
			raise Exception('no available ports')

		# invoke gdbserver
		dbg_args = [path_gdbserver, '--once', '--no-startup-with-shell', 'localhost:%d'%port, path, '--']
		dbg_args.extend(args)
		print(' '.join(dbg_args))
		try:
			subprocess.Popen(dbg_args, stdin=None, stdout=None, stderr=None, preexec_fn=gdblike.preexec)
		except Exception:
			raise Exception('invoking gdbserver (used path: %s)' % path_gdbserver)

		# connect to gdbserver
		self.connect('localhost', port)

	def connect(self, address, port):
		# connect to gdbserver
		self.sock = gdblike.connect(address, port)

		# initial commands
		rsp.tx_rx(self.sock, 'Hg0')
		# if 'multiprocess+' in list here, thread reply is like 'pX.Y' where X is core id, Y is thread id
		# negotiate server capabilities
		reply = rsp.tx_rx(self.sock, 'qSupported:swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386')
		for line in reply.split(';'):
			if '=' in line:
				(name, val) = line.split('=')
				self.server_capabilities[name] = val
			else:
				self.server_capabilities[line] = None
		#for (name,val) in self.server_capabilities.items():
		#	print('%s = %s' % (name,val))

		self.reg_info_load()

		# acquire pid as first tid
		reply = rsp.tx_rx(self.sock, '?')
		tdict = rsp.packet_T_to_dict(reply)
		self.tid = tdict['thread']
		self.pid = self.tid

	def mem_modules(self):
		module2addr = {}

		with open('/proc/%d/maps' % self.pid, 'r') as fp:
			lines = fp.readlines()

		for line in lines:
			line = line.strip()
			m = re.match(r'^([0-9a-f]+)-[0-9a-f]+ [rwxp-]{4} .* (/.*)$', line)
			if not m: continue
			(addr, module) = m.group(1,2)
			if module in module2addr: continue
			if os.path.exists(module):
				module2addr[module] = int(addr, 16)

		return module2addr
