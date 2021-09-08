#!/usr/bin/env python3

import os
import re
import shutil
import shlex
import socket
import subprocess
from struct import pack, unpack

from . import rsp
from . import utils
from . import gdblike
from . import DebugAdapter

class DebugAdapterGdb(gdblike.DebugAdapterGdbLike):
	def __init__(self, **kwargs):
		gdblike.DebugAdapterGdbLike.__init__(self, **kwargs)

		self.rsp = None

		self.module_cache = {}

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	def exec(self, path, args=[], **kwargs):
		if not os.access(path, os.X_OK):
			raise DebugAdapter.NotExecutableError(path)

		# resolve path to gdbserver
		path_gdbserver = shutil.which('gdbserver')
		if not (path_gdbserver and os.path.exists(path_gdbserver)):
			raise DebugAdapter.NotInstalledError('gdbserver')

		# get available port
		port = gdblike.get_available_port()
		if port == None:
			raise Exception('no available ports')

		# invoke gdbserver
		try:
			if kwargs.get('terminal', False):
				dbg_args = [path_gdbserver, '--once', '--no-startup-with-shell', 'localhost:%d'%port, shlex.quote(path)]
				dbg_args.extend([shlex.quote(arg) for arg in args])
				DebugAdapter.new_terminal(' '.join(dbg_args))
			else:
				dbg_args = [path_gdbserver, '--once', '--no-startup-with-shell', 'localhost:%d'%port, path]
				dbg_args.extend(args)
				subprocess.Popen(dbg_args, stdin=None, stdout=None, stderr=None, preexec_fn=gdblike.preexec)
		except Exception:
			raise Exception('invoking gdbserver (used path: %s)' % path_gdbserver)

		# connect to gdbserver
		self.connect('localhost', port)

	def connect_continued(self, sock, rsp_connect):
		self.sock = sock
		self.rspConn = rsp_connect

		self.reg_info_load()

		# acquire pid as first tid
		reply = self.rspConn.tx_rx('?')
		tdict = rsp.packet_T_to_dict(reply)
		self.tid = tdict.get('thread', None)
		self.target_pid_ = self.tid

	def connect(self, address, port):
		# connect to gdbserver
		sock = gdblike.connect(address, port)
		rspConn = rsp.RspConnection(sock)

		# initial commands
		rspConn.tx_rx('Hg0')
		# if 'multiprocess+' in list here, thread reply is like 'pX.Y' where X is core id, Y is thread id
		# negotiate server capabilities
		# TODO: replace these with something sensible, not something copied from a packet dump
		capabilities = 'swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386'
		rspConn.negotiate(capabilities)

		self.connect_continued(sock, rspConn)

	def mem_modules(self, cache_ok=True):
		if cache_ok and self.module_cache:
			return self.module_cache

		self.module_cache = {}

		fpath = '/proc/%d/maps' % self.target_pid_

		# TODO: prefer local open() if debuggee is on same filesystem as debugger
		#with open(fpath, 'r') as fp:
		#	lines = fp.readlines()
		data = self.get_remote_file(fpath)

		data = data.decode('utf-8')
		lines = data.split('\n')

		for line in lines:
			line = line.strip()
			m = re.match(r'^([0-9a-f]+)-[0-9a-f]+ [rwxp-]{4} .* (/.*)$', line)
			if not m: continue
			(addr, module) = m.group(1,2)
			if module in self.module_cache: continue
			self.module_cache[module] = int(addr, 16)

		return self.module_cache

	#--------------------------------------------------------------------------
	# NON-DEBUGADAPTER API
	#--------------------------------------------------------------------------
	def thread_stop_pkt_to_reason(self, tdict):
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

		# TODO: detect OS and adjust away from hardcoded Ubuntu 4.15.0-51-generic
		lookup = {
			1: DebugAdapter.STOP_REASON.SIGNAL_HUP,
			2: DebugAdapter.STOP_REASON.SIGNAL_INT,
			4: DebugAdapter.STOP_REASON.ILLEGAL_INSTRUCTION,
			6: DebugAdapter.STOP_REASON.SIGNAL_ABRT,
			8: DebugAdapter.STOP_REASON.CALCULATION,
			11: DebugAdapter.STOP_REASON.ACCESS_VIOLATION,
			15: DebugAdapter.STOP_REASON.SIGNAL_TERM,
			3: DebugAdapter.STOP_REASON.SIGNAL_QUIT,
			5: DebugAdapter.STOP_REASON.SINGLE_STEP,
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

		dreason = DebugAdapter.STOP_REASON.UNKNOWN
		result = (dreason, None)

		if 'signal' in tdict:
			signal = tdict['signal']

			# breakpoint and trap flag exception are both reported as SIGTRAP
			# use presence of 'swbreak' to differentiate, if possible
			if signal in linux_signal_to_name and linux_signal_to_name[signal] == 'SIGTRAP' and 'swbreak' in tdict:
				result = (DebugAdapter.STOP_REASON.BREAKPOINT, 0)
			else:
				if signal in lookup:
					result = (lookup[signal], None)
				else:
					result = (dreason, signal)

		#print('returning: ', result)
		return result
