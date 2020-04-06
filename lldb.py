#!/usr/bin/env python3

import os
import re
import struct
import shutil
import socket
import subprocess

from . import rsp
from . import gdblike
from . import DebugAdapter

def first_str_from_data(data):
	if b'\x00' in data:
		data = data[0:data.find(b'\x00')]
	return data.decode('utf-8')

class DebugAdapterLLDB(gdblike.DebugAdapterGdbLike):
	def __init__(self, **kwargs):
		gdblike.DebugAdapterGdbLike.__init__(self, **kwargs)

		# register state
		self.reg_info = {}

		# breakpoint state
		self.breakpoints = {} # address -> True

		# thread state
		self.thread_idx_selected = None

		# modules/dylibs state
		self.p_dyld_all_image_infos = None
		self.module_cache = {} # address -> {'path':<str>, 'ptime':<uint64>}

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, path, args=[]):
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
		try:
			subprocess.Popen(dbg_args, stdin=None, stdout=None, stderr=None, preexec_fn=gdblike.preexec)
		except Exception:
			raise Exception('invoking debugserver (used path: %s)' % path_debugserver)

		self.target_path_ = path
		self.connect('localhost', port)

	def connect(self, address, port):
		# connect to it
		self.sock = gdblike.connect(address, port)
		self.rspConn = rsp.RspConnection(self.sock)

		# negotiate capabilities
		# TODO: get some capabilities
		capabilities = 'swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;xmlRegisters=i386'
		self.rspConn.negotiate(capabilities)

		# learn initial registers
		self.reg_info_load()

		# learn initial pointer to shared lib info in dyld
		self.p_dyld_all_image_infos = int(self.rspConn.tx_rx('qShlibInfoAddr'), 16)

		# learn pid
		reply = self.rspConn.tx_rx('qProcessInfo')
		if reply.startswith('pid:'):
			self.target_pid_ = int(re.match(r'^pid:([a-fA-F0-9]+)', reply).group(1), 16)

	# threads
	def thread_list(self):
		reply = self.rspConn.tx_rx('qfThreadInfo', 'ack_then_reply')
		if not reply.startswith('m'):
			raise DebugAdapter.GeneralError("retrieving thread list from server after qfThreadInfo packet")
		tids = reply[1:].split(',')
		tids = list(map(lambda x: int(x,16), tids))
		return tids

	def thread_selected(self):
		reply = self.rspConn.tx_rx('?', 'ack_then_reply')
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
		reply = self.rspConn.tx_rx(payload, 'ack_then_ok')

		# set thread for other operations
		payload = 'Hg%x' % tid
		reply = self.rspConn.tx_rx(payload, 'ack_then_ok')

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

	def mem_modules(self, cache_ok=True):
		if not self.p_dyld_all_image_infos:
			self.module_cache = {}
			return self.mem_modules_slow()

		# points to struct dyld_all_image_infos
		# https://opensource.apple.com/source/dyld/dyld-195.5/include/mach-o/dyld_images.h.auto.html
		data = self.mem_read(self.p_dyld_all_image_infos, 40)
		(version, infoArrayCount, infoArray, notification, \
		processDetachedFromSharedRegion, libSystemInitialized, \
		_, _, _, _, _, _, dyldImageLoadAddress) = struct.unpack('<IIQQBBBBBBBBQ', data)

		if not libSystemInitialized or dyldImageLoadAddress == 0:
			self.module_cache = {}
			return self.mem_modules_slow()

		self.module_cache[dyldImageLoadAddress] = {'path':'/usr/lib/dyld', 'ptime':0}

		data = self.mem_read(infoArray, infoArrayCount*24)
		dyld_image_infos = [data[i:i+24] for i in range(0, len(data), 24)]

		for (i,dyld_image_info) in enumerate(dyld_image_infos):
			(pheader, ppath, ptime) = struct.unpack('<QQQ', dyld_image_info)
			#print('image %d/%d' % (i+1, infoArrayCount))
			#print('pheader: %X' % pheader)
			#print('ppath: %X' % ppath)
			#print('ptime: %X' % ptime)

			if not (pheader in self.module_cache) or self.module_cache[pheader]['ptime'] != ptime:
				path = '(blank)'
				try:
					path = first_str_from_data(self.mem_read(ppath, 1024))
				except Exception:
					pass
				self.module_cache[pheader] = {'path':path, 'ptime':ptime}

		return {self.module_cache[addr]['path']:addr for addr in self.module_cache}

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

	#--------------------------------------------------------------------------
	# NON-API UTILITIES
	#--------------------------------------------------------------------------

	def test(self):
		print('test')
		pass

	def thread_stop_pkt_to_reason(self, tdict):
		macos_signal_to_name = { 1: 'SIGHUP', 2: 'SIGINT', 3: 'SIGQUIT', 4:
		'SIGILL', 5: 'SIGTRAP', 6: 'SIGABRT', 7: 'SIGEMT', 8: 'SIGFPE', 9:
		'SIGKILL', 10: 'SIGBUS', 11: 'SIGSEGV', 12: 'SIGSYS', 13: 'SIGPIPE',
		14: 'SIGALRM', 15: 'SIGTERM', 16: 'SIGURG', 17: 'SIGSTOP', 18:
		'SIGTSTP', 19: 'SIGCONT', 20: 'SIGCHLD', 21: 'SIGTTIN', 22: 'SIGTTOU',
		23: 'SIGIO', 24: 'SIGXCPU', 25: 'SIGXFSZ', 26: 'SIGVTALRM', 27:
		'SIGPROF', 28: 'SIGWINCH', 29: 'SIGINFO', 30: 'SIGUSR1', 31: 'SIGUSR2'
		}

		macos_signal_to_debugadapter_reason = {
			1: DebugAdapter.STOP_REASON.SIGNAL_HUP,
			2: DebugAdapter.STOP_REASON.SIGNAL_INT,
			3: DebugAdapter.STOP_REASON.SIGNAL_QUIT,
			4: DebugAdapter.STOP_REASON.SIGNAL_ILL,
			5: DebugAdapter.STOP_REASON.SINGLE_STEP,
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

		metype2reason = {
			1: DebugAdapter.STOP_REASON.ACCESS_VIOLATION,
			2: DebugAdapter.STOP_REASON.ILLEGAL_INSTRUCTION,
			3: DebugAdapter.STOP_REASON.CALCULATION,
			4: DebugAdapter.STOP_REASON.EXC_EMULATION,
			5: DebugAdapter.STOP_REASON.EXC_SOFTWARE,
			6: DebugAdapter.STOP_REASON.BREAKPOINT,
			7: DebugAdapter.STOP_REASON.EXC_SYSCALL,
			8: DebugAdapter.STOP_REASON.EXC_MACH_SYSCALL,
			9: DebugAdapter.STOP_REASON.EXC_RPC_ALERT,
			10: DebugAdapter.STOP_REASON.EXC_CRASH
		}

		signal = tdict.get('signal')
		metype = tdict.get('metype')
		if metype != None: metype = int(metype, 16)
		mecount = tdict.get('mecount', '-1')
		if mecount != None: mecount = int(mecount, 16)
		medata = tdict.get('medata', '-1')
		#print('signal=0x%X metype=%s mecount=%s medata=%s' % (signal, metype, mecount, medata))

		# map the packet macos/lldb "T packet" data to a DebugAdapter reason
		result = (DebugAdapter.STOP_REASON.UNKNOWN, None)
		if metype != None and metype in metype2reason:
			result = (metype2reason[metype], None)
		elif signal in macos_signal_to_debugadapter_reason:
			result = (macos_signal_to_debugadapter_reason[signal], None)

		# done!
		#print('returning: ', result)
		return result

	def mem_modules_slow(self):
		module2addr = {}
		reply = self.rspConn.tx_rx('jGetLoadedDynamicLibrariesInfos:{"fetch_all_solibs":true}')
		for (addr, path) in re.findall(r'"load_address":(\d+).*?"pathname":"([^"]+)"', reply):
			addr = int(addr, 10)
			module2addr[path] = addr
		return module2addr

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
