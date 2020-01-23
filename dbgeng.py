#!/usr/bin/env python3

import re
import socket
from struct import pack, unpack
from binascii import hexlify, unhexlify
from ctypes import *

from . import DebugAdapter

DEBUG_STATUS_NO_CHANGE = 0
DEBUG_STATUS_GO = 1
DEBUG_STATUS_GO_HANDLED = 2
DEBUG_STATUS_GO_NOT_HANDLED = 3
DEBUG_STATUS_STEP_OVER = 4
DEBUG_STATUS_STEP_INTO = 5
DEBUG_STATUS_BREAK = 6
DEBUG_STATUS_NO_DEBUGGEE = 7
DEBUG_STATUS_STEP_BRANCH = 8
DEBUG_STATUS_IGNORE_EVENT = 9
DEBUG_STATUS_RESTART_REQUESTED = 10
DEBUG_STATUS_REVERSE_GO = 11
DEBUG_STATUS_REVERSE_STEP_BRANCH = 12
DEBUG_STATUS_REVERSE_STEP_OVER = 13
DEBUG_STATUS_REVERSE_STEP_INTO = 14
DEBUG_STATUS_OUT_OF_SYNC = 15
DEBUG_STATUS_WAIT_INPUT = 16
DEBUG_STATUS_TIMEOUT = 17

class DebugAdapterDbgeng(DebugAdapter.DebugAdapter):
	def __init__(self, **kwargs):
		self.dll = CDLL(".\windows\dbgengadapt.dll")
		assert self.dll

		# keep mapping between addresses (DbgAdapter namespace) and breakpoint
		# id's (dbgeng namespace)
		self.bp_addr_to_id = {}

	def __del__(self):
		print('del self.dll')
		del self.dll

	def thunk_stop_reason(self):
		estat = self.dll.get_exec_status()
		print('estat=%d' % estat)
		if estat == DEBUG_STATUS_BREAK:
			return (DebugAdapter.STOP_REASON.SIGNAL_TRAP, b'')
		if estat == DEBUG_STATUS_NO_DEBUGGEE:
			# TODO: does exited process have a return value?
			return (DebugAdapter.STOP_REASON.PROCESS_EXITED, 0)
		return (DebugAdapter.STOP_REASON.UNKNOWN, estat)

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, fpath):
		tmp = create_string_buffer(fpath.encode('utf-8'))
		if self.dll.process_start(tmp):
			raise Exception('unable to launch %s' % fpath)

	def attach(self, pid):
		if self.dll.process_attach(target):
			raise Exception('unable to attach to pid %d' % pid)

	def detach(self):
		pass

	def quit(self):
		pass

	# threads
	def thread_list(self):
		threads_n = self.dll.get_number_threads()
		return list(range(threads_n))

	def thread_selected(self):
		return self.dll.get_current_thread()	

	def thread_select(self, tid):
		self.dll.set_current_thread(tid)

	# breakpoints
	def breakpoint_set(self, addr):
		pfunc = self.dll.breakpoint_set
		pfunc.restype = c_int
		pfunc.argtypes = [c_ulonglong, POINTER(c_ulong)]
		bpid = c_ulong();
		rc = pfunc(addr, byref(bpid))
		if rc != 0:
			raise DebugAdapter.BreakpointSetError('dll returned %d' % rc)
		self.bp_addr_to_id[addr] = bpid.value

	def breakpoint_clear(self, addr):
		if not addr in self.bp_addr_to_id:
			raise DebugAdapter.BreakpointClearError('bp at addr 0x%X found' % addr)
		bpid = self.bp_addr_to_id[addr]
		self.dll.breakpoint_clear(bpid)
		del self.bp_addr_to_id[addr]

	def breakpoint_list(self):
		return list(self.bp_addr_to_id.keys())

	# registers
	def reg_read(self, name):
		pfunc = self.dll.reg_read
		pfunc.restype = c_int
		pfunc.argtypes = [c_char_p, POINTER(c_ulonglong)]
		val = c_ulonglong()
		rc = pfunc(c_char_p(name.encode('utf-8')), byref(val))
		if rc != 0:
			return None
		return val.value

	def reg_write(self, name, value):
		pfunc = self.dll.reg_write
		pfunc.restype = c_int
		pfunc.argtypes = [c_char_p, c_ulonglong]
		rc = pfunc(c_char_p(name.encode('utf-8')), value)
		if rc != 0:
			return None
		return 0

	def reg_list(self):
		pass

	def reg_bits(self, reg):
		pass

	# mem
	def mem_read(self, address, length):
		result = (c_uint8 * length)()

		pfunc = self.dll.mem_read
		pfunc.restype = c_int
		pfunc.argtypes = [c_ulonglong, c_ulong, POINTER(c_uint8)]

		rc = pfunc(address, length, result)
		if rc != 0:
			return None

		return b''.join(map(lambda x: x.to_bytes(1,'big'), list(result)))

	def mem_write(self, address, data):
		u8_arr = (c_uint8 * len(data))()
		for (i,b) in enumerate(data):
			u8_arr[i] = b

		pfunc = self.dll.mem_write
		pfunc.restype = c_int
		pfunc.argtypes = [c_ulonglong, POINTER(c_uint8), c_ulong]
		rc = pfunc(address, u8_arr, len(data))
		if rc != 0:
			return None

		return 0

	def mem_modules(self):
		pass

	# break
	def break_into(self):
		self.dll.break_into()

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		self.dll.go()
		return self.thunk_stop_reason()

	def step_into(self):
		self.dll.step_into()
		return self.thunk_stop_reason()

	def step_over(self):
		self.dll.step_over()
		return self.thunk_stop_reason()

	# testing
	def test(self):
		pass

