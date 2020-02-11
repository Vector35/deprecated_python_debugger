#!/usr/bin/env python3

import os
import re
import socket
from struct import pack, unpack
from ctypes import *
from enum import Enum, auto, unique
from . import DebugAdapter

class DEBUG_STATUS(Enum):
	NO_CHANGE = 0
	GO = 1
	GO_HANDLED = 2
	GO_NOT_HANDLED = 3
	STEP_OVER = 4
	STEP_INTO = 5
	BREAK = 6
	NO_DEBUGGEE = 7
	STEP_BRANCH = 8
	IGNORE_EVENT = 9
	RESTART_REQUESTED = 10
	REVERSE_GO = 11
	REVERSE_STEP_BRANCH = 12
	REVERSE_STEP_OVER = 13
	REVERSE_STEP_INTO = 14
	OUT_OF_SYNC = 15
	WAIT_INPUT = 16
	TIMEOUT = 17

# dll uses return values to indicate success/failure while we use exceptions
ERROR_UNSPECIFIED = -1

class DebugAdapterDbgeng(DebugAdapter.DebugAdapter):
	def __init__(self, **kwargs):
		DebugAdapter.DebugAdapter.__init__(self, **kwargs)

		fpath = os.path.abspath(__file__)
		fpath = os.path.dirname(fpath)
		fpath = os.path.join(fpath, 'dbgengadapt\dbgengadapt.dll')
		self.dll = CDLL(fpath)
		if not self.dll:
			raise DebugAdapter.GeneralError("loading dbgengadapt.dll")

		# keep mapping between addresses (DbgAdapter namespace) and breakpoint
		# id's (dbgeng namespace)
		self.bp_addr_to_id = {}

	def __del__(self):
		#print('destructor')
		pass

	def thunk_stop_reason(self):
		status = c_ulong()
		if self.dll.get_exec_status(byref(status)) != 0:
			raise DebugAdapter.GeneralError("retrieving execution status")
		status = DEBUG_STATUS(status.value)
		#print('execution status = ', status)

		if status == DEBUG_STATUS.BREAK:
			return (DebugAdapter.STOP_REASON.SIGNAL_TRAP, b'')

		if status == DEBUG_STATUS.NO_DEBUGGEE:
			code = c_ulong()
			if self.dll.get_exit_code(byref(code)) != 0:
				raise DebugAdapter.GeneralError("retrieving exit code")
			return (DebugAdapter.STOP_REASON.PROCESS_EXITED, code.value)

		# otherwise just return the numeric value of the status
		return (DebugAdapter.STOP_REASON.UNKNOWN, status.value)

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, fpath, args):
		if '/' in fpath:
			fpath = fpath.replace('/', '\\')
		fpath = create_string_buffer(fpath.encode('utf-8'))
		rc = self.dll.process_start(fpath)
		if rc:
			raise Exception('unable to launch %s, dbgeng adapter returned %d' % (fpath, rc))

	def attach(self, pid):
		if self.dll.process_attach(target):
			raise Exception('unable to attach to pid %d' % pid)

	def detach(self):
		self.dll.process_detach()
		pass

	def quit(self):
		self.dll.quit()
		pass

	# threads
	def thread_list(self):
		threads_n = self.dll.get_number_threads()
		if threads_n < 0:
			raise DebugAdapter.GeneralError("retrieving thread list")
		return list(range(threads_n))

	def thread_selected(self):
		tid = self.dll.get_current_thread()
		if tid < 0:
			raise DebugAdapter.GeneralError("retrieving selected thread")
		return tid

	def thread_select(self, tid):
		rc = self.dll.set_current_thread(tid)
		if rc < 0:
			raise DebugAdapter.GeneralError("selecting thread")

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
			raise DebugAdapter.BreakpointClearError('bp at addr not 0x%X found' % addr)
		bpid = self.bp_addr_to_id[addr]
		self.dll.breakpoint_clear(bpid)
		del self.bp_addr_to_id[addr]

	def breakpoint_list(self):
		return list(self.bp_addr_to_id.keys())

	# registers
	def reg_read(self, name):
		val = c_ulonglong()
		name = c_char_p(name.encode('utf-8'))
		if self.dll.reg_read(name, byref(val)) != 0:
			raise DebugAdapter.GeneralError("reading register")
		return val.value

	def reg_write(self, name, value):
		name = c_char_p(name.encode('utf-8'))
		value = c_ulonglong(value)
		if self.dll.reg_write(name, value) != 0:
			raise DebugAdapter.GeneralError("writing register")

	def reg_list(self):
		regcount = c_int()
		if self.dll.reg_count(byref(regcount)):
			raise DebugAdapter.GeneralError("retrieving register count")
		regcount = regcount.value
		regname = create_string_buffer(512);

		result = []
		for regidx in range(regcount):
			if self.dll.reg_name(regidx, regname) != 0:
				raise DebugAdapter.GeneralError("translating register index to name")
			result.append(regname.value.decode('utf-8'))

		return result

	def reg_bits(self, name):
		name = c_char_p(name.encode('utf-8'))
		val = c_int()
		if self.dll.reg_read(name, byref(val)) != 0:
			raise DebugAdapter.GeneralError("reading register")

		result = c_int()
		if self.dll.reg_width(name, byref(result)) != 0:
			raise DebugAdapter.GeneralError("retrieving register width")
		return result.value

	# mem
	def mem_read(self, address, length):
		result = (c_uint8 * length)()

		pfunc = self.dll.mem_read
		pfunc.restype = c_int
		pfunc.argtypes = [c_ulonglong, c_ulong, POINTER(c_uint8)]

		rc = pfunc(address, length, result)
		if rc != 0:
			raise DebugAdapter.GeneralError("reading from address 0x%X" % address)

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
			raise DebugAdapter.GeneralError("writing to address 0x%X" % address)

		return 0

	def mem_modules(self):
		module2addr = {}

		modules_n = c_int()
		if self.dll.module_num(byref(modules_n)) != 0:
			raise DebugAdapter.GeneralError("retrieving module list size")
		modules_n = modules_n.value

		image_path = create_string_buffer(4096) # or MAX_PATH, whatever
		image_addr = c_ulonglong()
		for idx in range(modules_n):
			if self.dll.module_get(idx, byref(image_path), byref(image_addr)) != 0:
				raise DebugAdapter.GeneralError("retrieving module name")
			module2addr[image_path.value.decode('utf-8')] = image_addr.value

		return module2addr

	# break
	def break_into(self):
		self.dll.break_into()

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		# TODO: Handle output
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

