#!/usr/bin/env python3

import os
import re
import time
import socket
import shlex
import threading
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

class WINNT_STATUS(Enum):
	STATUS_DATATYPE_MISALIGNMENT = 0x80000002
	STATUS_BREAKPOINT = 0x80000003
	STATUS_SINGLE_STEP = 0x80000004
	STATUS_ACCESS_VIOLATION = 0xC0000005
	STATUS_IN_PAGE_ERROR = 0xC0000006
	STATUS_NO_MEMORY = 0xC0000017
	STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
	STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025
	STATUS_INVALID_DISPOSITION = 0xC0000026
	STATUS_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
	STATUS_FLOAT_DENORMAL_OPERAND = 0xC000008D
	STATUS_FLOAT_DIVIDE_BY_ZERO = 0xC000008E
	STATUS_FLOAT_INEXACT_RESULT = 0xC000008F
	STATUS_FLOAT_INVALID_OPERATION = 0xC0000090
	STATUS_FLOAT_OVERFLOW = 0xC0000091
	STATUS_FLOAT_STACK_CHECK = 0xC0000092
	STATUS_FLOAT_UNDERFLOW = 0xC0000093
	STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094
	STATUS_INTEGER_OVERFLOW = 0xC0000095
	STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096
	STATUS_STACK_OVERFLOW = 0xC00000FD
	STATUS_CONTROL_C_EXIT = 0xC000013A

# dll uses return values to indicate success/failure while we use exceptions
ERROR_UNSPECIFIED = -1

class DebugAdapterDbgeng(DebugAdapter.DebugAdapter):
	def __init__(self, **kwargs):
		#print('dbgeng.__init__() by thread %d %s' % (threading.current_thread().ident, threading.current_thread().name))
		DebugAdapter.DebugAdapter.__init__(self, **kwargs)

		# keep mapping between addresses (DbgAdapter namespace) and breakpoint
		# id's (dbgeng namespace)
		self.bp_addr_to_id = {}

		#
		self.stop_reason_fallback = DebugAdapter.STOP_REASON.UNKNOWN

		#
		fpath = os.path.abspath(__file__)
		fpath = os.path.dirname(fpath)
		fpath = os.path.join(fpath, 'dbgengadapt\\dbgengadapt.dll')
		self.dll = CDLL(fpath)

		if not self.dll:
			raise DebugAdapter.GeneralError("loading %s" % fpath)

	def __del__(self):
		#print('dbgeng.__del__() by thread %d %s' % (threading.current_thread().ident, threading.current_thread().name))
		del self.dll
		self.dll = None

	def get_last_breakpoint_address(self):
		addr = c_ulonglong()
		if self.dll.get_last_breakpoint_address(byref(addr), None) != 0:
			raise DebugAdapter.GeneralError("retrieving last breakpoint address")
		return addr.value

	def get_last_exception_info(self):
		# TODO: handle 32 bit case
		#typedef struct _EXCEPTION_RECORD64 {
		#    DWORD    ExceptionCode;
		#    DWORD ExceptionFlags;
		#    DWORD64 ExceptionRecord;
		#    DWORD64 ExceptionAddress;
		#    DWORD NumberParameters;
		#    DWORD __unusedAlignment;
		#    DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
		#} EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;
		record = create_string_buffer(4+4+8+8+4+4+8*15)
		self.dll.get_exception_record64(record, None)
		(ExceptionCode, ExceptionFlags, ExceptionRecord, ExceptionAddress, NumberParameters) = \
			unpack('<IIQQI', record[0:28])

		#print('ExceptionCode: %X' % ExceptionCode)
		#print('ExceptionFlags: %X' % ExceptionFlags)
		#print('ExceptionRecord: %X' % ExceptionRecord)
		#print('ExceptionAddress: %X' % ExceptionAddress)

		return (ExceptionCode, ExceptionFlags, ExceptionRecord, ExceptionAddress, NumberParameters)

	def get_exec_status(self):
		status = c_ulong()
		if self.dll.get_exec_status(byref(status), None) != 0:
			raise DebugAdapter.GeneralError("retrieving execution status")
		return DEBUG_STATUS(status.value)

	def thunk_stop_reason(self):
		status = self.get_exec_status()
		#print('execution status = ', status)

		fallback = self.stop_reason_fallback
		self.stop_reason_fallback = False

		if status == DEBUG_STATUS.BREAK:
			iptr = self.reg_read('eip' if self.target_arch() =='x86' else 'rip')

			bpaddr = self.get_last_breakpoint_address()
			if bpaddr == iptr:
				return (DebugAdapter.STOP_REASON.BREAKPOINT, 0)

			(ExceptionCode, ExceptionFlags, ExceptionRecord, ExceptionAddress, NumberParameters) = \
				self.get_last_exception_info()
			if ExceptionAddress == iptr:
				lookup = {
					WINNT_STATUS.STATUS_BREAKPOINT.value: DebugAdapter.STOP_REASON.BREAKPOINT,
					WINNT_STATUS.STATUS_SINGLE_STEP.value: DebugAdapter.STOP_REASON.SINGLE_STEP,
					WINNT_STATUS.STATUS_ACCESS_VIOLATION.value: DebugAdapter.STOP_REASON.ACCESS_VIOLATION,
					WINNT_STATUS.STATUS_INTEGER_DIVIDE_BY_ZERO.value: DebugAdapter.STOP_REASON.CALCULATION,
					WINNT_STATUS.STATUS_FLOAT_DIVIDE_BY_ZERO.value: DebugAdapter.STOP_REASON.CALCULATION
				}
				if ExceptionCode in lookup:
					return (lookup[ExceptionCode], ExceptionCode)

				return (DebugAdapter.STOP_REASON.UNKNOWN, ExceptionCode)

			return (fallback, ExceptionCode)

		if status == DEBUG_STATUS.NO_DEBUGGEE:
			code = c_ulong()
			if self.dll.get_exit_code(byref(code), None) != 0:
				raise DebugAdapter.GeneralError("retrieving exit code")
			return (DebugAdapter.STOP_REASON.PROCESS_EXITED, code.value)

		# otherwise just return the numeric value of the status
		return (DebugAdapter.STOP_REASON.UNKNOWN, status.value)

	#--------------------------------------------------------------------------
	# API
	#--------------------------------------------------------------------------

	# session start/stop
	def exec(self, fpath, args, terminal=False):
		errmsg = create_string_buffer(4096)

		def enclose(s):
			return s if s.startswith('"') and s.endswith('"') else '"%s"'%s

		# form command line
		if '/' in fpath:
			fpath = fpath.replace('/', '\\')

		cmdline = enclose(fpath)
		if args:
			cmdline += ' ' + ' '.join([enclose(arg) for arg in args])

		# ask dll to create process
		cmdline_ = c_char_p(cmdline.encode('utf-8'))
		rc = self.dll.process_start(cmdline_, byref(errmsg))
		if rc:
			raise DebugAdapter.ProcessStartError(errmsg.value.decode('utf-8'))

		self.target_path_ = fpath

	def attach(self, pid):
		if self.dll.process_attach(pid, None):
			raise Exception('unable to attach to pid %d' % pid)

	def detach(self):
		self.dll.process_detach(None)

	def quit(self):
		status = self.get_exec_status()

		if status == DEBUG_STATUS.NO_DEBUGGEE:
			pass
		elif status == DEBUG_STATUS.BREAK:
			self.dll.quit(None)
		else:
			# targets waiting on I/O have considerable time before interrupt
			# request moves them to BREAK state
			for i in range(20):
				self.dll.break_into(None)
				time.sleep(.1)
				if self.get_exec_status() == DEBUG_STATUS.BREAK:
					break
			else:
				raise Exception('unable to quit, target won\'t break')

	# target info
	def target_arch(self):
		proc_type = c_ulong()
		if self.dll.get_executing_processor_type(byref(proc_type), None) != 0:
			raise Exception('unable to get executing processor type')
		proc_type = proc_type.value

		#IMAGE_FILE_MACHINE_I386 	x86 architecture
		if proc_type == 0x014c:
			return 'x86'
		#IMAGE_FILE_MACHINE_AMD64 	x64 architecture
		if proc_type == 0x8664:
			return 'x86_64'
		#IMAGE_FILE_MACHINE_ARM 	ARM architecture
		#IMAGE_FILE_MACHINE_IA64 	Intel Itanium architecture
		#IMAGE_FILE_MACHINE_EBC 	EFI byte code architecture
		raise Exception('unsupported processor type 0x%X' % proc_type)

	def target_path(self):
		return self.target_path_

	def target_pid(self):
		pid = c_ulong();
		if self.dll.get_pid(byref(pid), None) != 0:
			raise DebugAdapter.GeneralError("retrieving process id")
		return pid.value

	def target_base(self):
		base = c_ulonglong();
		if self.dll.get_image_base(byref(base), None) != 0:
			raise DebugAdapter.GeneralError("retrieving image base")
		return base.value

	# threads
	def thread_list(self):
		threads_n = self.dll.get_number_threads(None)
		if threads_n < 0:
			raise DebugAdapter.GeneralError("retrieving thread list")
		return list(range(threads_n))

	def thread_selected(self):
		tid = self.dll.get_current_thread(None)
		if tid < 0:
			raise DebugAdapter.GeneralError("retrieving selected thread")
		return tid

	def thread_select(self, tid):
		rc = self.dll.set_current_thread(tid, None)
		if rc < 0:
			raise DebugAdapter.GeneralError("selecting thread")

	# breakpoints
	def breakpoint_set(self, addr):
		pfunc = self.dll.breakpoint_set
		pfunc.restype = c_int
		pfunc.argtypes = [c_ulonglong, POINTER(c_ulong), c_char_p]
		bpid = c_ulong();
		rc = pfunc(addr, byref(bpid), None)
		if rc != 0:
			raise DebugAdapter.BreakpointSetError('bp at 0x%X, dll returned %d' % (addr, rc))
		self.bp_addr_to_id[addr] = bpid.value

	def breakpoint_clear(self, addr):
		if not addr in self.bp_addr_to_id:
			raise DebugAdapter.BreakpointClearError('bp at addr not 0x%X found' % addr)
		bpid = self.bp_addr_to_id[addr]
		self.dll.breakpoint_clear(bpid, None)
		del self.bp_addr_to_id[addr]

	def breakpoint_list(self):
		return list(self.bp_addr_to_id.keys())

	# registers
	def reg_read(self, name):
		if name == 'rflags' or name == 'eflags':
			name='efl'
		val = c_ulonglong()
		if self.dll.reg_read(c_char_p(name.encode('utf-8')), byref(val), None) != 0:
			raise DebugAdapter.GeneralError("reading register %s" % name)
		return val.value

	def reg_write(self, name, value):
		value = c_ulonglong(value)
		if self.dll.reg_write(c_char_p(name.encode('utf-8')), value, None) != 0:
			raise DebugAdapter.GeneralError("writing register %s" % name)

	def reg_list(self):
		regcount = c_int()
		if self.dll.reg_count(byref(regcount), None):
			raise DebugAdapter.GeneralError("retrieving register count")
		regcount = regcount.value
		regname = create_string_buffer(512);

		result = []
		for regidx in range(regcount):
			if self.dll.reg_name(regidx, regname, None) != 0:
				raise DebugAdapter.GeneralError("translating register index to name")
			result.append(regname.value.decode('utf-8'))

		return result

	def reg_bits(self, name):
		name = c_char_p(name.encode('utf-8'))
		val = c_int()
		if self.dll.reg_read(name, byref(val), None) != 0:
			raise DebugAdapter.GeneralError("reading register")

		result = c_int()
		if self.dll.reg_width(name, byref(result), None) != 0:
			raise DebugAdapter.GeneralError("retrieving register width")
		return result.value

	# mem
	def mem_read(self, address, length):
		result = (c_uint8 * length)()

		pfunc = self.dll.mem_read
		pfunc.restype = c_int
		pfunc.argtypes = [c_ulonglong, c_ulong, POINTER(c_uint8), c_char_p]

		rc = pfunc(address, length, result, None)
		if rc != 0:
			raise DebugAdapter.GeneralError("reading from address 0x%X" % address)

		return b''.join(map(lambda x: x.to_bytes(1,'big'), list(result)))

	def mem_write(self, address, data):
		u8_arr = (c_uint8 * len(data))()
		for (i,b) in enumerate(data):
			u8_arr[i] = b

		pfunc = self.dll.mem_write
		pfunc.restype = c_int
		pfunc.argtypes = [c_ulonglong, POINTER(c_uint8), c_ulong, c_char_p]
		rc = pfunc(address, u8_arr, len(data), None)
		if rc != 0:
			raise DebugAdapter.GeneralError("writing to address 0x%X" % address)

		return 0

	def mem_modules(self, cache_ok=True):
		module2addr = {}

		modules_n = c_int()
		if self.dll.module_num(byref(modules_n), None) != 0:
			raise DebugAdapter.GeneralError("retrieving module list size")
		modules_n = modules_n.value

		image_path = create_string_buffer(4096) # or MAX_PATH, whatever
		image_addr = c_ulonglong()
		for idx in range(modules_n):
			if self.dll.module_get(idx, byref(image_path), byref(image_addr), None) != 0:
				raise DebugAdapter.GeneralError("retrieving module name")
			module2addr[image_path.value.decode('utf-8')] = image_addr.value

		return module2addr

	# break
	def break_into(self):
		self.dll.break_into(None)

	# execution control, all return:
	# returns (STOP_REASON.XXX, <extra_info>)
	def go(self):
		# TODO: Handle output
		self.dll.go(None)
		return self.thunk_stop_reason()

	def step_into(self):
		self.stop_reason_fallback = DebugAdapter.STOP_REASON.SINGLE_STEP
		self.dll.step_into(None)
		return self.thunk_stop_reason()

	def step_over(self):
		self.stop_reason_fallback = DebugAdapter.STOP_REASON.SINGLE_STEP
		self.dll.step_over(None)
		return self.thunk_stop_reason()

	# testing
	def raw(self, data):
		pass

	def kill_comms(self):
		pass

	def test(self):
		pass

