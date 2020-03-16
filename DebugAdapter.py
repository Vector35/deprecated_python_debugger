import platform
from enum import Enum, auto, unique

class GeneralError(Exception):
	pass
class BreakpointClearError(Exception):
	pass
class BreakpointSetError(Exception):
	pass

@unique
class ADAPTER_TYPE(Enum):
	DEFAULT = 0
	LOCAL_DBGENG = auto()
	LOCAL_GDB = auto()
	LOCAL_LLDB = auto()
	REMOTE_DBGENG = auto()
	REMOTE_GDB = auto()
	REMOTE_LLDB = auto()

	@staticmethod
	def use_exec(adapter_type):
		return adapter_type in [
			ADAPTER_TYPE.DEFAULT,
			ADAPTER_TYPE.LOCAL_DBGENG,
			ADAPTER_TYPE.LOCAL_GDB,
			ADAPTER_TYPE.LOCAL_LLDB
		]

	@staticmethod
	def use_connect(adapter_type):
		return adapter_type in [
			ADAPTER_TYPE.REMOTE_DBGENG,
			ADAPTER_TYPE.REMOTE_GDB,
			ADAPTER_TYPE.REMOTE_LLDB
		]

	@staticmethod
	def can_use(adapter_type):
		system = platform.system()

		if system == 'Windows':
			return adapter_type in [
				ADAPTER_TYPE.DEFAULT,
				ADAPTER_TYPE.LOCAL_DBGENG,
				ADAPTER_TYPE.REMOTE_DBGENG,
				ADAPTER_TYPE.REMOTE_GDB,
				ADAPTER_TYPE.REMOTE_LLDB,
			]
		elif system == 'Linux':
			return adapter_type in [
				ADAPTER_TYPE.DEFAULT,
				ADAPTER_TYPE.LOCAL_GDB,
				ADAPTER_TYPE.REMOTE_DBGENG,
				ADAPTER_TYPE.REMOTE_GDB,
				ADAPTER_TYPE.REMOTE_LLDB,
			]
		elif system == 'Darwin':
			return adapter_type in [
				ADAPTER_TYPE.DEFAULT,
				ADAPTER_TYPE.LOCAL_LLDB,
				ADAPTER_TYPE.REMOTE_DBGENG,
				ADAPTER_TYPE.REMOTE_GDB,
				ADAPTER_TYPE.REMOTE_LLDB,
			]
		else:
			return False

def get_adapter_for_current_system(**kwargs):
	from . import dbgeng, gdb, lldb

	system = platform.system()

	if system == 'Windows':
		return dbgeng.DebugAdapterDbgeng(**kwargs)
	elif system == 'Linux':
		return gdb.DebugAdapterGdb(**kwargs)
	elif system == 'Darwin':
		return lldb.DebugAdapterLLDB(**kwargs)
	else:
		raise Exception('unsupported system: %s' % system)

def get_new_adapter(adapter_type = ADAPTER_TYPE.DEFAULT, **kwargs):
	from . import dbgeng, gdb, lldb

	if adapter_type == ADAPTER_TYPE.LOCAL_DBGENG or adapter_type == ADAPTER_TYPE.REMOTE_DBGENG:
		return dbgeng.DebugAdapterDbgeng(**kwargs)
	elif adapter_type == ADAPTER_TYPE.LOCAL_GDB or adapter_type == ADAPTER_TYPE.REMOTE_GDB:
		return gdb.DebugAdapterGdb(**kwargs)
	elif adapter_type == ADAPTER_TYPE.LOCAL_LLDB or adapter_type == ADAPTER_TYPE.REMOTE_LLDB:
		return lldb.DebugAdapterLLDB(**kwargs)
	elif adapter_type == ADAPTER_TYPE.DEFAULT:
		return get_adapter_for_current_system(**kwargs)
	else:
		raise Exception('unsupported adapter type: %s' % adapter_type)

@unique
class STOP_REASON(Enum):
	UNKNOWN = 0
	STDOUT_MESSAGE = auto()
	PROCESS_EXITED = auto()
	BACKEND_DISCONNECTED = auto()

	# macos's EXC_BAD_ACCESS
	# linux's SIGNAL_SEGV
	ACCESS_VIOLATION = auto()

	# macos's EXC_BREAKPOINT
	# linux's SIGNAL_TRAP
	SINGLE_STEP = auto()

	# macos's EXC_ARITHMETIC
	# linux's SIGNAL_FPE (floating point exception)
	CALCULATION = auto()

	#
	BREAKPOINT = auto()

	SIGNAL_HUP = auto()
	SIGNAL_INT = auto()
	SIGNAL_QUIT = auto()
	SIGNAL_ILL = auto()
	SIGNAL_ABRT = auto()
	SIGNAL_EMT = auto()
	SIGNAL_FPE = auto()
	SIGNAL_KILL = auto()
	SIGNAL_BUS = auto()
	SIGNAL_SEGV = auto()
	SIGNAL_SYS = auto()
	SIGNAL_PIPE = auto()
	SIGNAL_ALRM = auto()
	SIGNAL_TERM = auto()
	SIGNAL_URG = auto()
	SIGNAL_STOP = auto()
	SIGNAL_TSTP = auto()
	SIGNAL_CONT = auto()
	SIGNAL_CHLD = auto()
	SIGNAL_TTIN = auto()
	SIGNAL_TTOU = auto()
	SIGNAL_IO = auto()
	SIGNAL_XCPU = auto()
	SIGNAL_XFSZ = auto()
	SIGNAL_VTALRM = auto()
	SIGNAL_PROF = auto()
	SIGNAL_WINCH = auto()
	SIGNAL_INFO = auto()
	SIGNAL_USR1 = auto()
	SIGNAL_USR2 = auto()
	SIGNAL_STKFLT = auto()
	SIGNAL_BUX = auto()
	SIGNAL_POLL = auto()
	# TODO: get away from macos specific value
	EXC_BAD_INSTRUCTION = auto()
	EXC_EMULATION = auto()
	EXC_SOFTWARE = auto()
	EXC_SYSCALL = auto()
	EXC_MACH_SYSCALL = auto()
	EXC_RPC_ALERT = auto()
	EXC_CRASH = auto()

class DebugAdapter:
	def __init__(self, **kwargs):
		# stdout handling callback
		self.cb_stdout = kwargs.get('stdout', None)

	# session start/stop
	def exec(self, path, args=[]):
		raise NotImplementedError('')
	def attach(self, pid):
		raise NotImplementedError('')
	def connect(self, server, port):
		raise NotImplementedError('')
	def detach(self):
		''' quit debug session, debuggee left running '''
		raise NotImplementedError('')
	def quit(self):
		''' quit debug session, debuggee terminated '''
		raise NotImplementedError('')

	# target info
	def target_arch(self):
		raise NotImplementedError('')
	def target_path(self):
		raise NotImplementedError('')
	def target_pid(self):
		raise NotImplementedError('')
	def target_base(self):
		raise NotImplementedError('')

	# threads
	# 'index' is our abstracted thread identifier [0, 1, ..., n-1]
	# 'tid' or OS's assigned numeric thread identifier
	# 'selected' thread means subsequent actions (read registers, step) happen on this thread
	# 'active' thread means the latest execution-halting action (threw exception, hit breakpoint) occurred in this thread
	def thread_list(self):
		''' return a list of thread information '''
		raise NotImplementedError('')
	def thread_selected(self):
		''' return thread id that is active '''
		raise NotImplementedError('')
	def thread_select(self, tidx):
		''' make a given thread id active '''
		raise NotImplementedError('')

	# breakpoints
	def breakpoint_set(self, address):
		''' set software breakpoint at address '''
		raise NotImplementedError('')
	def breakpoint_clear(self, address):
		''' delete breakpoint by address '''
		raise NotImplementedError('')
	def breakpoint_list(self):
		''' return list of addresses '''
		raise NotImplementedError('')

	# register
	def reg_read(self, reg):
		raise NotImplementedError('')
	def reg_write(self, reg):
		raise NotImplementedError('')
	def reg_list(self):
		raise NotImplementedError('')
	def reg_bits(self, reg):
		raise NotImplementedError('')

	# mem
	def mem_read(self, address, length):
		raise NotImplementedError('')
	def mem_write(self, address, data):
		raise NotImplementedError('')
	def mem_modules(self, cache_ok=True):
		raise NotImplementedError('')

	# break
	def break_into(self):
		raise NotImplementedError('')

	# execution control
	def go(self):
		raise NotImplementedError('')
	def step_into(self):
		raise NotImplementedError('')
	def step_over(self):
		raise NotImplementedError('')

	# raw pass-thru (meaning depends on adapter)
	def raw(self, data):
		raise NotImplementedError('')

	# send data to process stdin
	def stdin_write(self, data):
		raise NotImplementedError('')
