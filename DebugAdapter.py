from enum import Enum, auto, unique

class GeneralError(Exception):
	pass
class BreakpointClearError(Exception):
	pass
class BreakpointSetError(Exception):
	pass

@unique
class STOP_REASON(Enum):
	UNKNOWN = 0
	STDOUT_MESSAGE = auto()
	PROCESS_EXITED = auto()
	BACKEND_DISCONNECTED = auto()
	SIGNAL_HUP = auto()
	SIGNAL_INT = auto()
	SIGNAL_QUIT = auto()
	SIGNAL_ILL = auto()
	SIGNAL_TRAP = auto()
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

class DebugAdapter:
	# session start/stop
	def exec(self, path):
		pass
	def attach(self, pid):
		pass
	def detach(self):
		''' quit debug session, debuggee left running '''
		pass
	def quit(self):
		''' quit debug session, debuggee terminated '''
		pass

	# threads
	# 'index' is our abstracted thread identifier [0, 1, ..., n-1]
	# 'tid' or OS's assigned numeric thread identifier
	# 'selected' thread means subsequent actions (read registers, step) happen on this thread
	# 'active' thread means the latest execution-halting action (threw exception, hit breakpoint) occurred in this thread
	def thread_list(self):
		''' return a list of thread information '''
		pass
	def thread_get_active(self):
		''' return thread id that is active '''
		pass
	def thread_select(self, tidx):
		''' make a given thread id active '''
		pass

	# breakpoints
	def breakpoint_set(self, address):
		''' set software breakpoint at address '''
		pass
	def breakpoint_clear(self, address):
		''' delete breakpoint by address '''
		pass
	def breakpoint_list(self):
		''' return list of addresses '''

	# register
	def reg_read(self, reg):
		pass
	def reg_write(self, reg):
		pass
	def reg_list(self):
		pass
	def reg_bits(self, reg):
		pass

	# mem
	def mem_read(self, address, length):
		pass
	def mem_write(self, address, data):
		pass
	def mem_modules(self):
		pass

	# break
	def break_into(self):
		pass

	# execution control
	def go():
		pass
	def step_into(self):
		pass
	def step_over(self):
		pass

	# raw pass-thru (meaning depends on adapter)
	def raw(self, data):
		pass
