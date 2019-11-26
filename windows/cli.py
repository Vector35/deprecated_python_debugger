import re
import sys
import time
import signal
import capstone
import threading
from ctypes import *
from binascii import hexlify
from struct import pack, unpack

import colorama

adapter = None
cbuf = None

def debug_status():
	lookup = [
		'DEBUG_STATUS_NO_CHANGE', 'DEBUG_STATUS_GO', 'DEBUG_STATUS_GO_HANDLED',
		'DEBUG_STATUS_GO_NOT_HANDLED', 'DEBUG_STATUS_STEP_OVER',
		'DEBUG_STATUS_STEP_INTO', 'DEBUG_STATUS_BREAK', 'DEBUG_STATUS_NO_DEBUGGEE',
		'DEBUG_STATUS_STEP_BRANCH', 'DEBUG_STATUS_IGNORE_EVENT',
		'DEBUG_STATUS_RESTART_REQUESTED', 'DEBUG_STATUS_REVERSE_GO',
		'DEBUG_STATUS_REVERSE_STEP_BRANCH', 'DEBUG_STATUS_REVERSE_STEP_OVER',
		'DEBUG_STATUS_REVERSE_STEP_INTO', 'DEBUG_STATUS_OUT_OF_SYNC',
		'DEBUG_STATUS_WAIT_INPUT', 'DEBUG_STATUS_TIMEOUT',
	]

	pfunc = adapter.get_exec_status
	pfunc.restype = c_int
	pfunc.argtypes = [POINTER(c_ulong)]
	exec_status = c_ulong()
	rc = pfunc(byref(exec_status))

	exec_status = exec_status.value
	print("get_exec_status() returned %d and status %d" % (rc, exec_status))
	result = ''
	if exec_status & 0x10000000:
		result += 'DEBUG_STATUS_INSIDE_WAIT|'
	if exec_status & 0x20000000:
		result += 'DEBUG_STATUS_WAIT_TIMEOUT|'
	result += lookup[exec_status & 0x1F]
	print('looking that up, we get: %s' % result)

def breakpoint_set(addr):
	pfunc = adapter.breakpoint_set
	pfunc.restype = c_int
	pfunc.argtypes = [c_ulonglong, POINTER(c_ulong)]
	bpid = c_ulong();
	rc = pfunc(addr, byref(bpid))
	if rc != 0:
		return None
	return bpid.value

def breakpoint_clear(bpid):
	if adapter.breakpoint_clear(bpid) == 0:
		return 0

def reg_read(reg_name):
	pfunc = adapter.reg_read
	pfunc.restype = c_int
	pfunc.argtypes = [c_char_p, POINTER(c_ulonglong)]
	reg_val = c_ulonglong()
	rc = pfunc(c_char_p(reg_name.encode('utf-8')), byref(reg_val))
	if rc != 0:
		return None
	return reg_val.value

def reg_write(reg_name, value):
	pfunc = adapter.reg_write
	pfunc.restype = c_int
	pfunc.argtypes = [c_char_p, c_ulonglong]
	rc = pfunc(c_char_p(reg_name.encode('utf-8')), value)
	if rc != 0:
		return None
	return 0

def mem_read(addr, length):
	result = (c_uint8 * length)()

	pfunc = adapter.mem_read
	pfunc.restype = c_int
	pfunc.argtypes = [c_ulonglong, c_ulong, POINTER(c_uint8)]

	rc = pfunc(addr, length, result)
	if rc != 0:
		return None

	return b''.join(map(lambda x: x.to_bytes(1,'big'), list(result)))

def mem_write(addr, data):
	u8_arr = (c_uint8 * len(data))()
	for (i,b) in enumerate(data):
		u8_arr[i] = b

	pfunc = adapter.mem_write
	pfunc.restype = c_int
	pfunc.argtypes = [c_ulonglong, POINTER(c_uint8), c_ulong]
	rc = pfunc(addr, u8_arr, len(data))
	if rc != 0:
		return None

	return 0

def set_current_thread(tid):
	if adapter.set_current_thread(tid):
		return None
	return tid

def threads_list():
	threads_n = adapter.get_number_threads()
	if threads_n == -1:
		print('ERROR: get_number_threads()')
		return

	tid = adapter.get_current_thread()
	if tid == -1:
		print('ERROR: get_current_thread()')
		return

	for i in range(threads_n):
		prefix = '--> ' if tid == i else '    '
		set_current_thread(i)
		rip = reg_read('rip')
		rip = ('%X'%rip).rjust(16,'0')
		print('%s%d: %s' % (prefix, i, rip))

	set_current_thread(tid)

def show_context():
	rax = reg_read("rax")
	rbx = reg_read("rbx")
	rcx = reg_read("rcx")
	rdx = reg_read("rdx")
	rsi = reg_read("rsi")
	rdi = reg_read("rdi")
	rip = reg_read("rip")
	rsp = reg_read("rsp")
	rbp = reg_read("rbp")
	r8 = reg_read("r8")
	r9 = reg_read("r9")
	r10 = reg_read("r10")
	r11 = reg_read("r11")
	r12 = reg_read("r12")
	r13 = reg_read("r13")
	r14 = reg_read("r14")
	r15 = reg_read("r15")

	if rax==None or r15==None:
		return

	print("rax=%016X rbx=%016X rcx=%016X" % (rax, rbx, rcx))
	print("rdx=%016X rsi=%016X rdi=%016X" % (rdx, rsi, rdi))
	print("rip=%016X rsp=%016X rbp=%016X" % (rip, rsp, rbp))
	print(" r8=%016X  r9=%016X r10=%016X" % (r8, r9, r10))
	print("r11=%016X r12=%016X r13=%016X" % (r11, r12, r13))
	print("r14=%016X r15=%016X" % (r14, r15))

	data = mem_read(rip, 16)
	if data:
		(asmstr, asmlen) = disasm1(data, rip)
		print('%016X: %s\t%s' % (rip, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

def disasm1(data, addr):
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	gen = md.disasm(data, addr)
	insn = next(gen)
	return ('%s %s' % (insn.mnemonic, insn.op_str), insn.size)

def disasm(data, addr):
	lines = []
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	offset = 0
	for i in md.disasm(data, addr):
		bytestr = hexlify(data[offset:offset+i.size]).decode('utf-8').ljust(16)
		asmstr = i.mnemonic + ' ' + i.op_str
		line = '%016X: %s %s' % (i.address, bytestr, asmstr)
		lines.append(line)
		offset += i.size
	return '\n'.join(lines)

def hex_dump(data, addr=0, grouping=1, endian='little'):
	result = ''

	while(data):
		ascii = ''
		buff16 = data[0:16]
		data = data[16:]
		result += "%08X: " % addr

		i = 0
		while i < 16:
			if(i < len(buff16)):
				f0 = { \
					'big':	{1:'>B', 2:'>H', 4:'>I', 8:'>Q'}, \
					'little': {1:'<B', 2:'<H', 4:'<I', 8:'<Q'} \
				}

				f1 = { \
					1:'%02X ', 2:'%04X ', 4:'%08X ', 8:'%016X ' \
				}

				temp = unpack(f0[endian][grouping], buff16[i:i+grouping])[0]

				result += f1[grouping] % temp

				for j in range(grouping):
					u8 = buff16[i+j]

					if(u8 >= ord(' ') and u8 <= ord('~')):
						ascii += chr(u8)
					else:
						ascii += '.'
			else:
				if grouping == 1:
					result += ' '*3
				elif grouping == 2:
					result += ' '*5
				elif grouping == 4:
					result += ' '*9
				elif grouping == 8:
					result += ' '*17

			i += grouping

		result += ' %s\n' % ascii

		addr += 16

	return result

def adjust_ctrl_c():
	STD_INPUT_HANDLE = -10
	ENABLE_PROCESSED_INPUT = 1
	kernel32 = windll.kernel32
	bRet = kernel32.SetConsoleCtrlHandler(0, 1)
	print("SetConsoleCtrlHandler(0, 1) returns %d\n", bRet)

	#handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
	#print("GetStdHandle(STD_INPUT_HANDLE) returns %d\n" % handle)
	#mode = c_uint()
	#pfunc = kernel32.GetConsoleMode
	#pfunc.restype = c_int
	#pfunc.argtypes = [POINTER(c_ulong)]
	#bRet = pfunc(byref(mode))
	#mode = mode.value
	#print("GetConsoleMode(%d) returns %08X\n" % (handle, mode))
	#mode |= ENABLE_PROCESSED_INPUT
	#bRet = kernel32.SetConsoleMode(handle, ENABLE_PROCESSED_INPUT)
	#print("SetConsoleMode(%d, %08X) returns %d\n" % (handle, mode, bRet))

adapter_blocking = False
user_still_wants_to_debug = False
enter_type = None
event_thread_cmd_avail = threading.Event()
event_debug_ok = threading.Event()
debug_thread_status = None

def debug_thread(action, target):
	global adapter
	global adapter_blocking

	adapter = CDLL(".\dbgengadapt.dll")
	if action == 'run':
		target = create_string_buffer(target.encode('utf-8'))
		if adapter.process_start(target):
			print('ERROR: adapter.process_start()')
			adapter.quit()
			adapter = None
			return

	elif action == 'attach':
		if adapter.process_attach(target):
			adapter.quit()
			adapter = None
			print('ERROR: adapter.process_attach()')
			return

	event_debug_ok.set()
	while 1:
		print("waiting for work...\n")
		event_thread_cmd_avail.wait()

		print("work signal found...\n");
		if not user_still_wants_to_debug:
			print("exit signal found, out!\n");
			break

		print('entering engine')
		adapter_blocking = True
		if enter_type == 'g':
			adapter.go()
		elif enter_type == 't':
			adapter.step_into()
		elif enter_type == 'p':
			adapter.step_over()
		adapter_blocking = False
		print('exited engine')

	print("debug thread exiting");
	adapter.quit()
	adapter = None

if __name__ == '__main__':
	user_still_wants_to_debug = True
	sema = threading.Semaphore()
	sema.acquire()

	if not sys.argv[1:]:
		action = 'run'
		target = b"c:\\windows\\system32\\notepad.exe"
	elif re.match(r'^\d+$', sys.argv[1]):
		action = 'attach'
		target = int(sys.argv[1])
	else:
		action = 'run'
		target = sys.argv[1]

	thread = threading.Thread(target=debug_thread, args=(action, target))
	thread.start()

	if not event_debug_ok.wait(2):
		print('ERROR: establishing debug thread')
		sys.exit(-1)

	while user_still_wants_to_debug:
		try:
			prompt = 'RUNNING>' if adapter_blocking else 'FAKEDBG>'
			text = input(prompt)
			if not text:
				continue

			if adapter_blocking and not text in ['break', 'breakinto']:
				print('target running, break into it first')
				continue

			# testing stuff
			if text == 'hello':
				adapter.hello()
			elif text in ['?', 'state']:
				debug_status()

			# thread list, thread switch
			elif text in ['~', 'threads']:
				threads_list()
			elif text[0:] and text[0]=='~' and text[-1]=='s':
				tid = int(text[1:-1])
				set_current_thread(tid)

			# breakpoint set/clear
			elif text.startswith('bp '):
				addr = int(text[3:], 16)
				bpid = breakpoint_set(addr)
				if bpid == None:
					print('ERROR')
				else:
					print('breakpoint %d set at 0x%X' % (bpid, addr))

			elif text.startswith('bc '):
				bpid = int(text[3:])
				if breakpoint_clear(bpid) == None:
					print('ERROR')

			# context, read regs, write regs
			elif text in ['r']:
				show_context()
			elif re.match(r'r .* .*$', text):
				(_, reg, val) = text.split(' ')
				reg_write(reg, int(val, 16))

			# read/write mem, disasm mem
			elif text.startswith('db '):
				addr = int(text[3:],16)
				data = mem_read(addr, 256)
				print(hex_dump(data, addr))
			elif text.startswith('eb '):
				m = re.match(r'^eb (\w+) (.*)$', text)
				addr = int(m.group(1), 16)
				bytes_ = bytes(map(lambda x: int(x,16), m.group(2).split()))
				mem_write(addr, bytes_)
			elif text.startswith('u '):
				addr = int(text[2:],16)
				data = mem_read(addr, 64)
				print(disasm(data, addr))

			# break into, go, step, step into
			elif text in ['break', 'breakinto']:
				adapter.break_into()

			elif text in list('gpt'):
				enter_type = text
				event_thread_cmd_avail.set()
				event_thread_cmd_avail.clear()

			# quit, detach, quit+detach
			elif text in ['q', 'quit', 'exit']:
				user_still_wants_to_debug = False
			elif text in ['qd', 'detach']:
				adapter.process_detach()
				user_still_wants_to_debug = False

			# else
			else:
				print('unrecognized: %s' % text)

		except KeyboardInterrupt as e:
			print("ctrl+c detected! quiting!\n")
			user_still_wants_to_debug = False

	# break out of debug wait thread
	if adapter_blocking:
		adapter.break_into()
	event_thread_cmd_avail.set()

	print("done!")
