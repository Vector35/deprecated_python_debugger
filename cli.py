#!/usr/bin/env python3

import re
import os
import sys
import struct
import signal
import platform
if platform.system() != 'Windows':
	import readline
else:
	import ctypes
from struct import pack, unpack
from binascii import hexlify, unhexlify
import colorama

sys.path.append('..')
import debugger.gdblike as gdblike
import debugger.gdb as gdb
import debugger.utils as utils
import debugger.DebugAdapter as DebugAdapter

(RED, GREEN, BROWN, NORMAL) = (utils.RED, utils.GREEN, utils.BROWN, utils.NORMAL)

# globals
adapter = None
context_last = {}

#--------------------------------------------------------------------------
# COMMON DEBUGGER TASKS
#--------------------------------------------------------------------------

def get_arch_dis():
	arch = adapter.target_arch()

	if arch in ['x86', 'x86_64', 'aarch64', 'z80']:
		return arch
	elif arch in ['arm', 'armv7', 'thumb', 'thumb2']:
		cpsr = adapter.reg_read('cpsr')
		if cpsr & 0x20:
			return 'thumb2eb' if (cpsr & 0x00000200) else 'thumb2'
		else:
			return 'armv7eb' if (cpsr & 0x00000200) else 'armv7'

	raise Exception('couldn\'t determine architecture to disassemble with')

def disasm1(data, addr):
	if not data: return
	arch_dis = get_arch_dis()

	#if 'binaryninja' in sys.modules:
	#	return utils.disasm1(data, addr, arch_dis)
	if arch == 'z80':
		from z80dis import z80
		decoded = z80.decode(data, addr)
		return (z80.disasm(decoded), decoded.len)
	else:
		import capstone
		if arch_dis == 'x86_64':
			md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
		elif arch_dis == 'x86':
			md = capstone.Cs(capstone.CS_ARCH_X86, 0)
		gen = md.disasm(data, addr)
		insn = next(gen)
		return ('%s %s' % (insn.mnemonic, insn.op_str), insn.size)

def disasm(data, addr):
	if not data: return
	arch_dis = get_arch_dis()

	#if 'binaryninja' in sys.modules:
	#	return utils.disasm(data, addr, arch_dis)
	if arch == 'z80':
		from z80dis import z80
		lines = []

		offset = 0
		while offset < len(data):
			try:
				decoded = z80.decode(data[offset:], addr)
			except Exception:
				break

			addrstr = '%s%04X%s' % (GREEN, addr+offset, NORMAL)
			bytestr = hexlify(data[offset:offset+decoded.len]).decode('utf-8').ljust(8)
			asmstr = z80.disasm(decoded)
			lines.append('%s: %s %s' % (addrstr, bytestr, asmstr))

			addr += decoded.len
			offset += decoded.len

		return '\n'.join(lines)
	else:
		import capstone
		offset = 0
		lines = []
		if arch_dis == 'x86_64':
			md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
		elif arch_dis == 'x86':
			md = capstone.Cs(capstone.CS_ARCH_X86, 0)
		for i in md.disasm(data, addr):
			addrstr = '%s%016X%s' % (GREEN, i.address, NORMAL)
			bytestr = hexlify(data[offset:offset+i.size]).decode('utf-8').ljust(16)
			asmstr = i.mnemonic + ' ' + i.op_str
			line = '%s: %s %s' % (addrstr, bytestr, asmstr)
			lines.append(line)
			offset += i.size
		return '\n'.join(lines)

def cpsr_tostr(cpsr):
	result = '('
	# bits [31, 27]
	result += 'N' if cpsr & 0x80000000 else 'n'
	result += 'Z' if cpsr & 0x40000000 else 'z'
	result += 'C' if cpsr & 0x20000000 else 'c'
	result += 'V' if cpsr & 0x10000000 else 'v'
	result += 'Q' if cpsr & 0x08000000 else 'q'

	# bits [26, 25]
	IT_LO = (cpsr & 0x06000000) > 25

	# bit 24
	result += 'J' if cpsr & 0x01000000 else 'j'

	# bits [19, 16]
	GE = (cpsr & 0x000F0000) >> 16

	# bits [15, 10]
	IT_HI = (cpsr & 0x0000FC00) > 10

	# bits [9, 5]
	result += 'E' if cpsr & 0x00000200 else 'e'
	result += 'A' if cpsr & 0x00000100 else 'a'
	result += 'I' if cpsr & 0x00000080 else 'i'
	result += 'F' if cpsr & 0x00000040 else 'f'
	result += 'T' if cpsr & 0x00000020 else 't'

	# bits [4, 0]
	M = cpsr & 0x0000001F

	IT = (IT_HI << 2) | IT_LO
	result += ' GE=%sb' % bin(GE)[2:]
	result += ' IT=%sb' % bin(IT)[2:]
	result += ' M=%sb' % bin(M)[2:]
	result += ')'

	return result

def context_display(pkt_T=None):
	global adapter
	global context_last

	try:
		tid = adapter.thread_selected()
		print('thread 0x%X:' % tid)
	except DebugAdapter.GeneralError:
		pass

	def r(reg, fmt='%016X'):
		return (BROWN+reg+NORMAL+'='+fmt) % adapter.reg_read(reg.strip())
	def e(reg, fmt='%08X'):
		return (BROWN+reg+NORMAL+'='+fmt) % adapter.reg_read(reg.strip())
	def s(reg, fmt='%04X'):
		return (BROWN+reg+NORMAL+'='+fmt) % adapter.reg_read(reg.strip())

	arch = adapter.target_arch()

	if arch == 'x86_64':
		print(r('rax'), r('rbx'), r('rcx'), r('rdx'))
		print(r('rsi'), r('rdi'), r('rbp'), r('rsp'))
		print(r(' r8'), r(' r9'), r('r10'), r('r11'))
		print(r('r12'), r('r13'), r('r14'), r('r15'))
		print(r('rip'), end='')

		if 'rflags' in adapter.reg_list():
			print(r(' rflags'))
		else:
			print(r(' eflags'))
	elif arch == 'x86':
		print(e('eax'), e('ebx'), e('ecx'), e('edx'))
		print(e('esi'), e('edi'), e('ebp'), e('esp'))
		print(e('eip'), e('eflags'))
	elif arch == 'aarch64':
		print(r(' x0'), r(' x1'), r(' x2'), r(' x3'))
		print(r(' x4'), r(' x5'), r(' x6'), r(' x7'))
		print(r(' x8'), r(' x9'), r('x10'), r('x11'))
		print(r('x12'), r('x13'), r('x14'), r('x15'))
		print(r('x16'), r('x17'), r('x18'), r('x19'))
		print(r('x20'), r('x21'), r('x22'), r('x23'))
		print(r('x24'), r('x25'), r('x26'), r('x27'))
		print(r('x28'), r('x29'), r('x30'), r(' sp'))
		print(r('pc'), e('cpsr'))
	elif arch == 'arm':
		cpsr = adapter.reg_read('cpsr')
		print(e(' r0'), e(' r1'), e(' r2'), e(' r3'))
		print(e(' r4'), e(' r5'), e(' r6'), e(' r7'))
		print(e(' r8'), e(' r9'), e('r10'), e('r11'))
		print(e('r12'), e(' sp'), e(' lr'))
		print(e(' pc'), e(' cpsr'), cpsr_tostr(cpsr))
	elif arch == 'z80':
		print(s(' af'), s('af\''))
		print(s(' bc'), s('bc\''))
		print(s(' de'), s('de\''))
		print(s(' hl'), s('hl\''))
		print(s(' ix'), s(' iy'))
		print(s(' sp'), s(' pc'))

	pc_name = {'aarch64':'pc', 'arm':'pc', 'x86_64':'rip', 'x86':'eip', 'z80':'pc'}[arch]
	pc_fmt = {'aarch64':'%016X', 'arm':'%08X', 'x86_64':'%016X', 'x86':'%08X', 'z80':'%04X'}[arch]
	pc = adapter.reg_read(pc_name)

	try:
		data = adapter.mem_read(pc, 16)
		if data:
			(asmstr, asmlen) = disasm1(data, pc)
			print(('%s'+pc_fmt+'%s: %s\t%s') % \
				(GREEN, pc, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))
	except DebugAdapter.GeneralError as e:
		print('%s%016X%s: couldn\'t read mem' % \
			(GREEN, pc, NORMAL))

def thread_display():
	tid_selected = adapter.thread_selected()

	for tid in adapter.thread_list():
		adapter.thread_select(tid)
		reg_pc_val = adapter.reg_read(reg_pc)
		seltxt = ['','(selected)'][tid == tid_selected]
		print('Thread tid=0x%X %s=0x%X %s' % (tid, reg_pc, reg_pc_val, seltxt))

	adapter.thread_select(tid_selected)
	pass

def debug_status():
	return

#--------------------------------------------------------------------------
# MAIN
#--------------------------------------------------------------------------

def handler_sigint(signal, frame):
	global adapter
	print('sending "break into" signal')
	adapter.break_into()

def adjust_ctrl_c():
	kernel32 = ctypes.windll.kernel32
	# If the HandlerRoutine parameter is NULL,
	# a TRUE value causes the calling process to ignore CTRL+C input
	bRet = kernel32.SetConsoleCtrlHandler(0, True)
	#print("SetConsoleCtrlHandler(0, 1) returns %d\n", bRet)

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

if __name__ == '__main__':
	colorama.init()

	# set up ctrl+c for break-into
	signal.signal(signal.SIGINT, handler_sigint)
	if platform.system() == 'Windows':
		adjust_ctrl_c()

	adapter = None

	args = list(reversed(sys.argv))
	tok = args.pop()
	if not args:
		print('usage:')
		print('%s [--terminal] <target_path> <target_args>' % tok)
		print('%s <server>:<port>' % tok)
		sys.exit(-1)

	tok = args.pop()
	# does it look like <server>:<port> ?
	if re.match(r'^.*:\d+$', tok):
		(host, port) = tok.split(':')
		adapter = gdblike.connect_sense(host, int(port))
	# otherwise treat as a path
	else:
		terminal = False
		if tok=='--terminal':
			terminal = True
			tok = args.pop()

		# determine target path
		fpath = tok
		if '~' in tok:
			fpath = os.expanduser(fpath)
		fpath = os.path.abspath(fpath)
		if not os.path.exists(fpath):
			raise Exception('file not found: %s' % fpath)

		adapter = DebugAdapter.get_adapter_for_current_system()

		# remaining debugger args become target args
		target_args = list(reversed(args))
		print(target_args)
		if terminal:
			adapter.exec(fpath, target_args, terminal=True)
		else:
			adapter.exec(fpath, target_args)

	arch = adapter.target_arch()

	user_goal = 'debug'
	while user_goal == 'debug':
		try:
			text = input('BINJADBG>')
			if not text:
				continue

			elif text == 'test':
				adapter.test()
			elif text == 'test2':
				print(adapter.target_path())
			elif text.startswith('raw '):
				print(adapter.raw(text[4:]))

			# thread list, thread switch
			elif text in ['~', 'threads']:
				thread_display()

			elif text[0:] and text[0]=='~' and text[-1]=='s':
				tid = int(text[1:-1], 16)
				print('switching to thread 0x%x' % tid)
				adapter.thread_select(tid)

			# breakpoint set/clear
			elif text.startswith('bp '):
				addr = int(text[3:], 16)
				adapter.breakpoint_set(addr)
				print('breakpoint set at 0x%X' % (addr))

			elif text.startswith('bc '):
				addr = int(text[3:], 16)
				adapter.breakpoint_clear(addr)
				print('breakpoint cleared at 0x%X' % addr)

			elif text == 'bl':
				print('breakpoint list:')
				for (i,addr) in enumerate(adapter.breakpoint_list()):
					print('%d: 0x%X' % (i, addr))

			# context, read regs, write regs
			elif text in ['r']:
				context_display()
			elif re.match(r'r \w+=.*$', text):
				(reg, val) = text[2:].split('=')
				adapter.reg_write(reg, int(val, 16))
			elif re.match(r'r \w+ .*$', text):
				(_, reg, val) = text.split(' ')
				adapter.reg_write(reg, int(val, 16))
			elif re.match(r'r \w+', text):
				(_, reg) = text.split(' ')
				val = adapter.reg_read(reg)
				print('%s=%016X' % (reg, val))
			elif text == '.regs':
				for name in adapter.reg_list():
					width = adapter.reg_bits(name)
					value = adapter.reg_read(name)
					print('%s (%d-bits) 0x%X' % (name, width, value))

			# read/write mem, disasm mem
			elif text.startswith('db '):
				addr = int(text[3:], 16)
				data = adapter.mem_read(addr, 128)
				print(utils.hex_dump(data, addr))
			elif text.startswith('eb '):
				m = re.match(r'^eb (\w+) (.*)$', text)
				addr = int(m.group(1), 16)
				bytes_ = bytes(map(lambda x: int(x,16), m.group(2).split()))
				adapter.mem_write(addr, bytes_)
			elif text.startswith('u '):
				addr = int(text[2:],16)
				data = adapter.mem_read(addr, 32)
				print(disasm(data, addr))
			elif text == 'lm':
				module2addr = adapter.mem_modules()
				for module in sorted(module2addr, key=lambda m: module2addr[m]):
					addr = module2addr[module]
					print('%016X: %s' % (addr, module))

			# break into, go, step, step into
			elif text in ['break', 'breakinto']:
				break_into()

			elif text in 'gpt':
				while 1:
					if text == 'g':
						(reason, data) = adapter.go()
					elif text == 't':
						(reason, data) = adapter.step_into()
					elif text == 'p':
						(reason, data) = adapter.step_over()

					if reason == DebugAdapter.STOP_REASON.STDOUT_MESSAGE:
						print('stdout: ', data)
					elif reason == DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED:
						print('backend disconnected, process was likely killed')
						user_goal = 'quit'
						break
					elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
						print('process exited, return code=%d' % data)
						user_goal = 'quit'
						break
					else:
						print('stopped, reason: %s' % reason.name)
						context_display()
						break

			# target info
			elif text == 'target':
				print('arch: %s' % adapter.target_arch())
				print('path: %s' % adapter.target_path())
				if adapter.target_pid() != None:
					print(' pid: 0x%X (%d)' % (adapter.target_pid(), adapter.target_pid()))
				else:
					print(' pid: <unavailable>')
				print('base: 0x%X' % adapter.target_base())

			# quit, detach, quit+detach
			elif text in ['q', 'quit', 'exit']:
				user_goal = 'quit'
				break
			elif text in ['qd', 'detach']:
				user_goal = 'detach'
				break

			# else
			else:
				print('unrecognized: %s' % text)

		except NotImplementedError:
			print('not implemented')
		except KeyboardInterrupt as e:
			print("ctrl+c detected! breaking in!\n")
			break_into()

	if user_goal == 'detach':
		adapter.detach()
	elif user_goal == 'quit':
		adapter.quit()

