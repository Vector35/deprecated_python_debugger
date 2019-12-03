#!/usr/bin/env python3

from binascii import hexlify, unhexlify
import capstone
import colorama
import re
import readline
from struct import pack, unpack
import signal
import sys

import lldb
import DebugAdapter

RED = '\x1B[31m'
GREEN = '\x1B[32m'
BROWN = '\x1B[33m'
NORMAL = '\x1B[0m'

# globals
adapter = None
context_last = {}



#--------------------------------------------------------------------------
# COMMON DEBUGGER TASKS
#--------------------------------------------------------------------------

def context_show(pkt_T=None):
	global adapter
	global context_last

	# get a new context
	#if not pkt_T:
	#	pkt_T = tx_rx('?', 'ack_then_reply')
	#context_last = packet_T_to_dict(pkt_T)

	# show it
	#thread_str = 'thread ?'
	#if 'thread' in context_last:
	#	thread_str = 'thread %x' % context_last['thread']

	#sig = context_last['signal']
	#if sig == 0:
	#	signal_str = '(no signal)'
	#elif sig in sig_num_to_name:
	#	signal_str = 'stopped due to signal %d (%s)' % (sig, sig_num_to_name[sig])
	#else:
	#	signal_str = 'stopped due to signal %d (UNKNOWN)' % sig

	#print('%s %s' % (thread_str, signal_str))

	rax = adapter.register_read('rax')
	rbx = adapter.register_read('rbx')
	rcx = adapter.register_read('rcx')
	rdx = adapter.register_read('rdx')
	rsi = adapter.register_read('rsi')
	rdi = adapter.register_read('rdi')
	rip = adapter.register_read('rip')
	rsp = adapter.register_read('rsp')
	rbp = adapter.register_read('rbp')
	r8 = adapter.register_read('r8')
	r9 = adapter.register_read('r9')
	r10 = adapter.register_read('r10')
	r11 = adapter.register_read('r11')
	r12 = adapter.register_read('r12')
	r13 = adapter.register_read('r13')
	r14 = adapter.register_read('r14')
	r15 = adapter.register_read('r15')

	print("%srax%s=%016X %srbx%s=%016X %srcx%s=%016X" % \
		(BROWN, NORMAL, rax, BROWN, NORMAL, rbx, BROWN, NORMAL, rcx))
	print("%srdx%s=%016X %srsi%s=%016X %srdi%s=%016X" %
		(BROWN, NORMAL, rdx, BROWN, NORMAL, rsi, BROWN, NORMAL, rdi))
	print("%srip%s=%016X %srsp%s=%016X %srbp%s=%016X" % \
		(BROWN, NORMAL, rip, BROWN, NORMAL, rsp, BROWN, NORMAL, rbp))
	print(" %sr8%s=%016X  %sr9%s=%016X %sr10%s=%016X" % \
		(BROWN, NORMAL, r8, BROWN, NORMAL, r9, BROWN, NORMAL, r10))
	print("%sr11%s=%016X %sr12%s=%016X %sr13%s=%016X" % \
		(BROWN, NORMAL, r11, BROWN, NORMAL, r12, BROWN, NORMAL, r13))
	print("%sr14%s=%016X %sr15%s=%016X" % \
		(BROWN, NORMAL, r14, BROWN, NORMAL, r15))

	data = adapter.mem_read(rip, 16)
	if data:
		(asmstr, asmlen) = disasm1(data, rip)
		print('%s%016X%s: %s\t%s' % \
			(GREEN, rip, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

def debug_status():
	return

#--------------------------------------------------------------------------
# UTILITIES
#--------------------------------------------------------------------------

def disasm1(data, addr):
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	gen = md.disasm(data, addr)
	insn = next(gen)
	return ('%s %s' % (insn.mnemonic, insn.op_str), insn.size)

def disasm(data, addr):
	if not data:
		return
	lines = []
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
	offset = 0
	for i in md.disasm(data, addr):
		addrstr = '%s%016X%s' % (GREEN, i.address, NORMAL)
		bytestr = hexlify(data[offset:offset+i.size]).decode('utf-8').ljust(16)
		asmstr = i.mnemonic + ' ' + i.op_str
		line = '%s: %s %s' % (addrstr, bytestr, asmstr)
		lines.append(line)
		offset += i.size
	return '\n'.join(lines)

def hex_dump(data, addr=0, grouping=1, endian='little'):
	result = ''

	while(data):
		ascii = ''
		buff16 = data[0:16]
		data = data[16:]
		result += "%s%016X%s: " % (GREEN, addr, NORMAL)

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

# handle asynchronous output packets from lldb server
def output_handler(packet):
	message = unhexlify(data[1:])
	print('stdout message: %s' % message)

#--------------------------------------------------------------------------
# MAIN
#--------------------------------------------------------------------------

# TODO: parse command line to select windbg/dbgeng adapter
adapter = lldb.DebugAdapterLLDB()

def handler(signal, frame):
    adapter.break_into()

if __name__ == '__main__':
	colorama.init()

	signal.signal(signal.SIGINT, handler)

	user_goal = 'debug'
	while user_goal == 'debug':
		try:
			text = input('FAKEDBG>')
			if not text:
				continue

			# testing stuff
			#elif text.startswith('packet '):
			#	reply = tx_rx(text[7:])
			#	packet_display(reply)

			# thread list, thread switch
			elif text in ['~', 'threads']:
				tids = adapter.thread_list()
				for (idx, tid) in enumerate(tids):
					print('%02d: tid=0x%X' % (idx, tid))

			elif text[0:] and text[0]=='~' and text[-1]=='s':
				tid = int(text[1:-1])
				adapter.thread_select(tid)

			# breakpoint set/clear
			elif text.startswith('bp '):
				addr = int(text[3:], 16)
				bpid = adapter.breakpoint_set(addr)
				if bpid == None:
					print('ERROR')
				else:
					print('breakpoint %d set at 0x%X' % (bpid, addr))

			elif text.startswith('bc '):
				bpid = int(text[3:])
				if adapter.breakpoint_clear(bpid) == None:
					print('ERROR')
				else:
					print('breakpoint id %d cleared' % bpid)

			elif text == 'bl':
				print('breakpoint list:')
				for (bpid, addr) in adapter.breakpoint_list().items():
					print('%d: 0x%X' % (bpid, addr))

			# context, read regs, write regs
			elif text in ['r']:
				context_show()
			elif re.match(r'r .* .*$', text):
				(_, reg, val) = text.split(' ')
				adapter.reg_write(reg, int(val, 16))

			# read/write mem, disasm mem
			elif text.startswith('db '):
				addr = int(text[3:], 16)
				data = adapter.mem_read(addr, 128)
				print(hex_dump(data, addr))
			elif text.startswith('eb '):
				m = re.match(r'^eb (\w+) (.*)$', text)
				addr = int(m.group(1), 16)
				bytes_ = bytes(map(lambda x: int(x,16), m.group(2).split()))
				adapter.mem_write(addr, bytes_)
			elif text.startswith('u '):
				addr = int(text[2:],16)
				data = mem_read(addr, 32)
				print(disasm(data, addr))

			# break into, go, step, step into
			elif text in ['break', 'breakinto']:
				break_into()

			elif text == 'test':
				(reason, data) = adapter.go()

			elif text in 'gpt':
				while 1:
					if text == 'g':
						(reason, data) = adapter.go()
					elif text == 't':
						(reason, data) = adapter.step_into()
					else:
						assert 0

					if reason == DebugAdapter.STOP_REASON.STDOUT_MESSAGE:
						print('stdout: ', data)
					elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
						print('process exited, return code=%d', data)
					else:
						print('stopped, reason: ', reason.name)
						context_show()
						break

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

		except KeyboardInterrupt as e:
			print("ctrl+c detected! breaking in!\n")
			break_into()

	if user_goal == 'detach':
		adapter.detach()
	elif user_goal == 'quit':
		adapter.quit()

