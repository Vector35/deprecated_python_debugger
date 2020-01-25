#!/usr/bin/env python
#
# unit tests for debugger

import os
import sys
import time
import platform
import threading

from struct import unpack

sys.path.append('..')
import debugger.helpers as helpers
import debugger.lldb as lldb
import debugger.DebugAdapter as DebugAdapter

RED = '\x1B[31m'
GREEN = '\x1B[32m'
BROWN = '\x1B[33m'
NORMAL = '\x1B[0m'

# globals
adapter = None

#--------------------------------------------------------------------------
# UTILITIES
#--------------------------------------------------------------------------

def get_file_data(fpath):
	with open(fpath, 'rb') as fp:
		return fp.read()

def get_entry(data):
	# little endian macho
	if data[0:4] == b'\xCF\xFA\xED\xFE':
		assert data[4:8] == b'\x07\x00\x00\x01' # CPU_TYPE_X86_X64
		ncmds = unpack('<I', data[16:20])[0]
		#print('ncmds: %d' % ncmds)
		vmaddr = None
		entryoff = None
		offs = 0x20
		for i in range(ncmds):
			cmd = unpack('<I', data[offs:offs+4])[0]
			cmdsize = unpack('<I', data[offs+4:offs+8])[0]
			if cmd == 0x19: # segment_command_64
				if data[offs+8:offs+16] == b'\x5F\x5F\x54\x45\x58\x54\x00\x00': # __TEXT
					vmaddr = unpack('<Q', data[offs+24:offs+32])[0]
					#print('vmaddr: %X' % vmaddr)
			if cmd == 0x80000028: # entry_point_command
				entryoff = unpack('<I', data[offs+8:offs+12])[0]
				#print('entryoff: %X' % entryoff)
			offs += cmdsize
		if not vmaddr:
			raise Exception('couldn\'t locate segment_command_64 (where __TEXT loads)')
		if entryoff == None:
			raise Exception('couldn\'t locate entry_point_command (where main is)')
		return vmaddr + entryoff

	# PE
	if data[0:2] == b'\x4d\x5a':
		e_lfanew = unpack('<I', data[0x3C:0x40])[0]
		assert data[e_lfanew:e_lfanew+6] == b'\x50\x45\x00\x00\x64\x86'
		entryoff = unpack('<I', data[e_lfanew+0x28:e_lfanew+0x2C])[0]
		vmaddr = unpack('<Q', data[e_lfanew+0x30:e_lfanew+0x38])[0]
		return vmaddr + entryoff

	raise Exception('unrecognized file type')

#------------------------------------------------------------------------------
# UTILITIES
#------------------------------------------------------------------------------

# 'helloworld' -> '.\testbins\helloworld.exe'
# or
# 'helloworld' -> './testbins/helloworld
def test_prog_to_fpath(prog):
	if platform.system() == 'Windows':
		prog = prog + '.exe'
	return os.path.join('testbins', prog)

def break_into(adapter):
	print('sending break')
	adapter.break_into()

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------

if __name__ == '__main__':
	# one-off tests
	if sys.argv[1:] and sys.argv[1] == 'oneoff':
		adapter = helpers.launch_get_adapter(test_prog_to_fpath('helloworld'))
		for (ridx,rname) in enumerate(adapter.reg_list()):
			width = adapter.reg_bits(rname)
			print('%d: %s (%d bits)' % (ridx, rname, width))
		adapter.quit()
		sys.exit(0)

	test_progs = ['helloworld', 'helloworld_thread', 'helloworld_loop']

	#
	# thread test
	#
	fpath = test_prog_to_fpath('helloworld_thread')
	adapter = helpers.launch_get_adapter(fpath)
	print('scheduling break in .5 seconds')
	threading.Timer(.5, break_into, [adapter]).start()
	print('going')
	adapter.go()
	print('back')
	print('switching to bad thread')
	try:
		adapter.thread_select(999)
	except DebugAdapter.GeneralError:
		pass
	print('asking for threads')
	if platform.system() == 'Windows':
		# main thread at WaitForMultipleObjects() + 4 created threads + debugger thread
		nthreads_expected = 6
	else:
		# main thread at pthread_join() + 4 created threads
		nthreads_expected = 4
	tids = adapter.thread_list()
	assert len(tids) == nthreads_expected
	tid_active = adapter.thread_selected()
	rips = []
	for tid in tids:
		adapter.thread_select(tid)
		rip = adapter.reg_read('rip')
		rips.append(rip)
		seltxt = '<--' if tid == tid_active else ''
		print('thread %02d: rip=0x%016X %s' % (tid, rip, seltxt))
	assert rips[0] != rips[1] # thread at WaitForMultipleObjects()/pthread_join() should be different
	print('switching to bad thread')
	try:
		adapter.thread_select(999)
	except DebugAdapter.GeneralError:
		pass
	print('scheduling break in .5 seconds')
	threading.Timer(.5, break_into, [adapter]).start()
	print('going')
	adapter.go()
	print('back')
	print('checking for %d threads' % nthreads_expected)
	assert len(adapter.thread_list()) == nthreads_expected
	print('done')
	adapter.quit()

	#
	# basic test
	#
	for prog in test_progs:
		fpath = test_prog_to_fpath(prog)

		data = get_file_data(fpath)
		entry = get_entry(data)

		print('file %s has entrypoint 0x%X' % (fpath, entry))
		print('launching %s' % fpath)
		adapter = helpers.launch_get_adapter(fpath)
		print('rip: 0x%X' % adapter.reg_read('rip'))

		# breakpoint set/clear should fail at 0
		try:
			adapter.breakpoint_clear(0)
		except DebugAdapter.BreakpointClearError:
			pass

		try:
			adapter.breakpoint_set(0)
		except DebugAdapter.BreakpointSetError:
			pass

		# breakpoint set/clear should succeed at entrypoint
		print('setting breakpoint at 0x%X' % entry)
		adapter.breakpoint_set(entry)
		print('clearing breakpoint at 0x%X' % entry)
		adapter.breakpoint_clear(entry)
		print('setting breakpoint at 0x%X' % entry)
		adapter.breakpoint_set(entry)

		# proceed to breakpoint
		print('going')
		(reason, info) = adapter.go()
		assert reason == DebugAdapter.STOP_REASON.SIGNAL_TRAP
		rip = adapter.reg_read('rip')
		print('rip: 0x%X' % rip)
		assert rip == entry

		# single step
		data = adapter.mem_read(rip, 15)
		assert len(data) == 15
		(asmstr, asmlen) = helpers.disasm1(data, 0)
		adapter.breakpoint_clear(entry)
		(reason, info) = adapter.step_into()
		assert reason == DebugAdapter.STOP_REASON.SIGNAL_TRAP
		rip2 = adapter.reg_read('rip')
		print('rip2: 0x%X' % rip2)
		assert rip + asmlen == rip2

		# registers
		for (ridx,rname) in enumerate(adapter.reg_list()):
			width = adapter.reg_bits(rname)
			print('%d: %s (%d bits)' % (ridx, rname, width))
		assert adapter.reg_bits('rax') == 64
		assert adapter.reg_bits('rax') == 64

		# reg write
		rax = adapter.reg_read('rax')
		rbx = adapter.reg_read('rbx')
		print('rax: 0x%X' % rax)
		print('rbx: 0x%X' % rbx)
		adapter.reg_write('rax', 0xDEADBEEF)
		rax2 = adapter.reg_read('rax')
		print('rax2: 0x%X' % rax2)
		assert rax2 == 0xDEADBEEF

		print('quiting')
		adapter.quit()
		adapter = None

	print('TESTS PASSED!')
