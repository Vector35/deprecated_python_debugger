#!/usr/bin/env python
#
# unit tests for debugger

import os
import sys
import time
import platform

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

if __name__ == '__main__':
	executables = ['helloworld', 'helloworld_thread', 'helloworld_loop']
	if platform.system() == 'Windows':
		executables = [x+'.exe' for x in executables]

	#executables = ['helloworld_thread.exe']
	for fname in executables:
		fpath = os.path.join('testbins', fname)

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

		time.sleep(2)

	print('TESTS PASSED!')
