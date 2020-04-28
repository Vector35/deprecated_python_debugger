#!/usr/bin/env python3

# demonstrate use of headless debugger to count opcode frequency for an md5 calculation
#
# you probably want to run sometimes like:
# $ ./md5_opc_freq.py ../testbins/md5/md5_x64-macos

import os
import sys
import struct
import platform
from collections import defaultdict
import binaryninja
from binaryninja.binaryview import BinaryViewType

RED = '\x1B[31m'
GREEN = '\x1B[32m'
YELLOW = '\x1B[93m'
NORMAL = '\x1B[0m'

# globals
tally = defaultdict(int)

# open for analysis
fpath = sys.argv[1]
bv = BinaryViewType.get_view_of_file(fpath)
bv.update_analysis_and_wait()

from debugger import DebugAdapter, lldb, gdb

def show_stats():
	global tally

	n_instrs = sum(tally.values())
	print('\x1B[H', end='') # cursor to top left
	print('\x1B[J', end='') # clear screen from cursor down
	for instr in sorted(tally, key=lambda x: tally[x], reverse=True):
		print('instr:%s%s%s total:%s%d%s percentage:%s%.02f%%%s' % (\
			YELLOW,instr.rjust(8),NORMAL,
			GREEN,tally[instr],NORMAL,
			RED,tally[instr]/n_instrs*100,NORMAL)
		)
# create debug adapter
if platform.system() == 'Linux':
	adapt = gdb.DebugAdapterGdb()
elif platform.system() == 'Darwin':
	adapt = lldb.DebugAdapterLLDB()
else:
	raise Exception('unknown system!')
adapt.exec(fpath, ['-sabcdefghijklmnopqrstuvwxyz'])

# sense aslr situation, resolve symbols
base = adapt.target_base()
base_bv = bv.start
delta = base - base_bv
print('analysis rooted at %s0x%X%s, target in memory at %s0x%X%s, delta %s0x%X%s' % (\
	GREEN,base_bv,NORMAL,
	GREEN,base,NORMAL,
	RED,delta,NORMAL))

for f in bv.functions:
	if f.symbol.full_name in ['MD5Init', '_MD5Init']: MD5Init = f.start + delta
	if f.symbol.full_name in ['MD5Update', '_MD5Update']: MD5Update = f.start + delta
	if f.symbol.full_name in ['MD5Final', '_MD5Final']: MD5Final = f.start + delta
print('  MD5Init: %s0x%X%s' % (GREEN,MD5Init,NORMAL))
print('MD5Update: %s0x%X%s' % (GREEN,MD5Update,NORMAL))
print(' MD5Final: %s0x%X%s' % (GREEN,MD5Final,NORMAL))

print('press any key to continue')
input()

# go until MD5 starts
adapt.breakpoint_set(MD5Init)
(reason, data) = adapt.go()
assert reason == DebugAdapter.STOP_REASON.BREAKPOINT
assert adapt.reg_read('rip') == MD5Init
adapt.breakpoint_clear(MD5Init)

print('at MD5Init()')

# step until MD5Final
while 1:
	(reason, data) = adapt.step_into()
	assert reason in [DebugAdapter.STOP_REASON.BREAKPOINT, DebugAdapter.STOP_REASON.SINGLE_STEP]
	rip = adapt.reg_read('rip')
	opc = bv.get_disassembly(rip - delta).split()[0]
	tally[opc] += 1
	show_stats()
	#print('0x%X %s' % (rip, opc))
	if adapt.reg_read('rip') == MD5Final:
		break

n_instrs = sum(tally.values())
print('at MD5Final(), %d instructions so far' % n_instrs)

# step until return to caller
rsp = adapt.reg_read('rsp')
stack = adapt.mem_read(rsp, 8)
caller = struct.unpack('<Q', stack)[0]
while 1:
	(reason, data) = adapt.step_into()
	assert reason in [DebugAdapter.STOP_REASON.BREAKPOINT, DebugAdapter.STOP_REASON.SINGLE_STEP]
	rip = adapt.reg_read('rip')
	opc = bv.get_disassembly(rip - delta).split()[0]
	tally[opc] += 1
	show_stats()
	if adapt.reg_read('rip') == caller:
		break

n_instrs = sum(tally.values())
print('returned from MD5Final(), %d instructions' % n_instrs)

for opc in sorted(tally, key=lambda x: tally[x], reverse=True):
	print('%s: %d (%.1f%%)' % (opc.ljust(8), tally[opc], 100*(tally[opc]/n_instrs)))

(reason, data) = adapt.go()
assert reason == DebugAdapter.STOP_REASON.PROCESS_EXITED

