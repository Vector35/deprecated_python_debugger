import os
import re
import time
import threading

import binaryninja
from binaryninja import Symbol, SymbolType, Type, Structure, StructureType
from binaryninja.plugin import PluginCommand
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, ViewType
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit

from . import helpers
from . import DebugAdapter, ProcessView
from . import lldb
from .dockwidgets import BreakpointsWidget, RegistersWidget, StackWidget, ThreadsWidget, MemoryWidget, ControlsWidget, DebugView, ConsoleWidget, widget

#------------------------------------------------------------------------------
# globals
#------------------------------------------------------------------------------

class DebuggerState:
	def __init__(self, bv):
		self.bv = bv
		self.adapter = None
		self.state = 'INACTIVE'
		# address -> adapter id
		self.breakpoints = {}
		self.memory_view = ProcessView.DebugProcessView(bv)
		self.old_symbols = []
		self.old_dvs = set()

	states = []

def get_state(bv):
	# Try to find an existing state object
	for state in DebuggerState.states:
		if state.bv == bv:
			return state

	# Else make a new one, initially inactive
	state = DebuggerState(bv)
	DebuggerState.states.append(state)
	return state

def delete_state(bv):
	print("Detroying debugger state for {}".format(bv))

	# Try to find an existing state object
	for (i, state) in enumerate(DebuggerState.states):
		if state.bv == bv:
			DebuggerState.states.pop(i)
			return

#--------------------------------------------------------------------------
# SUPPORT FUNCTIONS (HIGHER LEVEL)
#--------------------------------------------------------------------------

def context_display(bv):
	adapter = get_state(bv).adapter

	#----------------------------------------------------------------------
	# Update Registers
	#----------------------------------------------------------------------
	registers_widget = widget.get_dockwidget(bv, 'Registers')
	regs = []
	for register in adapter.reg_list():
		value = adapter.reg_read(register)
		bits = adapter.reg_bits(register)
		regs.append({
			'name': register,
			'bits': bits,
			'value': value
		})
	registers_widget.notifyRegistersChanged(regs)

	#----------------------------------------------------------------------
	# Update Threads
	#----------------------------------------------------------------------
	threads_widget = widget.get_dockwidget(bv, 'Threads')

	if bv.arch.name == 'x86_64':
		reg_ip_name = 'rip'
		reg_ip_width = 64
	else:
		raise NotImplementedError('only x86_64 so far')

	threads = []
	tid_selected = adapter.thread_selected()
	for tid in adapter.thread_list():
		adapter.thread_select(tid)
		reg_ip_val = adapter.reg_read(reg_ip_name)
		threads.append({
			'tid': tid,
			reg_ip_name: reg_ip_val,
			'bits': reg_ip_width,
			'selected': (tid == tid_selected)
		})
	adapter.thread_select(tid_selected)
	threads_widget.notifyThreadsChanged(threads)

	#----------------------------------------------------------------------
	# Update Stack
	#----------------------------------------------------------------------
	stack_widget = widget.get_dockwidget(bv, 'Stack')

	if bv.arch.name == 'x86_64':
		stack_pointer = adapter.reg_read('rsp')
		# Read up and down from rsp
		stack_range = [-8, 60] # Inclusive
		stack = []
		for i in range(stack_range[0], stack_range[1] + 1):
			offset = i * bv.arch.address_size
			address = stack_pointer + offset
			value = adapter.mem_read(address, bv.arch.address_size)
			value_int = value
			if bv.arch.endianness == binaryninja.Endianness.LittleEndian:
				value_int = value_int[::-1]
			value_int = int(value_int.hex(), 16)

			refs = []
			for register in regs:
				if register['value'] == address:
					refs.append({
						'source': 'register',
						'dest': 'address',
						'register': register
					})
				# Ignore zeroes because most registers start at zero and give false data
				if value_int != 0 and register['value'] == value_int:
					refs.append({
						'source': 'register',
						'dest': 'value',
						'register': register
					})

			stack.append({
				'offset': offset,
				'value': value,
				'address': address,
				'refs': refs
			})
		stack_widget.notifyStackChanged(stack)

	#--------------------------------------------------------------------------
	# Update Memory
	#--------------------------------------------------------------------------
	update_memory_view(bv)
	memory_dirty(bv)

	#--------------------------------------------------------------------------
	# Update Status
	#--------------------------------------------------------------------------

	rip = adapter.reg_read('rip')

	# select instruction currently at
	if bv.read(rip, 1):
		print('navigating to: 0x%X' % rip)
		statusText = 'STOPPED at 0x%016X' % rip
		bv.navigate(bv.file.view, rip)
	else:
		statusText = 'STOPPED at 0x%016X (outside view)' % rip
		print('address 0x%X outside of binary view, not setting cursor' % rip)

	state_stopped(bv, statusText)

	#data = adapter.mem_read(rip, 16)
	#if data:
	#	(asmstr, asmlen) = disasm1(data, rip)
	#	print('%s%016X%s: %s\t%s' % \
	#		(GREEN, rip, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

# Mark memory as dirty, will refresh memory view
def memory_dirty(bv):
	widget.get_dockwidget(bv, 'Memory').notifyMemoryChanged()

# Create symbols and variables for the memory view
def update_memory_view(bv):
	state = get_state(bv)
	adapter = state.adapter
	memory_view = state.memory_view

	assert adapter is not None
	assert memory_view is not None
	
	memory_view.mark_dirty()
	
	addr_regs = {}
	reg_addrs = {}

	for reg in adapter.reg_list():
		addr = adapter.reg_read(reg)
		reg_symbol_name = '$' + reg

		if addr not in addr_regs.keys():
			addr_regs[addr] = [reg_symbol_name]
		else:
			addr_regs[addr].append(reg_symbol_name)
		reg_addrs[reg] = addr

	for symbol in state.old_symbols:
		# Symbols are immutable so just destroy the old one
		memory_view.undefine_auto_symbol(symbol)

	for dv in state.old_dvs:
		memory_view.undefine_data_var(dv)

	state.old_symbols = []
	state.old_dvs = set()
	new_dvs = set()

	for (addr, regs) in addr_regs.items():
		symbol_name = "@".join(regs)
		fancy_name = ",".join(regs)
		
		memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, addr, fancy_name, raw_name=symbol_name))
		state.old_symbols.append(memory_view.get_symbol_by_raw_name(symbol_name))
		new_dvs.add(addr)
	
	for new_dv in new_dvs:
		memory_view.define_data_var(new_dv, Type.int(8))
		state.old_dvs.add(new_dv)

	# Special struct for stack frame
	if bv.arch.name == 'x86_64':
		width = reg_addrs['rbp'] - reg_addrs['rsp']
		if width > 0:
			if width > 0x1000:
				width = 0x1000
			struct = Structure()
			struct.type = StructureType.StructStructureType
			struct.width = width
			memory_view.undefine_data_var(reg_addrs['rsp'])
			memory_view.undefine_data_var(reg_addrs['rbp'])

			for i in range(0, width + 1, bv.arch.address_size):
				struct.insert(i, Type.pointer(bv.arch, Type.void()))

			memory_view.define_data_var(reg_addrs['rsp'], Type.structure_type(struct))
			memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, reg_addrs['rsp'], "$stack_frame", raw_name="$stack_frame"))

			state.old_symbols.append(memory_view.get_symbol_by_raw_name("$stack_frame"))
			state.old_dvs.add(reg_addrs['rsp'])


# breakpoint TAG removal - strictly presentation
# (doesn't remove actual breakpoints, just removes the binja tags that mark them)
#
def del_breakpoint_tags(bv, addresses=None):
	debug_state = get_state(bv)

	if addresses == None:
		addresses = debug_state.breakpoints

	for address in addresses:
		# delete breakpoint tags from all functions containing this address
		for func in bv.get_functions_containing(address):
			delqueue = [tag for tag in func.get_address_tags_at(address) if tag.data == 'breakpoint']
			for tag in delqueue:
				func.remove_user_address_tag(address, tag)

def buttons_xable(bv, states):
	assert len(states) == 8

	dw = get_state(bv).debug_view.controls

	buttons = [dw.btnRun, dw.btnRestart, dw.btnQuit, dw.btnDetach, dw.btnBreak,
		dw.btnResume, dw.btnStepInto, dw.btnStepOver]

	for (button, state) in zip(buttons, states):
		button.setEnabled(bool(state))

def debug_status(bv, message):
	main = get_state(bv).debug_view.controls
	main.editStatus.setText(message)

def state_inactive(bv, msg=None):
	debug_state = get_state(bv)

	# clear breakpoints
	del_breakpoint_tags(bv)
	debug_state.breakpoints = {}

	debug_state.state = 'INACTIVE'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, [1, 0, 0, 0, 0, 0, 0, 0])

def state_stopped(bv, msg=None):
	debug_state = get_state(bv)
	debug_state.state = 'STOPPED'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, [0, 1, 1, 1, 1, 1, 1, 1])

def state_running(bv, msg=None):
	debug_state = get_state(bv)
	debug_state.state = 'RUNNING'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, [0, 0, 0, 0, 1, 0, 0, 0])

def state_error(bv, msg=None):
	debug_state = get_state(bv)
	debug_state.state = 'ERROR'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, [1, 1, 1, 1, 1, 1, 1, 1])

def handle_stop_return(bv, reason, data):
	if reason == DebugAdapter.STOP_REASON.STDOUT_MESSAGE:
		state_stopped(bv, 'stdout: '+data)
		context_display(bv)
	elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
		debug_quit(bv)
		state_inactive(bv, 'process exited, return code=%d' % data)
	elif reason == DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED:
		debug_quit(bv)
		state_inactive(bv, 'backend disconnected (process exited?)')
	else:
		context_display(bv)

#------------------------------------------------------------------------------
# DEBUGGER FUNCTIONS (MEDIUM LEVEL)
#------------------------------------------------------------------------------

def debug_run(bv):
	fpath = bv.file.filename

	if not os.path.exists(fpath):
		raise Exception('cannot find debug target: ' + fpath)

	#adapter = lldb.DebugAdapterLLDB()
	adapter = helpers.launch_get_adapter(fpath)

	get_state(bv).adapter = adapter

	if bv and bv.entry_point:
		debug_breakpoint_set(bv, bv.entry_point)
		bv.navigate(bv.file.view, bv.entry_point)

	state_stopped(bv)
	context_display(bv)
	memory_dirty(bv)

def debug_quit(bv):
	adapter = get_state(bv).adapter
	if adapter:
		adapter.quit()
		get_state(bv).adapter = None
	state_inactive(bv)
	memory_dirty(bv)

def debug_restart(bv):
	debug_quit(bv)
	time.sleep(1)
	debug_run(bv) # sets state

def debug_detach(bv):
	adapter = get_state(bv).adapter
	assert adapter
	adapter.detach()
	get_state(bv).adapter = None
	state_inactive(bv)

def debug_break(bv):
	adapter = get_state(bv).adapter
	assert adapter
	adapter.break_into()

# non-blocking wrapper around adapter.go() (so user can nav around)
def debug_go(bv, gui_updates=True):
	adapter = get_state(bv).adapter
	assert adapter

	def debug_go_thread(bv):
		if gui_updates:
			state_running(bv)
		(reason, data) = adapter.go()
		if gui_updates:
			handle_stop_return(bv, reason, data)
			memory_dirty(bv)

	threading.Thread(target=debug_go_thread, args=(bv,)).start()

def debug_step(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	(reason, data) = (None, None)

	if bv.arch.name == 'x86_64':
		rip = adapter.reg_read('rip')

		# if currently a breakpoint at rip, temporarily clear it
		# TODO: detect windbg adapter because dbgeng's step behavior might ignore breakpoint
		# at current rip

		seq = []
		if rip in debug_state.breakpoints:
			seq.append((adapter.breakpoint_clear, (rip,)))
			seq.append((adapter.step_into, ()))
			seq.append((adapter.breakpoint_set, (rip,)))
		else:
			seq.append((adapter.step_into, ()))

		(reason, data) = exec_adapter_sequence(adapter, seq)
	else:
		raise NotImplementedError('step unimplemented for architecture %s' % bv.arch.name)

	handle_stop_return(bv, reason, data)
	memory_dirty(bv)

def debug_step_over(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	# TODO: detect windbg adapter because dbgeng has a builtin step_into() that we don't
	# have to synthesize
	if bv.arch.name == 'x86_64':
		rip = adapter.reg_read('rip')
		instxt = bv.get_disassembly(rip)
		inslen = bv.get_instruction_length(rip)
		ripnext = rip + inslen

		call = instxt.startswith('call ')
		bphere = rip in debug_state.breakpoints
		bpnext = ripnext in debug_state.breakpoints

		seq = []

		if not call:
			seq.append((adapter.step_into, ()))
		elif bphere and bpnext:
			seq.append((adapter.breakpoint_clear, (rip,)))
			seq.append((adapter.go, ()))
			seq.append((adapter.breakpoint_set, (rip,)))
		elif bphere and not bpnext:
			seq.append((adapter.breakpoint_clear, (rip,)))
			seq.append((adapter.breakpoint_set, (ripnext,)))
			seq.append((adapter.go, ()))
			seq.append((adapter.breakpoint_clear, (ripnext,)))
			seq.append((adapter.breakpoint_set, (rip,)))
		elif not bphere and bpnext:
			seq.append((adapter.go, ()))
		elif not bphere and not bpnext:
			seq.append((adapter.breakpoint_set, (ripnext,)))
			seq.append((adapter.go, ()))
			seq.append((adapter.breakpoint_clear, (ripnext,)))
		else:
			raise Exception('confused by call, bphere, bpnext state')

		(reason, data) = exec_adapter_sequence(adapter, seq)
		handle_stop_return(bv, reason, data)

	else:
		raise NotImplementedError('step over unimplemented for architecture %s' % bv.arch.name)

	state = 'stopped'
	memory_dirty(bv)

def debug_breakpoint_set(bv, address):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	if adapter.breakpoint_set(address) != 0:
		print('ERROR: breakpoint set failed')
		return None

	# create tag
	tt = bv.tag_types["Crashes"]
	for func in bv.get_functions_containing(address):
		tag = func.create_user_address_tag(address, tt, "breakpoint")

	# save it
	debug_state.breakpoints[address] = True
	print('breakpoint address=0x%X set' % (address))

	bp_widget = widget.get_dockwidget(bv, "Breakpoints")
	if bp_widget is not None:
		bp_widget.notifyBreakpointChanged()

	return 0

def debug_breakpoint_clear(bv, address):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	# find/remove address tag
	if address in debug_state.breakpoints:
		# delete from adapter
		if adapter.breakpoint_clear(address) != None:
			print('breakpoint address=0x%X cleared' % (address))
		else:
			print('ERROR: clearing breakpoint')

		# delete breakpoint tags from all functions containing this address
		del_breakpoint_tags(bv, [address])

		# delete from our list
		del debug_state.breakpoints[address]
	else:
		print('ERROR: breakpoint not found in list')

# execute a sequence of adapter commands, capturing the return of the last
# blocking call
def exec_adapter_sequence(adapter, seq):
	(reason, data) = (None, None)

	for (func, args) in seq:
		if func in [adapter.step_into, adapter.step_over, adapter.go]:
			(reason, data) = func(*args)
		else:
			func(*args)

	return (reason, data)

#------------------------------------------------------------------------------
# right click plugin
#------------------------------------------------------------------------------

def cb_bp_set(bv, address):
	debug_breakpoint_set(bv, address)

def cb_bp_clr(bv, address):
	debug_breakpoint_clear(bv, address)

#------------------------------------------------------------------------------
# "main"
#------------------------------------------------------------------------------

def initialize():
	widget.register_dockwidget(BreakpointsWidget.DebugBreakpointsWidget, "Breakpoints", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(RegistersWidget.DebugRegistersWidget, "Registers", Qt.RightDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ThreadsWidget.DebugThreadsWidget, "Threads", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(StackWidget.DebugStackWidget, "Stack", Qt.LeftDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ConsoleWidget.DebugConsoleWidget, "Debugger Console", Qt.BottomDockWidgetArea, Qt.Horizontal, False)

	PluginCommand.register_for_address("Set Breakpoint", "sets breakpoint at right-clicked address", cb_bp_set)
	PluginCommand.register_for_address("Clear Breakpoint", "clears breakpoint at right-clicked address", cb_bp_clr)
	ViewType.registerViewType(DebugView.DebugViewType())
