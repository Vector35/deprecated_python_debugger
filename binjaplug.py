import os
import re
import time
import threading

import binaryninja
from binaryninja import Symbol, SymbolType, Type, Structure, StructureType, execute_on_main_thread_and_wait
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
		self.last_rip = 0

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
	debug_state = get_state(bv)
	adapter = debug_state.adapter

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
	debug_state.debug_view.controls.setThreadList(threads)

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
	else:
		raise NotImplementedError('only x86_64 so far')

	#--------------------------------------------------------------------------
	# Update Memory
	#--------------------------------------------------------------------------
	update_memory_view(bv)
	memory_dirty(bv)

	#--------------------------------------------------------------------------
	# Update Status
	#--------------------------------------------------------------------------

	if bv.arch.name == 'x86_64':
		remote_rip = adapter.reg_read('rip')
		local_rip = debug_state.memory_view.remote_addr_to_local(remote_rip)
	else:
		raise NotImplementedError('only x86_64 so far')

	# Clear old highlighted rip
	for func in bv.get_functions_containing(debug_state.last_rip):
		func.set_auto_instr_highlight(debug_state.last_rip, binaryninja.HighlightStandardColor.NoHighlightColor)
	update_highlights(bv)
	debug_state.last_rip = local_rip

	# select instruction currently at
	if bv.read(local_rip, 1):
		print('navigating to: 0x%X' % local_rip)
		statusText = 'STOPPED'

		bv.navigate(bv.file.view, local_rip)
	else:
		statusText = 'STOPPED (outside view)'
		print('address 0x%X outside of binary view, not setting cursor' % remote_rip)

	state_stopped(bv, statusText)

	#data = adapter.mem_read(rip, 16)
	#if data:
	#	(asmstr, asmlen) = disasm1(data, rip)
	#	print('%s%016X%s: %s\t%s' % \
	#		(GREEN, rip, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

# Mark memory as dirty, will refresh memory view
def memory_dirty(bv):
	debug_state = get_state(bv)
	debug_state.memory_view.mark_dirty()
	if debug_state.debug_view is not None:
		debug_state.debug_view.notifyMemoryChanged()

# Create symbols and variables for the memory view
def update_memory_view(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	memory_view = debug_state.memory_view

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

	for symbol in debug_state.old_symbols:
		# Symbols are immutable so just destroy the old one
		memory_view.undefine_auto_symbol(symbol)

	for dv in debug_state.old_dvs:
		memory_view.undefine_data_var(dv)

	debug_state.old_symbols = []
	debug_state.old_dvs = set()
	new_dvs = set()

	for (addr, regs) in addr_regs.items():
		symbol_name = "@".join(regs)
		fancy_name = ",".join(regs)
		
		memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, addr, fancy_name, raw_name=symbol_name))
		debug_state.old_symbols.append(memory_view.get_symbol_by_raw_name(symbol_name))
		new_dvs.add(addr)
	
	for new_dv in new_dvs:
		memory_view.define_data_var(new_dv, Type.int(8))
		debug_state.old_dvs.add(new_dv)

	# Special struct for stack frame
	if bv.arch.name == 'x86_64':
		width = reg_addrs['rbp'] - reg_addrs['rsp']
		if width > 0:
			if width > 0x1000:
				width = 0x1000
			struct = Structure()
			struct.type = StructureType.StructStructureType
			struct.width = width
			for i in range(0, width, bv.arch.address_size):
				struct.insert(i, Type.pointer(bv.arch, Type.void()))
			memory_view.define_data_var(reg_addrs['rsp'], Type.structure_type(struct))
			memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, reg_addrs['rsp'], "$stack_frame", raw_name="$stack_frame"))

			debug_state.old_symbols.append(memory_view.get_symbol_by_raw_name("$stack_frame"))
			debug_state.old_dvs.add(reg_addrs['rsp'])

# Highlight lines 
def update_highlights(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter

	for bp in debug_state.breakpoints:
		for func in bv.get_functions_containing(bp):
			func.set_auto_instr_highlight(bp, binaryninja.HighlightStandardColor.RedHighlightColor)
	
	if adapter is not None:
		if bv.arch.name == 'x86_64':
			remote_rip = adapter.reg_read('rip')
			local_rip = debug_state.memory_view.remote_addr_to_local(remote_rip)
		else:
			raise NotImplementedError('only x86_64 so far')

		for func in bv.get_functions_containing(local_rip):
			func.set_auto_instr_highlight(local_rip, binaryninja.HighlightStandardColor.BlueHighlightColor)

# breakpoint TAG removal - strictly presentation
# (doesn't remove actual breakpoints, just removes the binja tags that mark them)
#
def del_breakpoint_tags(bv, local_addresses=None):
	debug_state = get_state(bv)

	if local_addresses == None:
		local_addresses = [debug_state.memory_view.local_addr_to_remote(addr) for addr in debug_state.breakpoints]

	for local_address in local_addresses:
		# delete breakpoint tags from all functions containing this address
		for func in bv.get_functions_containing(local_address):
			func.set_auto_instr_highlight(local_address, binaryninja.HighlightStandardColor.NoHighlightColor)
			delqueue = [tag for tag in func.get_address_tags_at(local_address) if tag.data == 'breakpoint']
			for tag in delqueue:
				func.remove_user_address_tag(local_address, tag)
	update_highlights(bv)

def buttons_xable(bv, **kwargs):
	controls = get_state(bv).debug_view.controls
	if controls is not None:
		controls.setActionsEnabled(**kwargs)

def buttons_set_default(bv, default):
	controls = get_state(bv).debug_view.controls
	if controls is not None:
		controls.setDefaultProcessAction(default)

def debug_status(bv, message):
	controls = get_state(bv).debug_view.controls
	if controls is not None:
		controls.editStatus.setText(message)

def state_inactive(bv, msg=None):
	debug_state = get_state(bv)

	# clear breakpoints
	del_breakpoint_tags(bv)
	debug_state.breakpoints = {}

	debug_state.state = 'INACTIVE'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, Starting=True, Stopping=False, Stepping=False, Break=False, Resume=False, Threads=False)
	buttons_set_default(bv, "Run")
	if debug_state.debug_view is not None:
		debug_state.debug_view.controls.setThreadList([])
		debug_state.debug_view.controls.setResumeBreak(False)

def state_stopped(bv, msg=None):
	debug_state = get_state(bv)
	debug_state.state = 'STOPPED'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, Starting=False, Stopping=True, Stepping=True, Break=True, Resume=True, Threads=True)
	buttons_set_default(bv, "Quit")
	if debug_state.debug_view is not None:
		debug_state.debug_view.controls.setResumeBreak(True)

def state_running(bv, msg=None):
	debug_state = get_state(bv)
	debug_state.state = 'RUNNING'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, Starting=False, Stopping=True, Stepping=False, Break=True, Resume=False, Threads=False)
	buttons_set_default(bv, "Quit")
	if debug_state.debug_view is not None:
		debug_state.debug_view.controls.setResumeBreak(False)

def state_busy(bv, msg=None):
	debug_state = get_state(bv)
	debug_state.state = 'RUNNING'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, Starting=False, Stopping=True, Stepping=False, Break=False, Resume=False, Threads=False)
	buttons_set_default(bv, "Quit")
	if debug_state.debug_view is not None:
		debug_state.debug_view.controls.setResumeBreak(False)

def state_error(bv, msg=None):
	debug_state = get_state(bv)
	debug_state.state = 'ERROR'
	debug_status(bv, msg or debug_state.state)
	buttons_xable(bv, Run=True, Restart=True, Quit=True, Attach=True, Detach=True, Break=True, Resume=True, StepInto=True, StepOver=True, StepReturn=True, Threads=True)
	buttons_set_default(bv, "Run")
	if debug_state.debug_view is not None:
		debug_state.debug_view.controls.setThreadList([])
		debug_state.debug_view.controls.setResumeBreak(True)	

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
	fpath = bv.file.original_filename

	if not os.path.exists(fpath):
		raise Exception('cannot find debug target: ' + fpath)

	#adapter = lldb.DebugAdapterLLDB()
	adapter = helpers.launch_get_adapter(fpath)

	debug_state = get_state(bv)
	debug_state.adapter = adapter
	debug_state.memory_view.update_base()

	if bv and bv.entry_point:
		local_entry = bv.entry_point
		remote_entry = debug_state.memory_view.local_addr_to_remote(local_entry)
		debug_breakpoint_set(bv, remote_entry)
		bv.navigate(bv.file.view, local_entry)

	state_stopped(bv)
	context_display(bv)
	memory_dirty(bv)

def debug_quit(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	if adapter:
		adapter.quit()
		debug_state.adapter = None
	state_inactive(bv)
	memory_dirty(bv)

def debug_restart(bv):
	debug_quit(bv)
	time.sleep(1)
	debug_run(bv) # sets state

def debug_detach(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter
	adapter.detach()
	debug_state.adapter = None
	state_inactive(bv)

def debug_break(bv):
	adapter = get_state(bv).adapter
	assert adapter
	adapter.break_into()

# non-blocking wrapper around adapter.go() (so user can nav around)
def debug_go(bv, gui_updates=True):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	def debug_go_thread(bv):
		if gui_updates:
			execute_on_main_thread_and_wait(lambda: state_busy(bv, 'RESUMING'))
		remote_rip = adapter.reg_read('rip')
		local_rip = debug_state.memory_view.remote_addr_to_local(remote_rip)
		bphere = local_rip in debug_state.breakpoints

		seq = []
		if bphere:
			seq.append((adapter.breakpoint_clear, (remote_rip,)))
			seq.append((adapter.go, ()))
			seq.append((adapter.breakpoint_set, (remote_rip,)))
		else:
			seq.append((adapter.go, ()))

		if gui_updates:
			execute_on_main_thread_and_wait(lambda: state_running(bv))
		(reason, data) = exec_adapter_sequence(adapter, seq)
		if gui_updates:
			execute_on_main_thread_and_wait(lambda: handle_stop_return(bv, reason, data))
			execute_on_main_thread_and_wait(lambda: memory_dirty(bv))

	threading.Thread(target=debug_go_thread, args=(bv,)).start()

def debug_step(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	def debug_step_thread():
		execute_on_main_thread_and_wait(lambda: state_busy(bv, "STEPPING"))
		(reason, data) = (None, None)

		if bv.arch.name == 'x86_64':
			remote_rip = adapter.reg_read('rip')
			local_rip = debug_state.memory_view.remote_addr_to_local(remote_rip)

			# if currently a breakpoint at rip, temporarily clear it
			# TODO: detect windbg adapter because dbgeng's step behavior might ignore breakpoint
			# at current rip

			seq = []
			if local_rip in debug_state.breakpoints:
				seq.append((adapter.breakpoint_clear, (remote_rip,)))
				seq.append((adapter.step_into, ()))
				seq.append((adapter.breakpoint_set, (remote_rip,)))
			else:
				seq.append((adapter.step_into, ()))

			(reason, data) = exec_adapter_sequence(adapter, seq)
		else:
			raise NotImplementedError('step unimplemented for architecture %s' % bv.arch.name)

		execute_on_main_thread_and_wait(lambda: handle_stop_return(bv, reason, data))
		execute_on_main_thread_and_wait(lambda: memory_dirty(bv))
	
	threading.Thread(target=debug_step_thread).start()

def debug_step_over(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	def debug_step_over_thread():
		execute_on_main_thread_and_wait(lambda: state_busy(bv, "STEPPING"))
		# TODO: detect windbg adapter because dbgeng has a builtin step_into() that we don't
		# have to synthesize
		if bv.arch.name == 'x86_64':
			remote_rip = adapter.reg_read('rip')
			local_rip = debug_state.memory_view.remote_addr_to_local(remote_rip)

			instxt = bv.get_disassembly(local_rip)
			inslen = bv.get_instruction_length(local_rip)
			local_ripnext = local_rip + inslen
			remote_ripnext = remote_rip + inslen

			call = instxt.startswith('call ')
			bphere = local_rip in debug_state.breakpoints
			bpnext = local_ripnext in debug_state.breakpoints

			seq = []

			if not call:
				if bphere:
					seq.append((adapter.breakpoint_clear, (remote_rip,)))
					seq.append((adapter.step_into, ()))
					seq.append((adapter.breakpoint_set, (remote_rip,)))
				else:
					seq.append((adapter.step_into, ()))
			elif bphere and bpnext:
				seq.append((adapter.breakpoint_clear, (remote_rip,)))
				seq.append((adapter.go, ()))
				seq.append((adapter.breakpoint_set, (remote_rip,)))
			elif bphere and not bpnext:
				seq.append((adapter.breakpoint_clear, (remote_rip,)))
				seq.append((adapter.breakpoint_set, (remote_ripnext,)))
				seq.append((adapter.go, ()))
				seq.append((adapter.breakpoint_clear, (remote_ripnext,)))
				seq.append((adapter.breakpoint_set, (remote_rip,)))
			elif not bphere and bpnext:
				seq.append((adapter.go, ()))
			elif not bphere and not bpnext:
				seq.append((adapter.breakpoint_set, (remote_ripnext,)))
				seq.append((adapter.go, ()))
				seq.append((adapter.breakpoint_clear, (remote_ripnext,)))
			else:
				raise Exception('confused by call, bphere, bpnext state')

			(reason, data) = exec_adapter_sequence(adapter, seq)
			execute_on_main_thread_and_wait(lambda: handle_stop_return(bv, reason, data))

		else:
			raise NotImplementedError('step over unimplemented for architecture %s' % bv.arch.name)

		state = 'stopped'
		execute_on_main_thread_and_wait(lambda: memory_dirty(bv))

	threading.Thread(target=debug_step_over_thread).start()

def debug_step_return(bv):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	def debug_step_return_thread():
		execute_on_main_thread_and_wait(lambda: state_busy(bv, "STEPPING"))
		if bv.arch.name == 'x86_64':
			remote_rip = adapter.reg_read('rip')
			local_rip = debug_state.memory_view.remote_addr_to_local(remote_rip)
			
			# TODO: If we don't have a function loaded, walk the stack
			funcs = bv.get_functions_containing(local_rip)
			if len(funcs) != 0:
				mlil = funcs[0].mlil
				
				bphere = local_rip in debug_state.breakpoints

				# Set a bp on every ret in the function and go
				old_bps = set()
				new_bps = set()
				for insn in mlil.instructions:
					if insn.operation == binaryninja.MediumLevelILOperation.MLIL_RET or insn.operation == binaryninja.MediumLevelILOperation.MLIL_TAILCALL:
						if insn.address in debug_state.breakpoints:
							rets.add(debug_state.memory_view.local_addr_to_remote(insn.address))
						else:
							new_bps.add(debug_state.memory_view.local_addr_to_remote(insn.address))

				seq = []
				if bphere and not local_rip in new_bps and not local_rip in old_bps:
					seq.append((adapter.breakpoint_clear, (remote_rip,)))
				for bp in new_bps:
					seq.append((adapter.breakpoint_set, (bp,)))
				seq.append((adapter.go, ()))
				for bp in new_bps:
					seq.append((adapter.breakpoint_clear, (bp,)))
				if bphere and not local_rip in new_bps and not local_rip in old_bps:
					seq.append((adapter.breakpoint_set, (remote_rip,)))

				(reason, data) = exec_adapter_sequence(adapter, seq)
				execute_on_main_thread_and_wait(lambda: handle_stop_return(bv, reason, data))
			else:
				print("Can't find current function")

		else:
			raise NotImplementedError('step over unimplemented for architecture %s' % bv.arch.name)

		state = 'stopped'
		execute_on_main_thread_and_wait(lambda: memory_dirty(bv))

	threading.Thread(target=debug_step_return_thread).start()


def debug_breakpoint_set(bv, remote_address):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	if adapter.breakpoint_set(remote_address) != 0:
		print('ERROR: breakpoint set failed')
		return None

	local_address = debug_state.memory_view.remote_addr_to_local(remote_address)

	# create tag
	tt = bv.tag_types["Crashes"]
	for func in bv.get_functions_containing(local_address):
		tags = [tag for tag in func.get_address_tags_at(local_address) if tag.data == 'breakpoint']
		if len(tags) == 0:
			tag = func.create_user_address_tag(local_address, tt, "breakpoint")

	# save it
	debug_state.breakpoints[local_address] = True
	print('breakpoint address=0x%X (remote=0x%X) set' % (local_address, remote_address))
	update_highlights(bv)

	bp_widget = widget.get_dockwidget(bv, "Breakpoints")
	if bp_widget is not None:
		bp_widget.notifyBreakpointChanged()

	return 0

def debug_breakpoint_clear(bv, remote_address):
	debug_state = get_state(bv)
	adapter = debug_state.adapter
	assert adapter

	local_address = debug_state.memory_view.remote_addr_to_local(remote_address)

	# find/remove address tag
	if local_address in debug_state.breakpoints:
		# delete from adapter
		if adapter.breakpoint_clear(remote_address) != None:
			print('breakpoint address=0x%X (remote=0x%X) cleared' % (local_address, remote_address))
		else:
			print('ERROR: clearing breakpoint')

		# delete breakpoint tags from all functions containing this address
		del_breakpoint_tags(bv, [local_address])

		# delete from our list
		del debug_state.breakpoints[local_address]
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

def cb_bp_set(bv, local_address):
	debug_state = get_state(bv)
	remote_address = debug_state.memory_view.local_addr_to_remote(local_address)
	debug_breakpoint_set(bv, remote_address)

def cb_bp_clr(bv, local_address):
	debug_state = get_state(bv)
	remote_address = debug_state.memory_view.local_addr_to_remote(local_address)
	debug_breakpoint_clear(bv, remote_address)

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
