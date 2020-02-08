import os
import re
import time

import binaryninja
from binaryninja import Symbol, SymbolType, Type, Structure, StructureType
from binaryninja.plugin import PluginCommand
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, ViewType
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit

from . import DebugAdapter, ProcessView
from .dockwidgets import BreakpointsWidget, RegistersWidget, StackWidget, ThreadsWidget, MemoryWidget, ControlsWidget, DebugView, ConsoleWidget, ModulesWidget, widget

#------------------------------------------------------------------------------
# globals
#------------------------------------------------------------------------------

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

#------------------------------------------------------------------------------
# DEBUGGER STATE / CONTROLLER
#
# Controller of the debugger for a single BinaryView
#------------------------------------------------------------------------------

class DebuggerState:
	states = []

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

	#--------------------------------------------------------------------------
	# SUPPORT FUNCTIONS (HIGHER LEVEL)
	#--------------------------------------------------------------------------

	def context_display(self):
		#----------------------------------------------------------------------
		# Update Registers
		#----------------------------------------------------------------------
		registers_widget = widget.get_dockwidget(self.bv, 'Registers')
		regs = []
		for register in self.adapter.reg_list():
			value = self.adapter.reg_read(register)
			bits = self.adapter.reg_bits(register)
			regs.append({
				'name': register,
				'bits': bits,
				'value': value
			})
		registers_widget.notifyRegistersChanged(regs)

		#----------------------------------------------------------------------
		# Update Modules
		#----------------------------------------------------------------------
		modules_widget = widget.get_dockwidget(self.bv, 'Modules')
		mods = []
		for (modpath, address) in self.adapter.mem_modules().items():
			mods.append({
				'address': address,
				'modpath': modpath
				# TODO: Length, segments, etc
			})
		mods.sort(key=lambda row: row['address'])
		modules_widget.notifyModulesChanged(mods)

		#----------------------------------------------------------------------
		# Update Threads
		#----------------------------------------------------------------------
		threads_widget = widget.get_dockwidget(self.bv, 'Threads')

		if self.bv.arch.name == 'x86_64':
			reg_ip_name = 'rip'
		else:
			raise NotImplementedError('only x86_64 so far')

		threads = []
		tid_selected = self.adapter.thread_selected()
		last_thread = tid_selected
		for tid in self.adapter.thread_list():
			if last_thread != tid:
				self.adapter.thread_select(tid)
				last_thread = tid
			reg_ip_val = self.adapter.reg_read(reg_ip_name)
			threads.append({
				'tid': tid,
				reg_ip_name: reg_ip_val,
				'selected': (tid == tid_selected)
			})
		if last_thread != tid_selected:
			self.adapter.thread_select(tid_selected)
		threads_widget.notifyThreadsChanged(threads)
		self.debug_view.controls.set_thread_list(threads)

		#----------------------------------------------------------------------
		# Update Stack
		#----------------------------------------------------------------------
		stack_widget = widget.get_dockwidget(self.bv, 'Stack')

		if self.bv.arch.name == 'x86_64':
			stack_pointer = self.adapter.reg_read('rsp')
			# Read up and down from rsp
			stack_range = [-8, 60] # Inclusive
			stack = []
			for i in range(stack_range[0], stack_range[1] + 1):
				offset = i * self.bv.arch.address_size
				address = stack_pointer + offset
				value = self.memory_view.read(address, self.bv.arch.address_size)
				value_int = value
				if self.bv.arch.endianness == binaryninja.Endianness.LittleEndian:
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

		#----------------------------------------------------------------------
		# Update Memory
		#----------------------------------------------------------------------
		self.update_memory_view()

		#----------------------------------------------------------------------
		# Update Status
		#----------------------------------------------------------------------

		if self.bv.arch.name == 'x86_64':
			remote_rip = self.adapter.reg_read('rip')
			local_rip = self.memory_view.remote_addr_to_local(remote_rip)
		else:
			raise NotImplementedError('only x86_64 so far')

		# Clear old highlighted rip
		for func in self.bv.get_functions_containing(self.last_rip):
			func.set_auto_instr_highlight(self.last_rip, binaryninja.HighlightStandardColor.NoHighlightColor)
		self.update_highlights()
		self.last_rip = local_rip

		# select instruction currently at
		if self.bv.read(local_rip, 1):
			print('navigating to: 0x%X' % local_rip)
			statusText = 'STOPPED'

			self.bv.navigate(self.bv.file.view, local_rip)
		else:
			statusText = 'STOPPED (outside view)'
			print('address 0x%X outside of binary view, not setting cursor' % remote_rip)

		self.debug_view.controls.state_stopped(statusText)

	# Mark memory as dirty, will refresh memory view
	def memory_dirty(self):
		self.memory_view.mark_dirty()
		if self.debug_view is not None:
			self.debug_view.notifyMemoryChanged()

	# Create symbols and variables for the memory view
	def update_memory_view(self):
		assert self.adapter is not None
		assert self.memory_view is not None

		addr_regs = {}
		reg_addrs = {}

		for reg in self.adapter.reg_list():
			addr = self.adapter.reg_read(reg)
			reg_symbol_name = '$' + reg

			if addr not in addr_regs.keys():
				addr_regs[addr] = [reg_symbol_name]
			else:
				addr_regs[addr].append(reg_symbol_name)
			reg_addrs[reg] = addr

		for symbol in self.old_symbols:
			# Symbols are immutable so just destroy the old one
			self.memory_view.undefine_auto_symbol(symbol)

		for dv in self.old_dvs:
			self.memory_view.undefine_data_var(dv)

		self.old_symbols = []
		self.old_dvs = set()
		new_dvs = set()

		for (addr, regs) in addr_regs.items():
			symbol_name = "@".join(regs)
			fancy_name = ",".join(regs)

			self.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, addr, fancy_name, raw_name=symbol_name))
			self.old_symbols.append(self.memory_view.get_symbol_by_raw_name(symbol_name))
			new_dvs.add(addr)

		for new_dv in new_dvs:
			self.memory_view.define_data_var(new_dv, Type.int(8))
			self.old_dvs.add(new_dv)

		# Special struct for stack frame
		if self.bv.arch.name == 'x86_64':
			width = reg_addrs['rbp'] - reg_addrs['rsp']
			if width > 0:
				if width > 0x1000:
					width = 0x1000
				struct = Structure()
				struct.type = StructureType.StructStructureType
				struct.width = width
				for i in range(0, width, self.bv.arch.address_size):
					struct.insert(i, Type.pointer(self.bv.arch, Type.void()))
				self.memory_view.define_data_var(reg_addrs['rsp'], Type.structure_type(struct))
				self.memory_view.define_auto_symbol(Symbol(SymbolType.ExternalSymbol, reg_addrs['rsp'], "$stack_frame", raw_name="$stack_frame"))

				self.old_symbols.append(self.memory_view.get_symbol_by_raw_name("$stack_frame"))
				self.old_dvs.add(reg_addrs['rsp'])

	# Highlight lines
	def update_highlights(self):
		for bp in self.breakpoints:
			for func in self.bv.get_functions_containing(bp):
				func.set_auto_instr_highlight(bp, binaryninja.HighlightStandardColor.RedHighlightColor)

		if self.adapter is not None:
			if self.bv.arch.name == 'x86_64':
				remote_rip = self.adapter.reg_read('rip')
				local_rip = self.memory_view.remote_addr_to_local(remote_rip)
			else:
				raise NotImplementedError('only x86_64 so far')

			for func in self.bv.get_functions_containing(local_rip):
				func.set_auto_instr_highlight(local_rip, binaryninja.HighlightStandardColor.BlueHighlightColor)

	def update_breakpoints(self):
		bps = []
		if self.adapter is not None:
			for remote_bp in self.adapter.breakpoint_list():
				local_bp = self.memory_view.remote_addr_to_local(remote_bp)
				if local_bp in self.breakpoints.keys():
					bps.append({
						'enabled': self.breakpoints[local_bp],
						'address': local_bp
					})

		bp_widget = widget.get_dockwidget(self.bv, "Breakpoints")
		bp_widget.notifyBreakpointsChanged(bps)

	def breakpoint_tag_add(self, local_address):
		# create tag
		tt = self.bv.tag_types["Crashes"]
		for func in self.bv.get_functions_containing(local_address):
			tags = [tag for tag in func.get_address_tags_at(local_address) if tag.data == 'breakpoint']
			if len(tags) == 0:
				tag = func.create_user_address_tag(local_address, tt, "breakpoint")

	# breakpoint TAG removal - strictly presentation
	# (doesn't remove actual breakpoints, just removes the binja tags that mark them)
	#
	def breakpoint_tag_del(self, local_addresses=None):
		if local_addresses == None:
			local_addresses = [self.memory_view.local_addr_to_remote(addr) for addr in self.breakpoints]

		for local_address in local_addresses:
			# delete breakpoint tags from all functions containing this address
			for func in self.bv.get_functions_containing(local_address):
				func.set_auto_instr_highlight(local_address, binaryninja.HighlightStandardColor.NoHighlightColor)
				delqueue = [tag for tag in func.get_address_tags_at(local_address) if tag.data == 'breakpoint']
				for tag in delqueue:
					func.remove_user_address_tag(local_address, tag)

	#--------------------------------------------------------------------------
	# DEBUGGER FUNCTIONS (MEDIUM LEVEL, BLOCKING)
	#--------------------------------------------------------------------------

	def run(self):
		fpath = self.bv.file.original_filename

		if not os.path.exists(fpath):
			raise Exception('cannot find debug target: ' + fpath)

		self.adapter = DebugAdapter.get_adapter_for_current_system()
		self.adapter.exec(fpath)

		self.memory_view.update_base()

		if self.bv and self.bv.entry_point:
			local_entry = self.bv.entry_point
			remote_entry = self.memory_view.local_addr_to_remote(local_entry)
			self.breakpoint_set(remote_entry)
		self.memory_dirty()

	def quit(self):
		if self.adapter is not None:
			try:
				self.adapter.quit()
			except BrokenPipeError:
				pass
			except ConnectionResetError:
				pass
			except OSError:
				pass
			finally:
				self.adapter = None
		self.memory_dirty()

	def restart(self):
		self.quit()
		time.sleep(1)
		self.run() # sets state

	def detach(self):
		if self.adapter is not None:
			try:
				self.adapter.detach()
			except BrokenPipeError:
				pass
			except ConnectionResetError:
				pass
			except OSError:
				pass
			finally:
				self.adapter = None
		self.memory_dirty()

	def pause(self):
		assert self.adapter
		result = self.adapter.break_into()
		self.memory_dirty()
		return result

	def go(self):
		assert self.adapter

		remote_rip = self.adapter.reg_read('rip')
		local_rip = self.memory_view.remote_addr_to_local(remote_rip)
		bphere = local_rip in self.breakpoints

		seq = []
		if bphere:
			seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
			seq.append((self.adapter.go, ()))
			seq.append((self.adapter.breakpoint_set, (remote_rip,)))
		else:
			seq.append((self.adapter.go, ()))

		result = self.exec_adapter_sequence(seq)
		self.memory_dirty()
		return result

	def step_into(self):
		assert self.adapter

		(reason, data) = (None, None)

		if self.bv.arch.name == 'x86_64':
			remote_rip = self.adapter.reg_read('rip')
			local_rip = self.memory_view.remote_addr_to_local(remote_rip)

			# if currently a breakpoint at rip, temporarily clear it
			# TODO: detect windbg adapter because dbgeng's step behavior might ignore breakpoint
			# at current rip

			seq = []
			if local_rip in self.breakpoints:
				seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
				seq.append((self.adapter.step_into, ()))
				seq.append((self.adapter.breakpoint_set, (remote_rip,)))
			else:
				seq.append((self.adapter.step_into, ()))
			# TODO: Cancel (and raise some exception)
			result = self.exec_adapter_sequence(seq)
			self.memory_dirty()
			return result
		else:
			raise NotImplementedError('step unimplemented for architecture %s' % self.bv.arch.name)

	def step_over(self):
		assert self.adapter

		try:
			self.adapter.step_over()
			return
		except NotImplementedError:
			pass

		if self.bv.arch.name == 'x86_64':
			remote_rip = self.adapter.reg_read('rip')
			local_rip = self.memory_view.remote_addr_to_local(remote_rip)

			if self.bv.read(local_rip, 1):
				instxt = self.bv.get_disassembly(local_rip)
				inslen = self.bv.get_instruction_length(local_rip)
			else:
				data = self.adapter.mem_read(remote_rip, 16)
				(tokens, length) = self.bv.arch.get_instruction_text(data, local_rip)
				instxt = ''.join([x.text for x in tokens])
				inslen = length

			local_ripnext = local_rip + inslen
			remote_ripnext = remote_rip + inslen

			call = instxt.startswith('call ')
			bphere = local_rip in self.breakpoints
			bpnext = local_ripnext in self.breakpoints

			seq = []

			if not call:
				if bphere:
					seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
					seq.append((self.adapter.step_into, ()))
					seq.append((self.adapter.breakpoint_set, (remote_rip,)))
				else:
					seq.append((self.adapter.step_into, ()))
			elif bphere and bpnext:
				seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
				seq.append((self.adapter.go, ()))
				seq.append((self.adapter.breakpoint_set, (remote_rip,)))
			elif bphere and not bpnext:
				seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
				seq.append((self.adapter.breakpoint_set, (remote_ripnext,)))
				seq.append((self.adapter.go, ()))
				seq.append((self.adapter.breakpoint_clear, (remote_ripnext,)))
				seq.append((self.adapter.breakpoint_set, (remote_rip,)))
			elif not bphere and bpnext:
				seq.append((self.adapter.go, ()))
			elif not bphere and not bpnext:
				seq.append((self.adapter.breakpoint_set, (remote_ripnext,)))
				seq.append((self.adapter.go, ()))
				seq.append((self.adapter.breakpoint_clear, (remote_ripnext,)))
			else:
				raise Exception('confused by call, bphere, bpnext state')
			# TODO: Cancel (and raise some exception)
			result = self.exec_adapter_sequence(seq)
			self.memory_dirty()
			return result

		else:
			raise NotImplementedError('step over unimplemented for architecture %s' % self.bv.arch.name)

	def step_return(self):
		assert self.adapter

		if self.bv.arch.name == 'x86_64':
			remote_rip = self.adapter.reg_read('rip')
			local_rip = self.memory_view.remote_addr_to_local(remote_rip)

			# TODO: If we don't have a function loaded, walk the stack
			funcs = self.bv.get_functions_containing(local_rip)
			if len(funcs) != 0:
				mlil = funcs[0].mlil

				bphere = local_rip in self.breakpoints

				# Set a bp on every ret in the function and go
				old_bps = set()
				new_bps = set()
				for insn in mlil.instructions:
					if insn.operation == binaryninja.MediumLevelILOperation.MLIL_RET or insn.operation == binaryninja.MediumLevelILOperation.MLIL_TAILCALL:
						if insn.address in self.breakpoints:
							rets.add(self.memory_view.local_addr_to_remote(insn.address))
						else:
							new_bps.add(self.memory_view.local_addr_to_remote(insn.address))

				seq = []
				if bphere and not local_rip in new_bps and not local_rip in old_bps:
					seq.append((self.adapter.breakpoint_clear, (remote_rip,)))
				for bp in new_bps:
					seq.append((self.adapter.breakpoint_set, (bp,)))
				seq.append((self.adapter.go, ()))
				for bp in new_bps:
					seq.append((self.adapter.breakpoint_clear, (bp,)))
				if bphere and not local_rip in new_bps and not local_rip in old_bps:
					seq.append((self.adapter.breakpoint_set, (remote_rip,)))
				# TODO: Cancel (and raise some exception)
				result = self.exec_adapter_sequence(seq)
				self.memory_dirty()
				return result
			else:
				print("Can't find current function")
				return (None, None)

		else:
			raise NotImplementedError('step over unimplemented for architecture %s' % self.bv.arch.name)

	def breakpoint_set(self, remote_address):
		assert self.adapter

		if self.adapter.breakpoint_set(remote_address) != 0:
			print('ERROR: breakpoint set failed')
			return False

		local_address = self.memory_view.remote_addr_to_local(remote_address)

		# save it
		self.breakpoints[local_address] = True
		print('breakpoint address=0x%X (remote=0x%X) set' % (local_address, remote_address))
		self.update_highlights()
		self.update_breakpoints()

		self.breakpoint_tag_add(local_address)

		return True

	def breakpoint_clear(self, remote_address):
		assert self.adapter

		local_address = self.memory_view.remote_addr_to_local(remote_address)

		# find/remove address tag
		if local_address in self.breakpoints:
			# delete from adapter
			if self.adapter.breakpoint_clear(remote_address) != None:
				print('breakpoint address=0x%X (remote=0x%X) cleared' % (local_address, remote_address))
			else:
				print('ERROR: clearing breakpoint')

			# delete breakpoint tags from all functions containing this address
			self.breakpoint_tag_del([local_address])

			# delete from our list
			del self.breakpoints[local_address]

			self.update_highlights()
			self.update_breakpoints()
		else:
			print('ERROR: breakpoint not found in list')

	# execute a sequence of adapter commands, capturing the return of the last
	# blocking call
	def exec_adapter_sequence(self, seq):
		(reason, data) = (None, None)

		for (func, args) in seq:
			if func in [self.adapter.step_into, self.adapter.step_over, self.adapter.go]:
				(reason, data) = func(*args)
				if reason == DebugAdapter.STOP_REASON.PROCESS_EXITED or reason == DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED:
					# Process is dead, stop sequence
					break
			else:
				func(*args)

		return (reason, data)

#------------------------------------------------------------------------------
# right click plugin
#------------------------------------------------------------------------------

def cb_bp_set(bv, local_address):
	debug_state = get_state(bv)
	remote_address = debug_state.memory_view.local_addr_to_remote(local_address)
	debug_state.breakpoint_set(remote_address)

def cb_bp_clr(bv, local_address):
	debug_state = get_state(bv)
	remote_address = debug_state.memory_view.local_addr_to_remote(local_address)
	debug_state.breakpoint_clear(remote_address)

#------------------------------------------------------------------------------
# "main"
#------------------------------------------------------------------------------

def initialize():
	widget.register_dockwidget(BreakpointsWidget.DebugBreakpointsWidget, "Breakpoints", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(RegistersWidget.DebugRegistersWidget, "Registers", Qt.RightDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ThreadsWidget.DebugThreadsWidget, "Threads", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(StackWidget.DebugStackWidget, "Stack", Qt.LeftDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ModulesWidget.DebugModulesWidget, "Modules", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	# TODO: Needs adapter support
	# widget.register_dockwidget(ConsoleWidget.DebugConsoleWidget, "Debugger Console", Qt.BottomDockWidgetArea, Qt.Horizontal, False)

	PluginCommand.register_for_address("Set Breakpoint", "sets breakpoint at right-clicked address", cb_bp_set)
	PluginCommand.register_for_address("Clear Breakpoint", "clears breakpoint at right-clicked address", cb_bp_clr)
	ViewType.registerViewType(DebugView.DebugViewType())
