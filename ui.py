from binaryninja.plugin import PluginCommand
from binaryninja import Endianness, HighlightStandardColor, LinearDisassemblyLine, LinearDisassemblyLineType, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenType
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, ViewType
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit
from .dockwidgets import BreakpointsWidget, RegistersWidget, StackWidget, ThreadsWidget, MemoryWidget, ControlsWidget, DebugView, ConsoleWidget, ModulesWidget, widget
from . import binjaplug

class DebuggerUI:
	def __init__(self, state):
		self.state = state
		self.debug_view = None

	def context_display(self):
		registers_widget = widget.get_dockwidget(self.state.bv, 'Registers')
		modules_widget = widget.get_dockwidget(self.state.bv, 'Modules')
		threads_widget = widget.get_dockwidget(self.state.bv, 'Threads')
		stack_widget = widget.get_dockwidget(self.state.bv, 'Stack')

		if self.state.adapter is None:
			# Disconnected
			registers_widget.notifyRegistersChanged([])
			modules_widget.notifyModulesChanged([])
			threads_widget.notifyThreadsChanged([])
			self.debug_view.controls.set_thread_list([])
			stack_widget.notifyStackChanged([])
			self.memory_dirty()
			return

		#----------------------------------------------------------------------
		# Update Registers
		#----------------------------------------------------------------------
		regs = []
		for register in self.state.adapter.reg_list():
			value = self.state.adapter.reg_read(register)
			bits = self.state.adapter.reg_bits(register)
			regs.append({
				'name': register,
				'bits': bits,
				'value': value
			})
		registers_widget.notifyRegistersChanged(regs)

		#----------------------------------------------------------------------
		# Update Modules
		#----------------------------------------------------------------------

		# Updating this widget is slow, so just show "Data is Stale" and the user
		# can refresh later if they desire
		modules_widget.mark_dirty()

		#----------------------------------------------------------------------
		# Update Threads
		#----------------------------------------------------------------------

		if self.state.bv.arch.name == 'x86_64':
			reg_ip_name = 'rip'
		else:
			raise NotImplementedError('only x86_64 so far')

		threads = []
		tid_selected = self.state.adapter.thread_selected()
		last_thread = tid_selected
		for tid in self.state.adapter.thread_list():
			if last_thread != tid:
				self.state.adapter.thread_select(tid)
				last_thread = tid
			reg_ip_val = self.state.adapter.reg_read(reg_ip_name)
			threads.append({
				'tid': tid,
				reg_ip_name: reg_ip_val,
				'selected': (tid == tid_selected)
			})
		if last_thread != tid_selected:
			self.state.adapter.thread_select(tid_selected)
		threads_widget.notifyThreadsChanged(threads)
		self.debug_view.controls.set_thread_list(threads)

		#----------------------------------------------------------------------
		# Update Stack
		#----------------------------------------------------------------------

		if self.state.bv.arch.name == 'x86_64':
			stack_pointer = self.state.adapter.reg_read('rsp')
			# Read up and down from rsp
			stack_range = [-8, 60] # Inclusive
			stack = []
			for i in range(stack_range[0], stack_range[1] + 1):
				offset = i * self.state.bv.arch.address_size
				address = stack_pointer + offset
				value = self.state.memory_view.read(address, self.state.bv.arch.address_size)
				value_int = value
				if self.state.bv.arch.endianness == Endianness.LittleEndian:
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
		self.state.update_memory_view()

		#----------------------------------------------------------------------
		# Update Status
		#----------------------------------------------------------------------

		if self.state.bv.arch.name == 'x86_64':
			remote_rip = self.state.adapter.reg_read('rip')
			local_rip = self.state.memory_view.remote_addr_to_local(remote_rip)
		else:
			raise NotImplementedError('only x86_64 so far')

		self.state.update_highlights()
		self.state.last_rip = local_rip

		# select instruction currently at
		if self.state.bv.read(local_rip, 1):
			self.debug_view.setRawDisassembly(False)
			self.state.bv.navigate(self.state.bv.file.view, local_rip)
			self.debug_view.controls.state_stopped()
		else:
			self.update_raw_disassembly()
			self.debug_view.controls.state_stopped_extern()

	def update_modules(self):
		mods = []
		for (modpath, address) in self.state.adapter.mem_modules().items():
			mods.append({
				'address': address,
				'modpath': modpath
				# TODO: Length, segments, etc
			})
		mods.sort(key=lambda row: row['address'])
		modules_widget = widget.get_dockwidget(self.state.bv, 'Modules')
		modules_widget.notifyModulesChanged(mods)

	def update_raw_disassembly(self):
		# Read a few instructions from rip and disassemble them
		inst_count = 50
		if self.state.bv.arch.name == 'x86_64':
			rip = self.state.adapter.reg_read('rip')
			# Assume the worst, just in case
			read_length = self.state.bv.arch.max_instr_length * inst_count
			data = self.state.memory_view.read(rip, read_length)

			lines = []

			# Append header line
			tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, "(Code not backed by loaded file, showing only raw disassembly)")]
			contents = DisassemblyTextLine(tokens, rip)
			line = LinearDisassemblyLine(LinearDisassemblyLineType.BasicLineType, None, None, 0, contents)
			lines.append(line)

			total_read = 0
			for i in range(inst_count):
				line_addr = rip + total_read
				(insn_tokens, length) = self.state.bv.arch.get_instruction_text(data[total_read:], line_addr)

				tokens = []
				color = HighlightStandardColor.NoHighlightColor
				if i == 0:
					if (rip + total_read) in self.state.breakpoints:
						# Breakpoint & pc
						tokens.append(InstructionTextToken(InstructionTextTokenType.TagToken, self.state.bv.tag_types["Crashes"].icon + ">", width=5))
						color = HighlightStandardColor.RedHighlightColor
					else:
						# PC
						tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, " ==> "))
						color = HighlightStandardColor.BlueHighlightColor
				else:
					if (rip + total_read) in self.state.breakpoints:
						# Breakpoint
						tokens.append(InstructionTextToken(InstructionTextTokenType.TagToken, self.state.bv.tag_types["Crashes"].icon, width=5))
						color = HighlightStandardColor.RedHighlightColor
					else:
						# Regular line
						tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "     "))
				# Address
				tokens.append(InstructionTextToken(InstructionTextTokenType.AddressDisplayToken, hex(line_addr)[2:], line_addr))
				tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "  "))
				tokens.extend(insn_tokens)

				# Convert to linear disassembly line
				contents = DisassemblyTextLine(tokens, line_addr, color=color)
				line = LinearDisassemblyLine(LinearDisassemblyLineType.CodeDisassemblyLineType, None, None, 0, contents)
				lines.append(line)

				total_read += length

			self.debug_view.setRawDisassembly(True, lines)

		else:
			raise NotImplementedError('only x86_64 so far')

	# Mark memory as dirty, will refresh memory view
	def memory_dirty(self):
		self.state.memory_dirty()
		if self.debug_view is not None:
			self.debug_view.notifyMemoryChanged()

	def update_breakpoints(self):
		bps = []
		if self.state.adapter is not None:
			for remote_bp in self.state.adapter.breakpoint_list():
				local_bp = self.state.memory_view.remote_addr_to_local(remote_bp)
				if local_bp in self.state.breakpoints.keys():
					bps.append({
						'enabled': self.state.breakpoints[local_bp],
						'address': local_bp
					})

		bp_widget = widget.get_dockwidget(self.state.bv, "Breakpoints")
		bp_widget.notifyBreakpointsChanged(bps)

#------------------------------------------------------------------------------
# right click plugin
#------------------------------------------------------------------------------

def cb_bp_set(bv, local_address):
	debug_state = binjaplug.get_state(bv)
	remote_address = debug_state.memory_view.local_addr_to_remote(local_address)
	debug_state.breakpoint_set(remote_address)
	debug_state.ui.context_display()

def cb_bp_clr(bv, local_address):
	debug_state = binjaplug.get_state(bv)
	remote_address = debug_state.memory_view.local_addr_to_remote(local_address)
	debug_state.breakpoint_clear(remote_address)
	debug_state.ui.context_display()

def require_adapter(bv, local_address):
	debug_state = binjaplug.get_state(bv)
	return debug_state.adapter is not None

#------------------------------------------------------------------------------
# "main"
#------------------------------------------------------------------------------

def initialize_ui():
	widget.register_dockwidget(BreakpointsWidget.DebugBreakpointsWidget, "Breakpoints", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(RegistersWidget.DebugRegistersWidget, "Registers", Qt.RightDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ThreadsWidget.DebugThreadsWidget, "Threads", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(StackWidget.DebugStackWidget, "Stack", Qt.LeftDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ModulesWidget.DebugModulesWidget, "Modules", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	# TODO: Needs adapter support
	# widget.register_dockwidget(ConsoleWidget.DebugConsoleWidget, "Debugger Console", Qt.BottomDockWidgetArea, Qt.Horizontal, False)

	PluginCommand.register_for_address("Set Breakpoint", "sets breakpoint at right-clicked address", cb_bp_set, is_valid=require_adapter)
	PluginCommand.register_for_address("Clear Breakpoint", "clears breakpoint at right-clicked address", cb_bp_clr, is_valid=require_adapter)

	ViewType.registerViewType(DebugView.DebugViewType())
