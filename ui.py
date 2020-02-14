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

	def widget(self, name):
		return widget.get_dockwidget(self.state.bv, name)

	def context_display(self):
		registers_widget = self.widget('Registers')
		modules_widget = self.widget('Modules')
		threads_widget = self.widget('Threads')
		stack_widget = self.widget('Stack')

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
		self.memory_dirty()

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
		modules_widget = self.widget('Modules')
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

		bp_widget = self.widget("Breakpoints")
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

def require_adapter(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.adapter is not None

#------------------------------------------------------------------------------
# Plugin actions for the various debugger controls
#------------------------------------------------------------------------------

def cb_process_run(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionRun.trigger()

def cb_process_restart(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionRestart.trigger()

def cb_process_quit(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionQuit.trigger()

def cb_process_attach(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionAttach.trigger()

def cb_process_detach(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionDetach.trigger()

def cb_process_settings(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionSettings.trigger()

def cb_control_pause(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionPause.trigger()

def cb_control_resume(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionResume.trigger()

def cb_control_step_into(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionStepInto.trigger()

def cb_control_step_over(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionStepOver.trigger()

def cb_control_step_return(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionStepReturn.trigger()

# -----------------------------------------------------------------------------

def valid_process_run(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionRun.isEnabled()

def valid_process_restart(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionRestart.isEnabled()

def valid_process_quit(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionQuit.isEnabled()

def valid_process_attach(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionAttach.isEnabled()

def valid_process_detach(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionDetach.isEnabled()

def valid_process_settings(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionSettings.isEnabled()

def valid_control_pause(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionPause.isEnabled()

def valid_control_resume(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionResume.isEnabled()

def valid_control_step_into(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionStepInto.isEnabled()

def valid_control_step_over(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionStepOver.isEnabled()

def valid_control_step_return(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionStepReturn.isEnabled()

#------------------------------------------------------------------------------
# Load plugin commands and actions
#------------------------------------------------------------------------------

def initialize_ui():
	widget.register_dockwidget(BreakpointsWidget.DebugBreakpointsWidget, "Breakpoints", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(RegistersWidget.DebugRegistersWidget, "Registers", Qt.RightDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ThreadsWidget.DebugThreadsWidget, "Threads", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(StackWidget.DebugStackWidget, "Stack", Qt.LeftDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ModulesWidget.DebugModulesWidget, "Modules", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	# TODO: Needs adapter support
	# widget.register_dockwidget(ConsoleWidget.DebugConsoleWidget, "Debugger Console", Qt.BottomDockWidgetArea, Qt.Horizontal, False)

	PluginCommand.register("Debugger\\Set Breakpoint", "sets breakpoint at right-clicked address", cb_bp_set, is_valid=require_adapter)
	PluginCommand.register("Debugger\\Clear Breakpoint", "clears breakpoint at right-clicked address", cb_bp_clr, is_valid=require_adapter)

	PluginCommand.register("Debugger\\Process\\Run", "Start new debugging session", cb_process_run, is_valid=valid_process_run)
	PluginCommand.register("Debugger\\Process\\Restart", "Restart debugging session", cb_process_restart, is_valid=valid_process_restart)
	PluginCommand.register("Debugger\\Process\\Quit", "Terminate debugged process and end session", cb_process_quit, is_valid=valid_process_quit)
	# PluginCommand.register("Debugger\\Process\\Attach", "Attach to running process", cb_process_attach, is_valid=valid_process_attach)
	PluginCommand.register("Debugger\\Process\\Detach", "Detach from current debugged process", cb_process_detach, is_valid=valid_process_detach)
	PluginCommand.register("Debugger\\Process\\Settings", "Open adapter settings menu", cb_process_settings, is_valid=valid_process_settings)
	PluginCommand.register("Debugger\\Control\\Pause", "Pause execution", cb_control_pause, is_valid=valid_control_pause)
	PluginCommand.register("Debugger\\Control\\Resume", "Resume execution", cb_control_resume, is_valid=valid_control_resume)
	PluginCommand.register("Debugger\\Control\\Step Into", "Step into assembly", cb_control_step_into, is_valid=valid_control_step_into)
	PluginCommand.register("Debugger\\Control\\Step Over", "Step over function call", cb_control_step_over, is_valid=valid_control_step_over)
	PluginCommand.register("Debugger\\Control\\Step Return", "Step until current function returns", cb_control_step_return, is_valid=valid_control_step_return)

	ViewType.registerViewType(DebugView.DebugViewType())
