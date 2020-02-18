from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit
from binaryninja.plugin import PluginCommand
from binaryninja import Endianness, HighlightStandardColor, LinearDisassemblyLine, LinearDisassemblyLineType, DisassemblyTextLine, InstructionTextToken, InstructionTextTokenType, execute_on_main_thread_and_wait
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, ViewType
from .dockwidgets import BreakpointsWidget, RegistersWidget, StackWidget, ThreadsWidget, MemoryWidget, ControlsWidget, DebugView, ConsoleWidget, ModulesWidget, widget
from . import binjaplug

class DebuggerUI:
	def __init__(self, state):
		self.state = state
		self.debug_view = None
		self.last_ip = 0

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

		threads = []
		tid_selected = self.state.adapter.thread_selected()
		last_thread = tid_selected
		for tid in self.state.adapter.thread_list():
			if last_thread != tid:
				self.state.adapter.thread_select(tid)
				last_thread = tid
			reg_ip_val = self.state.ip
			threads.append({
				'tid': tid,
				'ip': reg_ip_val,
				'selected': (tid == tid_selected)
			})
		if last_thread != tid_selected:
			self.state.adapter.thread_select(tid_selected)
		threads_widget.notifyThreadsChanged(threads)
		self.debug_view.controls.set_thread_list(threads)

		#----------------------------------------------------------------------
		# Update Stack
		#----------------------------------------------------------------------

		stack_pointer = self.state.stack_pointer
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

		#----------------------------------------------------------------------
		# Update Memory
		#----------------------------------------------------------------------
		self.state.update_memory_view()
		self.memory_dirty()

		#----------------------------------------------------------------------
		# Update Status
		#----------------------------------------------------------------------

		remote_rip = self.state.ip
		local_rip = self.state.memory_view.remote_addr_to_local(remote_rip)

		self.update_highlights()
		self.last_ip = local_rip

		# select instruction currently at
		if self.state.bv.read(local_rip, 1) and len(self.state.bv.get_functions_containing(local_rip)) > 0:
			self.debug_view.setRawDisassembly(False)
			self.state.bv.navigate(self.state.bv.file.view, local_rip)
			self.debug_view.controls.state_stopped()
		else:
			self.update_raw_disassembly()
			self.debug_view.controls.state_stopped_extern()

	# Highlight lines
	def update_highlights(self):
		# Clear old highlighted rip
		for func in self.state.bv.get_functions_containing(self.last_ip):
			func.set_auto_instr_highlight(self.last_ip, HighlightStandardColor.NoHighlightColor)

		for bp in self.state.breakpoints:
			for func in self.state.bv.get_functions_containing(bp):
				func.set_auto_instr_highlight(bp, HighlightStandardColor.RedHighlightColor)

		if self.state.adapter is not None:
			remote_rip = self.state.ip
			local_rip = self.state.memory_view.remote_addr_to_local(remote_rip)

			for func in self.state.bv.get_functions_containing(local_rip):
				func.set_auto_instr_highlight(local_rip, HighlightStandardColor.BlueHighlightColor)

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

		rip = self.state.ip
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

			if insn_tokens is None:
				insn_tokens = [InstructionTextToken(InstructionTextTokenType.TextToken, "??")]
				length = self.state.bv.arch.instr_alignment
				if length == 0:
					length = 1

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

	def breakpoint_tag_add(self, local_address):
		# create tag
		tt = self.state.bv.tag_types["Crashes"]
		for func in self.state.bv.get_functions_containing(local_address):
			tags = [tag for tag in func.get_address_tags_at(local_address) if tag.data == 'breakpoint']
			if len(tags) == 0:
				tag = func.create_user_address_tag(local_address, tt, "breakpoint")

	# breakpoint TAG removal - strictly presentation
	# (doesn't remove actual breakpoints, just removes the binja tags that mark them)
	#
	def breakpoint_tag_del(self, local_addresses=None):
		if local_addresses == None:
			local_addresses = [self.state.memory_view.local_addr_to_remote(addr) for addr in self.state.breakpoints]

		for local_address in local_addresses:
			# delete breakpoint tags from all functions containing this address
			for func in self.state.bv.get_functions_containing(local_address):
				func.set_auto_instr_highlight(local_address, HighlightStandardColor.NoHighlightColor)
				delqueue = [tag for tag in func.get_address_tags_at(local_address) if tag.data == 'breakpoint']
				for tag in delqueue:
					func.remove_user_address_tag(local_address, tag)

	def on_stdout(self, output):
		def on_stdout_main_thread(output):
			console_widget = self.widget('Debugger Console')
			console_widget.notifyStdout(output)
		execute_on_main_thread_and_wait(lambda: on_stdout_main_thread(output))

#------------------------------------------------------------------------------
# right click plugin
#------------------------------------------------------------------------------

def cb_bp_toggle(bv, local_address):
	debug_state = binjaplug.get_state(bv)
	remote_address = debug_state.memory_view.local_addr_to_remote(local_address)
	if local_address in debug_state.breakpoints:
		debug_state.breakpoint_clear(remote_address)
	else:
		debug_state.breakpoint_set(remote_address)
	debug_state.ui.context_display()

def valid_bp_toggle(bv, local_address):
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

def cb_control_step_into_asm(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionStepIntoAsm.trigger()

def cb_control_step_into_il(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionStepIntoIL.trigger()

def cb_control_step_over_asm(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionStepOverAsm.trigger()

def cb_control_step_over_il(bv):
	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is not None:
		debug_state.ui.debug_view.controls.actionStepOverIL.trigger()

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

def valid_control_step_into_asm(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionStepIntoAsm.isEnabled()

def valid_control_step_into_il(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionStepIntoIL.isEnabled()

def valid_control_step_over_asm(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionStepOverAsm.isEnabled()

def valid_control_step_over_il(bv):
	debug_state = binjaplug.get_state(bv)
	return debug_state.ui.debug_view is not None and debug_state.ui.debug_view.controls.actionStepOverIL.isEnabled()

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
	widget.register_dockwidget(ConsoleWidget.DebugConsoleWidget, "Debugger Console", Qt.BottomDockWidgetArea, Qt.Horizontal, False)

	PluginCommand.register_for_address("Debugger\\Toggle Breakpoint", "sets/clears breakpoint at right-clicked address", cb_bp_toggle, is_valid=valid_bp_toggle)

	PluginCommand.register("Debugger\\Process\\Run", "Start new debugging session", cb_process_run, is_valid=valid_process_run)
	PluginCommand.register("Debugger\\Process\\Restart", "Restart debugging session", cb_process_restart, is_valid=valid_process_restart)
	PluginCommand.register("Debugger\\Process\\Quit", "Terminate debugged process and end session", cb_process_quit, is_valid=valid_process_quit)
	# PluginCommand.register("Debugger\\Process\\Attach", "Attach to running process", cb_process_attach, is_valid=valid_process_attach)
	PluginCommand.register("Debugger\\Process\\Detach", "Detach from current debugged process", cb_process_detach, is_valid=valid_process_detach)
	PluginCommand.register("Debugger\\Process\\Settings", "Open adapter settings menu", cb_process_settings, is_valid=valid_process_settings)
	PluginCommand.register("Debugger\\Control\\Pause", "Pause execution", cb_control_pause, is_valid=valid_control_pause)
	PluginCommand.register("Debugger\\Control\\Resume", "Resume execution", cb_control_resume, is_valid=valid_control_resume)
	PluginCommand.register("Debugger\\Control\\Step Into (Assembly)", "Step into assembly", cb_control_step_into_asm, is_valid=valid_control_step_into_asm)
	PluginCommand.register("Debugger\\Control\\Step Into (IL)", "Step into IL", cb_control_step_into_il, is_valid=valid_control_step_into_il)
	PluginCommand.register("Debugger\\Control\\Step Over (Assembly)", "Step over function call", cb_control_step_over_asm, is_valid=valid_control_step_over_asm)
	PluginCommand.register("Debugger\\Control\\Step Over (IL)", "Step over function call", cb_control_step_over_il, is_valid=valid_control_step_over_il)
	PluginCommand.register("Debugger\\Control\\Step Return", "Step until current function returns", cb_control_step_return, is_valid=valid_control_step_return)

	ViewType.registerViewType(DebugView.DebugViewType())
