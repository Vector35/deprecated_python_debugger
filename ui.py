import binaryninjaui
if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
	from PySide6 import QtCore
	from PySide6.QtCore import Qt
	from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit
	from PySide6.QtGui import QDesktopServices
else:
	from PySide2 import QtCore
	from PySide2.QtCore import Qt
	from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit
	from PySide2.QtGui import QDesktopServices

from binaryninja.plugin import PluginCommand
from binaryninja import Endianness, HighlightStandardColor, execute_on_main_thread, execute_on_main_thread_and_wait, LowLevelILOperation, BinaryReader
from binaryninja.settings import Settings
from binaryninja.log import log_warn, log_error, log_debug
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, ViewType, ViewFrame
from .dockwidgets import BreakpointsWidget, RegistersWidget, StackWidget, ThreadsWidget, ControlsWidget, DebugView, ConsoleWidget, ModulesWidget, widget
from . import binjaplug
import datetime
import traceback
import os
import pathlib

class DebuggerUI:
	def __init__(self, state):
		self.state = state
		self.debug_view = None
		self.last_ip = 0
		self.regs = []
		self.stack = []

		registers_widget = self.widget("Debugger Registers")
		modules_widget = self.widget("Debugger Modules")
		threads_widget = self.widget("Debugger Threads")
		stack_widget = self.widget("Debugger Stack")
		bp_widget = self.widget("Debugger Breakpoints")
		#console_widget = self.widget('Debugger Console')

		if registers_widget is None or modules_widget is None or threads_widget is None or stack_widget is None or bp_widget is None:
			# One of the views failed to create, bail
			log_debug("Creating Debugger UI for view with missing dock widgets!")
			return

		# Initial view data
		self.context_display()
		self.update_highlights()
		self.update_breakpoints()
		Settings().register_group("debugger", "Debugger")
		key = 'debugger.extra_annotations'
		if not Settings().contains(key):
			Settings().register_setting(key, '{"description" : "Enables automatic additional annotations to be added to the start of functions that will persist after the debugger has moved away. Must break or step across the start of a function to trigger. Currently uses comments but will be migrated to ephemeral comments when that system is finished.", "title" : "Debugger Function Start Annotations", "default" : false, "type" : "boolean"}')

	def widget(self, name):
		return widget.get_dockwidget(self.state.bv, name)

	def context_display(self):
		registers_widget = self.widget("Debugger Registers")
		modules_widget = self.widget("Debugger Modules")
		threads_widget = self.widget("Debugger Threads")
		stack_widget = self.widget("Debugger Stack")

		if not self.state.connected:
			# Disconnected
			registers_widget.notifyRegistersChanged([])
			modules_widget.notifyModulesChanged([])
			threads_widget.notifyThreadsChanged([])
			if self.debug_view is not None:
				self.debug_view.controls.set_thread_list([])
			stack_widget.notifyStackChanged([])
			self.memory_dirty()
			return

		#----------------------------------------------------------------------
		# Update Memory
		#----------------------------------------------------------------------
		self.state.update_memory_view()
		self.memory_dirty()

		#----------------------------------------------------------------------
		# Update Registers
		#----------------------------------------------------------------------
		self.regs = []
		for (register, value) in self.state.registers:
			bits = self.state.registers.bits(register)
			self.regs.append({
				'name': register,
				'bits': bits,
				'value': value
			})
		registers_widget.notifyRegistersChanged(self.regs)

		#----------------------------------------------------------------------
		# Update Modules
		#----------------------------------------------------------------------

		# Updating this widget is slow, so just show "Data is Stale" and the user
		# can refresh later if they desire
		modules_widget.mark_dirty()

		#----------------------------------------------------------------------
		# Update Threads
		#----------------------------------------------------------------------

		threads = list(self.state.threads)
		threads_widget.notifyThreadsChanged(threads)
		if self.debug_view is not None:
			self.debug_view.controls.set_thread_list(threads)

		#----------------------------------------------------------------------
		# Update Stack
		#----------------------------------------------------------------------

		stack_pointer = self.state.stack_pointer
		# Read up and down from rsp
		stack_range = [-8, 60] # Inclusive
		self.stack = []
		for i in range(stack_range[0], stack_range[1] + 1):
			offset = i * self.state.remote_arch.address_size
			if offset < 0 and stack_pointer < -offset:
				# Address < 0
				continue

			address = stack_pointer + offset
			value = self.state.memory_view.read(address, self.state.remote_arch.address_size)
			if len(value) < self.state.remote_arch.address_size:
				# Cannot access this memory
				continue

			value_int = value
			if self.state.remote_arch.endianness == Endianness.LittleEndian:
				value_int = value_int[::-1]
			value_int = int(value_int.hex(), 16)

			refs = []
			# regs from above
			for reg in self.regs:
				if reg['value'] == address:
					refs.append({
						'source': 'register',
						'dest': 'address',
						'register': reg['name']
					})
				# Ignore zeroes because most registers start at zero and give false data
				if value_int != 0 and reg['value'] == value_int:
					refs.append({
						'source': 'register',
						'dest': 'value',
						'register': reg['name']
					})

			self.stack.append({
				'offset': offset,
				'value': value,
				'address': address,
				'refs': refs
			})
		stack_widget.notifyStackChanged(self.stack)

		#----------------------------------------------------------------------
		# Update Status
		#----------------------------------------------------------------------
		local_rip = self.state.local_ip
		self.update_highlights()
		self.last_ip = local_rip

		if self.debug_view is not None:
			if self.state.bv.read(local_rip, 1) and len(self.state.bv.get_functions_containing(local_rip)) > 0:
				self.debug_view.controls.state_stopped()
			else:
				self.debug_view.controls.state_stopped_extern()

	# Called after every button action
	def on_step(self):
		self.detect_new_code()
		self.annotate_context()
		self.context_display()
		self.update_breakpoints()
		self.navigate_to_rip()

	def annotate_context(self):
		if not Settings().get_bool("debugger.extra_annotations"):
			return
		if not self.state.connected:
			return
		remote_rip = self.state.ip
		local_rip = self.state.local_ip
		if self.state.bv.read(local_rip, 1) is None:
			return
		function = self.state.bv.get_function_at(local_rip)
		if not function:
			return
		annotation = "timestamp: {}\n\n".format(datetime.datetime.now().strftime('%H:%M:%S.%f'))
		address_size = self.state.remote_arch.address_size
		for reg in self.regs:
			if address_size*8 == reg['bits']:
				annotation += " {reg:>8} = {value:0{valuewidth}x}\n".format(reg=reg['name'], value=reg['value'], valuewidth=address_size*2)
		annotation += "\nStack:\n"
		# Read up and down from rsp
		for entry in self.stack[0:16]:
			annotation += " {offset:>2} {value:>{address_size}s} {address:x} {refs}\n".format(
				offset=entry['offset'],
				value=entry['value'].hex(),
				address=entry['address'],
				refs=entry['refs'],
				address_size = address_size*2
			)
		function.set_comment_at(local_rip, annotation)

	def evaluate_llil(self, state, llil):
		# Interpreter for LLIL instructions, using data from state
		if llil.operation == LowLevelILOperation.LLIL_CONST:
			return llil.operands[0]
		elif llil.operation == LowLevelILOperation.LLIL_CONST_PTR:
			return llil.operands[0]
		elif llil.operation == LowLevelILOperation.LLIL_REG:
			reg = llil.operands[0].name
			return state.registers[reg]
		elif llil.operation == LowLevelILOperation.LLIL_LOAD:
			addr = self.evaluate_llil(state, llil.operands[0])
			# Have to read from addr llil.size bytes
			reader = BinaryReader(state.memory_view)
			reader.seek(addr)

			if llil.size == 1:
				deref = reader.read8()
			elif llil.size == 2:
				deref = reader.read16()
			elif llil.size == 4:
				deref = reader.read32()
			else:
				deref = reader.read64()
			# Unimplemented: 128-bit, etc

			return deref
		elif llil.operation == LowLevelILOperation.LLIL_ADD:
			return self.evaluate_llil(state, llil.operands[0]) + self.evaluate_llil(state, llil.operands[1])
		elif llil.operation == LowLevelILOperation.LLIL_SUB:
			return self.evaluate_llil(state, llil.operands[0]) - self.evaluate_llil(state, llil.operands[1])
		elif llil.operation == LowLevelILOperation.LLIL_MUL:
			return self.evaluate_llil(state, llil.operands[0]) * self.evaluate_llil(state, llil.operands[1])
		elif llil.operation == LowLevelILOperation.LLIL_LSL:
			return self.evaluate_llil(state, llil.operands[0]) << self.evaluate_llil(state, llil.operands[1])
		elif llil.operation == LowLevelILOperation.LLIL_LSR:
			return self.evaluate_llil(state, llil.operands[0]) >> self.evaluate_llil(state, llil.operands[1])
		else:
			raise NotImplementedError('TODO: evaluate llil for %s' % llil.operation)

	def detect_new_code(self):
		if not self.state.connected:
			return

		local_rip = self.state.local_ip
		if local_rip < self.state.bv.start or local_rip >= self.state.bv.end:
			return

		if self.state.bv.read(local_rip, 1) is None:
			raise Exception('cannot read from local address 0x%X' % local_rip)

		update_analysis = False
		try:
			# if executing where a function isn't defined, define one!
			if len(self.state.bv.get_functions_containing(local_rip)) == 0:
				#print('adding function at: 0x%X' % local_rip)
				self.state.bv.add_function(local_rip)
				update_analysis = True

			# analyze current instruction through LLIL
			remote_rip = self.state.ip
			llil = self.state.remote_arch.get_low_level_il_from_bytes(self.state.memory_view.read(remote_rip, self.state.remote_arch.max_instr_length), remote_rip)
			call = llil.operation == LowLevelILOperation.LLIL_CALL
			jump = llil.operation == LowLevelILOperation.LLIL_JUMP or llil.operation == LowLevelILOperation.LLIL_JUMP_TO
			indirect = (call or jump) and llil.operands[0].operation not in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR]

			if not (call or jump):
				return

			remote_target = self.evaluate_llil(self.state, llil.dest)

			local_target = self.state.memory_view.remote_addr_to_local(remote_target)
			if local_target < self.state.bv.start or local_target >= self.state.bv.end:
				return

			# if call target is within bv, and no function, make one
			if call and (not self.state.bv.get_functions_containing(local_target)):
				self.state.bv.add_function(local_target)
				update_analysis = True

			# if call is indirect, optionally annotate the destination
			if call and indirect and Settings().get_bool("debugger.extra_annotations"):
				for func in self.state.bv.get_functions_containing(local_rip):
					annotation = 'called 0x%X' % remote_target
					comment = func.get_comment_at(local_rip)
					if not annotation in comment.split('\n'):
						if comment:
							annotation = '\n'+annotation
						func.set_comment_at(local_rip, comment+annotation)

			# if jump target isn't in analysis's indirect jumps, add it
			if jump and indirect:
				for func in self.state.bv.get_functions_containing(local_rip):
					# get auto and user branches, autos shadowed by user
					branches = [(b.dest_arch, b.dest_addr) for b in func.get_indirect_branches_at(local_rip)]
					new_branch = (self.state.remote_arch, local_target)
					if not new_branch in branches:
						#print('adding indirect branch target: 0x%X' % (new_branch[1]))
						branches.append(new_branch)
						func.set_user_indirect_branches(local_rip, list(branches))
						update_analysis = True
		except NotImplementedError as e:
			raise Exception("llil eval failed: {}".format(e))
		finally:
			if update_analysis:
				self.state.bv.update_analysis()


	def navigate_to_rip(self):
		if self.debug_view is not None:
			if not self.state.connected:
				rip = self.state.bv.entry_point
			else:
				rip = self.state.ip

			# select instruction currently at
			frame = ViewFrame.viewFrameForWidget(self.debug_view)
			frame.navigate(self.state.bv, rip, True, True)

	# Highlight lines
	def update_highlights(self):
		# Clear old highlighted rip
		for func in (self.state.bv.get_functions_containing(self.last_ip) or []):
			func.set_auto_instr_highlight(self.last_ip, HighlightStandardColor.NoHighlightColor)

		for (module, offset) in self.state.breakpoints:
			if module != self.state.bv.file.original_filename:
				continue
			bp = self.state.bv.start + offset
			for func in self.state.bv.get_functions_containing(bp):
				func.set_auto_instr_highlight(bp, HighlightStandardColor.RedHighlightColor)

		if self.state.connected:
			remote_rip = self.state.ip
			local_rip = self.state.memory_view.remote_addr_to_local(remote_rip)

			for func in (self.state.bv.get_functions_containing(local_rip) or []):
				func.set_auto_instr_highlight(local_rip, HighlightStandardColor.BlueHighlightColor)

	def update_modules(self):
		mods = []
		self.state.modules.mark_dirty()
		for (modpath, address) in self.state.modules:
			mods.append({
				'address': address,
				'modpath': modpath
				# TODO: Length, segments, etc
			})
		mods.sort(key=lambda row: row['address'])
		modules_widget = self.widget("Debugger Modules")
		modules_widget.notifyModulesChanged(mods)

	# Mark memory as dirty, will refresh memory view
	def memory_dirty(self):
		self.state.memory_dirty()
		if self.debug_view is not None:
			self.debug_view.notifyMemoryChanged()

	def update_breakpoints(self):
		bps = []
		if not self.state.connected:
			remote_list = []
		else:
			remote_list = self.state.adapter.breakpoint_list()

		for (module, offset) in self.state.breakpoints:
			if not self.state.connected:
				address = 0
				enabled = False
			else:
				modbase = self.state.modules[module]
				if modbase is not None:
					address = modbase + offset
					enabled = address in remote_list
				else:
					address = 0
					enabled = False

			bps.append({
				'enabled': enabled,
				'offset': offset,
				'module': module,
				'address': address
			})

		bp_widget = self.widget("Debugger Breakpoints")
		bp_widget.notifyBreakpointsChanged(bps)
		# Refresh disassembly to show the new bp
		if self.debug_view is not None:
			self.debug_view.refresh_raw_disassembly()

	def breakpoint_tag_add(self, local_address):
		# create tag
		tt = self.get_breakpoint_tag_type()

		for func in self.state.bv.get_functions_containing(local_address):
			tags = [tag for tag in func.get_address_tags_at(local_address) if tag.type == tt]
			if len(tags) == 0:
				tag = func.create_user_address_tag(local_address, tt, "breakpoint")

		self.context_display()

	# breakpoint TAG removal - strictly presentation
	# (doesn't remove actual breakpoints, just removes the binja tags that mark them)
	#
	def breakpoint_tag_del(self, local_addresses=None):
		if local_addresses == None:
			local_addresses = [self.state.bv.start + offset for (module, offset) in self.state.breakpoints if module == self.state.bv.file.original_filename]

		tt = self.get_breakpoint_tag_type()

		for local_address in local_addresses:
			# delete breakpoint tags from all functions containing this address
			for func in self.state.bv.get_functions_containing(local_address):
				func.set_auto_instr_highlight(local_address, HighlightStandardColor.NoHighlightColor)
				delqueue = [tag for tag in func.get_address_tags_at(local_address) if tag.type == tt]
				for tag in delqueue:
					func.remove_user_address_tag(local_address, tag)

		self.context_display()

	def get_breakpoint_tag_type(self):
		if "Breakpoints" in self.state.bv.tag_types:
			return self.state.bv.tag_types["Breakpoints"]
		else:
			return self.state.bv.create_tag_type("Breakpoints", "🛑")

	def on_stdout(self, output):
		#def on_stdout_main_thread(output):
		#	console_widget = self.widget('Debugger Console')
		#	console_widget.notifyStdout(output)
		#execute_on_main_thread(lambda: on_stdout_main_thread(output))
		pass

#------------------------------------------------------------------------------
# right click plugin
#------------------------------------------------------------------------------

def cb_bp_toggle(bv, address):
	debug_state = binjaplug.get_state(bv)

	# If the breakpoint should be set with the absolute address on memory
	is_absolute_address = False
	if bv == debug_state.memory_view or bv.parent_view == debug_state.memory_view:
		is_absolute_address = True

	if is_absolute_address:
		if debug_state.breakpoints.contains_absolute(address):
			debug_state.breakpoints.remove_absolute(address)
		else:
			debug_state.breakpoints.add_absolute(address)
	else:
		offset = address - bv.start
		if debug_state.breakpoints.contains_offset(bv.file.original_filename, offset):
			debug_state.breakpoints.remove_offset(bv.file.original_filename, offset)
			debug_state.ui.breakpoint_tag_del([address])
		else:
			debug_state.breakpoints.add_offset(bv.file.original_filename, offset)
			debug_state.ui.breakpoint_tag_add(address)
	debug_state.ui.update_breakpoints()

def valid_bp_toggle(bv, address):
	return True

#------------------------------------------------------------------------------
# Plugin actions for the various debugger controls
#------------------------------------------------------------------------------

def cb_process_run(bv):
	def switch_view():
		dh = DockHandler.getActiveDockHandler()
		vf = dh.getViewFrame()
		vf.setViewType('Debugger:' + bv.view_type)

	debug_state = binjaplug.get_state(bv)
	if debug_state.ui.debug_view is None:
		execute_on_main_thread_and_wait(switch_view)

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

	# if the debugger UI is up, the state with debuggee determines whether button is activated
	if debug_state.ui.debug_view is not None:
		return debug_state.ui.debug_view.controls.actionRun.isEnabled()

	# else, assume activated, initiate debug_state.ui on click
	return True

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

def helpDocs(context):
	docPath = os.path.join(os.path.dirname(__file__), "Documentation")
	URLPath = pathlib.Path(os.path.join(docPath, "Manual.html")).as_uri()
	QDesktopServices.openUrl(URLPath)

def initialize_ui():
	widget.register_dockwidget(BreakpointsWidget.DebugBreakpointsWidget, "Debugger Breakpoints", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(RegistersWidget.DebugRegistersWidget, "Debugger Registers", Qt.RightDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ThreadsWidget.DebugThreadsWidget, "Debugger Threads", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	widget.register_dockwidget(StackWidget.DebugStackWidget, "Debugger Stack", Qt.LeftDockWidgetArea, Qt.Vertical, False)
	widget.register_dockwidget(ModulesWidget.DebugModulesWidget, "Debugger Modules", Qt.BottomDockWidgetArea, Qt.Horizontal, False)
	#widget.register_dockwidget(ConsoleWidget.DebugConsoleWidget, "Debugger Console", Qt.BottomDockWidgetArea, Qt.Horizontal, False)

	PluginCommand.register_for_address("Debugger\\Toggle Breakpoint", "sets/clears breakpoint at right-clicked address", cb_bp_toggle, is_valid=valid_bp_toggle)

	PluginCommand.register("Debugger\\Process\\Run", "Start new debugging session", cb_process_run, is_valid=valid_process_run)
	PluginCommand.register("Debugger\\User Documentation", "Open Debugger Documentation", helpDocs, is_valid=valid_process_run)
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
