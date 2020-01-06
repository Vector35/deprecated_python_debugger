import re
import time

import binaryninja
from binaryninja.plugin import PluginCommand
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit

from . import DebugAdapter
from . import lldb
from .dockwidgets import BreakpointsWidget, RegistersWidget, StackWidget, ThreadsWidget, widget

#------------------------------------------------------------------------------
# globals
#------------------------------------------------------------------------------
adapter = None

state = 'INACTIVE'

# address -> adapter id
breakpoints = {}

#--------------------------------------------------------------------------
# SUPPORT FUNCTIONS (HIGHER LEVEL)
#--------------------------------------------------------------------------

def context_display(bv):
	global adapter

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

	rip = adapter.reg_read('rip')

	# select instruction currently at
	if bv.read(rip, 1):
		print('navigating to: 0x%X' % rip)
		statusText = 'STOPPED at 0x%016X' % rip
		bv.navigate(bv.file.view, rip)
	else:
		statusText = 'STOPPED at 0x%016X (outside view)' % rip
		print('address 0x%X outside of binary view, not setting cursor' % rip)

	widget.get_dockwidget(bv, 'Debugger Controls').editStatus.setText(statusText)

	#data = adapter.mem_read(rip, 16)
	#if data:
	#	(asmstr, asmlen) = disasm1(data, rip)
	#	print('%s%016X%s: %s\t%s' % \
	#		(GREEN, rip, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

# breakpoint TAG removal - strictly presentation
# (doesn't remove actual breakpoints, just removes the binja tags that mark them)
#
def del_breakpoint_tags(bv, addresses=None):
	global breakpoints

	if addresses == None:
		addresses = breakpoints

	for address in addresses:
		# delete breakpoint tags from all functions containing this address
		for func in bv.get_functions_containing(address):
			delqueue = [tag for tag in func.get_address_tags_at(address) if tag.data == 'breakpoint']
			for tag in delqueue:
				func.remove_user_address_tag(address, tag)

def buttons_xable(bv, states):
	assert len(states) == 8

	dw = widget.get_dockwidget(bv, 'Debugger Controls')

	buttons = [dw.btnRun, dw.btnRestart, dw.btnQuit, dw.btnDetach, dw.btnPause,
		dw.btnResume, dw.btnStepInto, dw.btnStepOver]

	for (button, state) in zip(buttons, states):
		button.setEnabled(bool(state))

def debug_status(bv, message):
	main = widget.get_dockwidget(bv, 'Debugger Controls')
	main.editStatus.setText(message)

def state_inactive(bv, msg=None):
	global adapter, state

	# clear breakpoints
	del_breakpoint_tags(bv)
	breakpoints = {}

	state = 'INACTIVE'
	debug_status(bv, msg or state)
	buttons_xable(bv, [1, 0, 0, 0, 0, 0, 0, 0])

def state_stopped(bv, msg=None):
	state = 'STOPPED'
	dw = widget.get_dockwidget(bv, 'Debugger Controls')
	debug_status(bv, msg or state)
	buttons_xable(bv, [0, 1, 1, 1, 1, 1, 1, 1])

def state_running(bv, msg=None):
	state = 'RUNNING'
	debug_status(bv, msg or state)
	buttons_xable(bv, [0, 0, 0, 0, 1, 0, 0, 0])

def state_error(bv, msg=None):
	state = 'ERROR'
	debug_status(bv, msg or state)
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
	global adapter
	adapter = lldb.DebugAdapterLLDB()

	if bv and bv.entry_point:
		debug_breakpoint_set(bv, bv.entry_point)
		bv.navigate(bv.file.view, bv.entry_point)

	state_stopped(bv)
	context_display(bv)

def debug_quit(bv):
	global adapter
	if adapter:
		adapter.quit()
		adapter = None
	state_inactive(bv)

def debug_restart(bv):
	debug_quit(bv)
	time.sleep(1)
	debug_run(bv) # sets state

def debug_detach(bv):
	global adapter
	assert adapter
	adapter.detach()
	adapter = None
	state_inactive(bv)

def debug_break(bv):
	global adapter
	assert adapter
	adapter.break_into()
	# TODO: wait for actual stop
	state_stopped(bv)
	context_display(bv)

def debug_go(bv):
	global adapter
	assert adapter
	(reason, data) = adapter.go()
	handle_stop_return(bv, reason, data)

def debug_step(bv):
	global adapter, state
	assert adapter

	(reason, data) = (None, None)

	if bv.arch.name == 'x86_64':
		rip = adapter.reg_read('rip')

		# if currently a breakpoint at rip, temporarily clear it
		# TODO: detect windbg adapter because dbgeng's step behavior might ignore breakpoint
		# at current rip

		seq = []
		if rip in breakpoints:
			seq.append((adapter.breakpoint_clear, (rip,)))
			seq.append((adapter.step_into, ()))
			seq.append((adapter.breakpoint_set, (rip,)))
		else:
			seq.append((adapter.step_into, ()))

		(reason, data) = exec_adapter_sequence(seq)
	else:
		raise NotImplementedError('step unimplemented for architecture %s' % bv.arch.name)

	handle_stop_return(bv, reason, data)

def debug_step_over(bv):
	global adapter
	assert adapter

	# TODO: detect windbg adapter because dbgeng has a builtin step_into() that we don't
	# have to synthesize
	if bv.arch.name == 'x86_64':
		rip = adapter.reg_read('rip')
		instxt = bv.get_disassembly(rip)
		inslen = bv.get_instruction_length(rip)
		ripnext = rip + inslen

		call = instxt.startswith('call ')
		bphere = rip in breakpoints
		bpnext = ripnext in breakpoints

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

		(reason, data) = exec_adapter_sequence(seq)
		handle_stop_return(bv, reason, data)

	else:
		raise NotImplementedError('step over unimplemented for architecture %s' % bv.arch.name)

	state = 'stopped'

def debug_breakpoint_set(bv, address):
	global breakpoints
	global adapter
	assert adapter

	if adapter.breakpoint_set(address) != 0:
		print('ERROR: breakpoint set failed')
		return None

	# create tag
	tt = bv.tag_types["Crashes"]
	for func in bv.get_functions_containing(address):
		tag = func.create_user_address_tag(address, tt, "breakpoint")

	# save it
	breakpoints[address] = True
	print('breakpoint address=0x%X set' % (address))

	bp_widget = widget.get_dockwidget(bv, "Breakpoints")
	if bp_widget is not None:
		bp_widget.notifyBreakpointChanged()

	return 0

def debug_breakpoint_clear(bv, address):
	global breakpoints
	global adapter
	assert adapter

	# find/remove address tag
	if address in breakpoints:
		# delete from adapter
		if adapter.breakpoint_clear(address) != None:
			print('breakpoint address=0x%X cleared' % (address))
		else:
			print('ERROR: clearing breakpoint')

		# delete breakpoint tags from all functions containing this address
		del_breakpoint_tags(bv, [address])

		# delete from our list
		del breakpoints[address]
	else:
		print('ERROR: breakpoint not found in list')

# execute a sequence of adapter commands, capturing the return of the last
# blocking call
def exec_adapter_sequence(seq):
	(reason, data) = (None, None)

	for (func, args) in seq:
		if func in [adapter.step_into, adapter.step_over, adapter.go]:
			(reason, data) = func(*args)
		else:
			func(*args)

	return (reason, data)

#------------------------------------------------------------------------------
# DEBUGGER BUTTONS WIDGET
#------------------------------------------------------------------------------

class DebugMainDockWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		layout = QVBoxLayout()
		layout.addStretch()

		# add "Target:"
		self.labelTarget = QLabel("Target: ", self)
		layout.addWidget(self.labelTarget)
		self.labelTarget.setAlignment(QtCore.Qt.AlignCenter)

		# add "Session Control:"
		l = QLabel("Session Control:", self)
		l.setAlignment(QtCore.Qt.AlignCenter)
		layout.addWidget(l)

		# add session control buttons
		lo = QHBoxLayout()
		self.btnRun = QPushButton("Run")
		self.btnRun.clicked.connect(lambda : debug_run(self.bv))
		self.btnRestart = QPushButton("Restart")
		self.btnRestart.clicked.connect(lambda : debug_restart(self.bv))
		self.btnQuit = QPushButton("Quit")
		self.btnQuit.clicked.connect(lambda : debug_quit(self.bv))
		self.btnDetach = QPushButton("Detach")
		self.btnDetach.clicked.connect(lambda : debug_detach(self.bv))
		lo.addWidget(self.btnRun)
		lo.addWidget(self.btnRestart)
		lo.addWidget(self.btnQuit)
		lo.addWidget(self.btnDetach)
		layout.addLayout(lo)

		# add "Execution Control:"
		l = QLabel("Execution Control: ", self)
		l.setAlignment(QtCore.Qt.AlignCenter)
		layout.addWidget(l)

		# add execution control buttons
		self.btnPause = QPushButton("Break")
		self.btnPause.clicked.connect(lambda : debug_break(self.bv))
		self.btnResume = QPushButton("Go")
		self.btnResume.clicked.connect(lambda : debug_go(self.bv))
		self.btnStepInto = QPushButton("Step")
		self.btnStepInto.clicked.connect(lambda : debug_step(self.bv))
		self.btnStepOver = QPushButton("Step Over")
		self.btnStepOver.clicked.connect(lambda : debug_step_over(self.bv))
		lo = QHBoxLayout()
		lo.addWidget(self.btnPause)
		lo.addWidget(self.btnResume)
		lo.addWidget(self.btnStepInto)
		lo.addWidget(self.btnStepOver)
		layout.addLayout(lo)

		l = QLabel("Debugger State: ", self)
		l.setAlignment(QtCore.Qt.AlignCenter)
		self.editStatus = QLineEdit('INACTIVE', self)
		self.editStatus.setReadOnly(True)
		self.editStatus.setAlignment(QtCore.Qt.AlignCenter)
		lo = QHBoxLayout()
		lo.addWidget(l)
		lo.addWidget(self.editStatus)
		layout.addLayout(lo)

		# layout done!
		layout.addStretch()
		self.setLayout(layout)

	#--------------------------------------------------------------------------
	# callbacks to us api/ui/dockhandler.h
	#--------------------------------------------------------------------------
	def notifyOffsetChanged(self, offset):
		#self.offset.setText(hex(offset))
		pass

	def notifyViewChanged(self, view_frame):
		# many options on view_frame, see api/ui/viewframe.h

		if view_frame is None:
			self.bv = None
		else:
			view = view_frame.getCurrentViewInterface()
			data = view.getData()
			assert type(data) == binaryninja.binaryview.BinaryView
			self.bv = data
			if self.bv.file and self.bv.file.filename:
				self.labelTarget.setText('Target: ' + self.bv.file.filename)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

#------------------------------------------------------------------------------
# tools menu stuff
#------------------------------------------------------------------------------

def hideDebuggerControls(binaryView):
	global dock_handler
	dock_handler.setVisible("Debugger Controls", False)

def showDebuggerControls(binaryView):
	global dock_handler
	dock_handler.setVisible("Debugger Controls", True)

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
	widget.register_dockwidget(DebugMainDockWidget, "Debugger Controls", Qt.BottomDockWidgetArea, Qt.Horizontal, True)
	widget.register_dockwidget(BreakpointsWidget.DebugBreakpointsWidget, "Breakpoints", Qt.RightDockWidgetArea, Qt.Vertical, True)
	widget.register_dockwidget(RegistersWidget.DebugRegistersWidget, "Registers", Qt.RightDockWidgetArea, Qt.Vertical, True)
	widget.register_dockwidget(ThreadsWidget.DebugThreadsWidget, "Threads", Qt.RightDockWidgetArea, Qt.Vertical, True)
	widget.register_dockwidget(StackWidget.DebugStackWidget, "Stack", Qt.RightDockWidgetArea, Qt.Vertical, True)

	PluginCommand.register("Hide Debugger Widget", "", hideDebuggerControls)
	PluginCommand.register("Show Debugger Widget", "", showDebuggerControls)
	PluginCommand.register_for_address("Set Breakpoint", "sets breakpoint at right-clicked address", cb_bp_set)
	PluginCommand.register_for_address("Clear Breakpoint", "clears breakpoint at right-clicked address", cb_bp_clr)

