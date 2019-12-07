import re

import binaryninja
from binaryninja.plugin import PluginCommand
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit

from . import DebugAdapter
from . import lldb

#------------------------------------------------------------------------------
# globals
#------------------------------------------------------------------------------
adapter = None

debug_dockwidgets = {}

# list of {'id':bpid, 'addr':address} entries
breakpoints = []

#--------------------------------------------------------------------------
# COMMON DEBUGGER TASKS
#--------------------------------------------------------------------------

def context_display(bv):
	global adapter
	global debug_dockwidgets

	context_widget = debug_dockwidgets.get('context')
	if not context_widget:
		return

	#tid = adapter.thread_selected()
	#print('thread 0x%X:' % tid)

	rax = adapter.reg_read('rax')
	rbx = adapter.reg_read('rbx')
	rcx = adapter.reg_read('rcx')
	rdx = adapter.reg_read('rdx')
	rsi = adapter.reg_read('rsi')
	rdi = adapter.reg_read('rdi')
	rip = adapter.reg_read('rip')
	rsp = adapter.reg_read('rsp')
	rbp = adapter.reg_read('rbp')
	r8 = adapter.reg_read('r8')
	r9 = adapter.reg_read('r9')
	r10 = adapter.reg_read('r10')
	r11 = adapter.reg_read('r11')
	r12 = adapter.reg_read('r12')
	r13 = adapter.reg_read('r13')
	r14 = adapter.reg_read('r14')
	r15 = adapter.reg_read('r15')

	context_widget.editRax.setText('%X' % rax)
	context_widget.editRbx.setText('%X' % rbx)
	context_widget.editRcx.setText('%X' % rcx)
	context_widget.editRdx.setText('%X' % rdx)
	context_widget.editRsi.setText('%X' % rsi)
	context_widget.editRdi.setText('%X' % rdi)
	context_widget.editRip.setText('%X' % rip)
	context_widget.editRsp.setText('%X' % rsp)
	context_widget.editRbp.setText('%X' % rbp)
	context_widget.editR08.setText('%X' % r8)
	context_widget.editR09.setText('%X' % r9)
	context_widget.editR10.setText('%X' % r10)
	context_widget.editR11.setText('%X' % r11)
	context_widget.editR12.setText('%X' % r12)
	context_widget.editR13.setText('%X' % r13)
	context_widget.editR14.setText('%X' % r14)
	context_widget.editR15.setText('%X' % r15)

	# select instruction currently at
	if bv.read(rip, 1):
		print('navigating to: 0x%X' % rip)
		bv.navigate(bv.file.view, rip)
	else:
		print('address 0x%X outside of binary view, not setting cursor' % rip)

	#data = adapter.mem_read(rip, 16)
	#if data:
	#	(asmstr, asmlen) = disasm1(data, rip)
	#	print('%s%016X%s: %s\t%s' % \
	#		(GREEN, rip, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

#------------------------------------------------------------------------------
# debugger functions
#------------------------------------------------------------------------------

def debug_run(bv):
	global adapter
	adapter = lldb.DebugAdapterLLDB()

	if bv and bv.entry_point:
		debug_breakpoint_set(bv, bv.entry_point)

def debug_quit(bv):
	global adapter
	assert adapter
	adapter.quit()
	adapter = None

def debug_detach(bv):
	global adapter
	assert adapter
	adapter.detach()
	adapter = None

def debug_break(bv):
	global adapter
	assert adapter
	adapter.break_into()

def debug_go(bv):
	global adapter
	assert adapter
	print('going in...')
	adapter.go()
	print('im out!')
	context_display(bv)

def debug_step(bv):
	global adapter
	assert adapter
	(reason, data) = adapter.step_into()

	if reason == DebugAdapter.STOP_REASON.STDOUT_MESSAGE:
		print('stdout: ', data)
	elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
		print('process exited, return code=%d', data)
	else:
		print('stopped, reason: ', reason.name)
		context_display(bv)

def debug_breakpoint_set(bv, address):
	global breakpoints
	global adapter
	assert adapter

	bpid = adapter.breakpoint_set(address)
	if bpid != None:
		# add it to breakpoint entries
		entry = {'id':bpid, 'addr':address}

		# create tag store that shit too
		tt = bv.tag_types["Crashes"]
		for func in bv.get_functions_containing(address):
			tag = func.create_user_address_tag(address, tt, "breakpoint")

		breakpoints.append(entry)
		print('breakpoint %d set, address=0x%X' % (entry['id'], entry['addr']))
	else:
		print('ERROR: breakpoint set failed')

def debug_breakpoint_clear(bv, address):
	global breakpoints
	global adapter
	assert adapter

	# find/remove address tag
	entry = [entry for entry in breakpoints if entry['addr'] == address][0]
	if entry:
		# delete from adapter
		bpid = entry['id']
		if adapter.breakpoint_clear(bpid) != None:
			print('breakpoint %d cleared, address=0x%X' % (entry['id'], entry['addr']))
		else:
			print('ERROR: clearing breakpoint')

		# delete breakpoint tags from all functions containing this address
		for func in bv.get_functions_containing(address):
			delqueue = [tag for tag in func.get_address_tags_at(address) if tag.data == 'breakpoint']
			for tag in delqueue:
				func.remove_user_address_tag(address, tag)

		# delete from our list
		breakpoints = [entry for entry in breakpoints if entry['addr'] != address]
	else:
		print('ERROR: breakpoint not found in list')

#------------------------------------------------------------------------------
# debugger registers widget
#------------------------------------------------------------------------------

class DebugContextDockWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		layout = QVBoxLayout()
		layout.addStretch()

		# add "Registers:"
		l = QLabel("Registers: ", self)
		l.setAlignment(QtCore.Qt.AlignCenter)
		layout.addWidget(l)

		# add rax, rbx, rcx
		lo = QHBoxLayout()
		lo.addWidget(QLabel('rax:', self))
		self.editRax = QLineEdit('0000000000000000', self)
		self.editRax.setReadOnly(True)
		lo.addWidget(self.editRax)
		lo.addWidget(QLabel('rbx:', self))
		self.editRbx = QLineEdit('0000000000000000', self)
		self.editRbx.setReadOnly(True)
		lo.addWidget(self.editRbx)
		lo.addWidget(QLabel('rcx:', self))
		self.editRcx = QLineEdit('0000000000000000', self)
		self.editRcx.setReadOnly(True)
		lo.addWidget(self.editRcx)
		layout.addLayout(lo)

		lo = QHBoxLayout()
		lo.addWidget(QLabel('rdx:', self))
		self.editRdx = QLineEdit('0000000000000000', self)
		self.editRdx.setReadOnly(True)
		lo.addWidget(self.editRdx)
		lo.addWidget(QLabel('rsi:', self))
		self.editRsi = QLineEdit('0000000000000000', self)
		self.editRsi.setReadOnly(True)
		lo.addWidget(self.editRsi)
		lo.addWidget(QLabel('rdi:', self))
		self.editRdi = QLineEdit('0000000000000000', self)
		self.editRdi.setReadOnly(True)
		lo.addWidget(self.editRdi)
		layout.addLayout(lo)

		lo = QHBoxLayout()
		lo.addWidget(QLabel('rip:', self))
		self.editRip = QLineEdit('0000000000000000', self)
		self.editRip.setReadOnly(True)
		lo.addWidget(self.editRip)
		lo.addWidget(QLabel('rsp:', self))
		self.editRsp = QLineEdit('0000000000000000', self)
		self.editRsp.setReadOnly(True)
		lo.addWidget(self.editRsp)
		lo.addWidget(QLabel('rbp:', self))
		self.editRbp = QLineEdit('0000000000000000', self)
		self.editRbp.setReadOnly(True)
		lo.addWidget(self.editRbp)
		layout.addLayout(lo)

		lo = QHBoxLayout()
		lo.addWidget(QLabel('r08:', self))
		self.editR08 = QLineEdit('0000000000000000', self)
		self.editR08.setReadOnly(True)
		lo.addWidget(self.editR08)
		lo.addWidget(QLabel('r09:', self))
		self.editR09 = QLineEdit('0000000000000000', self)
		self.editR09.setReadOnly(True)
		lo.addWidget(self.editR09)
		lo.addWidget(QLabel('r10:', self))
		self.editR10 = QLineEdit('0000000000000000', self)
		self.editR10.setReadOnly(True)
		lo.addWidget(self.editR10)
		layout.addLayout(lo)

		lo = QHBoxLayout()
		lo.addWidget(QLabel('rr11:', self))
		self.editR11 = QLineEdit('0000000000000000', self)
		self.editR11.setReadOnly(True)
		lo.addWidget(self.editR11)
		lo.addWidget(QLabel('r12:', self))
		self.editR12 = QLineEdit('0000000000000000', self)
		self.editR12.setReadOnly(True)
		lo.addWidget(self.editR12)
		lo.addWidget(QLabel('r13:', self))
		self.editR13 = QLineEdit('0000000000000000', self)
		self.editR13.setReadOnly(True)
		lo.addWidget(self.editR13)
		layout.addLayout(lo)

		lo = QHBoxLayout()
		lo.addWidget(QLabel('r14:', self))
		self.editR14 = QLineEdit('0000000000000000', self)
		self.editR14.setReadOnly(True)
		lo.addWidget(self.editR14)
		lo.addWidget(QLabel('r15:', self))
		self.editR15 = QLineEdit('0000000000000000', self)
		self.editR15.setReadOnly(True)
		lo.addWidget(self.editR15)
		lo.addWidget(QLabel('', self))
		self.editRcx = QLineEdit('0000000000000000', self)
		self.editRcx.setReadOnly(True)
		lo.addWidget(self.editRcx)
		layout.addLayout(lo)

		# layout done!
		layout.addStretch()
		self.setLayout(layout)

	#--------------------------------------------------------------------------
	# callbacks to us api/ui/dockhandler.h
	#--------------------------------------------------------------------------
	def notifyOffsetChanged(self, offset):
		pass

	def notifyViewChanged(self, view_frame):
		if view_frame is None:
			self.bv = None
		else:
			view = view_frame.getCurrentViewInterface()
			data = view.getData()
			assert type(data) == binaryninja.binaryview.BinaryView
			self.bv = data

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

	@staticmethod
	def create_widget(name, parent, data = None):
		global debug_dockwidgets
		ref = DebugContextDockWidget(parent, name, data)
		debug_dockwidgets['context'] = ref
		return ref

#------------------------------------------------------------------------------
# debugger buttons widget
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
		btnRun = QPushButton("Run")
		btnRun.clicked.connect(lambda : debug_run(self.bv))
		btnQuit = QPushButton("Quit")
		btnQuit.clicked.connect(lambda : debug_quit(self.bv))
		btnDetach = QPushButton("Detach")
		btnDetach.clicked.connect(lambda : debug_detach(self.bv))
		lo.addWidget(btnRun)
		lo.addWidget(btnQuit)
		lo.addWidget(btnDetach)
		layout.addLayout(lo)

		# add "Execution Control:"
		l = QLabel("Execution Control: ", self)
		l.setAlignment(QtCore.Qt.AlignCenter)
		layout.addWidget(l)

		# add execution control buttons
		btnPause = QPushButton("Break")
		btnPause.clicked.connect(lambda : debug_break(self.bv))
		btnResume = QPushButton("Go")
		btnResume.clicked.connect(lambda : debug_go(self.bv))
		btnStep = QPushButton("Step")
		btnStep.clicked.connect(lambda : debug_step(self.bv))
		lo = QHBoxLayout()
		lo.addWidget(btnPause)
		lo.addWidget(btnResume)
		lo.addWidget(btnStep)
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

	@staticmethod
	def create_widget(name, parent, data):
		global debug_dockwidgets
		ref = DebugMainDockWidget(parent, name, data)
		debug_dockwidgets['main'] = ref
		return ref



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
	mainWindow = QApplication.allWidgets()[0].window()

	# binaryninja/api/ui/dockhandler.h
	dock_handler = mainWindow.findChild(DockHandler, '__DockHandler')

	# create main debugger controls
	dock_handler.addDockWidget("Debugger Controls", DebugMainDockWidget.create_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True)
	dock_handler.addDockWidget("Debugger Context", DebugContextDockWidget.create_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True)

	PluginCommand.register("Hide Debugger Widget", "", hideDebuggerControls)
	PluginCommand.register("Show Debugger Widget", "", showDebuggerControls)
	PluginCommand.register_for_address("Set Breakpoint", "sets breakpoint at right-clicked address", cb_bp_set)
	PluginCommand.register_for_address("Clear Breakpoint", "clears breakpoint at right-clicked address", cb_bp_clr)

