import re

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

#--------------------------------------------------------------------------
# COMMON DEBUGGER TASKS
#--------------------------------------------------------------------------

def context_display(ddWidget):
	global adapter

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

	ddWidget.editRax.setText('%X' % rax)
	ddWidget.editRbx.setText('%X' % rbx)
	ddWidget.editRcx.setText('%X' % rcx)
	ddWidget.editRdx.setText('%X' % rdx)
	ddWidget.editRsi.setText('%X' % rsi)
	ddWidget.editRdi.setText('%X' % rdi)
	ddWidget.editRip.setText('%X' % rip)
	ddWidget.editRsp.setText('%X' % rsp)
	ddWidget.editRbp.setText('%X' % rbp)
	ddWidget.editR08.setText('%X' % r8)
	ddWidget.editR09.setText('%X' % r9)
	ddWidget.editR10.setText('%X' % r10)
	ddWidget.editR11.setText('%X' % r11)
	ddWidget.editR12.setText('%X' % r12)
	ddWidget.editR13.setText('%X' % r13)
	ddWidget.editR14.setText('%X' % r14)
	ddWidget.editR15.setText('%X' % r15)

#	print("%srax%s=%016X %srbx%s=%016X %srcx%s=%016X" % \
#		(BROWN, NORMAL, rax, BROWN, NORMAL, rbx, BROWN, NORMAL, rcx))
#	print("%srdx%s=%016X %srsi%s=%016X %srdi%s=%016X" %
#		(BROWN, NORMAL, rdx, BROWN, NORMAL, rsi, BROWN, NORMAL, rdi))
#	print("%srip%s=%016X %srsp%s=%016X %srbp%s=%016X" % \
#		(BROWN, NORMAL, rip, BROWN, NORMAL, rsp, BROWN, NORMAL, rbp))
#	print(" %sr8%s=%016X  %sr9%s=%016X %sr10%s=%016X" % \
#		(BROWN, NORMAL, r8, BROWN, NORMAL, r9, BROWN, NORMAL, r10))
#	print("%sr11%s=%016X %sr12%s=%016X %sr13%s=%016X" % \
#		(BROWN, NORMAL, r11, BROWN, NORMAL, r12, BROWN, NORMAL, r13))
#	print("%sr14%s=%016X %sr15%s=%016X" % \
#		(BROWN, NORMAL, r14, BROWN, NORMAL, r15))

	#data = adapter.mem_read(rip, 16)
	#if data:
	#	(asmstr, asmlen) = disasm1(data, rip)
	#	print('%s%016X%s: %s\t%s' % \
	#		(GREEN, rip, NORMAL, hexlify(data[0:asmlen]).decode('utf-8'), asmstr))

#------------------------------------------------------------------------------
# debugger functions
#------------------------------------------------------------------------------

def debug_run(ddWidget):
	global adapter
	adapter = lldb.DebugAdapterLLDB()

def debug_quit(ddWidget):
	global adapter
	assert adapter
	adapter.quit()
	adapter = None

def debug_detach(ddWidget):
	global adapter
	assert adapter
	adapter.detach()
	adapter = None

def debug_break(ddWidget):
	global adapter
	assert adapter
	adapter.break_into()

def debug_go(ddWidget):
	global adapter
	assert adapter

def debug_step(ddWidget):
	global adapter
	assert adapter
	(reason, data) = adapter.step_into()

	if reason == DebugAdapter.STOP_REASON.STDOUT_MESSAGE:
		print('stdout: ', data)
	elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
		print('process exited, return code=%d', data)
	else:
		print('stopped, reason: ', reason.name)
		context_display(ddWidget)

#------------------------------------------------------------------------------
# debugger buttons widget
#------------------------------------------------------------------------------

instance_id = 0
class DebuggerDockWidget(QWidget, DockContextHandler):
	# in practice, data is a BinaryView
	def __init__(self, parent, name, data):
		global instance_id
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
		btnRun.clicked.connect(lambda : debug_run(self))
		btnQuit = QPushButton("Quit")
		btnQuit.clicked.connect(lambda : debug_quit(self))
		btnDetach = QPushButton("Detach")
		btnDetach.clicked.connect(lambda : debug_detach(self))
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
		btnPause.clicked.connect(lambda : debug_break(self))
		btnResume = QPushButton("Go")
		btnResume.clicked.connect(lambda : debug_go(self))
		btnStep = QPushButton("Step")
		btnStep.clicked.connect(lambda : debug_step(self))
		lo = QHBoxLayout()
		lo.addWidget(btnPause)
		lo.addWidget(btnResume)
		lo.addWidget(btnStep)
		layout.addLayout(lo)

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

		instance_id += 1
		self.data = data

	#--------------------------------------------------------------------------
	# callbacks to us api/ui/dockhandler.h
	#--------------------------------------------------------------------------
	def notifyOffsetChanged(self, offset):
		#self.offset.setText(hex(offset))
		pass

	def notifyViewChanged(self, view_frame):
		# many options on view_frame, see api/ui/viewframe.h

		if view_frame is None:
			self.data = None
		else:
			view = view_frame.getCurrentViewInterface()
			self.data = view.getData()
			# self.data is a BinaryView
			if self.data.file and self.data.file.filename:
				self.labelTarget.setText('Target: ' + self.data.file.filename)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

	@staticmethod
	def create_widget(name, parent, data = None):
		return DebuggerDockWidget(parent, name, data)

	#--------------------------------------------------------------------------
	# extra shiz
	#--------------------------------------------------------------------------

#------------------------------------------------------------------------------
# "main"
#------------------------------------------------------------------------------
def hideDebuggerControls(binaryView):
	global dock_handler
	dock_handler.setVisible("Debugger Controls", False)

def showDebuggerControls(binaryView):
	global dock_handler
	dock_handler.setVisible("Debugger Controls", True)

def initialize():
	mainWindow = QApplication.allWidgets()[0].window()

	# binaryninja/api/ui/dockhandler.h
	dock_handler = mainWindow.findChild(DockHandler, '__DockHandler')
	dock_handler.addDockWidget("Debugger Controls", DebuggerDockWidget.create_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True)

	PluginCommand.register("Hide Debugger Widget", "", hideDebuggerControls)
	PluginCommand.register("Show Debugger Widget", "", showDebuggerControls)

