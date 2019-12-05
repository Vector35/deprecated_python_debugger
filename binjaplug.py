import re

from binaryninja.plugin import PluginCommand
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit

#------------------------------------------------------------------------------
# debugger functions
#------------------------------------------------------------------------------

def debug_run():
	print("debug_run() here!")

def debug_quit():
	print("debug_quit() here!")

def debug_detach():
	print("debug_detach() here!")

def debug_pause():
	print("debug_pause() here!")

def debug_resume():
	print("debug_resume() here!")

def debug_step():
	print("debug_step() here!")

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
		btnRun.clicked.connect(debug_run)
		btnQuit = QPushButton("Quit")
		btnQuit.clicked.connect(debug_quit)
		btnDetach = QPushButton("Detach")
		btnDetach.clicked.connect(debug_detach)
		lo.addWidget(btnRun)
		lo.addWidget(btnQuit)
		lo.addWidget(btnDetach)
		layout.addLayout(lo)

		# add "Execution Control:"
		l = QLabel("Execution Control: ", self)
		l.setAlignment(QtCore.Qt.AlignCenter)
		layout.addWidget(l)

		# add execution control buttons
		btnPause = QPushButton("Pause")
		btnPause.clicked.connect(debug_pause)
		btnResume = QPushButton("Resume")
		btnResume.clicked.connect(debug_resume)
		btnStep = QPushButton("Step")
		btnStep.clicked.connect(debug_step)
		lo = QHBoxLayout()
		lo.addWidget(btnPause)
		lo.addWidget(btnResume)
		lo.addWidget(btnStep)
		layout.addLayout(lo)

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

