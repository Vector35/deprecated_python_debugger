import binaryninja
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit

from .. import binjaplug

class DebugControlsWidget(QWidget, DockContextHandler):
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
		self.btnRun.clicked.connect(lambda : binjaplug.debug_run(self.bv))
		self.btnRestart = QPushButton("Restart")
		self.btnRestart.clicked.connect(lambda : binjaplug.debug_restart(self.bv))
		self.btnQuit = QPushButton("Quit")
		self.btnQuit.clicked.connect(lambda : binjaplug.debug_quit(self.bv))
		self.btnDetach = QPushButton("Detach")
		self.btnDetach.clicked.connect(lambda : binjaplug.debug_detach(self.bv))
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
		self.btnPause.clicked.connect(lambda : binjaplug.debug_break(self.bv))
		self.btnResume = QPushButton("Go")
		self.btnResume.clicked.connect(lambda : binjaplug.debug_go(self.bv))
		self.btnStepInto = QPushButton("Step")
		self.btnStepInto.clicked.connect(lambda : binjaplug.debug_step(self.bv))
		self.btnStepOver = QPushButton("Step Over")
		self.btnStepOver.clicked.connect(lambda : binjaplug.debug_step_over(self.bv))
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

	def __del__(self):
		# This widget is tasked with cleaning up the state after the view is closed
		binjaplug.delete_state(self.bv)

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
