import binaryninja
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit, QToolBar, QToolButton, QMenu, QAction

from .. import binjaplug

class DebugControlsWidget(QToolBar):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		QToolBar.__init__(self, parent)

		self.setStyleSheet("""
		QToolButton{padding: 4px 14px 4px 14px; font-size: 14pt;}
		QToolButton:disabled{color: palette(alternate-base)}
		""")

		self.actionRun = QAction("Run", self)
		self.actionRun.triggered.connect(lambda: binjaplug.debug_run(self.bv))
		self.actionRestart = QAction("Restart", self)
		self.actionRestart.triggered.connect(lambda: binjaplug.debug_restart(self.bv))
		self.actionQuit = QAction("Quit", self)
		self.actionQuit.triggered.connect(lambda: binjaplug.debug_quit(self.bv))
		self.actionAttach = QAction("Attach... (todo)", self)
		self.actionAttach.triggered.connect(lambda: ())
		self.actionDetach = QAction("Detach", self)
		self.actionDetach.triggered.connect(lambda: binjaplug.debug_detach(self.bv))
		self.actionSettings = QAction("Adapter Settings... (todo)", self)
		self.actionSettings.triggered.connect(lambda: ())
		self.actionBreak = QAction("Break", self)
		self.actionBreak.triggered.connect(lambda: binjaplug.debug_break(self.bv))
		self.actionResume = QAction("Resume", self)
		self.actionResume.triggered.connect(lambda: binjaplug.debug_go(self.bv))
		self.actionStepInto = QAction("Step Into", self)
		self.actionStepInto.triggered.connect(lambda: binjaplug.debug_step(self.bv))
		self.actionStepOver = QAction("Step Over", self)
		self.actionStepOver.triggered.connect(lambda: binjaplug.debug_step_over(self.bv))
		self.actionStepReturn = QAction("Step Return (todo)", self)
		self.actionStepReturn.triggered.connect(lambda: ())

		# session control menu
		self.controlMenu = QMenu("Process Control", self)
		self.btnRun = self.controlMenu.addAction(self.actionRun)
		self.btnRestart = self.controlMenu.addAction(self.actionRestart)
		self.btnQuit = self.controlMenu.addAction(self.actionQuit)
		self.controlMenu.addSeparator()
		self.btnAttach = self.controlMenu.addAction(self.actionAttach)
		self.btnDetach = self.controlMenu.addAction(self.actionDetach)
		self.controlMenu.addSeparator()
		self.btnSettings = self.controlMenu.addAction(self.actionSettings)

		self.btnControl = QToolButton(self)
		self.btnControl.setMenu(self.controlMenu)
		self.btnControl.setPopupMode(QToolButton.MenuButtonPopup)
		self.btnControl.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
		self.btnControl.setDefaultAction(self.actionRun)
		self.addWidget(self.btnControl)

		# execution control buttons
		self.btnBreak = self.addAction(self.actionBreak)
		self.btnResume = self.addAction(self.actionResume)
		self.btnStepInto = self.addAction(self.actionStepInto)
		self.btnStepOver = self.addAction(self.actionStepOver)
		self.btnStepReturn = self.addAction(self.actionStepReturn)

		# l = QLabel("Debugger State: ", self)
		self.editStatus = QLineEdit('INACTIVE', self)
		self.editStatus.setReadOnly(True)
		self.editStatus.setAlignment(QtCore.Qt.AlignCenter)
		self.addWidget(self.editStatus)

		# disable buttons
		self.setActionsEnabled(Run=True, Restart=False, Quit=False, Attach=True, Detach=False, Break=False, Resume=False, StepInto=False, StepOver=False, StepReturn=False)

	def __del__(self):
		# TODO: Move this elsewhere
		# This widget is tasked with cleaning up the state after the view is closed
		binjaplug.delete_state(self.bv)

	def setActionsEnabled(self, **kwargs):
		def enableStarting(e):
			self.actionRun.setEnabled(e)
			self.actionAttach.setEnabled(e)

		def enableStopping(e):
			self.actionRestart.setEnabled(e)
			self.actionQuit.setEnabled(e)
			self.actionDetach.setEnabled(e)

		def enableStepping(e):
			self.actionStepInto.setEnabled(e)
			self.actionStepOver.setEnabled(e)
			self.actionStepReturn.setEnabled(e)

		actions = {
			"Run": lambda e: self.actionRun.setEnabled(e),
			"Restart": lambda e: self.actionRestart.setEnabled(e),
			"Quit": lambda e: self.actionQuit.setEnabled(e),
			"Attach": lambda e: self.actionAttach.setEnabled(e),
			"Detach": lambda e: self.actionDetach.setEnabled(e),
			"Break": lambda e: self.actionBreak.setEnabled(e),
			"Resume": lambda e: self.actionResume.setEnabled(e),
			"StepInto": lambda e: self.actionStepInto.setEnabled(e),
			"StepOver": lambda e: self.actionStepOver.setEnabled(e),
			"StepReturn": lambda e: self.actionStepReturn.setEnabled(e),
			"Starting": enableStarting,
			"Stopping": enableStopping,
			"Stepping": enableStepping,
		}
		for (action, enabled) in kwargs.items():
			actions[action](enabled)

	def setDefaultProcessAction(self, action):
		actions = {
			"Run": self.actionRun,
			"Restart": self.actionRestart,
			"Quit": self.actionQuit,
			"Attach": self.actionAttach,
			"Detach": self.actionDetach,
		}
		self.btnControl.setDefaultAction(actions[action])

	#--------------------------------------------------------------------------
	# callbacks to us api/ui/dockhandler.h
	#--------------------------------------------------------------------------
	def notifyOffsetChanged(self, offset):
		#self.offset.setText(hex(offset))
		pass

	def notifyViewChanged(self, view_frame):
		# many options on view_frame, see api/ui/viewframe.h
		pass
		# if view_frame is None:
		# 	self.bv = None
		# else:
		# 	view = view_frame.getCurrentViewInterface()
		# 	data = view.getData()
		# 	assert type(data) == binaryninja.binaryview.BinaryView
		# 	self.bv = data
		# 	if self.bv.file and self.bv.file.filename:
		# 		self.labelTarget.setText('Target: ' + self.bv.file.filename)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True
