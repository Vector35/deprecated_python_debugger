import binaryninja
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit, QToolBar, QToolButton, QMenu, QAction

from .. import binjaplug

class DebugControlsWidget(QToolBar):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		QToolBar.__init__(self, parent)

		# TODO: Is there a cleaner way to do this?
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
		self.actionStepReturn = QAction("Step Return", self)
		self.actionStepReturn.triggered.connect(lambda: binjaplug.debug_step_return(self.bv))

		# session control menu
		self.controlMenu = QMenu("Process Control", self)
		self.controlMenu.addAction(self.actionRun)
		self.controlMenu.addAction(self.actionRestart)
		self.controlMenu.addAction(self.actionQuit)
		self.controlMenu.addSeparator()
		# TODO: Attach to running process
		# self.controlMenu.addAction(self.actionAttach)
		self.controlMenu.addAction(self.actionDetach)
		# TODO: Switch adapter/etc (could go in regular settings)
		# self.controlMenu.addSeparator()
		# self.controlMenu.addAction(self.actionSettings)

		self.btnControl = QToolButton(self)
		self.btnControl.setMenu(self.controlMenu)
		self.btnControl.setPopupMode(QToolButton.MenuButtonPopup)
		self.btnControl.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
		self.btnControl.setDefaultAction(self.actionRun)
		self.addWidget(self.btnControl)

		# execution control buttons
		self.addAction(self.actionBreak)
		self.addAction(self.actionResume)
		self.addAction(self.actionStepInto)
		self.addAction(self.actionStepOver)
		# TODO: Step until returning from current function
		self.addAction(self.actionStepReturn)

		self.threadMenu = QMenu("Threads", self)

		self.btnThreads = QToolButton(self)
		self.btnThreads.setMenu(self.threadMenu)
		self.btnThreads.setPopupMode(QToolButton.InstantPopup)
		self.btnThreads.setToolButtonStyle(Qt.ToolButtonTextOnly)
		self.addWidget(self.btnThreads)

		self.setThreadList([])

		self.editStatus = QLineEdit('INACTIVE', self)
		self.editStatus.setReadOnly(True)
		self.editStatus.setAlignment(QtCore.Qt.AlignCenter)
		self.addWidget(self.editStatus)

		# disable buttons
		self.setActionsEnabled(Run=True, Restart=False, Quit=False, Attach=True, Detach=False, Break=False, Resume=False, StepInto=False, StepOver=False, StepReturn=False)
		self.setResumeBreak(False)

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
			"Threads": lambda e: self.btnThreads.setEnabled(e),
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

	def setResumeBreak(self, is_resume):
		self.actionResume.setVisible(is_resume)
		self.actionBreak.setVisible(not is_resume)

	def setThreadList(self, threads):
		def select_thread_fn(tid):
			def select_thread(tid):
				stateObj = binjaplug.get_state(self.bv)
				if stateObj.state == 'STOPPED':
					adapter = stateObj.adapter
					adapter.thread_select(tid)
					binjaplug.context_display(self.bv)
				else:
					print('cannot set thread in state %s' % stateObj.state)

			return lambda: select_thread(tid)

		self.threadMenu.clear()
		if len(threads) > 0:
			selected = binjaplug.get_state(self.bv).adapter.thread_selected()
			for thread in threads:
				item_name = "Thread {} at {}".format(thread['tid'], hex(thread['rip']))
				action = self.threadMenu.addAction(item_name, select_thread_fn(thread['tid']))
				if thread['tid'] == selected:
					self.btnThreads.setDefaultAction(action)
		else:
			defaultThreadAction = self.threadMenu.addAction("Thread List")
			defaultThreadAction.setEnabled(False)
			self.btnThreads.setDefaultAction(defaultThreadAction)
