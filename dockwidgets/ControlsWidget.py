import binaryninja
from binaryninja import execute_on_main_thread_and_wait
from PySide2 import QtCore
from PySide2.QtCore import Qt
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit, QToolBar, QToolButton, QMenu, QAction
import threading

from .. import binjaplug, DebugAdapter

class DebugControlsWidget(QToolBar):
	def __init__(self, parent, name, data, debug_state):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data
		self.debug_state = debug_state

		QToolBar.__init__(self, parent)

		# TODO: Is there a cleaner way to do this?
		self.setStyleSheet("""
		QToolButton{padding: 4px 14px 4px 14px; font-size: 14pt;}
		QToolButton:disabled{color: palette(alternate-base)}
		""")

		self.actionRun = QAction("Run", self)
		self.actionRun.triggered.connect(lambda: self.perform_run())
		self.actionRestart = QAction("Restart", self)
		self.actionRestart.triggered.connect(lambda: self.perform_restart())
		self.actionQuit = QAction("Quit", self)
		self.actionQuit.triggered.connect(lambda: self.perform_quit())
		self.actionAttach = QAction("Attach... (todo)", self)
		self.actionAttach.triggered.connect(lambda: self.perform_attach())
		self.actionDetach = QAction("Detach", self)
		self.actionDetach.triggered.connect(lambda: self.perform_detach())
		self.actionSettings = QAction("Adapter Settings... (todo)", self)
		self.actionSettings.triggered.connect(lambda: self.perform_settings())
		self.actionPause = QAction("Pause", self)
		self.actionPause.triggered.connect(lambda: self.perform_pause())
		self.actionResume = QAction("Resume", self)
		self.actionResume.triggered.connect(lambda: self.perform_resume())
		self.actionStepInto = QAction("Step Into", self)
		self.actionStepInto.triggered.connect(lambda: self.perform_step_into())
		self.actionStepOver = QAction("Step Over", self)
		self.actionStepOver.triggered.connect(lambda: self.perform_step_over())
		self.actionStepReturn = QAction("Step Return", self)
		self.actionStepReturn.triggered.connect(lambda: self.perform_step_return())

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
		self.addAction(self.actionPause)
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

		self.set_thread_list([])

		self.editStatus = QLineEdit('INACTIVE', self)
		self.editStatus.setReadOnly(True)
		self.editStatus.setAlignment(QtCore.Qt.AlignCenter)
		self.addWidget(self.editStatus)

		# disable buttons
		self.set_actions_enabled(Run=True, Restart=False, Quit=False, Attach=True, Detach=False, Pause=False, Resume=False, StepInto=False, StepOver=False, StepReturn=False)
		self.set_resume_pause_action("Pause")

	def __del__(self):
		# TODO: Move this elsewhere
		# This widget is tasked with cleaning up the state after the view is closed
		binjaplug.delete_state(self.bv)

	def perform_run(self):
		self.debug_state.run()
		self.state_stopped()
		self.debug_state.context_display()

	def perform_restart(self):
		self.debug_state.restart()
		self.state_stopped()

	def perform_quit(self):
		self.debug_state.quit()
		self.state_inactive()

	def perform_attach(self):
		# TODO: Show dialog to select adapter/address/process
		pass

	def perform_detach(self):
		self.debug_state.detach()
		self.state_inactive()

	def perform_settings(self):
		# TODO: Show settings dialog
		pass

	def perform_pause(self):
		self.debug_state.pause()

	def perform_resume(self):

		def perform_resume_thread():
			(reason, data) = self.debug_state.go()
			execute_on_main_thread_and_wait(lambda: self.handle_stop_return(reason, data))
			execute_on_main_thread_and_wait(lambda: self.debug_state.context_display())

		self.state_running()
		threading.Thread(target=perform_resume_thread).start()

	def perform_step_into(self):

		def perform_step_into_thread():
			(reason, data) = self.debug_state.step_into()
			execute_on_main_thread_and_wait(lambda: self.handle_stop_return(reason, data))
			execute_on_main_thread_and_wait(lambda: self.debug_state.context_display())

		self.state_busy("STEPPING")
		threading.Thread(target=perform_step_into_thread).start()

	def perform_step_over(self):

		def perform_step_over_thread():
			(reason, data) = self.debug_state.step_over()
			execute_on_main_thread_and_wait(lambda: self.handle_stop_return(reason, data))
			execute_on_main_thread_and_wait(lambda: self.debug_state.context_display())

		self.state_busy("STEPPING")
		threading.Thread(target=perform_step_over_thread).start()

	def perform_step_return(self):

		def perform_step_return_thread():
			(reason, data) = self.debug_state.step_return()
			execute_on_main_thread_and_wait(lambda: self.handle_stop_return(reason, data))
			execute_on_main_thread_and_wait(lambda: self.debug_state.context_display())

		self.state_busy("STEPPING")
		threading.Thread(target=perform_step_return_thread).start()

	def set_actions_enabled(self, **kwargs):
		def enable_starting(e):
			self.actionRun.setEnabled(e)
			self.actionAttach.setEnabled(e)

		def enable_stopping(e):
			self.actionRestart.setEnabled(e)
			self.actionQuit.setEnabled(e)
			self.actionDetach.setEnabled(e)

		def enable_stepping(e):
			self.actionStepInto.setEnabled(e)
			self.actionStepOver.setEnabled(e)
			self.actionStepReturn.setEnabled(e)

		actions = {
			"Run": lambda e: self.actionRun.setEnabled(e),
			"Restart": lambda e: self.actionRestart.setEnabled(e),
			"Quit": lambda e: self.actionQuit.setEnabled(e),
			"Attach": lambda e: self.actionAttach.setEnabled(e),
			"Detach": lambda e: self.actionDetach.setEnabled(e),
			"Pause": lambda e: self.actionPause.setEnabled(e),
			"Resume": lambda e: self.actionResume.setEnabled(e),
			"StepInto": lambda e: self.actionStepInto.setEnabled(e),
			"StepOver": lambda e: self.actionStepOver.setEnabled(e),
			"StepReturn": lambda e: self.actionStepReturn.setEnabled(e),
			"Threads": lambda e: self.btnThreads.setEnabled(e),
			"Starting": enable_starting,
			"Stopping": enable_stopping,
			"Stepping": enable_stepping,
		}
		for (action, enabled) in kwargs.items():
			actions[action](enabled)

	def set_default_process_action(self, action):
		actions = {
			"Run": self.actionRun,
			"Restart": self.actionRestart,
			"Quit": self.actionQuit,
			"Attach": self.actionAttach,
			"Detach": self.actionDetach,
		}
		self.btnControl.setDefaultAction(actions[action])

	def set_resume_pause_action(self, action):
		self.actionResume.setVisible(action == "Resume")
		self.actionPause.setVisible(action == "Pause")

	def set_thread_list(self, threads):
		def select_thread_fn(tid):
			def select_thread(tid):
				stateObj = binjaplug.get_state(self.bv)
				if stateObj.state == 'STOPPED':
					adapter = stateObj.adapter
					adapter.thread_select(tid)
					self.debug_state.context_display()
				else:
					print('cannot set thread in state %s' % stateObj.state)

			return lambda: select_thread(tid)

		self.threadMenu.clear()
		if len(threads) > 0:
			for thread in threads:
				item_name = "Thread {} at {}".format(thread['tid'], hex(thread['rip']))
				action = self.threadMenu.addAction(item_name, select_thread_fn(thread['tid']))
				if thread['selected']:
					self.btnThreads.setDefaultAction(action)
		else:
			defaultThreadAction = self.threadMenu.addAction("Thread List")
			defaultThreadAction.setEnabled(False)
			self.btnThreads.setDefaultAction(defaultThreadAction)

	def state_inactive(self, msg=None):
		debug_state = binjaplug.get_state(self.bv)

		# clear breakpoints
		debug_state.breakpoint_tag_del()
		debug_state.breakpoints = {}

		debug_state.state = 'INACTIVE'
		self.editStatus.setText(msg or debug_state.state)
		self.set_actions_enabled(Starting=True, Stopping=False, Stepping=False, Pause=False, Resume=False, Threads=False)
		self.set_default_process_action("Run")
		self.set_thread_list([])
		self.set_resume_pause_action("Pause")

	def state_stopped(self, msg=None):
		debug_state = binjaplug.get_state(self.bv)
		debug_state.state = 'STOPPED'
		self.editStatus.setText(msg or debug_state.state)
		self.set_actions_enabled(Starting=False, Stopping=True, Stepping=True, Pause=True, Resume=True, Threads=True)
		self.set_default_process_action("Quit")
		self.set_resume_pause_action("Resume")

	def state_running(self, msg=None):
		debug_state = binjaplug.get_state(self.bv)
		debug_state.state = 'RUNNING'
		self.editStatus.setText(msg or debug_state.state)
		self.set_actions_enabled(Starting=False, Stopping=True, Stepping=False, Pause=True, Resume=False, Threads=False)
		self.set_default_process_action("Quit")
		self.set_resume_pause_action("Pause")

	def state_busy(self, msg=None):
		debug_state = binjaplug.get_state(self.bv)
		debug_state.state = 'RUNNING'
		self.editStatus.setText(msg or debug_state.state)
		self.set_actions_enabled(Starting=False, Stopping=True, Stepping=False, Pause=True, Resume=False, Threads=False)
		self.set_default_process_action("Quit")
		self.set_resume_pause_action("Pause")

	def state_error(self, msg=None):
		debug_state = binjaplug.get_state(self.bv)
		debug_state.state = 'ERROR'
		self.editStatus.setText(msg or debug_state.state)
		self.set_actions_enabled(Run=True, Restart=True, Quit=True, Attach=True, Detach=True, Pause=True, Resume=True, StepInto=True, StepOver=True, StepReturn=True, Threads=True)
		self.set_default_process_action("Run")
		self.set_thread_list([])
		self.set_resume_pause_action("Resume")

	def handle_stop_return(self, reason, data):
		if reason == DebugAdapter.STOP_REASON.STDOUT_MESSAGE:
			self.state_stopped('stdout: '+data)
		elif reason == DebugAdapter.STOP_REASON.PROCESS_EXITED:
			self.debug_state.quit()
			self.state_inactive('process exited, return code=%d' % data)
		elif reason == DebugAdapter.STOP_REASON.BACKEND_DISCONNECTED:
			self.debug_state.quit()
			self.state_inactive('backend disconnected (process exited?)')
