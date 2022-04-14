import binaryninjaui
if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
	from PySide6 import QtCore
	from PySide6.QtCore import Qt, QSize
	from PySide6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit, QTextEdit
	from PySide6.QtGui import QTextCursor
else:
	from PySide2 import QtCore
	from PySide2.QtCore import Qt, QSize
	from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit, QTextEdit
	from PySide2.QtGui import QTextCursor

import binaryninja
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont

from .. import binjaplug

class DebugConsoleWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		if not type(data) == binaryninja.binaryview.BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		layout = QVBoxLayout()
		self.consoleText = QTextEdit(self)
		self.consoleText.setReadOnly(True)
		self.consoleText.setFont(getMonospaceFont(self))
		layout.addWidget(self.consoleText, 1)

		inputLayout = QHBoxLayout()
		inputLayout.setContentsMargins(4, 4, 4, 4)

		promptLayout = QVBoxLayout()
		promptLayout.setContentsMargins(0, 5, 0, 5)

		inputLayout.addLayout(promptLayout)

		self.consoleEntry = QLineEdit(self)
		inputLayout.addWidget(self.consoleEntry, 1)

		self.entryLabel = QLabel("pydbg>>> ", self)
		self.entryLabel.setFont(getMonospaceFont(self))
		promptLayout.addWidget(self.entryLabel)
		promptLayout.addStretch(1)

		self.consoleEntry.returnPressed.connect(lambda: self.sendLine())

		layout.addLayout(inputLayout)
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		self.setLayout(layout)

	def sizeHint(self):
		return QSize(300, 100)

	def canWrite(self):
		debug_state = binjaplug.get_state(self.bv)
		try:
			return debug_state.adapter.stdin_is_writable()
		except:
			return False

	def sendLine(self):
		if not self.canWrite():
			return

		line = self.consoleEntry.text()
		self.consoleEntry.setText("")

		debug_state = binjaplug.get_state(self.bv)
		try:
			debug_state.send_console_input(line)
		except Exception as e:
			self.notifyStdout("Error sending input: {} {}\n".format(type(e).__name__, ' '.join(e.args)))

	def notifyStdout(self, line):
		self.consoleText.insertPlainText(line)

		# Scroll down
		cursor = self.consoleText.textCursor()
		cursor.clearSelection()
		cursor.movePosition(QTextCursor.End)
		self.consoleText.setTextCursor(cursor)

		self.updateEnabled()

	def updateEnabled(self):
		enabled = self.canWrite()
		self.consoleEntry.setEnabled(enabled)
		self.entryLabel.setText("stdin>>> " if enabled else "stdin (unavailable) ")

	#--------------------------------------------------------------------------
	# callbacks to us api/ui/dockhandler.h
	#--------------------------------------------------------------------------
	def notifyOffsetChanged(self, offset):
		self.updateEnabled()

	def notifyViewChanged(self, view_frame):
		self.updateEnabled()

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True
