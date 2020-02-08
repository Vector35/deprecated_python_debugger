import binaryninja
from binaryninjaui import DockHandler, DockContextHandler, UIActionHandler, getMonospaceFont
from PySide2 import QtCore
from PySide2.QtCore import Qt, QSize
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QLabel, QWidget, QPushButton, QLineEdit, QTextEdit

from .. import binjaplug

class DebugConsoleWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		layout = QVBoxLayout()
		self.consoleText = QTextEdit(self)
		self.consoleText.setReadOnly(True)
		layout.addWidget(self.consoleText, 1)

		inputLayout = QHBoxLayout()
		inputLayout.setContentsMargins(4, 4, 4, 4)

		promptLayout = QVBoxLayout()
		promptLayout.setContentsMargins(0, 5, 0, 5)

		inputLayout.addLayout(promptLayout)

		self.consoleEntry = QLineEdit(self)
		inputLayout.addWidget(self.consoleEntry, 1)

		label = QLabel("lldb>>> ", self)
		label.setFont(getMonospaceFont(self))
		promptLayout.addWidget(label)
		promptLayout.addStretch(1)

		self.consoleEntry.returnPressed.connect(lambda: self.consoleText.append("TODO"))

		layout.addLayout(inputLayout)
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		self.setLayout(layout)

	def sizeHint(self):
		return QSize(300, 100)

	#--------------------------------------------------------------------------
	# callbacks to us api/ui/dockhandler.h
	#--------------------------------------------------------------------------
	def notifyOffsetChanged(self, offset):
		pass

	def notifyViewChanged(self, view_frame):
		pass

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return view_frame.getCurrentView().startswith("Debugger:")
