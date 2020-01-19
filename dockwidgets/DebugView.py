from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QStyle, QSplitter

import binaryninja
import binaryninjaui
from binaryninja import BinaryView
from binaryninjaui import View, ViewType, UIActionHandler, LinearView, DisassemblyContainer, ViewFrame

from . import widget, ControlsWidget
from .. import binjaplug

class DebugView(QWidget, View):
	def __init__(self, parent, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		memory_view = binjaplug.get_state(data).memory_view
		binjaplug.get_state(data).debug_view = self

		QWidget.__init__(self, parent)
		View.__init__(self)

		self.setupView(self)

		self.current_offset = 0

		self.splitter = QSplitter(Qt.Orientation.Horizontal, self)

		frame = ViewFrame.viewFrameForWidget(self)
		self.memory_editor = LinearView(memory_view, frame)
		self.binary_editor = DisassemblyContainer(frame, data, frame)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.splitter.addWidget(self.binary_editor)
		self.splitter.addWidget(self.memory_editor)
		self.splitter.setSizes([100, 100])

		self.controls = ControlsWidget.DebugControlsWidget(self, "Controls", data)

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.controls)
		layout.addWidget(self.splitter, 100)
		self.setLayout(layout)
	
	def getData(self):
		return self.bv

	def getCurrentOffset(self):
		return self.current_offset
	
	def setCurrentOffset(self, offset):
		self.current_offset = offset
		UIContext.updateStatus(True)

	def getFont(self):
		return binaryninjaui.getMonospaceFont(self)

	def navigate(self, addr):
		return self.memory_editor.navigate(addr)

	def notifyMemoryChanged(self):
		adapter = binjaplug.get_state(self.bv).adapter

		# Refresh the editor
		if adapter is None:
			self.memory_editor.navigate(0)
			return

		self.memory_editor.navigate(adapter.reg_read('rsp'))

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

class DebugViewType(ViewType):
	def __init__(self):
		super(DebugViewType, self).__init__("Debugger", "Debugger")

	def getPriority(self, data, filename):
		return 1

	def create(self, data, view_frame):
		return DebugView(view_frame, data)

