from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize, QTimer
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QStyle, QSplitter, QLabel

import binaryninja
import binaryninjaui
from binaryninja import BinaryView
from binaryninjaui import View, ViewType, UIAction, UIActionHandler, LinearView, DisassemblyContainer, ViewFrame, DockHandler

from . import widget, ControlsWidget
from .. import binjaplug

class DebugView(QWidget, View):
	def __init__(self, parent, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data

		self.debug_state = binjaplug.get_state(data)
		memory_view = self.debug_state.memory_view
		self.debug_state.debug_view = self

		QWidget.__init__(self, parent)
		View.__init__(self)

		self.setupView(self)

		self.current_offset = 0

		self.splitter = QSplitter(Qt.Orientation.Horizontal, self)

		frame = ViewFrame.viewFrameForWidget(self)
		self.memory_editor = LinearView(memory_view, frame)
		self.binary_editor = DisassemblyContainer(frame, data, frame)

		# TODO: Handle these and change views accordingly
		# Currently they are just disabled as the DisassemblyContainer gets confused
		# about where to go and just shows a bad view
		self.binary_editor.getDisassembly().actionHandler().bindAction("View in Hex Editor", UIAction())
		self.binary_editor.getDisassembly().actionHandler().bindAction("View in Linear Disassembly", UIAction())
		self.binary_editor.getDisassembly().actionHandler().bindAction("View in Types View", UIAction())

		self.memory_editor.actionHandler().bindAction("View in Hex Editor", UIAction())
		self.memory_editor.actionHandler().bindAction("View in Disassembly Graph", UIAction())
		self.memory_editor.actionHandler().bindAction("View in Types View", UIAction())

		small_font = QApplication.font()
		small_font.setPointSize(11)

		left_layout = QVBoxLayout()
		left_layout.setSpacing(0)
		left_layout.setContentsMargins(0, 0, 0, 0)

		left_label = QLabel("Loaded File")
		left_label.setFont(small_font)
		left_layout.addWidget(left_label)
		left_layout.addWidget(self.binary_editor)

		left_widget = QWidget()
		left_widget.setLayout(left_layout)

		right_layout = QVBoxLayout()
		right_layout.setSpacing(0)
		right_layout.setContentsMargins(0, 0, 0, 0)

		right_label = QLabel("Debugged Process")
		right_label.setFont(small_font)
		right_layout.addWidget(right_label)
		right_layout.addWidget(self.memory_editor)

		right_widget = QWidget()
		right_widget.setLayout(right_layout)

		self.splitter.addWidget(left_widget)
		self.splitter.addWidget(right_widget)

		# Equally sized
		self.splitter.setSizes([0x7fffffff, 0x7fffffff])

		self.controls = ControlsWidget.DebugControlsWidget(self, "Controls", data, self.debug_state)

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.controls)
		layout.addWidget(self.splitter, 100)
		self.setLayout(layout)

		self.needs_update = True
		self.update_timer = QTimer(self)
		self.update_timer.setInterval(200)
		self.update_timer.setSingleShot(False)
		self.update_timer.timeout.connect(lambda: self.updateTimerEvent())

		# Add debugger state to the interpreter as `dbg`
		main_window = parent.window()
		dock_handler = main_window.findChild(DockHandler, '__DockHandler')
		if dock_handler:
			console = dock_handler.getDockWidget('Python Console')
			if console:
				# Hack: Currently no way to access the scripting provider directly
				# So just run the commands through the ui
				console.widget().addInput("import debugger\ndbg = debugger.get(bv)")

	def getData(self):
		return self.bv

	def getCurrentOffset(self):
		return self.binary_editor.getDisassembly().getCurrentOffset()

	def getFont(self):
		return binaryninjaui.getMonospaceFont(self)

	def navigate(self, addr):
		return self.binary_editor.getDisassembly().navigate(addr)

	def notifyMemoryChanged(self):
		self.needs_update = True

	def updateTimerEvent(self):
		if self.needs_update:
			self.needs_update = False
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

