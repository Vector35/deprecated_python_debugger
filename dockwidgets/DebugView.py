from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize, QTimer
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QStyle, QSplitter, QLabel

import binaryninja
import binaryninjaui
from binaryninja import BinaryView
from binaryninja.enums import InstructionTextTokenType
from binaryninjaui import View, ViewType, UIAction, UIActionHandler, LinearView, DisassemblyContainer, ViewFrame, DockHandler, TokenizedTextView

from . import widget, ControlsWidget
from .. import binjaplug

class DebugView(QWidget, View):
	def __init__(self, parent, data):
		if not type(data) == binaryninja.binaryview.BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.bv = data

		self.debug_state = binjaplug.get_state(data)
		memory_view = self.debug_state.memory_view
		self.debug_state.ui.debug_view = self

		QWidget.__init__(self, parent)
		View.__init__(self)

		self.setupView(self)

		self.current_offset = 0

		self.splitter = QSplitter(Qt.Orientation.Horizontal, self)

		frame = ViewFrame.viewFrameForWidget(self)
		self.memory_editor = LinearView(memory_view, frame)
		self.binary_editor = DisassemblyContainer(frame, data, frame)

		self.binary_text = TokenizedTextView(self, memory_view)
		self.is_raw_disassembly = False

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

		bv_layout = QVBoxLayout()
		bv_layout.setSpacing(0)
		bv_layout.setContentsMargins(0, 0, 0, 0)

		bv_label = QLabel("Loaded File")
		bv_label.setFont(small_font)
		bv_layout.addWidget(bv_label)
		bv_layout.addWidget(self.binary_editor)

		self.bv_widget = QWidget()
		self.bv_widget.setLayout(bv_layout)

		disasm_layout = QVBoxLayout()
		disasm_layout.setSpacing(0)
		disasm_layout.setContentsMargins(0, 0, 0, 0)

		disasm_label = QLabel("Raw Disassembly at PC")
		disasm_label.setFont(small_font)
		disasm_layout.addWidget(disasm_label)
		disasm_layout.addWidget(self.binary_text)

		self.disasm_widget = QWidget()
		self.disasm_widget.setLayout(disasm_layout)

		memory_layout = QVBoxLayout()
		memory_layout.setSpacing(0)
		memory_layout.setContentsMargins(0, 0, 0, 0)

		memory_label = QLabel("Debugged Process")
		memory_label.setFont(small_font)
		memory_layout.addWidget(memory_label)
		memory_layout.addWidget(self.memory_editor)

		self.memory_widget = QWidget()
		self.memory_widget.setLayout(memory_layout)

		self.splitter.addWidget(self.bv_widget)
		self.splitter.addWidget(self.memory_widget)

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
			adapter = self.debug_state.adapter

			# Refresh the editor
			if adapter is None:
				self.memory_editor.navigate(0)
				return

			self.memory_editor.navigate(adapter.reg_read('rsp'))

	def showEvent(self, event):
		if not event.spontaneous():
			self.update_timer.start()

	def hideEvent(self, event):
		if not event.spontaneous():
			self.update_timer.stop()

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

	def setRawDisassembly(self, raw=False, lines=[]):
		if raw != self.is_raw_disassembly:
			self.splitter.replaceWidget(0, self.disasm_widget if raw else self.bv_widget)
			self.is_raw_disassembly = raw

		# terrible workaround for libshiboken conversion issue
		for line in lines:
			# line is LinearDisassemblyLine
			last_tok = line.contents.tokens[-1]
			#if last_tok.type != InstructionTextTokenType.PossibleAddressToken: continue
			#if last_tok.width != 18: continue # strlen("0xFFFFFFFFFFFFFFF0")
			if last_tok.size != 8: continue
			#print('fixing: %s' % line)
			last_tok.value &= 0x7FFFFFFFFFFFFFFF

		self.binary_text.setLines(lines)

class DebugViewType(ViewType):
	def __init__(self):
		super(DebugViewType, self).__init__("Debugger", "Debugger")

	def getPriority(self, data, filename):
		return 1

	def create(self, data, view_frame):
		return DebugView(view_frame, data)

