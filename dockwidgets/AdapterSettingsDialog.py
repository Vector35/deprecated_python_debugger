from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QDialog, QPushButton, QFormLayout, QLineEdit, QLabel, QMenu

import binaryninja
import binaryninjaui
from binaryninja import BinaryView, Settings, SettingsScope
from binaryninjaui import DockContextHandler, UIActionHandler, LinearView, ViewFrame, UIContext

import shlex

from .. import binjaplug, DebugAdapter

class AdapterSettingsDialog(QDialog):
	def __init__(self, parent, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data
		QDialog.__init__(self, parent)

		debug_state = binjaplug.get_state(self.bv)

		self.setWindowTitle("Debug Adapter Settings")
		self.setMinimumSize(UIContext.getScaledWindowSize(400, 130))
		self.setAttribute(Qt.WA_DeleteOnClose)

		layout = QVBoxLayout()
		layout.setSpacing(0)

		titleLabel = QLabel("Adapter Settings")
		titleLayout = QHBoxLayout()
		titleLayout.setContentsMargins(0, 0, 0, 0)
		titleLayout.addWidget(titleLabel)

		self.adapterEntry = QPushButton(self)
		self.adapterMenu = QMenu(self)
		for adapter in DebugAdapter.ADAPTER_TYPE:
			def select_adapter(adapter):
				return lambda: self.selectAdapter(adapter)
			self.adapterMenu.addAction(adapter.name, select_adapter(adapter))
			if adapter == debug_state.adapter_type:
				self.adapterEntry.setText(adapter.name)

		self.adapterEntry.setMenu(self.adapterMenu)

		self.argumentsEntry = QLineEdit(self)
		self.addressEntry = QLineEdit(self)
		self.portEntry = QLineEdit(self)

		self.formLayout = QFormLayout()
		self.formLayout.addRow("Adapter Type", self.adapterEntry)
		self.formLayout.addRow("Command Line Arguments", self.argumentsEntry)
		self.formLayout.addRow("Address", self.addressEntry)
		self.formLayout.addRow("Port", self.portEntry)

		buttonLayout = QHBoxLayout()
		buttonLayout.setContentsMargins(0, 0, 0, 0)

		self.cancelButton = QPushButton("Cancel")
		self.cancelButton.clicked.connect(lambda: self.reject())
		self.acceptButton = QPushButton("Accept")
		self.acceptButton.clicked.connect(lambda: self.accept())
		self.acceptButton.setDefault(True)
		buttonLayout.addStretch(1)
		buttonLayout.addWidget(self.cancelButton)
		buttonLayout.addWidget(self.acceptButton)

		layout.addLayout(titleLayout)
		layout.addSpacing(10)
		layout.addLayout(self.formLayout)
		layout.addStretch(1)
		layout.addSpacing(10)
		layout.addLayout(buttonLayout)

		self.setLayout(layout)

		self.addressEntry.setText(debug_state.remote_host)
		self.portEntry.setText(str(debug_state.remote_port))

		self.addressEntry.textEdited.connect(lambda: self.apply())
		self.portEntry.textEdited.connect(lambda: self.apply())

		self.argumentsEntry.setText(' ' .join(shlex.quote(arg) for arg in debug_state.command_line_args))
		self.argumentsEntry.textEdited.connect(lambda: self.updateArguments())

		self.accepted.connect(lambda: self.apply())

	def selectAdapter(self, adapter):
		self.bv.store_metadata('debugger.adapter_type', adapter.value)
		debug_state = binjaplug.get_state(self.bv)
		debug_state.adapter_type = adapter
		self.adapterEntry.setText(adapter.name)

		if DebugAdapter.ADAPTER_TYPE.use_exec(adapter):
			self.argumentsEntry.setEnabled(True)
			self.addressEntry.setEnabled(False)
			self.portEntry.setEnabled(False)
		elif DebugAdapter.ADAPTER_TYPE.use_connect(adapter):
			self.argumentsEntry.setEnabled(False)
			self.addressEntry.setEnabled(True)
			self.portEntry.setEnabled(True)

	def apply(self):
		debug_state = binjaplug.get_state(self.bv)
		arguments = shlex.split(self.argumentsEntry.text())
		debug_state.command_line_args = arguments
		self.bv.store_metadata('debugger.command_line_args', arguments)

		address = self.addressEntry.text()
		port = int(self.portEntry.text())

		debug_state.remote_host = address
		debug_state.remote_port = port

		self.bv.store_metadata('debugger.remote_host', address)
		self.bv.store_metadata('debugger.remote_port', port)

	def updateArguments(self):
		try:
			arguments = shlex.split(self.argumentsEntry.text())
			self.acceptButton.setEnabled(True)
		except:
			self.acceptButton.setEnabled(False)

