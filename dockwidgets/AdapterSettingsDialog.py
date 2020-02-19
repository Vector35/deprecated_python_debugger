from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QDialog, QPushButton, QFormLayout, QLineEdit, QLabel

import binaryninja
import binaryninjaui
from binaryninja import BinaryView, Settings, SettingsScope
from binaryninjaui import DockContextHandler, UIActionHandler, LinearView, ViewFrame, UIContext

import shlex

from .. import binjaplug

class AdapterSettingsDialog(QDialog):
	def __init__(self, parent, data):
		assert type(data) == binaryninja.binaryview.BinaryView
		self.bv = data
		QDialog.__init__(self, parent)

		self.setWindowTitle("Debug Adapter Settings")
		self.setMinimumSize(UIContext.getScaledWindowSize(400, 130))
		self.setAttribute(Qt.WA_DeleteOnClose)

		layout = QVBoxLayout()
		layout.setSpacing(0)

		titleLabel = QLabel("Adapter Settings")
		titleLayout = QHBoxLayout()
		titleLayout.setContentsMargins(0, 0, 0, 0)
		titleLayout.addWidget(titleLabel)

		self.argumentsEntry = QLineEdit(self)
		# self.addressEntry = QLineEdit(self)
		# self.portEntry = QLineEdit(self)

		formLayout = QFormLayout()
		formLayout.addRow("Command Line Arguments", self.argumentsEntry)
		# formLayout.addRow("Address", self.addressEntry)
		# formLayout.addRow("Port", self.portEntry)

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
		layout.addLayout(formLayout)
		layout.addStretch(1)
		layout.addSpacing(10)
		layout.addLayout(buttonLayout)

		self.setLayout(layout)

		debug_state = binjaplug.get_state(self.bv)

		# settings = Settings()
		# address = settings.get_string_with_scope("debugger.adapter.address", data, SettingsScope.SettingsContextScope)
		# port = settings.get_integer_with_scope("debugger.adapter.port", data, SettingsScope.SettingsContextScope)

		# self.addressEntry.setText(address[0])
		# self.portEntry.setText(str(port[0]))

		# self.addressEntry.textEdited.connect(lambda: self.updateSettings())
		# self.portEntry.textEdited.connect(lambda: self.updateSettings())

		self.argumentsEntry.setText(' ' .join(shlex.quote(arg) for arg in debug_state.command_line_args))
		self.argumentsEntry.textEdited.connect(lambda: self.updateArguments())

		self.accepted.connect(lambda: self.apply())

	# def updateSettings(self):
	# 	settings = Settings()
	# 	address = self.addressEntry.text()
	# 	port = int(self.portEntry.text())
	# 	settings.set_string("debugger.adapter.address", address, self.bv, SettingsScope.SettingsContextScope)
	# 	settings.set_integer("debugger.adapter.port", port, self.bv, SettingsScope.SettingsContextScope)

	def apply(self):
		debug_state = binjaplug.get_state(self.bv)
		arguments = shlex.split(self.argumentsEntry.text())
		debug_state.command_line_args = arguments
		self.bv.store_metadata('debugger.command_line_args', arguments)

	def updateArguments(self):
		try:
			arguments = shlex.split(self.argumentsEntry.text())
			self.acceptButton.setEnabled(True)
		except:
			self.acceptButton.setEnabled(False)

