from PySide2 import QtCore
from PySide2.QtCore import Qt, QAbstractItemModel, QModelIndex, QSize
from PySide2.QtGui import QPalette, QFontMetricsF
from PySide2.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget, QTableView, QItemDelegate, QStyle, QHeaderView, QAbstractItemView

import binaryninjaui
from binaryninjaui import DockContextHandler, UIActionHandler, ThemeColor
from binaryninja import BinaryView

from . import widget
from .. import binjaplug

breakpoints = {}

class DebugBreakpointsListModel(QAbstractItemModel):
	def __init__(self, parent, bv):
		QAbstractItemModel.__init__(self, parent)
		self.bv = bv
		self.columns = ["Enabled", "Location", "Remote Address"]
		self.update_rows(None)

	def update_rows(self, new_rows):
		self.beginResetModel()

		if new_rows is None:
			self.rows = []
		else:
			self.rows = new_rows

		self.endResetModel()

	"""
	General outline for QAbstractItemModel. We have to implement any pure virtual functions (fn = 0)

	virtual QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const = 0;
	virtual QModelIndex parent(const QModelIndex &child) const = 0;
	virtual bool hasChildren(const QModelIndex &parent = QModelIndex()) const;

	virtual int rowCount(const QModelIndex &parent = QModelIndex()) const = 0;
	virtual int columnCount(const QModelIndex &parent = QModelIndex()) const = 0;

	virtual QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const = 0;
	virtual bool setData(const QModelIndex &index, const QVariant &value, int role = Qt::EditRole);

	virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
	virtual bool setHeaderData(int section, Qt::Orientation orientation, const QVariant &value, int role = Qt::EditRole);

	virtual void sort(int column, Qt::SortOrder order) override;
	virtual Qt::ItemFlags flags(const QModelIndex& i) const override;
	"""

	def index(self, row, column, parent):
		if parent.isValid() or column > len(self.columns) or row >= len(self.rows):
			return QModelIndex()
		return self.createIndex(row, column)

	def parent(self, child):
		return QModelIndex()

	def hasChildren(self, parent):
		return False

	def rowCount(self, parent):
		if parent.isValid():
			return 0
		return len(self.rows)

	def columnCount(self, parent):
		return len(self.columns)

	def headerData(self, section, orientation, role):
		if role != Qt.DisplayRole:
			return None
		if orientation == Qt.Vertical:
			return None
		return self.columns[section]

	def data(self, index, role):
		if not index.isValid():
			return None
		if index.row() < 0 or index.row() >= len(self.rows):
			return None
		if role != Qt.DisplayRole:
			return None

		conts = self.rows[index.row()]

		# Format data into displayable text
		if self.columns[index.column()] == 'Location':
			text = '%s+0x%x' % (conts['module'], conts['offset'])
		elif self.columns[index.column()] == 'Remote Address':
			text = '%x' % conts['address']
		elif self.columns[index.column()] == 'Enabled':
			text = str(conts['enabled'])
		return text


class DebugBreakpointsItemDelegate(QItemDelegate):
	def __init__(self, parent):
		QItemDelegate.__init__(self, parent)

		self.font = binaryninjaui.getMonospaceFont(parent)
		self.font.setKerning(False)
		self.baseline = QFontMetricsF(self.font).ascent()
		self.char_width = binaryninjaui.getFontWidthAndAdjustSpacing(self.font)[0]
		self.char_height = QFontMetricsF(self.font).height()
		self.char_offset = binaryninjaui.getFontVerticalOffset()

		self.expected_char_widths = [10, 20, 20]

	"""
	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	"""
	def sizeHint(self, option, idx):
		return QSize(self.char_width * self.expected_char_widths[idx.column()] + 4, self.char_height)

	"""
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	"""
	def paint(self, painter, option, idx):
		# Draw background highlight in theme style
		selected = option.state & QStyle.State_Selected != 0
		if selected:
			painter.setBrush(binaryninjaui.getThemeColor(ThemeColor.SelectionColor))
		else:
			painter.setBrush(option.backgroundBrush)
		painter.setPen(Qt.NoPen)
		painter.drawRect(option.rect)

		text = idx.data()
		max_width = option.rect.width() // self.char_width
		if len(text) > max_width:
			text = text[:max_width - 1] + '…'

		# Draw text
		painter.setFont(self.font)
		painter.setPen(option.palette.color(QPalette.WindowText).rgba())
		painter.drawText(2 + option.rect.left(), self.char_offset + self.baseline + option.rect.top(), str(text))


class DebugBreakpointsWidget(QWidget, DockContextHandler):
	def __init__(self, parent, name, data):
		if not type(data) == BinaryView:
			raise Exception('expected widget data to be a BinaryView')

		self.bv = data

		QWidget.__init__(self, parent)
		DockContextHandler.__init__(self, self, name)
		self.actionHandler = UIActionHandler()
		self.actionHandler.setupActionHandler(self)

		self.table = QTableView(self)
		self.model = DebugBreakpointsListModel(self.table, data)
		self.table.setModel(self.model)

		self.item_delegate = DebugBreakpointsItemDelegate(self)
		self.table.setItemDelegate(self.item_delegate)

		# self.table.setSortingEnabled(True)
		self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
		self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)

		self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
		self.table.verticalHeader().setVisible(False)

		self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
		self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)

		self.table.resizeColumnsToContents()
		self.table.resizeRowsToContents()

		for i in range(len(self.model.columns)):
			self.table.setColumnWidth(i, self.item_delegate.sizeHint(self.table.viewOptions(), self.model.index(-1, i, QModelIndex())).width())
		self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)

		layout = QVBoxLayout()
		layout.setContentsMargins(0, 0, 0, 0)
		layout.setSpacing(0)
		layout.addWidget(self.table)
		self.setLayout(layout)

	def notifyOffsetChanged(self, offset):
		pass

	def notifyBreakpointsChanged(self, new_rows):
		self.model.update_rows(new_rows)

	def contextMenuEvent(self, event):
		self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

	def shouldBeVisible(self, view_frame):
		if view_frame is None:
			return False
		else:
			return True

