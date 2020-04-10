from PySide2.QtWidgets import QApplication, QWidget
from binaryninjaui import DockHandler
import sys
import traceback

debug_dockwidgets = []

def create_widget(widget_class, name, parent, data, *args):
	# It is imperative this function return *some* value because Shiboken will try to deref what we return
	# If we return nothing (or throw) there will be a null pointer deref (and we won't even get to see why)
	# So in the event of an error or a nothing, return an empty widget that at least stops the crash
	try:
		widget = widget_class(parent, name, data, *args)

		if not widget:
			raise Exception('expected widget, got None')

		global debug_dockwidgets

		found = False
		for (bv, widgets) in debug_dockwidgets:
			if bv == data:
				widgets[name] = widget
				found = True

		if not found:
			debug_dockwidgets.append((data, {
				name: widget
			}))

		widget.destroyed.connect(lambda destroyed: destroy_widget(destroyed, widget, data, name))

		return widget
	except Exception as e:
		traceback.print_exc(file=sys.stderr)
		return QWidget(parent)

def destroy_widget(destroyed, old, data, name):
	# Gotta be careful to delete the correct widget here
	for (bv, widgets) in debug_dockwidgets:
		if bv == data:
			for (name, widget) in widgets.items():
				if widget == old:
					# If there are no other references to it, this will be the only one and the call
					# will delete it and invoke __del__.
					widgets.pop(name)
					return


def register_dockwidget(widget_class, name, area, orientation, default_visibility, *args):
	dock_handler = DockHandler.getActiveDockHandler()

	# create main debugger controls
	dock_handler.addDockWidget(name, lambda n,p,d: create_widget(widget_class, n, p, d, *args), area, orientation, default_visibility)

def get_dockwidget(data, name):
	for (bv, widgets) in debug_dockwidgets:
		if bv == data:
			return widgets.get(name)

	return None

