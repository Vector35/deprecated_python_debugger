# This plugin supports scripting both in the ui and in headless plugins
# Start scripts with the following:
# import debugger
# dbg = debugger.get(bv)

# warn if minimum version not met
import binaryninja
import sys
min_version = 2085
# git builds end with ' development'
if not binaryninja.core_version().endswith(" development"):
	(major, minor, incrementing) = map(int, binaryninja.core_version().split('-')[0].split('.'))
	if incrementing < min_version:
		if binaryninja.core_ui_enabled():
			binaryninja.interaction.show_message_box("Debugger Version Check Failed", "Debugger relies on features and fixes present in Binary Ninja >= %d. Errors may follow, please update." % min_version)
		else:
			print("Debugger relies on features and fixes present in Binary Ninja >= %d. Errors may follow, please update." % min_version, file=sys.stderr)

from . import binjaplug

"""
Retrieve the debugger state instance for a given BinaryView
"""
def get(bv):
	return binjaplug.get_state(bv)

