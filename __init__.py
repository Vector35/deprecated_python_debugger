# This plugin supports scripting both in the ui and in headless plugins
# Start scripts with the following:
# import debugger
# dbg = debugger.get(bv)

# warn if minimum version not met
import binaryninja
min_version = 2085
(major, minor, incrementing) = map(int, binaryninja.core_version().split('-')[0].split('.'))
if incrementing < min_version:
	binaryninja.interaction.show_message_box("Debugger Version Check Failed", "Debugger relies on features and fixes present in Binary Ninja >= %d. Errors may follow, please update." % min_version)

from . import binjaplug

"""
Retrieve the debugger state instance for a given BinaryView
"""
def get(bv):
	return binjaplug.get_state(bv)

