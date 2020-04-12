# This plugin supports scripting both in the ui and in headless plugins
# Start scripts with the following:
# import debugger
# dbg = debugger.get(bv)

# warn if minimum version not met
import binaryninja
import sys
import re

min_version = 2085
(incrementing, _, development) = re.search(r"^\d+.\d+.(\d+)( Personal)?( development)?", binaryninja.core_version()).groups()

# git builds end with ' development'
if not development:
	if int(incrementing) < min_version:
		message = "Debugger relies on features and fixes present in Binary Ninja >= {}. Errors may follow, please update.".format(min_version)
		if binaryninja.core_ui_enabled():
			binaryninja.interaction.show_message_box("Debugger Version Check Failed", message)
		else:
			print(message, file=sys.stderr)

from . import binjaplug

"""
Retrieve the debugger state instance for a given BinaryView
"""
def get(bv):
	return binjaplug.get_state(bv)

