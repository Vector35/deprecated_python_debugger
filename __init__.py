# This plugin supports scripting both in the ui and in headless plugins
# Start scripts with the following:
# import debugger
# dbg = debugger.get(bv)

import os
import re
import sys

# if binja license fails, assume standalone mode, with minimal debugger functionality
standalone = False
try:
	import binaryninja
except RuntimeError:
	standalone = True

# warn if minimum version not met
try:
	if standalone:
		raise Exception('no version check in standalone mode')

	from binaryninja import core_version, log_error

	(major, minor, buildid) = re.match(r'^(\d+)\.(\d+)\.?(\d+)?', core_version()).groups()
	major = int(major)
	minor = int(minor)
	buildid = int(buildid) if buildid is not None else 0xffffffff

	import json
	fpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugin.json')
	with open(fpath) as fp:
		data = json.load(fp)
		min_version = data['minimumbinaryninjaversion']

	# git builds end with ' development'
	if not (core_version().endswith('development') or core_version().endswith('test')):
		if buildid < min_version:
			log_error("Debugger relies on features and fixes present in Binary Ninja >= {}. Errors may follow, please update.".format(min_version))
except:
	pass

if sys.version_info < (3, 6, 0):
	# Stop executing this file, we will just throw on later imports
	raise Exception("Debugger requires Python 3.6 or greater")

if not standalone:
	from . import binjaplug

"""
Retrieve the debugger state instance for a given BinaryView
"""
def get(bv):
	return binjaplug.get_state(bv)

