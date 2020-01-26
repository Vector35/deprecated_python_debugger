import binaryninja
import binaryninjaui
from binaryninja import BinaryView, SegmentFlag

from . import binjaplug

"""
The debug memory BinaryView layout is in a few pieces:
- DebugProcessView represents the entire debugged process, containing segments for mapped memory
- DebugMemoryView represents the raw memory of the process (eg like a raw BinaryView)
"""

class DebugProcessView(BinaryView):
	name = "Debugged Process"
	def __init__(self, parent):
		self.memory = DebugMemoryView(parent)
		self.local_view = parent
		BinaryView.__init__(self, parent_view=self.memory, file_metadata=self.memory.file)

		# TODO: Read segments from debugger
		length = self.memory.perform_get_length()
		self.add_auto_segment(0, length, 0, length, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable)
		self.add_auto_section("Memory", 0, length)

	def perform_get_address_size(self):
		return self.parent_view.arch.address_size

	@classmethod
	def is_valid_for_data(self, data):
		return False

	def perform_get_length(self):
		return self.memory.perform_get_length()

	def perform_is_executable(self):
		return True

	def perform_is_valid_offset(self, addr):
		return True

	def mark_dirty(self):
		self.memory.mark_dirty()

	"""
	Get the base address of the binary in the debugged process
	"""
	def get_remote_start(self):	
		adapter = binjaplug.get_state(self.local_view).adapter
		modules = adapter.mem_modules()
		assert self.local_view.file.original_filename in modules
		return modules[self.local_view.file.original_filename]

	"""
	Determine if the debugged process is using ASLR for its code segment
	(eg in a PIE binary)
	"""
	def is_code_aslr(self):
		return self.get_remote_start() != self.local_view.start

	"""
	Given a local address (relative to the analysis binaryview),
	find its remote address (relative to the debugged process) after ASLR
	"""
	def local_addr_to_remote(self, local_addr):
		# TODO: Make sure the addr is within the loaded segments for our binary
		# Else return the original
		local_base = self.local_view.start
		remote_base = self.get_remote_start()
		return local_addr - local_base + remote_base

	"""
	Given a remote address (relative to the debugged process) after ASLR,
	find its local address (relative to the analysis binaryview)
	"""
	def remote_addr_to_local(self, remote_addr):
		# TODO: Make sure the addr is within the loaded segments for our binary
		# Else return the original
		local_base = self.local_view.start
		remote_base = self.get_remote_start()
		return remote_addr - remote_base + local_base

class DebugMemoryView(BinaryView):
	name = "Debugged Process Memory"
	def __init__(self, parent):
		BinaryView.__init__(self, parent_view=parent, file_metadata=parent.file)
		self.value_cache = {}

	def perform_get_address_size(self):
		return self.parent_view.arch.address_size

	@classmethod
	def is_valid_for_data(self, data):
		return False

	def perform_get_length(self):
		# Assume 8 bit bytes (hopefully a safe assumption)
		return (2 ** (self.perform_get_address_size() * 8)) - 1

	def perform_read(self, addr, length):
		adapter = binjaplug.get_state(self.parent_view).adapter
		if adapter is None:
			return None
		# Cache reads (will be cleared whenever view is marked dirty)
		if addr in self.value_cache.keys():
			return self.value_cache[addr]
		value = adapter.mem_read(addr, length)
		self.value_cache[addr] = value
		return value
	
	def perform_write(self, addr, data):
		adapter = binjaplug.get_state(self.parent_view).adapter
		if adapter is None:
			return 0
		# Assume any memory change invalidates all of memory (suboptimal, may not be necessary)
		self.mark_dirty()
		if adapter.mem_write(addr, data) == 0:
			return len(data)
		else:
			return 0
	
	def perform_is_executable(self):
		return True

	def perform_is_valid_offset(self, addr):
		return True

	# def perform_insert(self, addr, data):
	# def perform_remove(self, addr, length):
	# def perform_get_modification(self, addr):
	# def perform_is_offset_readable(self, offset):
	# def perform_is_offset_writable(self, addr):
	# def perform_is_offset_executable(self, addr):
	# def perform_get_next_valid_offset(self, addr):
	# def perform_get_start(self):
	# def perform_get_entry_point(self):
	# def perform_get_default_endianness(self):
	# def perform_is_relocatable(self):
		
	def mark_dirty(self):
		self.value_cache = {}

DebugProcessView.register()
DebugMemoryView.register()
