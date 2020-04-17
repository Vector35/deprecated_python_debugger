from binaryninja import BinaryView, SegmentFlag

from . import binjaplug
from . import DebugAdapter

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
		self.arch = parent.arch
		self.platform = parent.platform

		self.saved_bases = {}

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
	Update cached base address for the remote process
	"""
	def update_base(self):
		self.saved_bases = {}

	"""
	Get the base address of the binary in the debugged process
	"""
	def get_remote_base(self, relative_view=None):
		if relative_view is None:
			relative_view = self.local_view
		module = relative_view.file.original_filename
		if module not in self.saved_bases:
			debug_state = binjaplug.get_state(self.local_view)
			base = debug_state.modules[module]
			self.saved_bases[module] = base
		return self.saved_bases[module]

	"""
	Determine if the debugged process is using ASLR for its code segment
	(eg in a PIE binary)
	"""
	def is_code_aslr(self, relative_view=None):
		if relative_view is None:
			relative_view = self.local_view
		return self.get_remote_base(relative_view) != relative_view.start

	"""
	Given a local address (relative to the analysis binaryview),
	find its remote address (relative to the debugged process) after ASLR
	If the address is not within our view, it will be unchanged
	"""
	def local_addr_to_remote(self, local_addr, relative_view=None):
		if relative_view is None:
			relative_view = self.local_view
		local_base = relative_view.start
		remote_base = self.get_remote_base(relative_view)
		if local_addr < local_base or local_addr >= local_base + len(relative_view):
			# Not within our local binary, return original
			return local_addr
		return local_addr - local_base + remote_base

	"""
	Given a remote address (relative to the debugged process) after ASLR,
	find its local address (relative to the analysis binaryview)
	If the address is not within our view, it will be unchanged
	"""
	def remote_addr_to_local(self, remote_addr, relative_view=None):
		if relative_view is None:
			relative_view = self.local_view
		# TODO: Make sure the addr is within the loaded segments for our binary
		# Else return the original
		local_base = relative_view.start
		remote_base = self.get_remote_base(relative_view)
		local_addr = remote_addr - remote_base + local_base
		if local_addr < local_base or local_addr >= local_base + len(relative_view):
			# Not within our local binary, return original
			return remote_addr
		return local_addr

	"""
	Determine if a remote address is within the loaded BinaryView
	"""
	def is_local_addr(self, remote_addr, relative_view=None):
		if relative_view is None:
			relative_view = self.local_view
		local_base = relative_view.start
		remote_base = self.get_remote_base(relative_view)
		local_addr = remote_addr - remote_base + local_base
		return local_addr > local_base and local_addr < local_base + len(relative_view)

class DebugMemoryView(BinaryView):
	name = "Debugged Process Memory"
	def __init__(self, parent):
		BinaryView.__init__(self, parent_view=parent, file_metadata=parent.file)
		self.value_cache = {}
		self.error_cache = {}
		self.arch = parent.arch
		self.platform = parent.platform

	def perform_get_address_size(self):
		if self.parent_view is None or self.parent_view.arch is None:
			return 8 # Something sane
		return self.parent_view.arch.address_size

	@classmethod
	def is_valid_for_data(self, data):
		return False

	def perform_get_length(self):
		# Assume 8 bit bytes (hopefully a safe assumption)
		return (2 ** (self.perform_get_address_size() * 8)) - 1

	def perform_read(self, addr, length):
		if self.parent_view is None:
			return None
		adapter = binjaplug.get_state(self.parent_view).adapter
		if adapter is None:
			return None

		# ProcessView implements read caching in a manner inspired by CPU cache:
		# Reads are aligned on 256-byte boundaries and 256 bytes long

		# Cache read start: round down addr to nearest 256 byte boundary
		cache_start = addr & ~0xFF
		# Cache read end: round up addr+length to nearest 256 byte boundary
		cache_end = (addr + length + 0xFF) & ~0xFF
		# Cache read length: accounting for rounding down start and rounding up end
		cache_len = cache_end - cache_start
		# List of 256-byte block addresses to read into the cache to fully cover this region
		cache_blocks = range(cache_start, cache_start + cache_len, 0x100)

		result = b''

		for block in cache_blocks:
			if block in self.error_cache:
				return None
			if block not in self.value_cache:
				try:
					batch = adapter.mem_read(block, cache_len)
					# Cache storage is block => data for every block
					self.value_cache[block] = batch
				except DebugAdapter.GeneralError as e:
					# Probably disconnected; can't read
					self.error_cache[block] = True
					return None

			# Get data out of cache
			cached = self.value_cache[block]
			if addr + length < block + len(cached):
				# Last block
				cached = cached[:((addr + length) - block)]
			if addr > block:
				# First block
				cached = cached[addr-block:]
			result += cached

		return result

	def perform_write(self, addr, data):
		if self.parent_view is None:
			return 0
		adapter = binjaplug.get_state(self.parent_view).adapter
		if adapter is None:
			return 0
		# Assume any memory change invalidates all of memory (suboptimal, may not be necessary)
		self.mark_dirty()
		try:
			if adapter.mem_write(addr, data) == 0:
				return len(data)
			else:
				return 0
		except DebugAdapter.GeneralError as e:
			# Probably disconnected
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
		self.error_cache = {}

DebugProcessView.register()
DebugMemoryView.register()
