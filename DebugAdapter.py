class DebugAdapter:
	# session start/stop
	def exec(self, path):
		pass
	def attach(self, pid):
		pass
	def detach(self):
		''' quit debug session, debuggee left running '''
		pass
	def quit(self):
		''' quit debug session, debuggee terminated '''
		pass

	# threads
	def thread_get_ids(self):
		''' return a list of thread id's '''
		pass
	def thread_get_active(self):
		''' return thread id that is active '''
		pass
	def thread_switch(self, tid):
		''' make a given thread id active '''
		pass
	
	# breakpoints
	def breakpoint_set(self, address):
		''' set software breakpoint at address, return breakpoint id '''
		pass
	def breakpoint_clear(self, bpid):
		''' delete breakpoint by id '''
		pass
	def breakpoint_list(self):
		''' return map of bpid -> address '''

	# register
	def register_read(self, reg):
		pass
	def register_write(self, reg):
		pass
	def register_list(self):
		pass

	# mem
	def mem_read(self, address, length):
		pass
	def mem_write(self, address, data):
		pass

	# break
	def break_into(self):
		pass

	# execution control
	def go():
		pass
	def step_into(self):
		pass
	def step_over(self):
		pass

