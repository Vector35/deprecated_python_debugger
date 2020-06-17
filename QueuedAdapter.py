import threading
import traceback
from queue import Queue, Empty
from . import DebugAdapter

'''
Adapter shim that provides a thread-safe, blocking way to access an Adapter.
All adapter calls are done on one thread to not have race conditions on the socket.
'''
class QueuedAdapter(DebugAdapter.DebugAdapter):
	RECORD_STATS = False

	def __init__(self, adapter, **kwargs):
		DebugAdapter.DebugAdapter.__init__(self, **kwargs)
		self.adapter = adapter

		self.queue = Queue()
		self.results = {}
		self.next_index = 0
		self.lock = threading.Lock()
		self.worker_thread = threading.Thread(target=lambda: self.worker())
		self.worker_thread.start()

		self.function_stats = {}

	def __del__(self):
		pass

	# -------------------------------------------------------------------------
	# Thread-safe work queue for the adapter. Results and exceptions
	# are returned via the map self.results. Submitted jobs block for
	# completion with condition variables.
	# -------------------------------------------------------------------------

	def worker(self):
		while True:
			# Get next job
			index, job = self.queue.get()
			if job == 'break':
				break

			# Get condition variable
			cond = self.results[index]

			#
			try:
				self.queue.task_done()
				self.results[index] = (True, job())
			except Exception as e:
				#print('worker thread got exception: ', e)
				self.results[index] = (False, e)

			# Signal completion
			cond.acquire()
			cond.notify()
			cond.release()

	def submit(self, job):
		# Submissions to queue fail if thread isn't present
		if not (self.worker_thread and self.worker_thread.is_alive()):
			return False

		# Be sure to atomically increment the index counter
		with self.lock:
			index = self.next_index
			self.next_index += 1

		# Condition variable will be notified when the job is done
		cond = threading.Condition()
		# Acquire *before* the job is submitted so we don't lose a notify
		cond.acquire()
		self.results[index] = cond

		# Don't block on put() but instead on the condition variable
		self.queue.put((index, job), False)
		cond.wait()

		# Condition signalled, collect results
		cond.release()
		suceeded, result = self.results[index]
		del self.results[index]
		# False indicates an exception was thrown
		if not suceeded:
			raise result
		return result

	# -------------------------------------------------------------------------
	# Track statistics for which adapter functions are called the most, and
	# which stack traces call them (slow!)
	# -------------------------------------------------------------------------

	def record_stat(self, stat):
		if not QueuedAdapter.RECORD_STATS:
			return
		if stat in self.function_stats:
			self.function_stats[stat].append(traceback.extract_stack())
		else:
			self.function_stats[stat] = [traceback.extract_stack()]

	def dump_stats(self):
		for (stat, items) in sorted(self.function_stats.items(), key=lambda a: len(a[1]), reverse=True):
			print("{}: {}".format(stat, len(items)))

	# -------------------------------------------------------------------------
	# Stub functions for the adapter interface
	# All of these are routed through the work queue via submit() and are
	# thread-safe as a result
	# -------------------------------------------------------------------------

	def exec(self, path, args=[], **kwargs):
		self.record_stat("exec")
		return self.submit(lambda: self.adapter.exec(path, args, **kwargs))
	def attach(self, pid):
		self.record_stat("attach")
		return self.submit(lambda: self.adapter.attach(pid))
	def connect(self, server, port):
		self.record_stat("connect")
		return self.submit(lambda: self.adapter.connect(server, port))
	def detach(self):
		self.record_stat("detach")
		return self.submit(lambda: self.adapter.detach())
	def quit(self):
		self.record_stat("quit")

		# set loop break out signal (but thread could be blocking on previous call)
		self.queue.put((-1, 'break'), False)

		# bypass queue, we rely on underlying adapter's quit() to unblock our thread
		# (perhaps by closing the socket that our worker thread is recv() on)
		self.adapter.quit()

	def target_arch(self):
		self.record_stat("target_arch")
		return self.submit(lambda: self.adapter.target_arch())
	def target_path(self):
		self.record_stat("target_path")
		return self.submit(lambda: self.adapter.target_path())
	def target_pid(self):
		self.record_stat("target_pid")
		return self.submit(lambda: self.adapter.target_pid())
	def target_base(self):
		self.record_stat("target_base")
		return self.submit(lambda: self.adapter.target_base())

	def thread_list(self):
		self.record_stat("thread_list")
		return self.submit(lambda: self.adapter.thread_list())
	def thread_selected(self):
		self.record_stat("thread_selected")
		return self.submit(lambda: self.adapter.thread_selected())
	def thread_select(self, tidx):
		self.record_stat("thread_select")
		return self.submit(lambda: self.adapter.thread_select(tidx))

	def breakpoint_set(self, address):
		self.record_stat("breakpoint_set")
		return self.submit(lambda: self.adapter.breakpoint_set(address))
	def breakpoint_clear(self, address):
		self.record_stat("breakpoint_clear")
		return self.submit(lambda: self.adapter.breakpoint_clear(address))
	def breakpoint_list(self):
		self.record_stat("breakpoint_list")
		return self.submit(lambda: self.adapter.breakpoint_list())

	def reg_read(self, reg):
		self.record_stat("reg_read")
		return self.submit(lambda: self.adapter.reg_read(reg))
	def reg_write(self, reg, value):
		self.record_stat("reg_write")
		return self.submit(lambda: self.adapter.reg_write(reg, value))
	def reg_list(self):
		self.record_stat("reg_list")
		return self.submit(lambda: self.adapter.reg_list())
	def reg_bits(self, reg):
		self.record_stat("reg_bits")
		return self.submit(lambda: self.adapter.reg_bits(reg))

	def mem_read(self, address, length):
		self.record_stat("mem_read")
		return self.submit(lambda: self.adapter.mem_read(address, length))
	def mem_write(self, address, data):
		self.record_stat("mem_write")
		return self.submit(lambda: self.adapter.mem_write(address, data))
	def mem_modules(self, cache_ok=True):
		self.record_stat("mem_modules")
		return self.submit(lambda: self.adapter.mem_modules(cache_ok))

	def break_into(self):
		self.record_stat("break_into")
		# skip job queue (which is possibly waiting in go/step_into/step_over)
		threading.Thread(target=lambda: self.adapter.break_into()).start()

	def go(self):
		self.record_stat("go")
		return self.submit(lambda: self.adapter.go())
	def step_into(self):
		self.record_stat("step_into")
		return self.submit(lambda: self.adapter.step_into())
	def step_over(self):
		self.record_stat("step_over")
		return self.submit(lambda: self.adapter.step_over())

	def raw(self, data):
		self.record_stat("raw")
		return self.submit(lambda: self.adapter.raw(data))

