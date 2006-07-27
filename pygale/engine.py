import select
import sys, os
import time
try:
	import Tkinter
except ImportError:
	pass
if os.environ.get('DISPLAY', '') is not '':
	try:
		import pygtk
	except ImportError:
		pass
	else:
		pygtk.require('2.0')
		import gtk, gobject

DEBUG = 0

class TimeoutEngine:
	def __init__(self):
		self._timeout_list = []
		self._timer_callback = None


	def set_timer_callback(self, timer_callback):
		self._timer_callback = timer_callback


	def next_timeout(self):
		if self._timeout_list:
			return self._timeout_list[0][0]
		return None


	def process(self):
		ready_callbacks = []
		while self._timeout_list and \
		      self._timeout_list[0][0] < time.time():
			timeout_time, callback = self._timeout_list[0]
			del self._timeout_list[0]
			ready_callbacks.append(callback)
		for callback in ready_callbacks:
			callback()


	def add_callback(self, timeout, callback):
		if DEBUG: print 'Adding cb for timeout:', timeout
		timeout_time = time.time() + timeout / 1000.0
		index = 0
		for timeout_info in self._timeout_list:
			if timeout_info[0] > timeout_time:
				break
			index = index + 1
		self._timeout_list.insert(index, (timeout_time, callback))
		if self._timer_callback:
			self._timer_callback()


	def del_callback(self, callback):
		index = 0
		for timeout, match_callback in self._timeout_list:
			if match_callback == callback:
				del self._timeout_list[index]
				break
			index = index + 1

class SelectEngine:
	def __init__(self):
		self._callback_map = {}
		self._callback_write_map = {}
		self._timeouts = TimeoutEngine()

	def set_timer_callback(self, callback):
		self._timeouts.set_timer_callback(callback)

	def process(self, timeoutdelay = None):
		# if timeoutdelay is None, then that means block until something can
		# be returned
		# if timeoutdelay is zero, then that means poll and return
		# immediately
		if DEBUG: print 'Read cbs:', self._callback_map.keys()
		if DEBUG: print 'Write cbs:', self._callback_write_map.keys()
		if DEBUG: print 'timeoutdelay:', timeoutdelay
		now = time.time()
		
		next_timeout = self._timeouts.next_timeout()
		if DEBUG: print 'next timeout:', next_timeout
		if next_timeout is not None:
			if timeoutdelay is None:
				# User asked to block forever
				# But instead we'll go to the next timeout
				select_time = next_timeout - now
			elif next_timeout < timeoutdelay + now:
				# User set a timeout, but next timeout is sooner
				select_time = next_timeout - now
			else:
				# Wait for user-specified timeout period
				select_time = timeoutdelay
			if select_time < 0: select_time = 0
		else:
			# There is no next timeout; use user-specified timeout
			select_time = timeoutdelay
		if DEBUG: print 'select timeout is', select_time
		
		# Why is this here?
#		if not self._callback_map and not self._callback_write_map:
#			self._timeouts.process()
#			return

		try:
			read, write, exc = select.select(self._callback_map.keys(),
				self._callback_write_map.keys(), [], select_time)
		except select.error, e:
			# interrupted system call
			return
		for handle in read:
			if self._callback_map.has_key(handle):
				callback = self._callback_map[handle]
				callback()
		for handle in write:
			if self._callback_write_map.has_key(handle):
				callback = self._callback_write_map[handle]
				callback()
		# Process timeouts
		self._timeouts.process()

	def add_callback(self, handle, callback):
		if DEBUG: print 'Adding read callback for socket', handle
		self._callback_map[handle] = callback

	def add_write_callback(self, handle, callback):
		if DEBUG: print 'Adding write callback for socket', handle
		self._callback_write_map[handle] = callback

	def del_callback(self, handle):
		if DEBUG: print 'Deleting read callback for socket', handle
		if not self._callback_map.has_key(handle):
			if DEBUG: print '... but it does not exist!'
			return
		del self._callback_map[handle]

	def del_write_callback(self, handle):
		if DEBUG: print 'Deleting write callback for socket', handle
		if not self._callback_write_map.has_key(handle):
			if DEBUG: print '... but it does not exist!'
			return
		del self._callback_write_map[handle]

	def add_timeout(self, ms, callback):
		if DEBUG: print 'Adding timeout in milliseconds', ms, callback
		self._timeouts.add_callback(ms, callback)
		return callback
	
	def del_timeout(self, callback):
		if DEBUG: print 'Deleting timeout', callback
		self._timeouts.del_callback(callback)
	
class TkEngine:
	def __init__(self):
		self.w = Tkinter._default_root
		self._callback_map = {}
		self._callback_write_map = {}

	def process(self, timeout=None):
		if DEBUG: print 'Read cbs:', self._callback_map.keys()
		if DEBUG: print 'Write cbs:', self._callback_write_map.keys()
		pass

	def add_callback(self, handle, callback, write=0):
		self._callback_map[handle] = callback
		self.w.tk.createfilehandler(handle.fileno(),
			Tkinter.READABLE, lambda f, m, s=self, h=handle:
			s.read_ready(h))
	
	def add_write_callback(self, handle, callback):
		self._callback_write_map[handle] = callback
		self.w.tk.createfilehandler(handle.fileno(),
			Tkinter.WRITABLE, lambda f, m, s=self, h=handle:
			s.write_ready(h))

	def del_callback(self, handle):
		if self._callback_map.has_key(handle):
			del self._callback_map[handle]
			self.w.tk.deletefilehandler(handle.fileno())

	def del_write_callback(self, handle):
		if self._callback_write_map.has_key(handle):
			del self._callback_write_map[handle]
			self.w.tk.deletefilehandler(handle.fileno())

	def read_ready(self, handle):
		self._callback_map[handle]()

	def write_ready(self, handle):
		self._callback_write_map[handle]()

	def add_timeout(self, ms, callback):
		handle = self.w.after(ms, callback)
		return handle
	
	def del_timeout(self, handle):
		self.w.after_cancel(handle)

class GtkEngine:
	def __init__(self):
		self._callback_map = {}
		self._callback_write_map = {}
	
	def process(self, timeout=None):
		if DEBUG: print 'Read cbs:', self._callback_map.keys()
		if DEBUG: print 'Write cbs:', self._callback_write_map.keys()
		pass

	# Add read callback when data ready for reading
	def add_callback(self, handle, callback, write=0):
		if DEBUG:
			print 'Engine: adding read cb, handle', handle
		if handle in self._callback_map.keys():
			self.del_callback(handle)
		if gtk.pygtk_version >= (1,99,14):
			gtkhandle = gobject.io_add_watch(handle,
				gobject.IO_IN|gobject.IO_ERR|gobject.IO_HUP,
				lambda f, m, s=self, h=handle: s.read_ready(h))
		else:
			gtkhandle = gtk.input_add(handle, gtk.gdk.INPUT_READ,
				lambda f, m, s=self, h=handle: s.read_ready(h))
		self._callback_map[handle] = (callback, gtkhandle)
		if DEBUG:
			print 'read callback map:', self._callback_map

	def add_write_callback(self, handle, callback):
#		if DEBUG:
#			print 'Engine: adding write cb, handle', handle
		if gtk.pygtk_version >= (1,99,14):
			gtkhandle = gobject.io_add_watch(handle,
				gobject.IO_OUT|gobject.IO_ERR|gobject.IO_HUP,
				lambda f, m, s=self, h=handle: s.write_ready(h))
		else:
			gtkhandle = gtk.input_add(handle, gtk.gdk.INPUT_WRITE,
				lambda f, m, s=self, h=handle: s.write_ready(h))
		self._callback_write_map[handle] = (callback, gtkhandle)

	def del_callback(self, handle):
		if DEBUG:
			print 'Engine: deleting read cb, handle', handle
		if self._callback_map.has_key(handle):
			(callback, gtkhandle) = self._callback_map[handle]
			del self._callback_map[handle]
			if gtk.pygtk_version >= (1,99,14):
				gobject.source_remove(gtkhandle)
			else:
				gtk.input_remove(gtkhandle)
		if DEBUG:
			print 'read callback map:', self._callback_map

	def del_write_callback(self, handle):
		if DEBUG:
			print 'Engine: deleting write cb, handle', handle
		if self._callback_write_map.has_key(handle):
			(callback, gtkhandle) = self._callback_write_map[handle]
			del self._callback_write_map[handle]
			if gtk.pygtk_version >= (1,99,14):
				gobject.source_remove(gtkhandle)
			else:
				gtk.input_remove(gtkhandle)

	def read_ready(self, handle):
		if DEBUG:
			print 'socket ready for reading', handle
		if not self._callback_map.has_key(handle):
			print 'ERROR: cbmap has no handle', handle, self._callback_map.keys()
			return
		self._callback_map[handle][0]()
		if gtk.pygtk_version >= (1,99,14):
			return gtk.TRUE
	
	def write_ready(self, handle):
		self._callback_write_map[handle][0]()
		if gtk.pygtk_version >= (1,99,14):
			return gtk.TRUE
	
	def add_timeout(self, ms, callback):
		if gtk.pygtk_version >= (1,99,14):
			return gobject.timeout_add(ms, callback)
		else:
			return gtk.timeout_add(ms, callback)
	
	def del_timeout(self, handle):
		if gtk.pygtk_version >= (1,99,14):
			gobject.source_remove(handle)
		else:
			gtk.timeout_remove(handle)

engine = SelectEngine()
