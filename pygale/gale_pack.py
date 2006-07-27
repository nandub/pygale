import sys
global USE_PYTHON_UNICODE
if sys.version < '1.6':
	import unicode
	USE_PYTHON_UNICODE = 0
else:
	USE_PYTHON_UNICODE = 1

import string, time
from types import *
import pygale
import traceback

FRAG_TYPE_TEXT = 0
FRAG_TYPE_BINARY = 1
FRAG_TYPE_TIME = 2
FRAG_TYPE_INT = 3
FRAG_TYPE_LIST = 4
DEBUG = 0

class GaleTime:
	def __init__(self, sec_high, sec_low, frac_high, frac_low):
		self._sec_h = sec_high
		self._sec_l = sec_low
		self._frac_h = frac_high
		self._frac_l = frac_low
	
	def ctime(self):
		return time.ctime(self._sec_l)

# Time constants
GaleTimeZero = GaleTime(-2147483647-1, 0, 0, 0)
GaleTimeForever = GaleTime(2147483647, 2147483647, 2147483647,
	2147483647)

def pack32bit(n):
	return chr((n>>24)&0xFF) + chr((n>>16)&0xFF) \
		+ chr((n>>8)&0xFF) + chr(n&0xFF)

def unpack32bit(s):
	return (long(ord(s[0]))<<24) | (long(ord(s[1]))<<16) \
		| (long(ord(s[2]))<<8) | ord(s[3])

# ------------------------------------------------------------
# Routines for constructing strings with various datatypes

def push_int(i):
	return pack32bit(i)

def push_lenstr(s, chars=1):
	if chars:
		out = push_int(len(s)) + push_string(s)
	else:
		widestr = push_string(s)
		out = push_int(len(widestr)) + widestr
	return out

def push_string(s):
	if USE_PYTHON_UNICODE:
		if type(s) is UnicodeType:
			return s.encode('utf-16be')
		else:
			return unicode(s, 'iso-8859-1').encode('utf-16be')
	else:
		return unicode.latin1_to_unicode(s)

# ------------------------------------------------------------
# Routines for translating between gale groups and Python dicts

class GaleDict:
	def __init__(self):
		self.__data = []
	def __setitem__(self, key, val):
		self.__data.append((key, val))
	def __getitem__(self, key):
		out = []
		for k, val in self.__data:
			if k == key:
				out.append(val)
		return out
	def update(self, gd):
		self.__data = self.__data + gd.data()
	def data(self):
		return self.__data
	def keys(self):
		keylist = []
		for k, val in self.__data:
			if k not in keylist:
				keylist.append(k)
		return keylist
	def has_key(self, key):
		for k, val in self.__data:
			if k == key:
				return 1
		return 0

class GaleFragList:
	def __init__(self):
		self.d = GaleDict()
	def __repr__(self):
		return 'FragList: ' + `self.d.data()`

	def set(self, name, type, value):
		self.d[name] = (type, value)
	def get_text(self, name):
		"Return a list of text fragments matching this name"
		out = []
		for (type, value) in self.d[name]:
			if type == FRAG_TYPE_TEXT:
				out.append(value)
		return out
	def get_text_first(self, name, default=None):
		"""Return the first text fragment matching this name, default if
		none"""
		ret = self.get_text(name)
		if not ret:
			return default
		else:
			return ret[0]
	def get_int(self, name):
		"Return a list of int fragments matching this name"
		out = []
		for (type, value) in self.d[name]:
			if type == FRAG_TYPE_INT:
				out.append(value)
		return out
	def get_int_first(self, name, default=None):
		"""Return the first int fragment matching this name, default if
		none"""
		ret = self.get_int(name)
		if not ret:
			return default
		else:
			return ret[0]
	def get_binary(self, name):
		"Return a list of binary fragments matching this name"
		out = []
		for (type, value) in self.d[name]:
			if type == FRAG_TYPE_BINARY:
				out.append(value)
		return out
	def get_binary_first(self, name, default=None):
		"""Return the first binary fragment matching this name, default if
		none"""
		ret = self.get_binary(name)
		if not ret:
			return default
		else:
			return ret[0]
	def get_time(self, name):
		"Return a list of time fragments matching this name"
		out = []
		for (type, value) in self.d[name]:
			if type == FRAG_TYPE_TIME:
				out.append(value)
		return out
	def get_time_first(self, name, default=None):
		"""Return the first time fragment matching this name, default if
		none"""
		ret = self.get_time(name)
		if not ret:
			return default
		else:
			return ret[0]
	def get_list(self, name):
		"Return a list of list fragments matching this name"
		out = []
		for (type, value) in self.d[name]:
			if type == FRAG_TYPE_LIST:
				out.append(value)
		return out
	def get_list_first(self, name, default=None):
		"""Return the first list fragment matching this name, default if
		none"""
		ret = self.get_list(name)
		if not ret:
			return default
		else:
			return ret[0]
	def has_key(self, *args):
		return apply(self.d.has_key, args)
	def update(self, galefraglist):
		self.d.update(galefraglist.d)
	def keys(self):
		return self.d.keys()
	def __getitem__(self, key):
		"Returns a list of values matching this key"
		return self.d[key]

# DAN_IS_STOOPID is set to true when the fragment does not contain the
# leading four 0 bytes (such as in a version 3 public key).
def group_to_FragList(p, DAN_IS_STOOPID=0):
	"Turn a gale group (wire protocol) into a GaleFragList instance"
	d = GaleFragList()
	# The next 4 bytes are marked as "reserved"
	if not DAN_IS_STOOPID:
		(reserved, p) = pop_int(p)
	while p:
		# Type 0 for text, 1 for binary data, etc.
		(frag_type, p) = pop_int(p)
		(frag_len, p) = pop_int(p)
		(frag, p) = pop_data(p, frag_len)

		# Pull the name of the fragment out
		# TODO: does this unpack FRAG_TYPE_LIST correctly?
		(frag_name_len, frag) = pop_int(frag)
		(frag_name, frag) = pop_string(frag, frag_name_len,
			chars=1)
		if frag_type == FRAG_TYPE_TEXT:
			(frag_value, frag) = pop_string(frag, len(frag))
		elif frag_type == FRAG_TYPE_INT:
			(frag_value, frag) = pop_int(frag)
		else:
			(frag_value, frag) = pop_data(frag, len(frag))
		if frag_type == FRAG_TYPE_TIME:
			# Ignore the high-order 32 bits
			frag_value = unpack32bit(frag_value[4:8])
		if DEBUG:
			print 'Found fragment:', frag_name
		d.set(frag_name, frag_type, frag_value)
	return d

def FragList_to_group(d):
	"Turn a GaleFragList instance into a gale group (wire protocol)"
	out = ''
	for key in d.keys():
		list = d[key]
		for (fragtype, value) in list:
			frag = ''
			frag = frag + push_lenstr(key)
			if fragtype == FRAG_TYPE_TEXT:
				if USE_PYTHON_UNICODE:
					if type(value) not in [StringType, UnicodeType]:
						print 'Error: Skipping fragment %s (%s)' % (key,
							`value`)
					else:
						frag = frag + push_string(value)
				else:
					if type(value) is not StringType:
						print 'Error: Skipping fragment %s (%s)' % (key,
							`value`)
					else:
						frag = frag + push_string(value)
			elif fragtype == FRAG_TYPE_TIME:
				# TODO: handle time better
				# Assume the high-order 32 bits are zero
				if type(value) is not IntType:
					raise TypeError, 'Time fragment not type int'
				frag = frag + push_int(0)
				frag = frag + push_int(value)
				# Assume the fraction is zero, too
				frag = frag + push_int(0)
				frag = frag + push_int(0)
			elif fragtype == FRAG_TYPE_INT:
				frag = frag + push_int(value)
			elif fragtype == FRAG_TYPE_LIST:
				frag = frag + dict_to_group(value)
			elif fragtype == FRAG_TYPE_BINARY:
				frag = frag + value
			else:
				raise TypeError, 'unknown fragment type'
			out = out + push_int(fragtype) +\
				push_int(len(frag)) + frag
	return out

## DAN_IS_STOOPID is set to true when the fragment does not contain the
## leading four 0 bytes (such as in a version 3 public key).
#def group_to_dict(p, DAN_IS_STOOPID=0):
#	g = GaleDict()
#	# The next 4 bytes are marked as "reserved"
#	if not DAN_IS_STOOPID:
#		(reserved, p) = pop_int(p)
#	while p:
#		# Type 0 for text, 1 for binary data, etc.
#		(frag_type, p) = pop_int(p)
#		(frag_len, p) = pop_int(p)
#		(frag, p) = pop_data(p, frag_len)
#
#		# Pull the name of the fragment out
#		# TODO: does this unpack FRAG_TYPE_LIST correctly?
#		(frag_name_len, frag) = pop_int(frag)
#		(frag_name, frag) = pop_string(frag, frag_name_len,
#			chars=1)
#		if frag_type == FRAG_TYPE_TEXT:
#			(frag_value, frag) = pop_string(frag, len(frag))
#		else:
#			(frag_value, frag) = pop_data(frag, len(frag))
#		if frag_type == FRAG_TYPE_TIME:
#			# Ignore the high-order 32 bits
#			frag_value = unpack32bit(frag_value[4:8])
#		g[frag_name] = (frag_type, frag_value)
#	return g

# ------------------------------------------------------------
# Routines for popping various datatypes off the front of a string

# if chars=0, len is the number of bytes
# if chars=1, len is the number of characters (bytes=len*2)
def pop_string(p, len, chars=0):
	if chars == 1:
		len = len * 2
	s = p[:len]
	if USE_PYTHON_UNICODE:
		try:
			# Replace unknown characters with the official Unicode
			# replacement character, U+FFFD
			ret = unicode(s, 'utf-16be', 'replace')
		except UnicodeError:
			return ('Unicode error', p[len:])
		else:
			return (ret, p[len:])
	else:
		ret = unicode.unicode_to_latin1(s)
		return (ret, p[len:])

# Pop a length, then a string of that length
# if chars=0, len is the number of bytes
# if chars=1, len is the number of characters (bytes=len*2)
def pop_lenstr(p, chars=0):
	(len, p) = pop_int(p)
	return pop_string(p, len, chars)

def pop_int(p):
	# Check to be sure p has at least 4 bytes
	if len(p) < 4:
		if DEBUG:
			print 'ERROR: popping int of length', len(p)
			traceback.print_stack()
		
		raise pygale.PyGaleWarn, "bad binary format: expected integer"
	num = unpack32bit(p[:4])
	return (num, p[4:])

def pop_data(p, len):
	data = p[:len]
	return (data, p[len:])

def pop_nulltermstr(p):
	i = string.find(p, '\000')
	if i == -1:
		raise pygale.PyGaleWarn, 'expected null terminated str'
	s = p[:i]
	return (s, p[i+1:])

def pop_bytes(p, numbytes=1):
	s = p[:numbytes]
	return (s, p[numbytes:])

def pop_time(p):
	(sec_high, p) = pop_int(p)
	(sec_low, p) = pop_int(p)
	(frac_high, p) = pop_int(p)
	(frac_low, p) = pop_int(p)
	t = GaleTime(sec_high, sec_low, frac_high, frac_low)
	return (t, p)

# Pop an rle-encoded bitstring
# len is either the encoded size or the decoded size
def pop_rle(p, len):
	out = ''
	try:
		while len:
			(control, p) = pop_bytes(p)
			control = ord(control)
			count = (control & 0x7f) + 1
			if (count > len):
				raise pygale.PyGaleErr, 'bad rle encoding (count > len)'
			if control & 0x80:
				# High bit set in control means count is length of
				# valid bytes
				(chars, p) = pop_bytes(p, count)
				out = out + chars
			else:
				(char, p) = pop_bytes(p, 1)
				out = out + char * count
			len = len - count
	except Exception, e:
		raise pygale.PyGaleErr, 'bad RLE encoding: ' + str(e)

	return (out, p)
