#!/usr/bin/env python

import engine, pygale
import urlparse, socket, select, string, errno, re, os

DEFAULT_HTTP_PORT = 80
# Timeout on reads (in secs) --- after 5 minutes
READ_TIMEOUT = 5 * 60

DEBUG = 0

# Handles only http urls!
def fetch_url(url, callback, maxsize=None):
	u = URLFetcher(url, callback, maxsize)
	u.start_fetching()

class URLFetcher:
	# maxsize in bytes
	def __init__(self, url, callback, maxsize=None):
		self.callback = callback
		self.url = url
		self.maxsize = maxsize

		# http proxy
		proxy = os.environ.get('http_proxy',
			os.environ.get('HTTP_PROXY', None))
		if proxy:
			fields = urlparse.urlparse(proxy)
			self.host, self.port = self.splitHostPort(fields[1],
				DEFAULT_HTTP_PORT)
			self.urlrequest = 'GET %s HTTP/1.0\n\n' % url
		else:
			fields = urlparse.urlparse(url)
			self.host, self.port = self.splitHostPort(fields[1],
				DEFAULT_HTTP_PORT)
			req = fields[2]
			if fields[3]:
				req = req + ';' + fields[3]
			if fields[4]:
				req = req + '?' + fields[4]
			if fields[5]:
				req = req + '#' + fields[5]
			self.urlrequest = 'GET %s HTTP/1.0\nHost: %s\n\n' % (
				req, self.host)

		self.data = ''
	
	# take a host string in the form "host:port" and return a (host,
	# port) tuple.  if port is not specified, return default port.
	def splitHostPort(self, host, defaultPort):
		if ':' in host:
			i = string.index(host, ':')
			port = int(host[i+1:])
			host = host[:i]
		else:
			port = defaultPort
		return (host, port)

	def start_fetching(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock = s
		s.setblocking(0)
		try:
			s.connect((self.host, self.port))
		except socket.error, e:
			if e[0] == errno.EINPROGRESS or e[0] == 10035:
				engine.engine.add_write_callback(s, self.fetch_url2)
			else:
				pygale.call_error_handler('Error fetching thumbnail: %s' %
					str(e))
		else:
			self.fetch_url2()
		return

	def fetch_url2(self):
		# Connected to socket; send request
		engine.engine.del_write_callback(self.sock)
		try:
			self.sock.send(self.urlrequest)
		except socket.error, e:
			pygale.call_error_handler('Error fetching %s: %s'
				% (self.url, e))
			self.callback(None)
			return
		engine.engine.add_callback(self.sock, self.fetch_url3)
		self.timeout_handle = engine.engine.add_timeout(
			READ_TIMEOUT * 1000, self.cleanup)

	def fetch_url3(self):
		# Data ready for reading
		while 1:
			read, write, ex = select.select([self.sock], [], [], 0)
			if self.sock in read:
				try:
					chunk = self.sock.recv(1024)
				except socket.error, e:
					pygale.call_error_handler('Error fetching %s: %s'
						% (self.url, e))
					engine.engine.del_callback(self.sock)
					engine.engine.del_timeout(self.timeout_handle)
					self.callback(None)
					return
				if not chunk:
					# Server closed connection
					self.cleanup()
					return
				self.data = self.data + chunk
				if self.maxsize and len(self.data) > self.maxsize:
					# We've seen enough
					self.cleanup()
					return
			else:
				return
	
	def process(self, data):
		# check for bad response code
		firstnewline = string.find(data, '\r\n')
		firstline = data[:firstnewline]
		group = re.search('HTTP/[\d\.]+ (\d\d\d) .*', firstline)
		if not group:
			return None
		respcode = group.group(1)
		if respcode != '200':
			return None

		# Read up to the first blank line (to strip off the headers)
		index = string.find(data, '\r\n\r\n')
		if index == -1:
			return data
		else:
			return data[index+4:]

	def cleanup(self, *args):
		# Delete the callback and make do with what we have
		engine.engine.del_callback(self.sock)	
		engine.engine.del_write_callback(self.sock)
		engine.engine.del_timeout(self.timeout_handle)
		self.sock.close()
		self.callback(self.process(self.data))

if __name__ == '__main__':
	main()

