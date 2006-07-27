#!/usr/bin/env python

import pyxmpp
import pyxmpp.jabber
import pyxmpp.jabber.muc
import sys, getopt, string, os, time, getpass
try:
	import readline
except:
	print 'No readline module found; line-editing capabilities unavailable'

# Default behavior
RETURN_RECEIPT = 0
DONT_SEND = 0

# Debugging
DEBUG = 1
VERSION = '0.1'

def usage(arg):
	print 'jsend.py version %s' % VERSION
	print "Usage: %s [-gdv] location [location ...] [/keyword...]" % arg
	print 'Flags:    -g        send group chat message'
	print '          -d        enable debugging'
	print '          -v        show version'

def print_msg(msg):
	date = time.strftime('%m-%d %H:%M:%S ',
		time.localtime(time.time()))
	msg = date + string.strip(msg)
	print msg

def enter_puff():
	text = ''
	while 1:
		try:
			line = raw_input()
		except EOFError:
			break
		except KeyboardInterrupt:
			print 'Message aborted.'
			sys.exit(0)
		if line == '.':
			break
		text = text + line + '\r\n'
	if text.endswith('\r\n'):
		text = text[:-2]
	return text

def sendpuff(client, type, loc, subtopic=None):
	# Print the header
	bolded_loc = '[1m' + loc + '[0m'
	header = 'To: %s' % bolded_loc
	print header
	print '(End your message with EOF or a solitary dot.)'

	# Get the puff text
	pufftext = enter_puff()

	# Send puff
	ret = client.get_stream().send(pyxmpp.Message(type=type,
		to=loc, body=pufftext, subject=subtopic))

	print 'Message sent.'

def process(client, timeout):
	now = time.time()
	while time.time() < now + timeout:
		client.get_stream().loop_iter(1)

class SendOnlyClient(pyxmpp.jabber.Client):
	def session_started(self):
		# override Client's session_started method
		# don't send presence
		#self.get_stream().send(pyxmpp.Presence(type='unavailable'))
		#self.request_roster()
		pass

# return tuple of (jabber id, subtopic)
def split_location(loc):
	i = loc.find('@')
	if i == -1:
		return (loc, None)
	else:
		localpart = loc[:i]
		domain = loc[i:]
		if '.' not in localpart:
			return (loc, None)
		else:
			j = localpart.find('.')
			node = localpart[:j]
			subtopic = localpart[j+1:]
			jabberid = node + domain
			return (jabberid, subtopic)

def main():
	global DEBUG
	opts, args = getopt.getopt(sys.argv[1:], 'gd:v')
	type = 'normal'
	for (opt, val) in opts:
		if opt == '-d':
			DEBUG = True
		elif opt == '-v':
			usage(sys.argv[0])
			sys.exit(0)
		elif opt == '-g':
			type = 'groupchat'
		else:
			usage(sys.argv[0])
			print 'Unknown option:', opt
			sys.exit(0)
	if not args:
		usage(sys.argv[0])
		sys.exit(0)

	# Initialize PyGale before processing locations
	if DEBUG:
		print 'Creating client'
	
	username = getpass.getuser()
	jid = pyxmpp.JID('%s@ofb.net/jsend' % username)
	password = getpass.getpass('Password: ')
	cl = SendOnlyClient(jid=jid, password=password)
	if DEBUG:
		print 'Connecting...'
	ret = cl.connect()
#	process(cl, 1)
	if DEBUG:
		print 'Done, result:', ret
	if DEBUG:
		print 'sending...'

	# Extract locations from cmdline args
	# TODO: condiments/keywords
	locs = args

	if type == 'groupchat':
		# join chat room in order to send message
		roommgr = pyxmpp.jabber.muc.MucRoomManager(cl.get_stream())
		for loc in locs:
			base_jid, subtopic = split_location(loc)
			roomjid = pyxmpp.JID(base_jid)
			room = roommgr.join(roomjid, username + '@ofb.net.js',
				pyxmpp.jabber.muc.MucRoomHandler())
			sendpuff(cl, type, base_jid, subtopic=subtopic)
			room.leave()
	else:
		for loc in locs:
			sendpuff(cl, type, loc)
	
	# wait for it to go through
	try:
#		cl.loop(1)
		process(cl, 1)
		cl.get_stream().close()
		cl.disconnect()
	except KeyboardInterrupt:
		sys.exit(0)

if __name__ == '__main__':
	main()
