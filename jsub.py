#!/usr/bin/env python

# A simple jsub client

import sys, getopt, time, string, os, getpass
import pyxmpp
import pyxmpp.jabber
import pyxmpp.jabber.muc
from pygale import pretty

DEBUG = 0
VERSION = '0.1'

def usage(arg):
	print 'jsub.py version %s' % VERSION
	print "Usage: %s [-dhv] [location ...]" % arg

def messageHandler(msg):
#	print '!!! Got message of type:', msg.get_type()
	type = msg.get_type()
	if not type:
		type = 'normal'
	if type in ['normal', 'chat']:
		return handleChat(msg)
	elif type == 'groupchat':
		return handleGroupChat(msg)
	else:
		print '!!! unsupported message type:', msg.get_type()
		return False

def presenceHandler(msg, file=sys.stdout, termwidth=80):
#	print '!!! Received presence:', msg, dir(msg)
#	print 'To:', msg.get_to()
#	print 'Type:', msg.get_type()
#	print 'Status:', msg.get_status()
#	print 'From:', msg.get_from()
#	print 'Id:', msg.get_id()
#	print 'Priority:', msg.get_priority()

	type = msg.get_type()
	_from = msg.get_from()
	status = msg.get_status()
	if not type:
		type = 'online'
	if status:
		status = ' (%s)' % status
	else:
		status = ''
	hdr = pretty.bold('*')
	file.write(hdr + ' %s is %s%s\n' % (_from, type, status))
	return True

class MyRoomHandler(pyxmpp.jabber.muc.MucRoomHandler):
	def user_joined(self, user, stanza):
		print 'User %s joined room' % user
	def message_received(self, user, stanza):
		print 'Message received:', stanza

def handleChat(msg, file=sys.stdout, termwidth=80):
#	print 'Received message:', msg, dir(msg)
	sender_jid = msg.get_from()
	if sender_jid:
		sender = sender_jid.node + '@' + sender_jid.domain
		if sender_jid.resource:
			sender = sender + '/' + sender_jid.resource
	else:
		sender = 'unknown sender'

	subject = msg.get_subject()
	thread = msg.get_thread()
	to_jid = msg.get_to()
	if subject:
		to = to_jid.node + '.' + subject + '@' + to_jid.domain
	else:
		to = to_jid.node + '@' + to_jid.domain
	if to_jid.resource:
		to = to + '/' + to_jid.resource
	type = msg.get_type()
	body = msg.get_body()
	if not body:
		return
	else:
		body = pretty.format(body)
	date = time.strftime('%m-%d %H:%M:%S', time.localtime(time.time()))

	file.write('\r' + ('-' * termwidth) + '\n')
	header = 'To: %s' % pretty.bold_location(to)
	file.write(header + '\n')

	if body:
		file.write(body.encode('latin-1'))
	bolded_sig = "-- %s at %s --" %\
		(sender, date)
	normal_sig = "-- %s at %s --" % (sender, date)
	bolded_sig = ' ' * (termwidth-len(normal_sig)) + bolded_sig
	nonbolded_sig = ' ' * (termwidth-len(normal_sig)) + normal_sig
	if file.isatty():
		file.write(bolded_sig + '\n')
	else:
		file.write(nonbolded_sig + '\n')
	return True

def handleGroupChat(msg, file=sys.stdout, termwidth=80):
	sender_jid = msg.get_from()
	if sender_jid:
		if sender_jid.resource:
			sender = sender_jid.resource
		else:
			sender = '*no-handle*'
	else:
		sender = '*unsigned*'

	subject = msg.get_subject()
	thread = msg.get_thread()
	if subject:
		to = sender_jid.node + '.' + subject + '@' + sender_jid.domain
	else:
		to = sender_jid.node + '@' + sender_jid.domain
	body = msg.get_body()
	if not body:
		return
	else:
		body = pretty.format(body)
	date = time.strftime('%m-%d %H:%M:%S', time.localtime(time.time()))

	file.write('\r' + ('-' * termwidth) + '\n')
	header = 'To: %s' % pretty.bold_location(to)
	file.write(header + '\n')

	if body:
		file.write(body.encode('latin-1'))
	bolded_sig = "-- %s at %s --" %\
		(sender, date)
	normal_sig = "-- %s at %s --" % (sender, date)
	bolded_sig = ' ' * (termwidth-len(normal_sig)) + bolded_sig
	nonbolded_sig = ' ' * (termwidth-len(normal_sig)) + normal_sig
	if file.isatty():
		file.write(bolded_sig + '\n')
	else:
		file.write(nonbolded_sig + '\n')
	return True


class MyClient(pyxmpp.jabber.Client):
	def session_started(self):
		print 'session started, sending presence'
		self.get_stream().send(pyxmpp.Presence())

if __name__ == '__main__':
	opts, args = getopt.getopt(sys.argv[1:], 'dvh')
	quiet = 0
	for opt, val in opts:
		if opt == '-d':
			DEBUG = True
		elif opt == '-v' or opt == '-h':
			usage(sys.argv[0])
			sys.exit()
#	if len(args) < 1:
#		usage(sys.argv[0])
#		sys.exit()
	

	# Initialize PyGale before processing locations
	if DEBUG:
		print 'Creating client'
	
	username = getpass.getuser()
	jid = pyxmpp.JID('%s@ofb.net/jsub' % username)
	password = getpass.getpass('Password: ')
	cl = MyClient(jid=jid, password=password)
	if DEBUG:
		print 'Connecting...'
	ret = cl.connect()
	if DEBUG:
		print 'Done, result:', ret
	
	cl.get_stream().set_message_handler('chat', messageHandler)
	cl.get_stream().set_message_handler('normal', messageHandler)
	cl.get_stream().set_message_handler('groupchat', messageHandler)
	cl.get_stream().set_presence_handler('available', presenceHandler)
#	cl.get_stream().set_presence_handler('subscribe', presenceHandler)
	cl.get_stream().set_presence_handler('unavailable', presenceHandler)
	cl.get_stream().set_presence_handler('', presenceHandler)

	# Join MUC chatrooms
	roommgr = pyxmpp.jabber.muc.MucRoomManager(cl.get_stream())
	if args:
		for loc in args:
			roomjid = pyxmpp.JID(loc)
			roommgr.join(roomjid, username + '@ofb.net', MyRoomHandler())

	if DEBUG:
		print 'processing...'
	try:
		try:
			cl.loop(1)
		except KeyboardInterrupt, e:
			pass
	finally:
		print 'Disconnecting'
		cl.disconnect()
