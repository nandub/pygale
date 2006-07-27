#!/uns/bin/python

import os, sys, string, re, time, string
import pygale, gale_env, userinfo

#------------------------------------------------------------
# Global configuration
#------------------------------------------------------------

def bold_location(text):
	if sys.platform == 'win32':
		return text
	else:
		i = string.rfind(text, '@')
		local = text[:i]
		domain = text[i:]
		return "[1m" + local + "[0m" + domain

def bold_keyword(text):
	if sys.platform == 'win32':
		return text
	else:
		return '[1m' + text + '[0m'

def format(text, termwidth=80):
	lines = string.split(text, '\r\n')
	if lines and lines[-1] != '':
		lines.append('')
	out = []
	while lines:
		l = lines[0]
		lines = lines[1:]
		if len(l) > termwidth:
			wrappoint = string.rfind(l, ' ', 0, termwidth)
			if wrappoint == -1:
				# No space, wrap at termwidth
				while len(l) > termwidth:
					out.append(l[:termwidth])
					l = l[termwidth:]
				out.append(l)
			else:
				out.append(l[:wrappoint])
				lines.insert(0, l[wrappoint+1:])
		else:
			out.append(l)
	return string.join(out, '\n')

def show(puff, file=None, termwidth=80):
	# If not otherwise specified, use stdout
	if file is None:
		file = sys.stdout

	#--------------------------------------------------
	# Catch all the message headers in the envvars
	#--------------------------------------------------
	# Sender: real name of person sending puff
	sender = puff.get_text_first('message/sender', 'Unknown sender')
	# Location, eg "pub.comp.linux@ofb.net"
	locations = puff.get_loc()
	# Sign: Gale ID of sender, eg "tlau@ofb.net"
	signer = puff.get_signer('Unknown sig')
	if signer is None:
		signer = '*unsigned*'
	# Date message was sent, eg "1998-08-24 15:18:47"
	date = puff.get_time_first('id/time', None)
	if date is None:
		date = time.strftime('%m-%d %H:%M:%S', time.localtime(time.time()))
	else:
		date = time.strftime('%m-%d %H:%M:%S', time.localtime(date))
	# Escryption recipients, list of ids
	recipients = puff.get_recipients()
	if '' in recipients:
		# null key
		recipients = []
	# Status of recipient for a receipt, eg "in/present"
	status = puff.get_text_first('notice/presence', None)
	# Receipt (new-style only)
	receipt = puff.get_text_first('answer.receipt', None)
	# Client used to send puff
	idclass = puff.get_text_first('id/class', 'Unknown client')

	# Get the text of the message
	text = puff.get_text_first('message/body', '')
	if text:
		text = format(text, termwidth)

	# Receipts
	if status is not None or receipt is not None:
		s = '* %s' % date
		if receipt is not None:
			s = s + ' received:'
		if status is not None:
			s = s + ' %s' % status
		if file.isatty():
			s = s + ' %s (%s)\n' % (bold_location(signer), sender)
		else:
			s = s + ' %s (%s)\n' % (signer, sender)
		file.write(s)
		return
	
	# Beep on "private" puff
	# Private means it was encrypted but not to the signer
	if file.isatty() and recipients and signer and signer not in recipients:
		file.write('\007')
	
	# separator bar
	file.write('\r' + ('-' * termwidth) + '\n')
	# Bold locations
	locs = string.split(locations, None)
	if file.isatty():
		locs = map(bold_location, locs)

	# Format message
	header = 'To: %s' % string.join(locs, ' ')
	keywords = puff.get_text('message.keyword')
	if keywords:
		if file.isatty():
			keywords = map(bold_keyword, keywords)
		keyw_text = map(lambda x: '/' + x, keywords)
		header = header + ' %s' % string.join(keyw_text, ' ')
	if puff.get_text('question.receipt'):
		header = header + ' [rcpt]'
	file.write(header + '\n')

	if text:
		file.write(text.encode('latin-1'))
	bolded_sig = "-- %s (%s) at %s --" %\
		(bold_location(signer), sender, date)
	normal_sig = "-- %s (%s) at %s --" % (signer, sender, date)
	bolded_sig = ' ' * (termwidth-len(normal_sig)) + bolded_sig
	nonbolded_sig = ' ' * (termwidth-len(normal_sig)) + normal_sig
	if file.isatty():
		file.write(bolded_sig + '\n')
	else:
		file.write(nonbolded_sig + '\n')

if __name__ == '__main__':
	main()
