import string, sys

def bold(text):
	if sys.platform == 'win32':
		return text
	else:
		return "[1m" + text + "[0m"

def bold_location(text):
	if sys.platform == 'win32':
		return text
	else:
		i = string.rfind(text, '@')
		local = text[:i]
		domain = text[i:]
		return "[1m" + local + "[0m" + domain

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

