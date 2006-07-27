#!/usr/bin/env python

import string
from types import *

UNICODE_ERR = 'Unicode conversion error'

def u_to_l_char(ch1, ch2):
	if ch1 != '\000':
		return '?'
	else:
		return ch2

def unicode_to_latin1(str):
	out = ''
	if len(str) % 2 != 0:
		raise UNICODE_ERR, 'String length must be even'
	for i in range(len(str) / 2):
		out = out + u_to_l_char(str[i*2], str[i*2+1])
	return out

def latin1_to_unicode(str):
	if type(str) is not StringType:
		raise TypeError, 'argument must be a string, not "%s"' % `str`
	return string.join(map(lambda x: '\000' + x, str), '')
