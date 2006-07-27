#!/usr/bin/env python
#
# $Id: log.py,v 1.1.1.1 2002/09/03 18:21:25 tlau Exp $
#

def write(message):
	log_file = open("log.txt", "a")
	log_file.write(message)
	log_file.close()
