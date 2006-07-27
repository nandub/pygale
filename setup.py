#!/usr/bin/env python

import sys, string, os
try:
        import distutils
except ImportError:
	print
	print '*** ERROR! ***'
	print 'Unable to import Python Distribution Utilities'
	print 'Either upgrade to Python 2.0 or better, or install'
	print 'the distutils before installing PyGale:'
	print '    http://www.python.org/sigs/distutils-sig/download.html'
	sys.exit(-1)
from distutils.core import setup, Extension

def have_swig():
	# This really only works on unix; it should be implemented in
	# distutils itself, really
	# Yucky hack
	swig_output = os.popen('swig -version 2>&1', 'r').read()
	if string.find(swig_output, 'SWIG Version 1.1') != -1:
                sys.stderr.write('SWIG 1.1 is no longer supported with '
                    ' pygale.  Please upgrade to version 1.3.10 or later.  '
                    'The maintainer apologizes for the inconvenience.\n')
	if string.find(swig_output, 'SWIG Version 1.3') != -1:
		return 1
	else:
		return 0

if sys.platform == 'win32':
	include_dirs = ['/peterh/ext/openssl-0.9.6a/inc32']
	library_dirs = ['/peterh/ext/openssl-0.9.6a/out32dll']
	libraries = ['libeay32']
else:
	include_dirs = []
	library_dirs = []
	libraries = ['crypto']

# Set up openssl extension
extensions = []
source_files = []
sub_module_names = \
[
	'bn',
	'evp',
	'rand',
	'rsa',
]

if have_swig():
	extension = '.i'
else:
	extension = '.c'
for module_name in sub_module_names:
	source_files.append('py-openssl/%sc%s' % (module_name, extension))
source_files.append('py-openssl/opensslc.c')
new_extension = Extension('opensslc', source_files, 
			  include_dirs = include_dirs, 
			  library_dirs = library_dirs, libraries = libraries)
extensions.append(new_extension)

setup (name = "python-pygale",
       version = "1.2.3",
       description = "Python Gale interface",
       author = "Tessa Lau",
       author_email = "tlau-pygale@ofb.net",
       url = "http://fugu.gale.org",
       packages = ['pygale', 'pygale.openssl'],
       ext_package = 'pygale.openssl',
       ext_modules = extensions,
	  scripts = ['gsub.py', 'gsend.py', 'pygale-config']
)
