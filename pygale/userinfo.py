import os
import sys
import string

# Exports the following three module-level variables:
# home_dir
# user_name	(e.g. Tessa Lau)
# login_name	(e.g. tlau)

def get_start_dir():
	start_dir = os.path.dirname(sys.argv[0])
	orig_dir = os.getcwd()
	if start_dir:
		os.chdir(start_dir)
	start_dir = os.getcwd()
	os.chdir(orig_dir)
	return start_dir

if sys.platform == 'win32':
	try:
		import win32api
		user_name = win32api.GetUserName()
		login_name = user_name
	except ImportError:
		user_name = 'Unknown'
		login_name = 'unknown'
	# get_start_dir is temporory. This should be using SHGetSpecialFolderLocation
	home_dir = os.path.join(get_start_dir(), 'users', user_name)
else:
	import pwd
	pwd_info = pwd.getpwuid(os.geteuid())
	gecos = pwd_info[4]
	commapos = string.find(gecos, ',')
	if commapos != -1:
		user_name = gecos[:commapos]
	else:
		user_name = gecos
	login_name = pwd_info[0]
	if os.environ.has_key('HOME'):
		home_dir = os.environ['HOME']
	else:
		home_dir = pwd_info[5]
