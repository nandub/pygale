#!/usr/bin/env python

import os, sys, socket, shutil, string
import pygale, gale_env, userinfo, version, ROOT

PYGALE_CONF = os.environ.get('PYGALE_CONF', 'pygale.conf')

# Check for existing conf file, and if it doesn't exist, run the
# configurator
def check():
	pygaledir = gale_env.get('PYGALE_DIR',
		os.path.join(userinfo.home_dir, '.gale'))
	conf_file = os.path.join(pygaledir, PYGALE_CONF)
	if os.path.exists(conf_file):
		gale_env.load_file(conf_file)
		if gale_env.get('PYGALE_VERSION', '1.0') >= version.VERSION:
			return
	run_setup()

def make_path(path_name):
	current_path = path_name
	unmade_dirs = []
	while current_path and not os.path.exists(current_path):
		unmade_dirs.insert(0, current_path)
		current_path = os.path.dirname(current_path)
	for dir_name in unmade_dirs:
		os.mkdir(dir_name)

def conditional_mkdir(dir_name, perms = None):
	parent = os.path.dirname(dir_name)
	if parent and not os.path.exists(parent):
		conditional_mkdir(parent)
	if not os.path.exists(dir_name):
		print 'Creating directory', dir_name
		try:
			os.mkdir(dir_name)
		except Exception, e:
			print 'Unable to create directory %s: %s' % (dir_name, e)
			sys.exit(-1)
		if perms is not None:
			os.chmod(dir_name, perms)

def get_gale_sys_env():	
	pygaledir = gale_env.get('PYGALE_DIR',
		os.path.join(userinfo.home_dir, '.gale'))
	fname = os.path.join(pygaledir, PYGALE_CONF)
	if os.path.exists(fname):
		gale_env.load_file(fname)
		result = 'Reading PyGale settings from ' + fname
	else:
		# Assume some reasonable defaults
		try:
			gale_env.set('GALE_SYS_DIR', os.path.join(string.strip(
				os.popen('gale-config --prefix', 'r').read()),
				'etc', 'gale'))
		except:			
			# Can't find gale-config; Gale probably isn't installed
			if sys.platform == 'win32':
				gale_env.set('GALE_SYS_DIR', get_start_dir())
			else:
				gale_env.set('GALE_SYS_DIR', '/usr/local/etc/gale')
		conffile = os.path.join(gale_env.get('GALE_SYS_DIR'), 'conf')
		if os.path.exists(conffile):
			confvars = gale_env.parse_sys_conf(conffile)
			result = 'Reading Gale settings from ' + conffile
		else:
			confvars = {}
			result = 'No existing Gale configuration found'
		if confvars.has_key('GALE_DOMAIN'):
			gale_env.set('GALE_DOMAIN', confvars['GALE_DOMAIN'])
		
	return result

def write_settings():
	print
	GALE_SYS_DIR = gale_env.get('GALE_SYS_DIR')
	conditional_mkdir(GALE_SYS_DIR, 0755)
	conditional_mkdir(os.path.join(GALE_SYS_DIR, 'auth'), 0755)
	conditional_mkdir(os.path.join(GALE_SYS_DIR, 'auth', 'cache'), 0777)
	conditional_mkdir(os.path.join(GALE_SYS_DIR, 'auth', 'local'), 01777)
	conditional_mkdir(os.path.join(GALE_SYS_DIR, 'auth', 'private'), 0755)
	conditional_mkdir(os.path.join(GALE_SYS_DIR, 'auth', 'trusted'), 0755)
	root_key_path = os.path.join(GALE_SYS_DIR, 'auth', 'trusted', 'ROOT')
	if not os.path.exists(root_key_path):
		try:
			f = open(root_key_path, 'wb')
			f.write(ROOT.rootkey)
			f.close()
			os.chmod(root_key_path, 0644)
		except:
			print '#' * 50
			print 'Trouble installing the ROOT key in its proper location.'
			print 'WARNING!  Puffs will not be verified!'
			print '#' * 50
	galedir = gale_env.get('GALE_DIR',
		os.path.join(userinfo.home_dir, '.gale'))
	conditional_mkdir(galedir)
	conditional_mkdir(os.path.join(galedir, 'auth'))
	conditional_mkdir(os.path.join(galedir, 'auth', 'local'))
	conditional_mkdir(os.path.join(galedir, 'auth', 'private'))
	conditional_mkdir(os.path.join(galedir, 'auth', 'trusted'))
	pygaledir = gale_env.get('PYGALE_DIR',
		os.path.join(userinfo.home_dir, '.gale'))
	fname =  os.path.join(pygaledir, PYGALE_CONF)
	print 'Writing configuration ...',
	f = open(fname, 'w')
	f.write('PYGALE_VERSION %s\n' % version.VERSION)
	f.write('GALE_SYS_DIR %s\n' % gale_env.get('GALE_SYS_DIR'))
	f.write('GALE_ID %s\n' % gale_env.get('GALE_ID'))
	f.write('GALE_DOMAIN %s\n' % gale_env.get('GALE_DOMAIN'))
	f.write('GALE_NAME %s\n' % gale_env.get('GALE_NAME'))
	f.close()
	
	print 'done'
	print 'To modify this configuration, edit', fname

def run_setup():
	print get_gale_sys_env()
	print
	print 'PyGale configuration'

	galedir = gale_env.get('PYGALE_DIR',
		os.path.join(userinfo.home_dir, '.gale'))
	if not os.path.exists(galedir):
		print 'Creating directory', galedir
		# make PYGALE_DIR
		make_path(galedir)
		
	conffile = os.path.join(galedir, PYGALE_CONF)
	if os.path.exists(conffile):
		print 'Reading settings from %s' % conffile
		gale_env.load_file(conffile)
	
	gale_sys_dir = gale_env.get('GALE_SYS_DIR', '/usr/local/etc/gale')
	print
	print 'Gale system directory'
	print 'This directory contains the public key cache and other Gale-'
	print 'specific data.  It can and should be shared between Gale users'
	print 'on the same machine or network.  If you have an existing Gale'
	print 'installation, enter its path here.  Otherwise, I will create'
	print 'this directory for you.'
	gsd = raw_input('Gale system directory [%s]: ' % gale_sys_dir)
	if gsd:
		gale_sys_dir = gsd
	gale_env.set('GALE_SYS_DIR', gale_sys_dir)

	print
	print 'Gale domain'
	print 'Enter the default domain to be appended to unqualified locations.'
	print 'It also determines the Gale server you connect to.'
	print "If you don't know what this is, contact your local Gale"
	print 'administrator.'
	domain = gale_env.get('GALE_DOMAIN', None)
	if domain is None:
		try:
			domain = socket.gethostbyaddr(socket.gethostname())[0]
		except:
			domain = 'NODOMAIN'
	gd = raw_input('Gale domain [%s]: ' % domain)
	if gd:
		domain = gd
	gale_env.set('GALE_DOMAIN', domain)

	print
	print 'Gale ID'
	print 'Enter the id that identifies you to other Gale users.  You must'
	print 'have a valid public/private key pair for this id.'
	gale_user = pygale.gale_user()
	gu = raw_input('Gale ID [%s]: ' % gale_user)
	if gu:
		gale_user = gu
	gale_env.set('GALE_ID', gale_user)

	# check for private key file
	privkey = os.path.join(galedir, 'auth', 'private', gale_user)
	privkey_gpri = os.path.join(galedir, 'auth', 'private',
		gale_user + '.gpri')

	file_exists = 0
	if os.path.exists(privkey_gpri) or os.path.exists(privkey):
		file_exists = 1
	
	while not file_exists:
		print
		print 'The Gale ID you have specified requires a private key file.'
		print 'Normally it would exist as one of these files:'
		print '   ', privkey_gpri
		print '   ', privkey
		print 'Please enter the location of your private key file.'
		pkf = raw_input('Private key file: ')
		if not os.path.exists(pkf):
			continue
		if pkf == privkey or pkf == privkey_gpri:
			file_exists = 1
			continue
		print 'Copying private key to %s' % privkey_gpri
		if not os.path.exists(os.path.dirname(privkey_gpri)):
			make_path(os.path.dirname(privkey_gpri))
		shutil.copy(pkf, privkey_gpri)
		file_exists = 1

	# select user name
	print
	print 'Enter your name.  This is a freeform string that accompanies'
	print 'every puff.  People generally use their full name (e.g., Joe'
	print 'Smith).'

	# Use (in order) GALE_NAME or our username
	fullname = gale_env.get('GALE_NAME', userinfo.user_name)
	gn = raw_input('Name [%s]: ' % fullname)
	if gn:
		fullname = gn
	gale_env.set('GALE_NAME', fullname)

	# write
	write_settings()


