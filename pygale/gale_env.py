#!/usr/bin/env python

import os, re, socket, sys, string, userinfo

# Defaults go here
NAMESPACE = { }

SettingsErr = 'SettingsErr'

PYGALE_CONF = os.environ.get('PYGALE_CONF', 'pygale.conf')

def init(galeconf=None, domain=None):
  # Read gale conf
  if galeconf is None:
    galedir = get('GALE_DIR', os.path.join(userinfo.home_dir, '.gale'))
    galeconf = os.path.join(galedir, 'conf')
  if os.path.exists(galeconf):
    vars = parse_sys_conf(galeconf)
    NAMESPACE.update(vars)
  
  pygaleconf = os.path.join(NAMESPACE['PYGALE_DIR'], PYGALE_CONF)
  if os.path.exists(pygaleconf):
    vars = parse_sys_conf(pygaleconf)
    NAMESPACE.update(vars)
  if domain:
    set('GALE_DOMAIN', domain)

def set_pygale_dir():
  # Find the pygale dir; this is automatically done on module import
  if os.environ.has_key('PYGALE_DIR'):
    pygaledir = os.environ['PYGALE_DIR']
  else:
    pygaledir = os.path.join(userinfo.home_dir, '.gale')
  NAMESPACE['PYGALE_DIR'] = pygaledir

def load_file(fname):
  vars = parse_sys_conf(fname)
  NAMESPACE.update(vars)

def get(envvar, default=''):
  if os.environ.has_key(envvar):
    return os.environ[envvar]
  
  elif NAMESPACE.has_key(envvar):
    return NAMESPACE[envvar]
  
  else:
    return default

def set(envvar, value):
  NAMESPACE[envvar] = value
  
def get_list(envvar, default=''):
  var = get(envvar, default)
  return re.split('[ ,]*', var)

def has_key(envvar):
  return os.environ.has_key(envvar) or NAMESPACE.has_key(envvar)

def parse_sys_conf(fn):
  data = open(fn, 'r').readlines()
  vars = {}
  lastvar = None
  lastval = None
  for line in data:
    line = string.rstrip(line)
    if not line or line[0] == '#':
      continue
    if line[0] in string.whitespace and lastvar is not None:
      val = string.strip(line)
      if lastval is None:
        lastval = val
      else:
        lastval = lastval + '\n' + val
    else:
      if lastval is not None:
        # Set variable
        vars[lastvar] = lastval
        lastvar = None
        lastval = None

      ret = string.split(line, None, 1)
      lastvar = ret[0]
      if len(ret) > 1:
        lastval = ret[1]

  if lastval is not None:
    vars[lastvar] = lastval
  
  return vars

set_pygale_dir()
#init()
