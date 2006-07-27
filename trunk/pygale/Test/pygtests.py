#!/usr/bin/env python

"""
Run a battery of unit tests.

Running the tests is, in theory, trivial... just
  ./pygtests.py
should do it.  If all the tests pass, you will see no messages.  You
can add a -v switch if you actually want to watch the tests passing.
However, there are some setup pitfalls to keep in mind:

  1.  The installed form of the pygale package differs from the
      pygale/pygale directory in CVS in that it contains a file,
      openssl/opensslc.so, that is built by Swig from the
      pygale/py-openssl directory.  These tests do require opensslc.so
      to be in place, so the easiest thing to do is to install pygale
      by running
        python setup.py install
      from the top pygale directory.

  2.  There are several things named pygale (the directory pygale, its
      subdirectory pygale/pygale, and pygale/pygale/pygale.py), so if
      you're in the wrong directory, the standard "from pygale import
      pygale" could pick up the wrong thing and break.  This test
      attempts to solve this problem by deleting the CWD from the
      module search path so the system-installed version of pygale
      will be used.

"""

import sys, doctest, getopt, os

# TODO - just figure out how to find the package directory and scan
# all modules
ALL_TESTS= '''
  pygale authcache openssl.bn openssl.rand openssl.rsa openssl.evp
'''.split()

def testdataDir():
  dirname= os.path.dirname(sys.argv[0]) or '.'
  d= os.path.join(dirname, 'testdata')
  if not os.path.isdir(d):
    print >> sys.stderr, 'Unable to open testdata in %s; dying.' % d
    sys.exit(1)
  return d

def main(args):

  # The CWD is removed from the system path to avoid picking up the
  # wrong pygale on import; see, the source tree contains two
  # directories named pygale and a file called pygale.py, and none of
  # them is what we want to import here, because the tests require the
  # Swigged opensslc.so to be built.
  origsyspath= sys.path[:]
  for danger in '.', '':
    while danger in sys.path:
      sys.path.remove(danger)

  ov, args= getopt.getopt(args, 'v')
  verbose= '-v' in dict(ov)
  failures= 0
  print sys.path
  from pygale import pygale
  pygale._testInit(testdataDir())
  for modname in args or ALL_TESTS:
    module= __import__('pygale.%s' % modname, globals(), locals(),
        modname.split('.')[-1:])
    if verbose:
      print module
    f= doctest.testmod(module)[0]
    failures += f
  sys.path= origsyspath
  return min(127, failures)

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
