"""
Expose some functions from the OpenSSL rand module.  See rand(3)
(OpenSSL version).

"""

import opensslc
try:
  import _randc as randc
except ImportError:
  import randc

def screen():
  """
  Seed the random number generator with the screen buffer.  This
  bizarre function only does anything on Windows; on other systems,
  it's a no-op.

  >>> screen()

  """
  randc.RAND_screen()

def seed(data):
  """
  Seed the random number generator with as many random bytes as you
  could dig up from somewhere and paste together into a str.

  >>> seed('abcdefghijklmnop')
  
  """
  randc.RAND_seed(data, len(data))

def bytes(num):
  """
  Return the specified number of random bytes in a str.

  >>> len(bytes(15))
  15

  """
  return randc.python_RAND_bytes(num)
