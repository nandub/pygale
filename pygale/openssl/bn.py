"""
Expose the ability to create OpenSSL BIGNUM objects (multiprecision
integers -- see bn(3)).

"""

import opensslc
try:
  import _bnc as bnc
except ImportError:
  import bnc
import wrap

class BIGNUM(wrap.Wrapper):
  def __init__(self, ptr = None):
#   attr_dict = \
#   {
#     'd': (bnc.BIGNUM_d_get, bnc.BIGNUM_d_set, None),
#   }
    wrap.Wrapper.__init__(self, ptr, bnc.BN_new, bnc.BN_free)

  def to_long(self):
    return long(bnc.BN_bn2hex(self.ptr), 16)

def bin2bn(data):
  r"""
  Convert a string of bytes in big endian order into a bignum with at
  least 8 * (len of string) bits of precision.

  >>> '%x' % bin2bn('\xde\xad\xbe\xefABCD').to_long()
  'deadbeef41424344'

  Python strings are length-counted, not 0-terminated, so 0 bytes can
  be used with impunity to construct the bignum.

  >>> bin2bn('\0\1\0').to_long()
  256L

  """
  return BIGNUM(bnc.BN_bin2bn(data, len(data), None))
