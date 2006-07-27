"""
Expose the fields of a C struct.

>>> r= RSA()
>>> r.flags= 0xa0
>>> r.flags
160
>>> r.iqmp= bn.bin2bn('iqmp')
>>> r.iqmp.to_long()
1769041264L
>>> r.dmq1= bn.bin2bn('dmq1')
>>> r.dmq1.to_long()
1684894001L
>>> r.dmp1= bn.bin2bn('dmp1')
>>> r.dmp1.to_long()
1684893745L
>>> r.p= bn.bin2bn('p')
>>> r.p.to_long() == ord('p')
True
>>> r.q= bn.bin2bn('q')
>>> r.q.to_long() == ord('q')
True
>>> r.d= bn.bin2bn('d')
>>> r.d.to_long() == ord('d')
True
>>> r.e= bn.bin2bn('e')
>>> r.e.to_long() == ord('e')
True
>>> r.n= bn.bin2bn('n')
>>> r.n.to_long() == ord('n')
True

>>> del r

"""

import opensslc
try:
  import _rsac as rsac
except ImportError:
  import rsac
import wrap
import bn

class RSA(wrap.Wrapper):
  def __init__(self, ptr = None):
    attr_dict = \
    {
      'flags': (rsac.RSA_flags_get, rsac.RSA_flags_set, None),
      'iqmp': (rsac.RSA_iqmp_get, rsac.RSA_iqmp_set, bn.BIGNUM),
      'dmq1': (rsac.RSA_dmq1_get, rsac.RSA_dmq1_set, bn.BIGNUM),
      'dmp1': (rsac.RSA_dmp1_get, rsac.RSA_dmp1_set, bn.BIGNUM),
      'q': (rsac.RSA_q_get, rsac.RSA_q_set, bn.BIGNUM),
      'p': (rsac.RSA_p_get, rsac.RSA_p_set, bn.BIGNUM),
      'd': (rsac.RSA_d_get, rsac.RSA_d_set, bn.BIGNUM),
      'e': (rsac.RSA_e_get, rsac.RSA_e_set, bn.BIGNUM),
      'n': (rsac.RSA_n_get, rsac.RSA_n_set, bn.BIGNUM),
    }
    wrap.Wrapper.__init__(self, ptr, rsac.RSA_new, rsac.RSA_free, attr_dict)

