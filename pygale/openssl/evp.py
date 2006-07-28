"""
The mysterious evp module.

Test by jtr, adapted from tlau's pygale/tests/test.py.

>>> import os
>>> td= lambda x: os.path.join(os.environ['PYGALE_TEST_DIR'], x)

>>> key_file= open(td('private/selma@test.yammer.net.gpri'))
>>> priv_key= openssl.evp.PKEY()
>>> priv_key.assign_RSA(openssl.rsa.RSA())
>>> key_data= key_file.read()
>>> key_file.close()
>>> import_privkey(key_data, priv_key.pkey.rsa)

>>> key_file= open(td('public/selma@test.yammer.net.gpub'))
>>> pub_key= openssl.evp.PKEY()
>>> pub_key.assign_RSA(openssl.rsa.RSA())
>>> pub_data= key_file.read()
>>> key_file.close()
>>> import_pubkey(key_data, pub_key.pkey.rsa)

>>> context= openssl.evp.MD_CTX()
>>> context.SignInit(openssl.evp.md5())
>>> context.SignUpdate('foobar')
>>> signature= context.SignFinal(priv_key)
>>> context= openssl.evp.MD_CTX()
>>> context.VerifyInit(openssl.evp.md5())
>>> context.VerifyUpdate('foobar')
>>> result = context.VerifyFinal(signature, pub_key)
>>> context= openssl.evp.CIPHER_CTX()
>>> iv, encrypted_keys= context.SealInit(openssl.evp.des_ede3_cbc(),
...     [pub_key])
>>> result= context.SealUpdate('foo')
>>> encrypted_data= context.SealFinal()
>>> result= context.OpenInit(openssl.evp.des_ede3_cbc(),
...     encrypted_keys[0], iv, priv_key)
>>> result= context.OpenUpdate(encrypted_data)
>>> result= context.OpenFinal()
>>> priv_key= None
>>> key_data= None
>>> key_file= None
>>> pub_data= None
>>> context= None
>>> signature= None
>>> result= None
>>> iv= None
>>> encrypted_keys= None

"""

import opensslc
try:
  import _evpc as evpc
except ImportError:
  import evpc
import rsa
import wrap

class MD(wrap.Wrapper):
  def __init__(self, ptr= None):
    wrap.Wrapper.__init__(self, ptr)

class MD_CTX(wrap.Wrapper):
  def __init__(self, ptr= None):
    wrap.Wrapper.__init__(self, ptr, evpc.EVP_MD_CTX_new, evpc.EVP_MD_CTX_free)

  def SignInit(self, type):
    evpc.EVP_SignInit(self.ptr, type.ptr)

  def SignUpdate(self, signature_data):
    evpc.EVP_SignUpdate(self.ptr, signature_data, len(signature_data))

  def SignFinal(self, key):
    return evpc.python_EVP_SignFinal(self.ptr, key.ptr)

  def VerifyInit(self, type):
    evpc.EVP_VerifyInit(self.ptr, type.ptr)

  def VerifyUpdate(self, signed_data):
    evpc.EVP_VerifyUpdate(self.ptr, signed_data, len(signed_data))

  def VerifyFinal(self, signature, key):
    return evpc.EVP_VerifyFinal(self.ptr, signature, len(signature), key.ptr)

class PKEY(wrap.Wrapper):
  def __init__(self, ptr= None):
    wrap.Wrapper.__init__(self, ptr, evpc.EVP_PKEY_new, evpc.EVP_PKEY_free,
        {'pkey': (evpc.EVP_PKEY_pkey_get, None, PKEY_pkey)})

  def assign_RSA(self, rsa_key): 
    evpc.EVP_PKEY_assign_RSA(self.ptr, rsa_key.ptr)
    rsa_key.free_ptr= 0

class PKEY_pkey(wrap.Wrapper):
  def __init__(self, ptr):
    wrap.Wrapper.__init__(self, ptr, None, None, {'rsa':
        (evpc.EVP_PKEY_pkey_rsa_get, evpc.EVP_PKEY_pkey_rsa_set, rsa.RSA)})

class CIPHER(wrap.Wrapper):
  def __init__(self, ptr= None):
    wrap.Wrapper.__init__(self, ptr)

class CIPHER_CTX(wrap.Wrapper):
  def __init__(self, ptr= None):
    wrap.Wrapper.__init__(self, ptr, evpc.EVP_CIPHER_CTX_new,
        evpc.EVP_CIPHER_CTX_free)

  def SealInit(self, type, public_keys):
    return evpc.python_EVP_SealInit(self.ptr, type.ptr, public_keys)

  def SealUpdate(self, unencrypted_data):
    return evpc.python_EVP_SealUpdate(self.ptr, unencrypted_data)

  def SealFinal(self):
    return evpc.python_EVP_SealFinal(self.ptr)

  def OpenInit(self, type, encrypted_key, iv, private_key):
    return evpc.EVP_OpenInit(self.ptr, type.ptr, encrypted_key,
        len(encrypted_key), iv, private_key.ptr)

  def OpenUpdate(self, encrypted_data):
    return evpc.python_EVP_OpenUpdate(self.ptr, encrypted_data)

  def OpenFinal(self):
    return evpc.python_EVP_OpenFinal(self.ptr)

def md5():
  return MD(evpc.EVP_md5())

def des_ede3_cbc():
  return CIPHER(evpc.EVP_des_ede3_cbc())
