#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging

''' insure ctypes basic types are subverted '''
from haystack import model

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembers,RangeValue,NotNull,CString,EVP_CIPHER_CTX_APP_DATA_PTR

import ctypes_openssl_generated as gen

log=logging.getLogger('openssl.model')

''' hmac.h:69 '''
HMAC_MAX_MD_CBLOCK=128
''' evp.h:91 '''
EVP_MAX_BLOCK_LENGTH=32
EVP_MAX_IV_LENGTH=16
AES_MAXNR=14 # aes.h:66
RIJNDAEL_MAXNR=14

# we have to alloc a big chunk
BN_ULONG=ctypes.c_ulong

class OpenSSLStruct(LoadableMembers):
  ''' defines classRef '''
  pass


# evp/e_aes.c:66
class EVP_AES_KEY(OpenSSLStruct):
  _fields_ = [
  ('ks', gen.AES_KEY),
	]
  def fromPyObj(self,pyobj):
    self.ks = gen.AES_KEY().fromPyObj(pyobj.ks)
    return self


class EVP_RC4_KEY(OpenSSLStruct): # evp/e_rca.c
  _fields_ = [
  ('ks', gen.RC4_KEY)
  ]




################ START copy generated classes ##########################



#logging.basicConfig(level=logging.DEBUG)


import inspect,sys
# auto import gen.* into . ?

def pasteModelMethodsOn(klass, register):
  #model.pasteLoadableMemberMethodsOn(klass)
  klass.classRef = register.classRef
  return klass

def copyGeneratedClasses(src, dst, register):
  ''' 
  @param me : dst module
  @param src : src module, generated
  '''
  __root_module_name,__dot,__module_name = dst.__name__.rpartition('.')
  _loaded=0
  _registered=0
  for (name, klass) in inspect.getmembers(src, inspect.isclass):
    if type(klass) == type(ctypes.Structure):
      if klass.__module__.endswith('%s_generated'%(__module_name) ) :
        setattr(dst, name, klass)
        pasteModelMethodsOn(klass, register)
        #log.debug("painted on %s"%klass)
        _loaded+=1
    else:
      #log.debug("%s - %s"%(name, klass))
      pass
    # register structs and basic Types pointers
    if klass.__module__ == src.__name__ or klass.__module__.endswith('%s_generated'%(src.__name__) ) :
      register.classRef[ctypes.POINTER( klass)] = klass
      _registered+=1
  log.debug('loaded %d C structs from %s structs'%( _loaded, src.__name__))
  log.debug('registered %d Pointers types'%( _registered))
  log.debug('There is %d members in %s'%(len(src.__dict__), src.__name__))
  return 

def createPOPOClasses( targetmodule ):
  ''' Load all model classes and create a similar non-ctypes Python class  
    thoses will be used to translate non pickable ctypes into POPOs.
  '''
  _created=0
  for klass,typ in inspect.getmembers(targetmodule, inspect.isclass):
    if typ.__module__.startswith(targetmodule.__name__):
      kpy = type('%s_py'%(klass),(model.pyObj,),{})
      setattr(targetmodule, '%s_py'%(klass), kpy )
      _created+=1
      if typ.__module__ != targetmodule.__name__: # copy also to generated
        setattr(sys.modules[typ.__module__], '%s_py'%(klass), kpy )
        #log.debug("Created %s_py"%klass)
  log.debug('created %d POPO types'%( _created))
  return


copyGeneratedClasses(gen, sys.modules[__name__], OpenSSLStruct )

createPOPOClasses( sys.modules[__name__] )

#print 'DONE'

################ END   copy generated classes ##########################







''' aes.h:78 '''
####### AES_KEY #######
def AES_KEY_getKey(self):
  #return array2bytes(self.rd_key)
  return ','.join(["0x%lx"%key for key in self.rd_key])
def AES_KEY_getRounds(self):
  return self.rounds
def AES_KEY_fromPyObj(self,pyobj):
  #copy rd_key
  self.rd_key=bytes2array(pyobj.rd_key,ctypes.c_ulong)
  #copy rounds
  self.rounds=pyobj.rounds
  return self
AES_KEY.getKey = AES_KEY_getKey
AES_KEY.getRounds = AES_KEY_getRounds
AES_KEY.fromPyObj = AES_KEY_fromPyObj
#######


# BIGNUM
BIGNUM.expectedValues={
    "neg": [0,1]
  }
def BIGNUM_loadMembers(self, mappings, maxDepth):
  ''' 
  #self._d = process.readArray(attr_obj_address, ctypes.c_ulong, self.top) 
  ## or    
  #ulong_array= (ctypes.c_ulong * self.top)    
  '''
  if not self.isValid(mappings):
    log.debug('BigNUm tries to load members when its not validated')
    return False
  # Load and memcopy d / BN_ULONG *
  attr_obj_address=getaddress(self.d)
  if not bool(self.d):
    log.debug('BIGNUM has a Null pointer d')
    return True
  memoryMap = is_valid_address_value( attr_obj_address, mappings)
  contents=(BN_ULONG*self.top).from_buffer_copy(memoryMap.readArray(attr_obj_address, BN_ULONG, self.top))
  log.debug('contents acquired %d'%ctypes.sizeof(contents))
  self.d.contents=BN_ULONG.from_address(ctypes.addressof(contents))
  self.d=ctypes.cast(contents, ctypes.POINTER(BN_ULONG) ) 
  return True

def BIGNUM_isValid(self,mappings):
  if ( self.dmax < 0 or self.top < 0 or self.dmax < self.top ):
    return False
  return LoadableMembers.isValid(self,mappings)

def BIGNUM___str__(self):
  d= getaddress(self.d)
  return ("BN { d=0x%lx, top=%d, dmax=%d, neg=%d, flags=%d }"%
              (d, self.top, self.dmax, self.neg, self.flags) )

BIGNUM.loadMembers = BIGNUM_loadMembers
BIGNUM.isValid     = BIGNUM_isValid
BIGNUM.__str__     = BIGNUM___str__
#################



# STACK tack/stack.h:74

# CRYPTO_EX_DATA crypto.h:158:
def CRYPTO_EX_DATA_loadMembers(self, mappings, maxDepth):
  ''' erase self.sk'''
  #self.sk=ctypes.POINTER(STACK)()
  return LoadableMembers.loadMembers(self, mappings, maxDepth)
def CRYPTO_EX_DATA_isValid(self,mappings):
  ''' erase self.sk'''
  # TODO why ?
  #self.sk=ctypes.POINTER(STACK)()
  return LoadableMembers.isValid(self,mappings)

CRYPTO_EX_DATA.loadMembers = CRYPTO_EX_DATA_loadMembers 
CRYPTO_EX_DATA.isValid     = CRYPTO_EX_DATA_isValid 
#################

'''
#ENGINE_CMD_DEFN engine/engine.h:272
class ENGINE_CMD_DEFN(OpenSSLStruct):
	_fields_ = [
  ('cmd_num',ctypes.c_uint),
  ('cmd_name', CString),
  ('cmd_desc', CString),
  ('cmd_flags',ctypes.c_uint)
  ]  
'''

'''
class ENGINE(OpenSSLStruct):
  pass
ENGINE._fields_ = [
  ('id', CString),
  ('name', CString),
  ('rsa_meth',ctypes.POINTER(ctypes.c_int) ),
  ('dsa_meth',ctypes.POINTER(ctypes.c_int) ),
  ('dh_meth',ctypes.POINTER(ctypes.c_int) ),
  ('ecdh_meth',ctypes.POINTER(ctypes.c_int) ),
  ('ecdsa_meth',ctypes.POINTER(ctypes.c_int) ),
  ('rand_meth',ctypes.POINTER(ctypes.c_int) ),
  ('store_meth',ctypes.POINTER(ctypes.c_int) ),
  ('ciphers',ctypes.POINTER(ctypes.c_int) ), ## fn typedef int (*ENGINE_CIPHERS_PTR)(ENGINE *, const EVP_CIPHER **, const int **, int);
  ('digest',ctypes.POINTER(ctypes.c_int) ),  ## fn typedef int (*ENGINE_DIGESTS_PTR)(ENGINE *, const EVP_MD **, const int **, int);
  ('destroy',ctypes.POINTER(ctypes.c_int) ), ## fn typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
  ('init',ctypes.POINTER(ctypes.c_int) ),    ## fn typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
  ('finish',ctypes.POINTER(ctypes.c_int) ),  ## fn typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
  ('ctrl',ctypes.POINTER(ctypes.c_int) ),    ## fn typedef int (*ENGINE_CTRL_FUNC_PTR)(ENGINE *, int, long, void *, void (*f)(void));
  ('load_privkey',ctypes.POINTER(EVP_PKEY) ), ## fn EVP_PKEY *
  ('load_pubkey',ctypes.POINTER(EVP_PKEY) ),  ## fn EVP_PKEY *
  ('load_ssl_client_cert',ctypes.POINTER(ctypes.c_int) ), ## fn typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *ssl,
  ('cmd_defns',ctypes.POINTER(ENGINE_CMD_DEFN) ), ##
  ('flags',ctypes.c_int),
  ('struct_ref',ctypes.c_int),
  ('funct_ref',ctypes.c_int),
  ('ex_data',CRYPTO_EX_DATA),
  ('prev',ctypes.POINTER(ENGINE) ),
  ('nex',ctypes.POINTER(ENGINE) )
  ]
'''

"""
class RSA(OpenSSLStruct):
  ''' rsa/rsa.h '''
  loaded=False
  _fields_ = [
  ("pad",  ctypes.c_int), 
  ("version",  ctypes.c_long),
  ("meth",ctypes.POINTER(BIGNUM)),#const RSA_METHOD *meth;
  ("engine",ctypes.POINTER(ENGINE)),#ENGINE *engine;
  ('n', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
  ('e', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
  ('d', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
  ('p', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
  ('q', ctypes.POINTER(BIGNUM) ), ## still in ssh memap
  ('dmp1', ctypes.POINTER(BIGNUM) ),
  ('dmq1', ctypes.POINTER(BIGNUM) ),
  ('iqmp', ctypes.POINTER(BIGNUM) ),
  ("ex_data", CRYPTO_EX_DATA ),
  ("references", ctypes.c_int),
  ("flags", ctypes.c_int),
  ("_method_mod_n", ctypes.POINTER(BN_MONT_CTX) ),
  ("_method_mod_p", ctypes.POINTER(BN_MONT_CTX) ),
  ("_method_mod_q", ctypes.POINTER(BN_MONT_CTX) ),
  ("bignum_data",ctypes.POINTER(ctypes.c_ubyte)), ## moue c_char_p ou POINTER(c_char) ?
  ("blinding",ctypes.POINTER(BIGNUM)),#BN_BLINDING *blinding;
  ("mt_blinding",ctypes.POINTER(BIGNUM))#BN_BLINDING *mt_blinding;
  ]
"""  
RSA.expectedValues={
    "pad": [0], 
    "version": [0], 
    "references": RangeValue(0,0xfff),
    "n": [NotNull],
    "e": [NotNull],
    "d": [NotNull],
    "p": [NotNull],
    "q": [NotNull],
    "dmp1": [NotNull],
    "dmq1": [NotNull],
    "iqmp": [NotNull]
  }
def RSA_printValid(self,mappings):
  log.debug( '----------------------- LOADED: %s'%self.loaded)
  log.debug('pad: %d version %d ref %d'%(self.pad,self.version,self.references) )
  log.debug(is_valid_address( self.n, mappings)    )
  log.debug(is_valid_address( self.e, mappings)    )
  log.debug(is_valid_address( self.d, mappings)    )
  log.debug(is_valid_address( self.p, mappings)    )
  log.debug(is_valid_address( self.q, mappings)    )
  log.debug(is_valid_address( self.dmp1, mappings) ) 
  log.debug(is_valid_address( self.dmq1, mappings) )
  log.debug(is_valid_address( self.iqmp, mappings) )
  return
def RSA_loadMembers(self, mappings, maxDepth):
  #self.meth = 0 # from_address(0)
  # ignore bignum_data.
  #self.bignum_data = 0
  self.bignum_data.ptr.value = 0
  #self.blinding = 0
  #self.mt_blinding = 0

  if not LoadableMembers.loadMembers(self, mappings, maxDepth):
    log.debug('RSA not loaded')
    return False
  return True

RSA.printValid  = RSA_printValid
RSA.loadMembers = RSA_loadMembers



"""
class DSA(OpenSSLStruct):
  _fields_ = [
  ("pad",  ctypes.c_int), 
  ("version",  ctypes.c_long),
  ("write_params",ctypes.c_int),
  ('p', ctypes.POINTER(BIGNUM) ),
  ('q', ctypes.POINTER(BIGNUM) ),
  ('g', ctypes.POINTER(BIGNUM) ),
  ('pub_key', ctypes.POINTER(BIGNUM) ),
  ('priv_key', ctypes.POINTER(BIGNUM) ),
  ('kinv', ctypes.POINTER(BIGNUM) ),
  ('r', ctypes.POINTER(BIGNUM) ),
  ("flags", ctypes.c_int),
  ("_method_mod_p", ctypes.POINTER(BN_MONT_CTX) ),
  ("references", ctypes.c_int),
  ("ex_data", CRYPTO_EX_DATA ),
  ("meth",ctypes.POINTER(ctypes.c_int)),#  const DSA_METHOD *meth;
  ("engine",ctypes.POINTER(ENGINE))
  ]
"""
DSA.expectedValues={
    "pad": [0], 
    "version": [0], 
    "references": RangeValue(0,0xfff),
    "p": [NotNull],
    "q": [NotNull],
    "g": [NotNull],
    "pub_key": [NotNull],
    "priv_key": [NotNull]
  }
def DSA_printValid(self,mappings):
  log.debug( '----------------------- \npad: %d version %d ref %d'%(self.pad,self.version,self.write_params) )
  log.debug(is_valid_address( self.p, mappings)    )
  log.debug(is_valid_address( self.q, mappings)    )
  log.debug(is_valid_address( self.g, mappings)    )
  log.debug(is_valid_address( self.pub_key, mappings)    )
  log.debug(is_valid_address( self.priv_key, mappings)    )
  return
def DSA_loadMembers(self, mappings, maxDepth):
  # clean other structs
  # r and kinv can be null
  self.meth = None
  self._method_mod_p = None
  #self.engine = None
  
  if not LoadableMembers.loadMembers(self, mappings, maxDepth):
    log.debug('DSA not loaded')
    return False

  return True

DSA.printValid  = DSA_printValid
DSA.loadMembers = DSA_loadMembers


#ok
"""
class EVP_CIPHER(OpenSSLStruct):
  ''' evp.h:332 '''	
  _fields_ = [
  ("nid",  ctypes.c_int), 
  ("block_size",  ctypes.c_int), 
  ("key_len",  ctypes.c_int), 
  ("iv_len",  ctypes.c_int), 
  ("flags",  ctypes.c_ulong), 
  ("init",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("do_cipher",  ctypes.POINTER(ctypes.c_int)), # function () ## crypt func.
  ("cleanup",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("ctx_size",  ctypes.c_int), 
  ("set_asn1_parameters",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("get_asn1_parameters",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("ctrl",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("app_data",  ctypes.POINTER(ctypes.c_ubyte)) 
  ]
"""  
EVP_CIPHER.expectedValues={
    "key_len": RangeValue(1,0xff), # key_len *8 bits ..2040 bits for a key is enought ? 
                                   # Default value for variable length ciphers 
    "iv_len": RangeValue(1,0xff), #  
    "init": [NotNull], 
    "do_cipher": [NotNull], 
    #"cleanup": [NotNull], # aes-cbc ?
    "ctx_size": RangeValue(0,0xffff), #  app_data struct should not be too big
  }
"""
#mok
class EVP_CIPHER_CTX(OpenSSLStruct):
  ''' evp.h:332 '''	
  _fields_ = [
  ("cipher",  ctypes.POINTER(EVP_CIPHER)), 
  ("engine",  ctypes.POINTER(ctypes.c_int)), ## TODO ENGINE*
  ("encrypt",  ctypes.c_int), 
  ("buf_len",  ctypes.c_int), 
  ("oiv",  ctypes.c_ubyte*EVP_MAX_IV_LENGTH),## unsigned char  oiv[EVP_MAX_IV_LENGTH];
  ("iv",  ctypes.c_ubyte*EVP_MAX_IV_LENGTH), ##unsigned char  iv[EVP_MAX_IV_LENGTH];
  ("buf",  ctypes.c_ubyte*EVP_MAX_BLOCK_LENGTH), ##unsigned char buf[EVP_MAX_BLOCK_LENGTH];
  ("num",  ctypes.c_int), 
  ("app_data",  EVP_CIPHER_CTX_APP_DATA_PTR), # utilise par ssh_aes/rijndael
  ("key_len",  ctypes.c_int), 
  ("flags",  ctypes.c_ulong), 
  ("cipher_data",  EVP_CIPHER_CTX_APP_DATA_PTR), ## utilise par rc4 ?
  ("final_used",  ctypes.c_int), 
  ("block_mask",  ctypes.c_int), 
  ("final",  ctypes.c_ubyte*EVP_MAX_BLOCK_LENGTH) ###unsigned char final[EVP_MAX_BLOCK_LENGTH]
  ]
"""
EVP_CIPHER_CTX.expectedValues={
    "cipher": [NotNull], 
    "encrypt": [0,1], 
    "buf_len": RangeValue(0,EVP_MAX_BLOCK_LENGTH), ## number we have left, so must be less than buffer_size
    #"engine": , # can be null
    #"app_data": , # can be null if cipher_data is not
    #"cipher_data": , # can be null if app_data is not
    "key_len": RangeValue(1,0xff), # key_len *8 bits ..2040 bits for a key is enought ? 
  }
  
def EVP_CIPHER_CTX_getOIV(self):
  return array2bytes(self.oiv)
def EVP_CIPHER_CTX_getIV(self):
  return array2bytes(self.iv)

EVP_CIPHER_CTX.getOIV = EVP_CIPHER_CTX_getOIV
EVP_CIPHER_CTX.getIV  = EVP_CIPHER_CTX_getIV

"""
#mok
class EVP_MD(OpenSSLStruct):
  ''' struct env_md_st evp.h:227 '''
  _fields_ = [
  ("type",  ctypes.c_int), 
  ("pkey_type",  ctypes.c_int), 
  ("md_size",  ctypes.c_int), 
  ("flags",  ctypes.c_ulong), 
  ("init",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("update",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("final",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("copy",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("cleanup",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("sign",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("verify",  ctypes.POINTER(ctypes.c_int)), # function () 
  ("required_pkey_type",  ctypes.c_int*5), #required_pkey_type[5]
  ("block_size",  ctypes.c_int), 
  ("ctx_size",  ctypes.c_int)
  ]

class EVP_MD_CTX(OpenSSLStruct):
  ''' evp.h:304 '''
  _fields_ = [
  ("digest",  ctypes.POINTER(EVP_MD)),
  ("engine",  ctypes.POINTER(ENGINE) ), #
  ("flags",  ctypes.c_ulong),
  ("md_data",  ctypes.POINTER(ctypes.c_ubyte))
  ]

class HMAC_CTX(OpenSSLStruct):
  ''' hmac.h:75 '''
  _fields_ = [
  ("md",  ctypes.POINTER(EVP_MD)), 
  ("md_ctx",  EVP_MD_CTX), 
  ("i_ctx",  EVP_MD_CTX), 
  ("o_ctx",  EVP_MD_CTX), 
  ("key_length",  ctypes.c_uint), 
  ("key",  ctypes.c_char * HMAC_MAX_MD_CBLOCK)
  ] 

"""










# checkks
'''
src=sys.modules[__name__]
for (name, klass) in inspect.getmembers(src, inspect.isclass):
  if klass.__module__ == src.__name__ or klass.__module__.endswith('%s_generated'%(src.__name__) ) :
    if not klass.__name__.endswith('_py'):
      print klass, len(klass.classRef)
'''

def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and klass.__module__.endswith('%s_generated'%(__name__) ) :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)
  #print 'SSLCipherSuiteInfo:',ctypes.sizeof(SSLCipherSuiteInfo)
  #print 'SSLChannelInfo:',ctypes.sizeof(SSLChannelInfo)


if __name__ == '__main__':
  printSizeof()

