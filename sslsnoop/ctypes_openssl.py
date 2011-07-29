#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging, sys

''' insure ctypes basic types are subverted '''
from haystack import model

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembers,RangeValue,NotNull,CString

import ctypes_openssl_generated as gen

log=logging.getLogger('openssl.model')

''' hmac.h:69 '''
HMAC_MAX_MD_CBLOCK=128
''' evp.h:91 '''
EVP_MAX_BLOCK_LENGTH=32
EVP_MAX_IV_LENGTH=16
AES_MAXNR=14 # aes.h:66
RIJNDAEL_MAXNR=14


# ============== Internal type defs ==============


class OpenSSLStruct(LoadableMembers):
  ''' defines classRef '''
  pass

BN_ULONG = ctypes.c_ulong


################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################




############# Start expectedValues and methods overrides #################

NIDs = dict( [(getattr(gen, s), s) for s in gen.__dict__ if s.startswith('NID_') ])
def getCipherName(nid):
  if nid not in NIDs:
    return None
  nidname = NIDs[nid]
  LNattr = 'SN'+nidname[3:] # del prefix 'NID'
  return getattr(gen, LNattr)

def getCipherDataType(nid):
  name = getCipherName(nid)
  if name is None:
    return None
  for t in EVP_CIPHER.CIPHER_DATA:
    if name.startswith( t ):
      return EVP_CIPHER.CIPHER_DATA[t]
  return None


''' rc4.h:71 '''
####### RC4_KEY #######
def RC4_KEY_getData(self):
  return array2bytes(self.data)
def RC4_KEY_fromPyObj(self,pyobj):
  #copy P and S
  self.data = bytes2array(pyobj.data, ctypes.c_uint)
  self.x = pyobj.x
  self.y = pyobj.y
  return self
RC4_KEY.getData = RC4_KEY_getData
RC4_KEY.fromPyObj = RC4_KEY_fromPyObj
#######

''' cast.h:80 '''
####### CAST_KEY #######
def CAST_KEY_getData(self):
  return array2bytes(self.data)
def CAST_KEY_getShortKey(self):
  return self.short_key
def CAST_KEY_fromPyObj(self,pyobj):
  #copy P and S
  self.data = bytes2array(pyobj.data, ctypes.c_uint)
  self.short_key = pyobj.short_key
  return self
CAST_KEY.getData = CAST_KEY_getData
CAST_KEY.getShortKey = CAST_KEY_getShortKey
CAST_KEY.fromPyObj = CAST_KEY_fromPyObj
#######



''' blowfish.h:101 '''
####### BF_KEY #######
def BF_KEY_getP(self):
  return array2bytes(self.P)
  #return ','.join(["0x%lx"%key for key in self.rd_key])
def BF_KEY_getS(self):
  return array2bytes(self.S)
def BF_KEY_fromPyObj(self,pyobj):
  #copy P and S
  self.P = bytes2array(pyobj.P, ctypes.c_ulong)
  self.S = bytes2array(pyobj.S, ctypes.c_ulong)
  return self
BF_KEY.getP = BF_KEY_getP
BF_KEY.getS = BF_KEY_getS
BF_KEY.fromPyObj = BF_KEY_fromPyObj
#######


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


############ BIGNUM
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


######## RSA key
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



########## DSA Key
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

######### EP_CIPHER
EVP_CIPHER.expectedValues={
    #crypto/objects/objects.h 0 is undef .. crypto cipher is a smaller subset :
    # 1-10 19 29-46 60-70 91-98 104 108-123 166
    # but for argument sake, we have to keep an open mind
    "nid": RangeValue( min(NIDs.keys()), max(NIDs.keys()) ), 
    "block_size": [1,2,4,6,8,16,24,32,48,64,128], # more or less
    "key_len": RangeValue(1,0xff), # key_len *8 bits ..2040 bits for a key is enought ? 
                                   # Default value for variable length ciphers 
    "iv_len": RangeValue(0,0xff), #  rc4 has no IV ?
    "init": [NotNull], 
    "do_cipher": [NotNull], 
    #"cleanup": [NotNull], # aes-cbc ?
    "ctx_size": RangeValue(0,0xffff), #  app_data struct should not be too big
  }
EVP_CIPHER.CIPHER_DATA = { 
	 "DES": DES_key_schedule,
	 "3DES": DES_key_schedule,
	 "BF": BF_KEY,
	 "CAST": CAST_KEY,
	 "RC4": RC4_KEY,
	 "ARCFOUR": RC4_KEY,
	 "AES": AES_KEY,
  }


########### EVP_CIPHER_CTX
EVP_CIPHER_CTX.expectedValues={
    "cipher": [NotNull], 
    "encrypt": [0,1], 
    "buf_len": RangeValue(0,EVP_MAX_BLOCK_LENGTH), ## number we have left, so must be less than buffer_size
    #"engine": , # can be null
    #"app_data": , # can be null if cipher_data is not
    #"cipher_data": , # can be null if app_data is not
    "key_len": RangeValue(1,0xff), # key_len *8 bits ..2040 bits for a key is enought ? 
  }

# loadMembers, if nid & cipher_data-> we can assess cipher_data format to be a XX_KEY
def EVP_CIPHER_CTX_loadMembers(self, mappings, maxDepth):
  if not super(EVP_CIPHER_CTX,self).loadMembers(mappings, maxDepth):
    return False
  log.debug('trying to load cipher_data Structs.')
  '''
  if bool(cipher) and bool(self.cipher.nid) and is_valid_address(cipher_data):
    memcopy( self.cipher_data, cipher_data_addr, self.cipher.ctx_size)
    # cast possible on cipher.nid -> cipherType
  '''
  if self.cipher.contents.nid == 0: # NID_undef, not openssl doing
    log.info('The cipher is home made - the cipher context data should be application dependant (app_data)')
    return True
    
  struct = getCipherDataType( self.cipher.contents.nid) 
  log.debug('cipher type is %s - loading %s'%( getCipherName(self.cipher.contents.nid), struct ))
  if(struct is None):
    log.warning("Unsupported cipher %s"%(self.cipher.contents.nid))
    return True
  
  # c_void_p is a basic type.
  attr_obj_address = self.cipher_data
  memoryMap = is_valid_address_value( attr_obj_address, mappings, struct)
  log.debug( "cipher_data CAST into : %s "%(struct) )
  if not memoryMap:
    log.warning('in CTX On second toughts, cipher_data seems to be at an invalid address. That should not happen (often).')
    log.warning('%s addr:0x%lx size:0x%lx addr+size:0x%lx '%(is_valid_address_value( attr_obj_address, mappings), 
                                attr_obj_address, ctypes.sizeof(struct), attr_obj_address+ctypes.sizeof(struct)))
    return True
  #ok
  st = memoryMap.readStruct(attr_obj_address, struct )
  model.keepRef(st, struct, attr_obj_address)
  self.cipher_data = ctypes.c_void_p(ctypes.addressof(st)) 
  # check debug
  attr=getattr(self, 'cipher_data')      
  log.debug('Copied 0x%lx into %s (0x%lx)'%(ctypes.addressof(st), 'cipher_data', attr))      
  log.debug('LOADED cipher_data as %s from 0x%lx (%s) into 0x%lx'%(struct, 
        attr_obj_address, is_valid_address_value(attr_obj_address, mappings, struct), attr ))
  log.debug('\t\t---------\n%s\t\t---------'%st.toString())
  return True

def EVP_CIPHER_CTX_toPyObject(self):
    d=super(EVP_CIPHER_CTX,self).toPyObject()
    log.debug('Cast a EVP_CIPHER_CTX into PyObj')
    # cast app_data or cipher_data to right struct
    if bool(self.cipher_data):
      struct = getCipherDataType( self.cipher.contents.nid)
      if struct is not None:
        # CAST c_void_p to struct
        d.cipher_data = struct.from_address(self.cipher_data).toPyObject()
    return d

def EVP_CIPHER_CTX_getOIV(self):
  return array2bytes(self.oiv)
def EVP_CIPHER_CTX_getIV(self):
  return array2bytes(self.iv)

EVP_CIPHER_CTX.loadMembers = EVP_CIPHER_CTX_loadMembers
EVP_CIPHER_CTX.toPyObject = EVP_CIPHER_CTX_toPyObject
EVP_CIPHER_CTX.getOIV = EVP_CIPHER_CTX_getOIV
EVP_CIPHER_CTX.getIV  = EVP_CIPHER_CTX_getIV

##########


# checkks
'''
import sys,inspect
src=sys.modules[__name__]
for (name, klass) in inspect.getmembers(src, inspect.isclass):
  #if klass.__module__ == src.__name__ or klass.__module__.endswith('%s_generated'%(src.__name__) ) :
  #  #if not klass.__name__.endswith('_py'):
  print klass, type(klass) #, len(klass.classRef)
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

