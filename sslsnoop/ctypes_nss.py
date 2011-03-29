#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
from haystack.model import is_valid_address,getaddress,array2bytes,bytes2array,LoadableMembers,RangeValue,NotNull,CString,EVP_CIPHER_CTX_APP_DATA_PTR
import haystack.model
import ctypes_nss_generated as gen

log=logging.getLogger('ctypes_nss')

'''
http://mxr.mozilla.org/firefox/source/security/nss/lib/ssl/ssl.h
http://mxr.mozilla.org/firefox/source/security/nss/lib/ssl/sslt.h
http://mxr.mozilla.org/firefox/source/security/nss/lib/ssl/sslimpl.h#912
'''

class NSSStruct(LoadableMembers):
  ''' defines classRef '''
  pass

def pasteNSSStructOver(klass):
  model.pasteLoadableMemberMethodsOn(klass)
  klass.classRef = NSSStruct.classRef
  return klass

'''
 We are gonna load all generated structures into local __module__, adding
 LoadableMembers method classes and classRef on them.
 
 We just have to define expectedValues
'''

# replace c_char_p with our String handler
if type(gen.STRING) != type(CString):
  print 'STRING is not model.CString. Please correct ctypes_nss_geenrated with :' 
  print 'from model import CString' 
  print 'STRING = CString' 
  import sys
  sys.exit()

# set expected values 
gen.SSLCipherSuiteInfo.expectedValues={
  "cipherSuite": RangeValue(0,0x0100), # sslproto.h , ECC is 0xc00
  "authAlgorithm": RangeValue(0,4),
  "keaType": RangeValue(0,4),
  "symCipher": RangeValue(0,9),
  "macAlgorithm": RangeValue(0,4),
}

gen.SSLChannelInfo.expectedValues={
  'compressionMethod':RangeValue(0,1),
}

gen.SECItem.expectedValues={
  'type':RangeValue(0,15), # security/nss/lib/util/seccomon.h:64
}

gen.SECKEYPublicKey.expectedValues={
  'keyType':RangeValue(0,6), # security/nss/lib/cryptohi/keythi.h:189
}

#gen.NSSLOWKEYPublicKey.expectedValues={
#  'keyType':RangeValue(0,5), # security/nss/lib/softoken/legacydb/lowkeyti.h:123
#}

gen.CERTCertificate.expectedValues={ # XXX TODO CHECK VALUES security/nss/lib/certdb/certt.h
  'keyIDGenerated': [0,1], # ok
  'keyUsage': [RangeValue(0,gen.KU_ALL), # security/nss/lib/certdb/certt.h:570
      gen.KU_KEY_AGREEMENT_OR_ENCIPHERMENT ,
      RangeValue(gen.KU_NS_GOVT_APPROVED, gen.KU_ALL | gen.KU_NS_GOVT_APPROVED),
      gen.KU_KEY_AGREEMENT_OR_ENCIPHERMENT | gen.KU_NS_GOVT_APPROVED ] ,
  'rawKeyUsage': [RangeValue(0,gen.KU_ALL), # security/nss/lib/certdb/certt.h:570
      gen.KU_KEY_AGREEMENT_OR_ENCIPHERMENT ,
      RangeValue(gen.KU_NS_GOVT_APPROVED, gen.KU_ALL | gen.KU_NS_GOVT_APPROVED),
      gen.KU_KEY_AGREEMENT_OR_ENCIPHERMENT | gen.KU_NS_GOVT_APPROVED ] ,
  'keyUsagePresent': [0,1], # ok
  'nsCertType': [ RangeValue(0,0xff), # security/nss/lib/certdb/certt.h:459
      RangeValue(gen.EXT_KEY_USAGE_TIME_STAMP , gen.EXT_KEY_USAGE_TIME_STAMP | 0xff ), # not sure
      RangeValue(gen.EXT_KEY_USAGE_STATUS_RESPONDER  , gen.EXT_KEY_USAGE_STATUS_RESPONDER | 0xff ), # not sure
      RangeValue(gen.EXT_KEY_USAGE_TIME_STAMP | gen.EXT_KEY_USAGE_STATUS_RESPONDER  , 
                  gen.EXT_KEY_USAGE_TIME_STAMP | gen.EXT_KEY_USAGE_STATUS_RESPONDER | 0xff ) ] , # not sure
  'keepSession': [0,1], # ok
  'timeOK': [0,1], # ok
  'isperm': [0,1], # ok
  'istemp': [0,1], # ok
  'isRoot': [0,1], # ok
  'ownSlot': [0,1], # ok
  'referenceCount': RangeValue(1,0xffff), # no idea... should be positive for sure. more than 65535 ref ? naah
  'subjectName': NotNull, # a certificate must have one...
}

gen.CERTSignedCrl.expectedValues = {
  'isperm': [0,1], # ok
  'istemp': [0,1], # ok
  'referenceCount': RangeValue(1,0xffff), # no idea... should be positive for sure. more than 65535 ref ? naah
}

gen.CERTCertTrustStr.expectedValues = {
  #'sslFlags': [1<<i for i in range(0,11+1)] , # ok security/nss/lib/softoken/legacydb/pcertt.h:438
  'sslFlags': RangeValue(0, 1<<12) , # simpler
  'emailFlags': RangeValue(0, 1<<12) , # simpler
  'objectSigningFlags': RangeValue(0, 1<<12) , # simpler
}

import inspect,sys
# auto import gen.* into . ?
__my_module__ = sys.modules[__name__]
_loaded=0
for (name,klass) in inspect.getmembers(gen, inspect.isclass):
  if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_nss_generated' :
    setattr(__my_module__, name, klass)
    _loaded+=1
log.debug('loaded %d C structs from NSS'%(_loaded))

''' Load all generateed classes to local classRef '''
NSSStruct.classRef=dict([ (ctypes.POINTER( klass), klass) for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass) if klass.__module__ == __name__ or klass.__module__ == 'ctypes_nss_generated'])

''' Load all model classes and create a similar non-ctypes Python class  
  thoses will be used to translate non pickable ctypes into POPOs.
'''
for klass,typ in inspect.getmembers(sys.modules[__name__], inspect.isclass):
  if typ.__module__ == __name__:
    setattr(sys.modules[__name__], '%s_py'%(klass), type('%s_py'%(klass),(object,),{}) )

# copy classRef and methods, we have to wait after all class are loaded and in NSSStruct.classRef
for (name,klass) in inspect.getmembers(gen, inspect.isclass):
  if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_nss_generated' :
    pasteNSSStructOver(klass)





def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_nss_generated' :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)
  #print 'SSLCipherSuiteInfo:',ctypes.sizeof(SSLCipherSuiteInfo)
  #print 'SSLChannelInfo:',ctypes.sizeof(SSLChannelInfo)

if __name__ == '__main__':
  printSizeof()

