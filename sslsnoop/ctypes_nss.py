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
from haystack.model import LoadableMembersStructure,RangeValue,NotNull,CString, IgnoreMember

import ctypes_nss_generated as gen

log=logging.getLogger('ctypes_nss')


# ============== Internal type defs ==============

'''
http://mxr.mozilla.org/firefox/source/security/nss/lib/ssl/ssl.h
http://mxr.mozilla.org/firefox/source/security/nss/lib/ssl/sslt.h
http://mxr.mozilla.org/firefox/source/security/nss/lib/ssl/sslimpl.h#912
'''

class NSSStruct(LoadableMembersStructure):
  ''' defines classRef '''
  pass



# replace c_char_p with our String handler
if type(gen.STRING) != type(CString):
  print 'STRING is not model.CString. Please correct ctypes_nss_generated with :' 
  print 'from model import CString' 
  print 'STRING = CString' 
  import sys
  sys.exit()


################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################




############# Start expectedValues and methods overrides #################



sslSocket.expectedValues = {
 "fd": RangeValue(1,0xffff), 
  #"version": [0x0002, 0x0300, 0x0301 ], #sslproto.h
  "version": RangeValue(1,0x0301), 
  "clientAuthRequested": [0,1], # 
  "delayDisabled": [0,1], # 
  "firstHsDone": [0,1], # 
  "handshakeBegun": [0,1], # 
  "TCPconnected": [0,1], # 
  "lastWriteBlocked": [0,1], # 
  "url": NotNull,
  }



sslOptions.expectedValues = {
#  "useSecurity": [0,1], # doh... 
  "handshakeAsClient" : [1],
  "handshakeAsServer" : [0],
}

sslSecurityInfo.expectedValues = {
  "cipherType": RangeValue(1,0xffffffff),
  #"writeBuf" : IgnoreMember,
}


ssl3State.expectedValues = {
}


ssl3CipherSpec.expectedValues = {
  "cipher_def" : NotNull,
  "mac_def" : NotNull,
}


'''
# set expected values 
SSLCipherSuiteInfo.expectedValues={
  "cipherSuite": RangeValue(0,0x0100), # sslproto.h , ECC is 0xc00
  "authAlgorithm": RangeValue(0,4),
  "keaType": RangeValue(0,4),
  "symCipher": RangeValue(0,9),
  "macAlgorithm": RangeValue(0,4),
}

SSLChannelInfo.expectedValues={
  'compressionMethod':RangeValue(0,1),
}

SECItem.expectedValues={
  'type':RangeValue(0,15), # security/nss/lib/util/seccomon.h:64
}

SECKEYPublicKey.expectedValues={
  'keyType':RangeValue(0,6), # security/nss/lib/cryptohi/keythi.h:189
}

#NSSLOWKEYPublicKey.expectedValues={
#  'keyType':RangeValue(0,5), # security/nss/lib/softoken/legacydb/lowkeyti.h:123
#}

CERTCertificate.expectedValues={ # XXX TODO CHECK VALUES security/nss/lib/certdb/certt.h
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

CERTSignedCrl.expectedValues = {
  'isperm': [0,1], # ok
  'istemp': [0,1], # ok
  'referenceCount': RangeValue(1,0xffff), # no idea... should be positive for sure. more than 65535 ref ? naah
}

CERTCertTrustStr.expectedValues = {
  #'sslFlags': [1<<i for i in range(0,11+1)] , # ok security/nss/lib/softoken/legacydb/pcertt.h:438
  'sslFlags': RangeValue(0, 1<<12) , # simpler
  'emailFlags': RangeValue(0, 1<<12) , # simpler
  'objectSigningFlags': RangeValue(0, 1<<12) , # simpler
}

'''

##########


def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_nss_generated' :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)
  #print 'SSLCipherSuiteInfo:',ctypes.sizeof(SSLCipherSuiteInfo)
  #print 'SSLChannelInfo:',ctypes.sizeof(SSLChannelInfo)

if __name__ == '__main__':
  printSizeof()

