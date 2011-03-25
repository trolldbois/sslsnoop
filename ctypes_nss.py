#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
log=logging.getLogger('ctypes_nss')

from model import is_valid_address,getaddress,array2bytes,bytes2array,LoadableMembers,RangeValue,NotNull,CString,EVP_CIPHER_CTX_APP_DATA_PTR
import model
import ctypes_nss_generated as gen

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

from model import CString
# replace c_char_p with our String handler
gen.STRING = CString
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

import inspect,sys
# auto import gen.* into . ?
__my_module__ = sys.modules[__name__]
_loaded=0
for (name,klass) in inspect.getmembers(gen, inspect.isclass):
  if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_nss_generated' :
    setattr(__my_module__, name, klass)
    pasteNSSStructOver(klass)
    _loaded+=1
log.debug('loaded %d C structs from NSS'%(_loaded))



''' Load all generateed classes to local classRef '''
NSSStruct.classRef=dict([ (ctypes.POINTER( klass), klass) for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass) if klass.__module__ == __name__])

''' Load all model classes and create a similar non-ctypes Python class  
  thoses will be used to translate non pickable ctypes into POPOs.
'''
for klass,typ in inspect.getmembers(sys.modules[__name__], inspect.isclass):
  if typ.__module__ == __name__:
    setattr(sys.modules[__name__], '%s_py'%(klass), type('%s_py'%(klass),(object,),{}) )


def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_nss_generated' :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)
  #print 'SSLCipherSuiteInfo:',ctypes.sizeof(SSLCipherSuiteInfo)
  #print 'SSLChannelInfo:',ctypes.sizeof(SSLChannelInfo)

if __name__ == '__main__':
  printSizeof()

