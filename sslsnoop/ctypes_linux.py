#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes

from haystack import model
from haystack.model import is_valid_address,getaddress,array2bytes,bytes2array,LoadableMembers,RangeValue,NotNull,CString,EVP_CIPHER_CTX_APP_DATA_PTR
import ctypes_linux_generated as gen

import logging
log=logging.getLogger('ctypes_linux')


class KernelStruct(LoadableMembers):
  ''' defines classRef '''
  pass

def pasteKernelStructOver(klass):
  model.pasteLoadableMemberMethodsOn(klass)
  klass.classRef = KernelStruct.classRef
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
gen.task_struct.expectedValues={
  'pid': RangeValue(1,65535),
  'tgid': RangeValue(1,65535),
  'flags': RangeValue(1,0xffffffff), #sched.h:1700 , 1 or 2 bits on each 4 bits group
  'files': NotNull, # guessing
  'fs': NotNull, # guessing
  #'comm': NotNull, # process name
}


import inspect,sys
# auto import gen.* into . ?
__my_module__ = sys.modules[__name__]
_loaded=0
for (name,klass) in inspect.getmembers(gen, inspect.isclass):
  if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_linux_generated' :
    setattr(__my_module__, name, klass)
    _loaded+=1
log.debug('loaded %d C structs from Kernel structs'%(_loaded))

''' Load all generateed classes to local classRef '''
KernelStruct.classRef=dict([ (ctypes.POINTER( klass), klass) for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass) if klass.__module__ == __name__ or klass.__module__ == 'ctypes_linux_generated'])

''' Load all model classes and create a similar non-ctypes Python class  
  thoses will be used to translate non pickable ctypes into POPOs.
'''
for klass,typ in inspect.getmembers(sys.modules[__name__], inspect.isclass):
  if typ.__module__.startswith(__name__):
    kpy = type('%s_py'%(klass),(model.pyObj,),{})
    setattr(sys.modules[__name__], '%s_py'%(klass), kpy )
    if typ.__module__ != __name__: # class is ctypes_xxx_generated
      setattr(sys.modules[typ.__module__], '%s_py'%(klass), kpy )
    #log.info("Created %s_py"%klass)

# copy classRef and methods, we have to wait after all class are loaded and in NSSStruct.classRef
for (name,klass) in inspect.getmembers(gen, inspect.isclass):
  if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_linux_generated' :
    pasteKernelStructOver(klass)
    #log.info("painted on %s"%klass)




def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and klass.__module__ == 'ctypes_linux_generated' :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)
  #print 'SSLCipherSuiteInfo:',ctypes.sizeof(SSLCipherSuiteInfo)
  #print 'SSLChannelInfo:',ctypes.sizeof(SSLChannelInfo)

if __name__ == '__main__':
  printSizeof(200)

