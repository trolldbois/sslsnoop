#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
from ptrace.debugger.memory_mapping import readProcessMappings
import logging
log=logging.getLogger('model')


''' returns if the address of the struct is in the mapping area
'''
def is_valid_address(obj,mappings, structType=None):
  '''static int is_valid_address(unsigned long addr, mappings_t *mappings) {'''
  # check for null pointers
  #print 'is_valid_address'
  addr=getaddress(obj)
  if addr == 0:
    return False
  for m in mappings:
    if addr in m:
      # check if end of struct is ALSO in m
      if (structType is not None):
        s=ctypes.sizeof(structType)
        if (addr+s) not in m:
          return False
      return True
  return False

''' returns the address of the struct
'''
def getaddress(obj):
  # check for null pointers
  #print 'getaddress'
  if bool(obj):
    if not hasattr(obj,'contents'):
      return 0
    #print 'get adressses is '
    return ctypes.addressof(obj.contents)
  else:
    #print 'object pointer is null'
    return 0  

def sstr(obj):
  #print obj, ctypes.addressof(obj),
  if bool(obj):
    #print 'obj.contents ',type(obj.contents)
    return str(obj.contents)
  else:
    #print 'sstr: None'
    return "0x0"


class LoadableMembers(ctypes.Structure):
  loaded=False
  valid=False
  def loadMembers(self,process):
    ''' 
    isValid() should have been tested before, otherwise.. it's gonna fail...
    we copy memory from process for each pointer
    and assign it to a python object _here, then we assign 
    the member to be a pointer to _here'''
    if self.loaded:
      return True
    if not self.valid:
      log.error("%s not loaded, it's not even valid"%(self.__class__.__name__))
      return False
    mappings= readProcessMappings(process)
    # we only load struct here. basic type must be done by specialized methods.
    classRef=dict([ (ctypes.POINTER( t), t) for t in [BIGNUM, STACK, CRYPTO_EX_DATA, RSA, DSA, BN_MONT_CTX, EVP_CIPHER, EVP_CIPHER_CTX, EVP_MD]])
    ## go through all members. if they are pointers AND not null AND in valid memorymapping AND a struct type, load them as struct pointers
    for attrname,attrtype in self._fields_:
      if attrtype.__module__ == 'ctypes':
        # basic type, ignore
        continue
      if attrtype not in classRef:
        continue
      attr=getattr(self,attrname)
      # check null, in mappings and contents types.
      ## already checked by self.valid - we hope - if not is_valid_address(obj,mappings):
      if not bool(attr): # null is ok
        continue
      if not hasattr(attr,'contents'): # not struct is ok
        continue
      _attrname='_'+attrname
      attr_obj_address=getaddress(attr)
      #log.debug('getaddress(self.%s) 0x%lx'%(attrname, attr_obj_address) )
      #save ref to keep mem alloc - XXX Useful ?
      _attrType=classRef[attrtype]
      ## boundary Double validation - check if address space of supposed valid member is cool and fits in mappings
      if ( not is_valid_address( attr, mappings, _attrType) ):
        log.warning('member %s has been unvalidated by boudaries check'%attrname)
        return False
      setattr(self, _attrname, process.readStruct(attr_obj_address, _attrType ) )
      #save pointer to it's place
      setattr(self, attrname, ctypes.pointer( getattr(self, _attrname) ) )
      # recurse
      attr=getattr(self,attrname)
      if not bool(attr):
        log.warning('Member %s is null after copy: %s'%(attrname,attr))
        continue
      # attr.contents isntance is always different
      contents=attr.contents
      if (not contents.isValid(mappings) ):
        log.debug('Member %s is invalid: %s'%(attrname,attr))
        self.valid=False
        return False
      # go and load
      ret=contents.loadMembers(process)
      #if attrname == 'n':
      #  print ctypes.addressof(contents), contents.top
      #  print ctypes.addressof(attr.contents), attr.contents.top
      if not ret:
        log.debug('member %s was not loaded'%(attrname))
        return False
    self.loaded=True
    return True
    
  def __str__(self):
    s=repr(self)+'\n'
    for field,typ in self._fields_:
      attr=getattr(self,field)
      if not bool(attr):
        s+='%s: 0x0\n'%field
      elif hasattr(attr,'contents'):
        s+='%s: 0x%lx\n'%(field, getaddress(getattr(self,field)) )  
      else:
        s+='%s: %s\n'%(field,attr )  
    return s


