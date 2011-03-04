#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
log=logging.getLogger('model')

class mapping:
  '''  struct _mapping *next;
  unsigned long address;
  unsigned int size;
  int flags;
  const char *name;
  mappings_t *mappings;
  char * data;
  '''
  next=None
  address=0
  size=0
  flags=0
  name=None
  mappings=0
  data=None
  def __init__(self,address,size,flags,name):
    self.address=address
    self.size=size
    self.flags=flags
    self.name=name
      
class mappings:
  pid=None
  maps=None

#ok
class BIGNUM(ctypes.Structure):
  _fields_ = [
  ("d",ctypes.POINTER(ctypes.c_ulong) ), #BN_ULONG *
  ('top',ctypes.c_int),
  ('dmax',ctypes.c_int),
  ('neg',ctypes.c_int),
  ('flags',ctypes.c_int)
  ]
  def isValid(self):
    if ( self.dmax < 0 or self.top < 0 or self.dmax < self.top ):
      return False
    if ( not (self.neg == 1 or self.neg == 0 ) ) :
      return False 
    return True
  def __str__(self):
    if self.d:
      d=ctypes.addressof(self.d.contents)
    else:
      d=0
    return ("BN { d=0x%lx, top=%d, dmax=%d, neg=%d, flags=%d }"%
                (d, self.top, self.dmax, self.neg, self.flags) )
#ok
class STACK(ctypes.Structure):
  _fields_ = [
  ("num",ctypes.c_int),
  ("data",ctypes.c_char_p),
  ("sorted",ctypes.c_int),
  ("num_alloc",ctypes.c_int),
  ("comp",ctypes.POINTER(ctypes.c_int) ) ]

#ok
class CRYPTO_EX_DATA(ctypes.Structure):
  _fields_ = [
  ("sk",ctypes.POINTER(STACK) ),
  ("dummy",ctypes.c_int)]
  
#ok
class BN_MONT_CTX(ctypes.Structure):
  _fields_ = [
  ("ri",ctypes.c_int),
  ("RR",BIGNUM),
  ("N",BIGNUM),
  ("Ni",BIGNUM),
  ("n0",ctypes.c_ulong),
  ("flags",ctypes.c_int)]


''' returns 0 if the address seems to be valid
          -1 else.
'''
def is_valid_address(obj,mappings):
  '''static int is_valid_address(unsigned long addr, mappings_t *mappings) {'''
  # check for null pointers
  if bool(obj):
    addr=ctypes.addressof(obj.contents)
    #log.debug("addr: 0x%lx"%addr)
    for m in mappings:
      #log.debug(m)
      if addr in m:
        return True
  return False

def getaddress(obj):
  if bool(obj):
    return ctypes.addressof(obj.contents)
  else:
    return 0  

def sstr(obj):
  print obj, ctypes.addressof(obj),
  if bool(obj):
    print obj.contents
    return str(obj.contents)
  else:
    print None
    return "NULL"
#KO
class RSA(ctypes.Structure):
  _fields_ = [
  ("pad",  ctypes.c_int), 
  ("version",  ctypes.c_long),
  ("meth",ctypes.POINTER(BIGNUM)),#const RSA_METHOD *meth;
  ("engine",ctypes.POINTER(BIGNUM)),#ENGINE *engine;
  ('n', ctypes.POINTER(BIGNUM) ),
  ('e', ctypes.POINTER(BIGNUM) ),
  ('d', ctypes.POINTER(BIGNUM) ),
  ('p', ctypes.POINTER(BIGNUM) ),
  ('q', ctypes.POINTER(BIGNUM) ),
  ('dmp1', ctypes.POINTER(BIGNUM) ),
  ('dmq1', ctypes.POINTER(BIGNUM) ),
  ('iqmp', ctypes.POINTER(BIGNUM) ),
  ("ex_data", CRYPTO_EX_DATA ),
  ("references", ctypes.c_int),
  ("flags", ctypes.c_int),
  ("_method_mod_n", ctypes.POINTER(BN_MONT_CTX) ),
  ("_method_mod_p", ctypes.POINTER(BN_MONT_CTX) ),
  ("_method_mod_q", ctypes.POINTER(BN_MONT_CTX) ),
  ("bignum_data",ctypes.c_char_p),
  ("blinding",ctypes.POINTER(BIGNUM)),#BN_BLINDING *blinding;
  ("mt_blinding",ctypes.POINTER(BIGNUM))#BN_BLINDING *mt_blinding;
  ]
  def printValid(self,mappings):
    log.debug( '----------------------- pad: %d version %d ref %d'%(self.pad,self.version,self.references) )
    log.debug(is_valid_address( self.n, mappings)    )
    log.debug(is_valid_address( self.e, mappings)    )
    log.debug(is_valid_address( self.d, mappings)    )
    log.debug(is_valid_address( self.p, mappings)    )
    log.debug(is_valid_address( self.q, mappings)    )
    log.debug(is_valid_address( self.dmp1, mappings) ) 
    log.debug(is_valid_address( self.dmq1, mappings) )
    log.debug(is_valid_address( self.iqmp, mappings) )
  def isValid(self,mappings):
    ''' struct is valid when :
    '''
    return (self.pad ==0 and self.version ==0 and
          (0 <= self.references <= 0xfff)  and
        is_valid_address( self.n, mappings)    and
        is_valid_address( self.e, mappings)    and
        is_valid_address( self.d, mappings)    and
        is_valid_address( self.p, mappings)    and
        is_valid_address( self.q, mappings)    and
        is_valid_address( self.dmp1, mappings) and
        is_valid_address( self.dmq1, mappings) and
        is_valid_address( self.iqmp, mappings) )
  def __str__(self):
    s=repr(self)+'\n'
    for field,typ in self._fields_:
      if typ != ctypes.c_char_p and typ != ctypes.c_int and typ != CRYPTO_EX_DATA:
        #s+='%s: 0x%lx\n'%(field, getaddress(getattr(self,field)) )  
        s+='%s: %s\n'%(field, sstr(getattr(self,field)) )  
      else:
        s+='%s: %s\n'%(field,getattr(self,field) )  
    return s
    
#KO
class DSA(ctypes.Structure):
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
  ("meth",ctypes.POINTER(BIGNUM)),#  const DSA_METHOD *meth;
  ("engine",ctypes.POINTER(BIGNUM))#ENGINE *engine;
  ]
  def isValid(self,mappings):
    return (
        self.pad ==0 and self.version ==0 and
        (0 <= self.references <= 0xfff)  and
        is_valid_address( self.p, mappings)        and
        is_valid_address( self.q, mappings)        and
        is_valid_address( self.g, mappings)        and
        is_valid_address( self.priv_key, mappings) and
        is_valid_address( self.pub_key, mappings)  and
        is_valid_address( self.kinv, mappings) and
        is_valid_address( self.r, mappings)  )
  def __str__(self):
    s=repr(self)+'\n'
    for field,typ in self._fields_:
      if typ != ctypes.c_char_p and typ != ctypes.c_int and type != CRYPTO_EX_DATA:
        s+='%s: 0x%lx\n'%(field, getaddress(getattr(self,field)) )  
      else:
        s+='%s: %s\n'%(field,getattr(self,field) )        
    return s
  
  
