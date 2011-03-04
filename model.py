#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes

class mapping:
  '''	struct _mapping *next;
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
	("d",ctypes.c_ulong), #BN_ULONG
	('top',ctypes.c_int),
	('dmax',ctypes.c_int),
	('neg',ctypes.c_int),
	('flags',ctypes.c_int)]

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
def is_valid_address(addr,mappings):
  '''static int is_valid_address(unsigned long addr, mappings_t *mappings) {'''
  for m in mappings:
    if addr in m:
      return True
  return False


#KO
class RSA(ctypes.Structure):
  _fields_ = [
  ("pad",	ctypes.c_int), 
	("version",	ctypes.c_long),
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
  def isValid(self,mappings):
    return (self.pad and self.version and
        	(self.references < 0) and (self.references > 0xff)  and
        is_valid_address( ctypes.addressof(self.n), mappings)    and
        is_valid_address( ctypes.addressof(self.e), mappings)    and
        is_valid_address( ctypes.addressof(self.d), mappings)    and
        is_valid_address( ctypes.addressof(self.p), mappings)    and
        is_valid_address( ctypes.addressof(self.q), mappings)    and
        is_valid_address( ctypes.addressof(self.dmp1), mappings) and
        is_valid_address( ctypes.addressof(self.dmq1), mappings) and
        is_valid_address( ctypes.addressof(self.iqmp), mappings)  )

#KO
class DSA(ctypes.Structure):
  _fields_ = [
  ("pad",	ctypes.c_int), 
	("version",	ctypes.c_long),
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
	("meth",ctypes.POINTER(BIGNUM)),#	const DSA_METHOD *meth;
	("engine",ctypes.POINTER(BIGNUM))#ENGINE *engine;
  ]
  def isValid(self,mappings):
    return (
        self.pad and self.version and
        (self.references < 0) and (self.references > 0xff)  and
        is_valid_address( ctypes.addressof(self.p), mappings)        and
        is_valid_address( ctypes.addressof(self.q), mappings)        and
        is_valid_address( ctypes.addressof(self.g), mappings)        and
        is_valid_address( ctypes.addressof(self.priv_key), mappings) and
        is_valid_address( ctypes.addressof(self.pub_key), mappings)  and
        is_valid_address( ctypes.addressof(self.kinv), mappings) and
        is_valid_address( ctypes.addressof(self.r), mappings)  )
  
  
