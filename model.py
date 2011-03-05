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
def is_valid_address(obj,mappings):
  '''static int is_valid_address(unsigned long addr, mappings_t *mappings) {'''
  # check for null pointers
  #print 'is_valid_address'
  addr=getaddress(obj)
  if addr == 0:
    return False
  for m in mappings:
    if addr in m:
      return True
  return False

''' returns the address of the struct
'''
def getaddress(obj):
  # check for null pointers
  #print 'getaddress'
  if bool(obj):
    #print 'get adressses is '
    return ctypes.addressof(obj.contents)
  else:
    #print 'object pointer is null'
    return 0  

def sstr(obj):
  #print obj, ctypes.addressof(obj),
  if bool(obj):
    #print obj.contents
    return str(obj.contents)
  else:
    print None
    return "NULL"


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
  def loadMembers(self,process):
    ''' 
    isValid() should have been tested before, otherwise.. it's gonna fail...
    we copy memory from process for each pointer
    and assign it to a python object _here, then we assign 
    the member to be a pointer to _here'''
    # Load and memcopy d / BN_ULONG *
    attr_obj_address=getaddress(self.d)
    #print self
    self._d = process.readArray(attr_obj_address, ctypes.c_ulong, self.top) 
    ## or    
    #ulong_array= (ctypes.c_ulong * self.top)
    #self._d = process.readStruct(attr_obj_address, ulong_array) 
    self.d  = ctypes.cast(ctypes.pointer( self._d ), ctypes.POINTER(ctypes.c_ulong))
    return True
  
  def isValid(self,mappings):
    #print 'BIGNUM.isValid 1'
    #print self.flags
    if ( self.dmax < 0 or self.top < 0 or self.dmax < self.top ):
      return False
    #print 'BIGNUM.isValid 2'
    if ( not (self.neg == 1 or self.neg == 0 ) ) :
      return False 
    #print 'BIGNUM.isValid 3'
    #last test on memory address
    return is_valid_address( self.d, mappings)
    #return True
  
  def __str__(self):
    #print 'coucou',repr(self)
    #return repr(self)
    #print self.d
    #print 'add',ctypes.addressof(self.d)
    #print 'addc',ctypes.addressof(self.d.contents)
    ## is_valid_address(d,mappings) could be False
    #if self.d:
    #  print 'coucou2'
    #  d=ctypes.addressof(self.d.contents)
    #else:
    #  print 'coucou2.2'
    #  d=0
    d=0
    print 'coucou'
    print self.top
    return 'BIGNUM NB'
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
    return
  def loadMembers(self,process):
    ''' 
    isValid() should have been tested before, otherwise.. it's gonna fail...
    we copy memory from process for each pointer
    and assign it to a python object _here, then we assign 
    the member to be a pointer to _here'''
    # BIGNUMS
    for attrname in ['n','e','d','p','q','dmp1','dmq1','iqmp']:
      attr=getattr(self,attrname)
      _attrname='_'+attrname
      attr_obj_address=getaddress(attr)
      #log.debug('getaddress(self.%s) 0x%lx'%(attrname, attr_obj_address) )
      #save ref to keep mem alloc
      setattr(self, _attrname, process.readStruct(attr_obj_address,BIGNUM) )
      #save NB pointer to it's place
      setattr(self, attrname, ctypes.pointer( getattr(self, _attrname) ) )
      #### load inner structures pointers
      attr=getattr(self,attrname)
      mappings= readProcessMappings(process)
      if not ( attr and attr.contents.isValid(mappings) ):
        log.debug('BN %s is invalid: %s'%(attrname,attr))
        return False
      # go and load
      attr.contents.loadMembers(process)
    # XXXX clean other structs
    self.meth=None
    self._method_mod_n = None
    self._method_mod_p = None
    self._method_mod_q = None
    self.bignum_data = None
    self.blinding = None
    return True
    
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
        s+='%s: 0x%lx\n'%(field, getaddress(getattr(self,field)) )  
        #s+='%s: %s\n'%(field, sstr(getattr(self,field)) )  
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
  def printValid(self,mappings):
    log.debug( '----------------------- \npad: %d version %d ref %d'%(self.pad,self.version,self.write_params) )
    log.debug(is_valid_address( self.p, mappings)    )
    log.debug(is_valid_address( self.q, mappings)    )
    log.debug(is_valid_address( self.g, mappings)    )
    log.debug(is_valid_address( self.pub_key, mappings)    )
    log.debug(is_valid_address( self.priv_key, mappings)    )
    return
  def internalCheck(self):
    '''  pub_key = g^privKey mod p '''
    return
  def loadMembers(self,process):
    ''' 
    isValid() should have been tested before, otherwise.. it's gonna fail...
    we copy memory from process for each pointer
    and assign it to a python object _here, then we assign 
    the member to be a pointer to _here'''
    # BIGNUMS
    #print 'dsa.loadMember()'
    for attrname in ['p','q','g','pub_key','priv_key','kinv','r']:
      mappings= readProcessMappings(process)

      attr=getattr(self,attrname)
      _attrname='_'+attrname
      attr_obj_address=getaddress(getattr(self,attrname))
      #attr_obj_address=getaddress(attr)      
      log.debug('getaddress(self.%s) 0x%lx'%(attrname, attr_obj_address) )
      log.debug('getaddress(self.%s) 0x%lx'%('q', getaddress(self.q)) )
      log.debug('getaddress(self.%s) 0x%lx'%('p', getaddress(self.p)) )
      log.debug('getaddress(self.%s) 0x%lx'%('g', getaddress(self.g)) )
      print self
      if not is_valid_address(attr,mappings):
        print 'returned invalid adress for %s 0x%lx'%(attrname,attr_obj_address)
        return False
      
      #log.debug('getaddress(self.%s) 0x%lx'%(attrname, attr_obj_address) )
      #save ref to keep mem alloc
      setattr(self, _attrname, process.readStruct(attr_obj_address, BIGNUM) )
      #save NB pointer to it's place
      setattr(self,  attrname, ctypes.pointer( getattr(self, _attrname) ) )
      #### load inner structures pointers
      attr=getattr(self,attrname)

      print 'read mappings'

      mappings= readProcessMappings(process)
      if getattr(self,_attrname).isValid(mappings):
        getattr(self,_attrname).loadMembers(process)
        print 'members loaded'
      else:
        log.warning('%s is not valid'%_attrname)
        return False

      #attr.contents can't be loaded
      #if not ( attr and attr.contents.isValid(mappings) ):
      #  log.debug('BN %s is invalid: %s'%(attrname,attr))
      #  return False

      #print self._p.top
      #print self.p.contents.top
      
      #if not attr.contents.isValid(mappings):
      #  log.warning('BN %s is invalid: %s'%(attrname,attr))
      #  return False

      #print 'load contents'
      # go and load
      #attr.contents.loadMembers(process)
    # XXXX clean other structs
    self.meth=None
    self._method_mod_p = None
    self.engine = None
    return True
    
  def isValid(self,mappings):
    return (
        self.pad ==0 and self.version ==0 and
        (0 <= self.references <= 0xfff)  and
        is_valid_address( self.p, mappings)        and
        is_valid_address( self.q, mappings)        and
        is_valid_address( self.g, mappings)        and
        is_valid_address( self.priv_key, mappings) and
        is_valid_address( self.pub_key, mappings)  and
        #is_valid_address( self.kinv, mappings) and  # kinv and r can be null
        #is_valid_address( self.r, mappings)  ) 
        True )
  def __str__(self):
    s=repr(self)+'\n'
    for field,typ in self._fields_:
      if typ != ctypes.c_char_p and typ != ctypes.c_int and typ != CRYPTO_EX_DATA:
        s+='%s: 0x%lx\n'%(field, getaddress(getattr(self,field)) )  
        #s+='%s: %s\n'%(field, sstr(getattr(self,field)) )  
      else:
        s+='%s: %s\n'%(field,getattr(self,field) )        
    return s
  
  
