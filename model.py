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
    
def isBasicType(obj):
  return type(obj).__module__=='ctypes' or type(obj).__module__=='_ctypes' or type(obj).__module__=='__builtin__'

def isStructType(obj):
  ''' a struct is what WE have created '''
  return isinstance(obj,LoadableMembers)

def isPointerType(obj):
  if isBasicType(obj) or isStructType(obj):
    return False
  #print 'isPointerType'
  attrtype=type(obj)
  #print attrtype , type(obj), type(obj).__module__ 
  return type(ctypes.POINTER(attrtype)).__name__== 'PointerType'

class RangeValue:
  def __init__(self,low,high):
    self.low=low
    self.high=high
  def __contains__(self,obj):
    return self.low <= obj <= self.high

class LoadableMembers(ctypes.Structure):
  loaded=False
  valid=False
  ''' ctypes.POINTER types for automatic address space checks '''
  classRef=[]  
  validFields=set()
  expectedValues=dict()

  def isValid(self,mappings):
    '''  checks if each members has coherent data  '''
    if self.valid:
      return self.valid
    self.valid = self._isValid(mappings)
    log.debug('isValid = %s'%self.valid)
    return self.valid

  def _isValid(self,mappings):
    ''' For each Field, check on of the three case, 
      a) basic types (check for expectedValues), 
        if field as some expected values in expectedValues
           check field value against expectedValues[fieldname]
           if False, return False, else continue
      
      b) struct(check isValid) 
        check if the inner struct isValid()
        if False, return False, else continue
      
      c) Pointer(check valid_address or expectedValues is None == NULL )
        if field as some expected values in expectedValues 
          ( None or 0 ) are the only valid options to design NULL pointers
           check field getaddress() value against expectedValues[fieldname] // if NULL
              if True(address is NULL and it's a valid value), continue
           check getaddress against is_valid_address() 
              if False, return False, else continue
    '''
    for attrname,attrtype in self._fields_:
      attr=getattr(self,attrname)
      # a) 
      if isBasicType(attr):
        if attrname in self.expectedValues:
          if attr not in self.expectedValues[attrname]:
            log.debug('%s %s %s bad value not in self.expectedValues[attrname]:'%(attrname,attrtype,repr(attr) ))
            return False
        log.debug('%s %s %s ok'%(attrname,attrtype,repr(attr) ))
        self.validFields.add(attrname)
        continue
      # b)
      if isStructType(attr):
        ### do i need to load it first ? becaus it should be memcopied with the super()..
        if not attr.isValid(mappings):
          log.debug('%s %s %s isValid FALSE'%(attrname,attrtype,repr(attr) ))
          return False
        log.info('%s %s %s isValid TRUE'%(attrname,attrtype,repr(attr) ))
        if attr.__class__.__name__ == 'CRYPTO_EX_DATA':
          print 'isValid field for inner struct, in super.isValid',attrname,attrtype,attr.valid
          attr=getattr(self,attrname)
          print 'isValid field for inner struct, in super.isValid',attrname,attrtype,attr.valid

        self.validFields.add(attrname)
        continue
      # c) 
      if isPointerType(attr):
        if attrname in self.expectedValues:
          # test if NULL is an option
          if not bool(attr):
            if not ( (None in self.expectedValues[attrname]) or
                     (0 in self.expectedValues[attrname]) ):
              log.debug('%s %s %s isNULL and that is NOT EXPECTED'%(attrname,attrtype,repr(attr) ))
              return False
            log.debug('%s %s %s isNULL and that is OK'%(attrname,attrtype,repr(attr) ))
            self.validFields.add(attrname)
            continue
        # all case, 
        _attrType=None
        if attrtype not in self.classRef:
          log.debug("I can't know the size of the basic type behind the %s pointer, it's a pointer to basic type")
          _attrType=None
        else:
          # test valid address mapping
          _attrType=self.classRef[attrtype]
        if ( not is_valid_address( attr, mappings, _attrType) ) and (getaddress(attr) != 0):
          log.debug('%s %s %s 0x%lx INVALID'%(attrname,attrtype, repr(attr) ,getaddress(attr)))
          return False
        # null is accepted by default 
        log.debug('%s %s %s 0x%lx OK'%(attrname,attrtype,repr(attr) ,getaddress(attr)))
        self.validFields.add(attrname)
        continue
      # ?
      log.error('What type are You ?: %s'%attrname)
    # loop done
    self.valid=True
    return self.valid

  def _isLoadableMember(self, attr):
    attrtype=type(attr)
    return ( (isPointerType(attr) and ( attrtype in self.classRef) and bool(attr) ) or
              isStructType(attr) )

  def loadMembers(self,process):
    ''' 
    isValid() should have been tested before, otherwise.. it's gonna fail...
    we copy memory from process for each pointer
    and assign it to a python object _here, then we assign 
    the member to be a pointer to _here'''
    #print 'LM.loadMemebrs'
    if self.loaded:
      print 'heu... a bit short'
      return True
    if not self.valid:
      #if self.__class__.__name__ == 'CRYPTO_EX_DATA':
      #  return False
      log.error("%s not loaded, it's not even valid"%(self.__class__.__name__))
      return False
    mappings= readProcessMappings(process)
    ## go through all members. if they are pointers AND not null AND in valid memorymapping AND a struct type, load them as struct pointers
    for attrname,attrtype in self._fields_:
      attr=getattr(self,attrname)
      if not self._isLoadableMember(attr):
        if attr.__class__.__name__ == 'CRYPTO_EX_DATA':
          print 'Internal valid field in loadMembers :',attr,attrtype,attr.valid
        log.debug("%s %s not loadable  "%(attrname,attrtype) )
        continue
      # load it, fields are valid
      if isStructType(attr):
        if self.__class__.__name__ == 'CRYPTO_EX_DATA':
          print attr,attrtype
        if not attr.loadMembers(process):
          log.debug("%s %s not valid, erreur while loading inner struct "%(attrname,attrtype) )
          print "cannot load %s but field in validFields ?",(attrname, attrname in self.validFields) 
          return False
        log.debug("%s %s inner struct LOADED "%(attrname,attrtype) )
        continue
      else:
        # we have PointerType here 
        _attrname='_'+attrname
        _attrType=self.classRef[attrtype]
        attr_obj_address=getaddress(attr)
        # memcpy and save objet ref + pointer in attr
        #print '0x%lx'%getaddress(getattr(self,attrname))
        #print '0x%lx'%getaddress(attr)
        #print 'avant'
        fieldIsValid=is_valid_address( attr, mappings, _attrType)
        log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attrtype,attr_obj_address, fieldIsValid ))
        if(not fieldIsValid):
          log.error("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attrtype,attr_obj_address, fieldIsValid ))
          continue
        ##### VALID INSTR.
        obj=process.readStruct(attr_obj_address, _attrType )
        obj_p=ctypes.pointer( obj)
        setattr(self, attrname, obj_p )        
        #setattr(self, attrname, ctypes.pointer( process.readStruct(attr_obj_address, _attrType ) ) )        
        #setattr(self, _attrname, process.readStruct(attr_obj_address, _attrType ) ) 
        #setattr(self, attrname, ctypes.pointer( getattr(self, _attrname) ) )
        #attr=getattr(self,attrname)
        #####
        #print '0x%lx'%getaddress(getattr(self,attrname))
        #print '0x%lx'%getaddress(attr)
        #print '0x%lx'%ctypes.addressof(obj)
        #print 'obj.top: ',obj.top
        #print 'attr.contents: 0x%lx'%ctypes.addressof(attr.contents)
        #print 'attr.contents.top',attr.contents.top
        #print 'OK good'

        log.debug("%s %s loaded memcopy from 0x%lx to 0x%lx"%(attrname, attrtype,attr_obj_address, (getaddress(attr))   ))
        #print '0x%lx'%getaddress(getattr(self,attrname))
        #print '0x%lx'%getaddress(attr)
        #print '0x%lx'%ctypes.addressof(obj)
        #print 'obj.top: ',obj.top
        #print 'attr.contents: 0x%lx'%ctypes.addressof(attr.contents)
        #print 'attr.contents.top',attr.contents.top
        #print 'bad'

        setattr(self, attrname, obj_p )        

        #print '0x%lx'%getaddress(getattr(self,attrname))
        #print '0x%lx'%getaddress(attr)
        #print '0x%lx'%ctypes.addressof(obj)
        #print 'obj.top: ',obj.top
        #print 'attr.contents: 0x%lx'%ctypes.addressof(attr.contents)
        #print 'attr.contents.top',attr.contents.top
        #print 'OK good'
        
        # recursive validation checks on new struct
        if not bool(attr):
          log.warning('Member %s is null after copy: %s'%(attrname,attr))
          continue
        print 'before 0x%lx'%getaddress(attr)
        #print 'obj.top: ',obj.top
        # attr.contents instance is always different, so keep the copy
        contents=attr.contents
        print 'dying 0x%lx'%getaddress(attr)
        #print 'obj.top: ',obj.top
        if (not contents.isValid(mappings) ):
          log.debug('Member %s is invalid: %s'%(attrname,attr))
          self.valid=False
          return False
        print 'in venise'
        # go and load the pointed struct members recursively
        if not contents.loadMembers(process):
          log.debug('member %s was not loaded'%(attrname))
          return False
        print 'NEXT'
      #TATAFN
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
        s+='%s: %s'%(field,attr )  
    return s


