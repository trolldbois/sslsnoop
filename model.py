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
  # or use obj.classRef

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

class NotNullComparable:
  def __contains__(self,obj):
    return bool(obj)
  def __eq__(self,obj):
    return bool(obj)

NotNull=NotNullComparable()

class LoadableMembers(ctypes.Structure):
  #loaded=False ## useless member instance doesn't stick
  #valid=False ## useless members doesn't stick
  ''' ctypes.POINTER types for automatic address space checks '''
  classRef=[]  
  #validFields=set() #useless
  expectedValues=dict()

  def isValid(self,mappings):
    '''  checks if each members has coherent data  '''
    valid = self._isValid(mappings)
    log.debug('%s isValid = %s'%(self.__class__.__name__,valid))
    return valid

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
        continue
      # b)
      if isStructType(attr):
        ### do i need to load it first ? becaus it should be memcopied with the super()..
        if not attr.isValid(mappings):
          log.debug('%s %s %s isValid FALSE'%(attrname,attrtype,repr(attr) ))
          return False
        log.debug('%s %s %s isValid TRUE'%(attrname,attrtype,repr(attr) ))
        continue
      # c) 
      if isPointerType(attr):
        #### try to debug mem
        setattr(self,attrname+'ContentAddress',getaddress(attr))
        ####
        if attrname in self.expectedValues:
          # test if NULL is an option
          if not bool(attr):
            if not ( (None in self.expectedValues[attrname]) or
                     (0 in self.expectedValues[attrname]) ):
              log.debug('%s %s %s isNULL and that is NOT EXPECTED'%(attrname,attrtype,repr(attr) ))
              return False
            log.debug('%s %s %s isNULL and that is OK'%(attrname,attrtype,repr(attr) ))
            continue
        # all case, 
        _attrType=None
        if attrtype not in self.classRef:
          #log.debug("I can't know the size of the basic type behind the %s pointer, it's a pointer to basic type")
          _attrType=None
        else:
          # test valid address mapping
          _attrType=self.classRef[attrtype]
        if ( not is_valid_address( attr, mappings, _attrType) ) and (getaddress(attr) != 0):
          log.debug('%s %s %s 0x%lx INVALID'%(attrname,attrtype, repr(attr) ,getaddress(attr)))
          return False
        # null is accepted by default 
        log.debug('%s %s 0x%lx OK'%(attrname,repr(attr) ,getaddress(attr)))
        continue
      # ?
      log.error('What type are You ?: %s'%attrname)
    # loop done
    return True

  def _isLoadableMember(self, attr):
    attrtype=type(attr)
    return ( (isPointerType(attr) and ( attrtype in self.classRef) and bool(attr) ) or
              isStructType(attr) )

  def loadMembers(self,process,mappings):
    ''' 
    isValid() should have been tested before, otherwise.. it's gonna fail...
    we copy memory from process for each pointer
    and assign it to a python object _here, then we assign 
    the member to be a pointer to _here'''
    log.debug('%s loadMembers'%(self.__class__.__name__))
    if not self.isValid(mappings):
      return False
    log.debug('%s do loadMembers ----------------'%(self.__class__.__name__))
    ## go through all members. if they are pointers AND not null AND in valid memorymapping AND a struct type, load them as struct pointers
    for attrname,attrtype in self._fields_:
      attr=getattr(self,attrname)
      if not self._isLoadableMember(attr):
        log.debug("%s %s not loadable  bool(attr) = %s"%(attrname,attrtype, bool(attr)) )
        continue
      # load it, fields are valid
      if isStructType(attr):
        log.debug('%s %s is STRUCT'%(attrname,attrtype) )
        if not attr.loadMembers(process,mappings):
          log.debug("%s %s not valid, erreur while loading inner struct "%(attrname,attrtype) )
          return False
        log.debug("%s %s inner struct LOADED "%(attrname,attrtype) )
        continue
      else:
        # we have PointerType here 
        _attrname='_'+attrname
        _attrType=self.classRef[attrtype]
        attr_obj_address=getaddress(attr)
        ####
        previous=getattr(self,attrname+'ContentAddress')
        if attr_obj_address !=previous:
          log.warning('Change of poitner value between validation and loading... 0x%lx 0x%lx'%(previous,attr_obj_address))
        # memcpy and save objet ref + pointer in attr
        # we know the field is considered valid, so if it's not in memory_space, we can ignore it
        fieldIsValid=is_valid_address( attr, mappings, _attrType)
        if(not fieldIsValid):
          # big BUG Badaboum, why did pointer changed validity/value ?
          log.debug("%s %s not loadable 0x%lx but VALID "%(attrname, attr,attr_obj_address ))
          continue
        log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attr,attr_obj_address, fieldIsValid ))
        ##### VALID INSTR.
        attr.contents=_attrType.from_buffer_copy(process.readStruct(attr_obj_address, _attrType ))

        log.debug("%s %s loaded memcopy from 0x%lx to 0x%lx"%(attrname, attr,attr_obj_address, (getaddress(attr))   ))
        # recursive validation checks on new struct
        if not bool(attr):
          log.warning('Member %s is null after copy: %s'%(attrname,attr))
          continue
        # go and load the pointed struct members recursively
        if not attr.contents.loadMembers(process,mappings):
          log.debug('member %s was not loaded'%(attrname))
          return False
      #TATAFN
    log.debug('%s END loadMembers ----------------'%(self.__class__.__name__))
    return True
    
  def __str__(self):
    s=repr(self)+'\n'
    for field,typ in self._fields_:
      attr=getattr(self,field)
      if isPointerType(attr):
        s+='%s: 0x%lx\n'%(field, getaddress(getattr(self,field)) )  
      elif isStructType(attr):
        s+='%s: {\t%s}\n'%(field, getattr(self,field) )  
      else:
        s+='%s: %s\n'%(field,attr )  
    return s


