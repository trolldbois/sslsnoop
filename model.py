#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes,os
from struct import pack
from ptrace.debugger.memory_mapping import readProcessMappings
import logging
log=logging.getLogger('model')

MEMCACHE=[]


''' returns if the address of the struct is in the mapping area
'''
def is_valid_address(obj,mappings, structType=None):
  '''static int is_valid_address(unsigned long addr, mappings_t *mappings) {'''
  # check for null pointers
  #print 'is_valid_address'
  addr=getaddress(obj)
  if addr == 0:
    return False
  return is_valid_address_value(addr,mappings,structType)

def is_valid_address_value(addr,mappings,structType=None):
  for m in mappings:
    if addr in m:
      # check if end of struct is ALSO in m
      if (structType is not None):
        s=ctypes.sizeof(structType)
        if (addr+s) not in m:
          return False
      return True
  return False

def is_address_local(obj, structType=None):
  ''' costly , checks if obj is mapped to local memory '''
  addr=getaddress(obj)
  if addr == 0:
    return False
  class P:
    pid=os.getpid()
  mappings= readProcessMappings(P())
  return is_valid_address(obj,mappings, structType)

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

def bytestr(obj):
  #print obj, ctypes.addressof(obj),
  if not isBasicTypeArrayType(obj):
    return "NOT-AN-BasicType-ARRAY"
  sb=b''
  for i in range(0, ctypes.sizeof(obj) ):
    sb+=pack("b",obj[i])
  return repr(sb)
    
def isBasicType(obj):
  return  (type(obj).__module__ in ['ctypes','_ctypes','__builtin__']) 

def isStructType(obj):
  ''' a struct is what WE have created '''
  return isinstance(obj,LoadableMembers)
  # or use obj.classRef
  
def isPointerType(obj):
  if isBasicType(obj) or isStructType(obj):
    return False
  return type(obj).__class__.__name__== 'PointerType'

def isBasicTypeArrayType(obj):
  return isArrayType(obj) and isBasicType(obj[0])

def isArrayType(obj):
  return type(obj).__class__.__name__=='ArrayType'

def isCStringPointer(obj):
  return obj.__class__.__name__ == 'CString'

def isUnionType(obj):
  return isinstance(obj,ctypes.Union) and not isCStringPointer(obj)


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

class CString(ctypes.Union):
  _fields_=[
  ("string", ctypes.c_char_p),
  ("ptr", ctypes.POINTER(ctypes.c_ubyte) )
  ]
  def toString(self):
    if not bool(self.ptr):
      return "<NULLPTR>"
    return self.string
  pass

class EVP_CIPHER_CTX_APP_DATA(ctypes.c_ubyte):
#ByteArray=ctypes.c_ubyte*1
#class EVP_CIPHER_CTX_APP_DATA(ByteArray):
  #_field_=[('_length_=1
#  _length_=1024
#  _type_=ctypes.c_ubyte
  pass

EVP_CIPHER_CTX_APP_DATA_PTR=ctypes.POINTER(EVP_CIPHER_CTX_APP_DATA)
#MYEVP_CTX_PTR=ctypes.POINTER(ctypes.c_ubyte)
#class EVP_CIPHER_CTX_APP_DATA_PTR(ctypes.POINTER(ctypes.c_ubyte)):


#debug
def printWhois(attr):
  print ' : isBasicType(attr): %s bool(attr): %s'%(isBasicType(attr) ,bool(attr)) 
  print ' : isCStringPointer(attr): %s isStructType(attr): %s'%(isCStringPointer(attr) ,isStructType(attr)) 
  print ' : isArrayType(attr): %s isBasicTypeArrayType(attr): %s'%(isArrayType(attr) ,isBasicTypeArrayType(attr)) 
  print ' : isPointerType(attr): %s type(attr) %s '%(isPointerType(attr),type(attr) ) 
  print ' : ',attr.__class__.__name__, type(attr)


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
      
      c) is an array ?
      
      d) Pointer(check valid_address or expectedValues is None == NULL )
        if field as some expected values in expectedValues 
          ( None or 0 ) are the only valid options to design NULL pointers
           check field getaddress() value against expectedValues[fieldname] // if NULL
              if True(address is NULL and it's a valid value), continue
           check getaddress against is_valid_address() 
              if False, return False, else continue
    '''
    for attrname,attrtype in self._fields_:
      attr=getattr(self,attrname)
      if attrname in [] :
        print 'Ivalid ',repr(self)
        printWhois(attr)
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
      if isBasicTypeArrayType(attr):
        #log.info('%s is arraytype %s we decided it was valid',attrname,repr(attr))#
        continue
      elif isArrayType(attr):
        log.info('%s is arraytype %s we decided it was valid',attrname,repr(attr))#
        continue
      # d)
      
      if isCStringPointer(attr):
        myaddress=getaddress(attr.ptr)
        if attrname in self.expectedValues:
          # test if NULL is an option
          if not bool(myaddress) :
            if not ( (None in self.expectedValues[attrname]) or
                     (0 in self.expectedValues[attrname]) ):
              log.debug('%s %s %s isNULL and that is NOT EXPECTED'%(attrname,attrtype,repr(attr) ))
              return False
            log.debug('%s %s %s isNULL and that is OK'%(attrname,attrtype,repr(attr) ))
            continue
        if ( not is_valid_address_value( myaddress, mappings) ) :
          log.debug('%s %s %s 0x%lx INVALID'%(attrname,attrtype, repr(attr) ,myaddress))
          print 'CString %s is INVALID 0x%lx'%(attrname,myaddress)
          return False
        log.debug('%s %s %s is at 0x%lx OK'%(attrname,attrtype,repr(attr),myaddress ))
        continue
      # e) 
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
      if isUnionType(attr):
        #log.warning('Union are not validated , yet ')
        continue
      log.error('What type are You ?: %s'%attrname)
      print '====== What type are You ?: %s'%attrname
    # loop done
    return True

  def _isLoadableMember(self, attr):
    '''
      Un VoidPointer ne doit pas etre Loadable
    '''
    attrtype=type(attr)
    return ( (isPointerType(attr) and ( attrtype in self.classRef) and bool(attr) ) or
              isStructType(attr)  or isCStringPointer(attr) )

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
      ### debug
      if attrname in []:
        print repr(self)
        printWhois(attr)
        print ' : _isLoadableMember() %s'%(self._isLoadableMember(attr) )
      # skip static basic data members
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
      # we have PointerType here . Basic or complex
      # exception cases
      if isCStringPointer(attr):
        # can't use basic c_char_p because we can't load in foreign memory
        attr_obj_address=getaddress(attr.ptr)
        MAX_SIZE=255
        log.debug("%s %s is defined as a CString, loading from 0x%lx is_valid_address %s"%(
                        attrname,attr,attr_obj_address, is_valid_address(attr,mappings) ))
        txt,full=process.readCString(attr_obj_address, MAX_SIZE )
        if not full:
          log.warning('buffer size was too small for this CString')
        attr.string=txt
        continue
      else:
        _attrname='_'+attrname
        _attrType=self.classRef[attrtype]
        attr_obj_address=getaddress(attr)
        ####
        previous=getattr(self,attrname+'ContentAddress')
        if attr_obj_address !=previous:
          log.warning('Change of pointer value between validation and loading... 0x%lx 0x%lx'%(previous,attr_obj_address))
        # memcpy and save objet ref + pointer in attr
        # we know the field is considered valid, so if it's not in memory_space, we can ignore it
        fieldIsValid=is_valid_address( attr, mappings, _attrType)
        if(not fieldIsValid):
          # big BUG Badaboum, why did pointer changed validity/value ?
          log.warning("%s %s not loadable 0x%lx but VALID "%(attrname, attr,attr_obj_address ))
          continue
        log.debug("%s %s loading from 0x%lx (is_valid_address: %s)"%(attrname,attr,attr_obj_address, fieldIsValid ))
        ##### VALID INSTR.
        attr.contents=_attrType.from_buffer_copy(process.readStruct(attr_obj_address, _attrType ))
        #####
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
    
  def toString(self,prefix=''):
    s="%s # %s\n"%(prefix,repr(self) )
    for field,typ in self._fields_:
      attr=getattr(self,field)
      if isStructType(attr):
        s+=prefix+'"%s": {\t%s%s},\n'%(field, attr.toString(prefix+'\t'),prefix )  
      #elif isBasicTypeArrayType(attr):
      #  #s+=prefix+'"%s": %s,\n'%(field, bytestr(attr) )  
      #  s+='['+','.join(["%lx"%(val) for val in attr ])
      elif isBasicTypeArrayType(attr): ## array of something else than int
        s+=prefix+'"%s" :['%(field)+','.join(["0x%lx"%(val) for val in attr ])+'],\n'
        continue
      elif isArrayType(attr): ## array of something else than int/byte
        s+=prefix+'"%s" :['%(field)+','.join(["%s"%(val) for val in attr ])+'],\n'
        continue
      elif isPointerType(attr):
        if not bool(attr) :
          s+=prefix+'"%s": 0x%lx,\n'%(field, getaddress(attr) )   # only print address/null
        elif not is_address_local(attr) :
          s+=prefix+'"%s": 0x%lx, #(FIELD NOT LOADED)\n'%(field, getaddress(attr) )   # only print address in target space
        else:
          # we can read the pointers contents
          # if isBasicType(attr.contents): ?
          # if isArrayType(attr.contents): ?
          contents=attr.contents
          if isStructType(contents):
            s+=prefix+'"%s": { #(0x%lx) -> %s%s},\n'%(field, getaddress(attr), attr.contents.toString(prefix+'\t'),prefix) # use struct printer
          else:
            s+=prefix+'"%s": { #(0x%lx) -> %s\n%s},\n'%(field, getaddress(attr), attr.contents, prefix) # use struct printer
      elif isCStringPointer(attr):
        s+=prefix+'"%s": "%s" , #(CString) \n'%(field, attr.string)  
      else:
        s+=prefix+'"%s": %s,\n'%(field, repr(attr) )  
    return s

  def __str__(self):
    s=repr(self)+'\n'
    for field,typ in self._fields_:
      attr=getattr(self,field)
      if isStructType(attr):
        s+='%s: {\t%s}\n'%(field, attr )  
      elif isBasicTypeArrayType(attr):
        s+='%s: %s\n'%(field, bytestr(attr) )  
      elif isArrayType(attr): ## array of something else than int
        nbElements=ctypes.sizeof(attr[0])/ctypes.sizeof(attr[0])
        subs='%s:'+'\t'.join([" %s"%(field, val) for val in attr])
        s+='%s: [%s]\n'%(field, subs )  
      elif isPointerType(attr):
        if not bool(attr) :
          s+='%s: 0x%lx\n'%(field, getaddress(attr) )   # only print address/null
        elif not is_address_local(attr) :
          s+='%s: 0x%lx (FIELD NOT LOADED)\n'%(field, getaddress(attr) )   # only print address in target space
        else:
          # we can read the pointers contents
          # if isBasicType(attr.contents): ?
          # if isArrayType(attr.contents): ?
          s+='%s (0x%lx) -> {%s}\n'%(field, getaddress(attr), attr.contents) # use struct printer
      elif isCStringPointer(attr):
        s+='%s: %s (CString) \n'%(field, attr.string)  
      else:
        s+='%s: %s\n'%(field, repr(attr) )  
    return s

def APP_DATA_value(obj,struct):
    return struct.from_buffer(obj.contents)

def APP_DATA_toString(obj,struct,prefix='\t'):
    print 'ok',
    s=prefix+repr(obj)+'\n'
    print 'building ',
    contents=APP_DATA_value(obj,struct)
    print '__str__ '
    s+=prefix+'%s: {\t%s%s}\n'%(struct.__name__, contents.toString(prefix+'\t'),prefix )  
    return s


