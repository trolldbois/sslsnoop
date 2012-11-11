#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging
import sys

from haystack import model
from haystack.model import is_valid_address,is_valid_address_value,pointer2bytes,array2bytes,bytes2array,getaddress
from haystack.model import LoadableMembersStructure,RangeValue,NotNull,CString, IgnoreMember
from ctypes_openssl import EVP_CIPHER_CTX, EVP_MD, HMAC_CTX
from ctypes_openssl import AES_KEY, RC4_KEY, CAST_KEY, BF_KEY, DES_key_schedule

log=logging.getLogger('ctypes_openssh')


MODE_MAX=2 #kex.h:62
AES_BLOCK_LEN=16 #umac.c:168
AES_BLOCK_SIZE=16 
RIJNDAEL_BLOCKSIZE=16
L1_KEY_LEN=1024 #umac.c:298
L1_KEY_SHIFT=16 #umac.c:316
UMAC_OUTPUT_LEN=8 #umac.c:55
STREAMS=(UMAC_OUTPUT_LEN / 4) #umac.c:310
HASH_BUF_BYTES=64 # umac.c:315
SSH_SESSION_KEY_LENGTH=32 # ssh.h:84
MAXNR = 14

UINT64=ctypes.c_uint64
UINT32=ctypes.c_uint32
UINT8=ctypes.c_uint8



class OpenSSHStruct(LoadableMembersStructure):
  ''' defines classRef '''
  pass

## Cipher's custom contexts
## cf EVP_CIPHER_CTX.app_data
class ssh_aes_ctr_ctx(OpenSSHStruct):
  ''' cipher-ctr.c:39 
  Cipher-custom context
  '''
  _fields_ = [
	('aes_ctx', AES_KEY),
	('aes_counter', ctypes.c_ubyte*AES_BLOCK_SIZE)
	]
  def getCtx(self):
    rd_key = self.aes_ctx.getKey()
    rounds = self.aes_ctx.getRounds()
    return (rd_key,rounds) 
  def getCounter(self):
    return array2bytes(self.aes_counter)
  def fromPyObj(self,pyobj):
    #recurse copy aes_ctx
    self.aes_ctx = AES_KEY().fromPyObj(pyobj.aes_ctx)
    #copy counter
    self.aes_counter=bytes2array(pyobj.aes_counter, ctypes.c_ubyte)
    return self



class rijndael_ctx(OpenSSHStruct):
  _fields_ = [
  ('decrypt', ctypes.c_int),
  ('Nr', ctypes.c_int),
  ('ek', ctypes.c_uint32*(4*(MAXNR + 1))),
  ('dk', ctypes.c_uint32*(4*(MAXNR + 1)))
  ]
  def getEk(self):
    return array2bytes(self.ek)
  def getDk(self):
    return array2bytes(self.dk)
  def fromPyObj(self,pyobj):
    self.decrypt = pyobj.decrypt
    self.Nr = pyobj.Nr
    self.ek = bytes2array(pyobj.ek, ctypes.c_uint32)
    self.dk = bytes2array(pyobj.dk, ctypes.c_uint32)
    return self
  
class ssh_rijndael_ctx(OpenSSHStruct):
  ''' cipher-aes.c:43 '''
  _fields_ = [
  ('r_ctx', rijndael_ctx),
  ('r_iv', ctypes.c_ubyte*RIJNDAEL_BLOCKSIZE)
  ]
  def getCtx(self):
    return self.r_ctx.getKey() 
  def getIV(self):
    return array2bytes(self.r_iv)
  def fromPyObj(self,pyobj):
    #recurse copy aes_ctx
    self.r_ctx = rijndael_ctx().fromPyObj(pyobj.r_ctx)
    #copy counter
    self.r_iv = bytes2array(pyobj.r_iv, ctypes.c_ubyte)
    return self


    
class Cipher(OpenSSHStruct):
  ''' cipher.c:60 '''
  _fields_ = [
  ("name",  CString ), # yeah,  c_char_p can't handle us
  ("number",  ctypes.c_int), # for ssh1 only cipher.c and cipher.h:45 // -3 == SSH_CIPHER_SSH2
  ("block_size",  ctypes.c_uint), 
  ("key_len",  ctypes.c_uint), 
  ("discard_len",  ctypes.c_uint), 
  ("cbc_mode",  ctypes.c_uint), 
  ("evptype",  ctypes.POINTER(ctypes.c_int)) ## fn const EVP_CIPHER * function() qui renvoit & de la structure EVP_CIPHER
  ]
  expectedValues = {
  'name': NotNull,
  }
 

class CipherContext(OpenSSHStruct):
  ''' cipher.h:65 '''
  _fields_ = [
  ("plaintext",  ctypes.c_int), 
  ("evp",  EVP_CIPHER_CTX),
  ("cipher", ctypes.POINTER(Cipher))
  ]
  expectedValues = {
  'plaintext': [0,1],
  'cipher': NotNull
  }
  cipherContexts={ # we could check SSH_CIPHER_XXX in self.cipher->number
	 "aes128-ctr": ssh_aes_ctr_ctx,
	 "aes192-ctr": ssh_aes_ctr_ctx,
	 "aes256-ctr": ssh_aes_ctr_ctx,
	 "acss@openssh.org": None,
  }
  def loadMembers(self, mappings, maxDepth):
    if not LoadableMembersStructure.loadMembers(self, mappings, maxDepth):
      return False
    #log.debug('evp    app_data    attr_obj_address=0x%lx'%(self.evp.app_data) )
    #log.debug('evp    cipher_data attr_obj_address=0x%lx'%(self.evp.cipher_data) )  ##none
    cipher = model.getRef( Cipher, getaddress(self.cipher) )
    ciphername = cipher.name.toString() 
    # cast evp.app_data into a valid struct
    if ciphername in self.cipherContexts:
      # evp.cipher.nid should be 0
      struct = self.cipherContexts[ciphername]
      if (struct is None):
        log.warning("Unsupported cipher %s"%(ciphername))
        return True
      attr_obj_address = self.evp.app_data
      memoryMap = is_valid_address_value( attr_obj_address, mappings, struct)
      log.debug( "CipherContext CAST app_data into : %s "%( struct) )
      if not memoryMap:
        log.warning('On second toughts, app_data seems to be at an invalid address. That should not happen (often).')
        log.warning('%s addr:0x%lx size:0x%lx addr+size:0x%lx '%(is_valid_address_value( attr_obj_address, mappings), 
                                    attr_obj_address, ctypes.sizeof(struct), attr_obj_address+ctypes.sizeof(struct)))
        return False # DEBUG kill it
      # read the void * and keep a ref
      st = memoryMap.readStruct(attr_obj_address, struct )
      model.keepRef(st, struct, attr_obj_address)
      # yeah... no. "self.evp.app_data = xx" means SEGFAULT.
      evp_app_data = ctypes.c_void_p(ctypes.addressof(st)) 
      
      log.debug('Copied 0x%lx into app_data (0x%lx)'%(attr_obj_address, evp_app_data.value) )
      log.debug('LOADED app_data as %s from 0x%lx (%s) into 0x%lx'%(struct, 
            attr_obj_address, is_valid_address_value(attr_obj_address,mappings,struct), evp_app_data.value))
      log.debug('\t\t---------\n%s\t\t---------'%(st.toString() ) )
    else:
      log.debug("Unknown cipher %s, can't load a data struct for the EVP_CIPHER_CTX->app_data"%(ciphername))
    return True
  
  def getEvpAppData(self):
    cipher = model.getRef( Cipher, getaddress(self.cipher) )
    ciphername = cipher.name.toString() 
    if ciphername in self.cipherContexts:
      struct = self.cipherContexts[ciphername]
      if(struct is None):
        log.warning("Unsupported cipher %s"%(ciphername))
        log.warning("%s"%(cipher.toString()))
        return None
      log.debug('CAST evp.app_data Into %s'%(struct))
      attr_obj_address = self.evp.app_data
      st = model.getRef(struct, attr_obj_address)
      #st = struct.from_address(attr)
      log.debug('app_data value is : 0x%lx'%(attr_obj_address))
      log.debug(st.toString())
      return st
    return None

class Enc(OpenSSHStruct):
  ''' kex.h:84 '''
  _fields_ = [
  ("name",  CString ),  
  ("cipher", ctypes.POINTER(Cipher)),
  ("enabled",  ctypes.c_int), 
  ("key_len",  ctypes.c_uint), 
  ("block_size",  ctypes.c_uint), 
  ("key",  ctypes.POINTER(ctypes.c_ubyte)), #u_char ? -> ctypes.c_ubyte_p ?
  ("iv",  ctypes.POINTER(ctypes.c_ubyte))
  ]
  def loadMembers(self, mappings, maxDepth):
    if not LoadableMembersStructure.loadMembers(self, mappings, maxDepth):
      return False
    # Load and memcopy key and iv
    log.debug('Enc Memcopying a Key with %d bytes'%self.key_len)
    attr_obj_address = getaddress(self.key)
    log.debug('got key @%x '%(attr_obj_address))
    memoryMap = is_valid_address_value( attr_obj_address, mappings)
    # DEBUG - I do question the buffer_copy.
    log.debug('memoryMap is %s - \nmake array '%(memoryMap))
    array=(ctypes.c_ubyte*self.key_len).from_buffer_copy(memoryMap.readArray(attr_obj_address, ctypes.c_ubyte, self.key_len))
    # save key as bitstream
    ##key_contents = ctypes.c_ubyte.from_buffer(array)
    key_contents = array
    log.debug('keep ref ')
    model.keepRef(key_contents, model.get_subtype(self.key), attr_obj_address)
    
    log.debug('Enc Memcopying a IV with %d bytes'%( self.block_size) )
    attr_obj_address=getaddress(self.iv)
    memoryMap = is_valid_address_value( attr_obj_address, mappings)
    log.debug('make array ')
    array=(ctypes.c_ubyte*self.block_size).from_buffer_copy(memoryMap.readArray(attr_obj_address, ctypes.c_ubyte,self.block_size))
    # save iv contents as bitstream
    ##iv_contents = ctypes.c_ubyte.from_buffer(array)
    iv_contents = array
    log.debug('keep ref')
    model.keepRef(iv_contents, model.get_subtype(self.iv), attr_obj_address)
    
    log.debug('ENC KEY(%d bytes) and IV(%d bytes) acquired'%(self.key_len,self.block_size))
    return True
  def getKey(self):
    #return pointer2bytes(self.key, self.key_len)
    return model.array2bytes(model.getRef( model.get_subtype(self.key), getaddress(self.key)) )
  def getIV(self):
    #return pointer2bytes(model.getRef(ctypes.Array, getaddress(self.iv)), self.block_size) 
    return model.array2bytes(model.getRef( model.get_subtype(self.iv), getaddress(self.iv)) )

  def toPyObject(self):
    d=OpenSSHStruct.toPyObject(self)
    d.key = self.getKey()
    d.iv = self.getIV()
    return d
  
  def toString(self,prefix=''):
    s="%s # %s\n"%(prefix,repr(self) )
    for field,typ in self._fields_:
      attr=getattr(self,field)
      if field == 'key':
        #s+=prefix+'"%s": %s\n'%(field, self.getKey() )  
        s+=self._attrToString(self.getKey(),field,typ,prefix)
      elif field == 'iv':
        #s+=prefix+'"%s": %s\n'%(field, self.getIV() )  
        s+=self._attrToString(self.getIV(),field,typ,prefix)
      else:
        s+=self._attrToString(attr,field,typ,prefix)
    return s
  
class nh_ctx(OpenSSHStruct):
  ''' umac.c:323 '''
  _fields_ = [
  ("nh_key",  UINT8 *(L1_KEY_LEN + L1_KEY_SHIFT * (STREAMS - 1)) ), 
  ("data",  UINT8 * HASH_BUF_BYTES), 
  ("next_data_empty",  ctypes.c_int), 
  ("bytes_hashed",  ctypes.c_int), 
  ("state",  UINT64 * STREAMS)
  ]

class uhash_ctx(OpenSSHStruct):
  ''' umac.c:772 '''
  _fields_ = [
  ("hash",  nh_ctx), 
  ("poly_key_8",  UINT64 * STREAMS), 
  ("poly_accum",  UINT64 * STREAMS), 
  ("ip_keys",  UINT64 * STREAMS * 4), 
  ("ip_trans",  UINT32 * STREAMS), 
  ("msg_len",  UINT32)
  ]


class pdf_ctx(OpenSSHStruct):
  ''' umac:221 '''
  _fields_ = [
  ("cache",  UINT8 * AES_BLOCK_LEN), #UINT8 
  ("nonce",  UINT8 * AES_BLOCK_LEN), #UINT8 
  ("prf_key",  AES_KEY * 1) #typedef AES_KEY aes_int_key[1];
  ]

class umac_ctx(OpenSSHStruct):
  ''' umac:1179 '''
  _fields_ = [
  ("hash",  uhash_ctx), 
  ("pdf",  pdf_ctx), 
  ("free_ptr",  ctypes.c_void_p)
  ]

class Mac(OpenSSHStruct):
  ''' kex.h:90 '''
  _fields_ = [
  ("name",  CString ),  
  ("enabled",  ctypes.c_int), 
  ("mac_len",  ctypes.c_uint), 
  ("key",  ctypes.POINTER(ctypes.c_ubyte)), #u_char ? 
  ("key_len",  ctypes.c_uint), 
  ("type",  ctypes.c_int), 
  ("evp_md",  ctypes.POINTER(EVP_MD)),
  ("evp_ctx",  HMAC_CTX),
  ("umac_ctx",  ctypes.POINTER(umac_ctx)) 
  ]
  expectedValues={
    "type": [0,1,2], # unknown, SSH_EVP or SSH_UMAC
    "enabled": [0,1], # 
    "umac_ctx": IgnoreMember, # packet.c:1781
  }
  ''' if mac.type == SSH_EVP: (1) # mac.c:47
        evp_ctx is loaded/used when 
      else if mac.type == SSH_UMAC (2)
        umac_ctx is loaded/used

     We should conditionnally loadMembers on evp_ctx or umac_ctx, but, hey.. poc here...
  '''
  def loadMembers(self, mappings, maxDepth):
    if not LoadableMembersStructure.loadMembers(self, mappings, maxDepth):
      return False
    # Load and memcopy key 
    log.debug('Memcopying a Key with %d bytes'%self.key_len)
    attr_obj_address=getaddress(self.key)
    memoryMap = is_valid_address_value( attr_obj_address, mappings)    
    array=(ctypes.c_ubyte*self.key_len).from_buffer_copy(memoryMap.readArray(attr_obj_address, ctypes.c_ubyte, self.key_len))
    model.keepRef(array, model.get_subtype(self.key), attr_obj_address)

    log.debug('unmac_ctx has been nulled and ignored. its not often used by any ssh impl. Not useful for us anyway.')
    log.debug('MAC KEY(%d bytes) acquired'%(self.key_len))
    return True
  def getKey(self):
    #return pointer2bytes(self.key,self.key_len)
    return model.array2bytes( model.getRef( model.get_subtype(self.key), getaddress(self.key)) )

  def toPyObject(self):
    d=OpenSSHStruct.toPyObject(self)
    d.key = self.getKey()
    return d

  def toString(self,prefix=''):
    s="%s # %s\n"%(prefix,repr(self) )
    for field,typ in self._fields_:
      attr=getattr(self,field)
      if field == 'key':
        #s+=prefix+'"%s": %s\n'%(field, self.getKey() )  
        s+=self._attrToString(self.getKey(),field,typ,prefix)
      else:
        s+=self._attrToString(attr,field,typ,prefix)
    return s

class Comp(OpenSSHStruct):
  ''' kex.h:100 '''
  _fields_ = [
  ("type",  ctypes.c_int), 
  ("enabled",  ctypes.c_int), 
  ("name",  CString ) 
  ]

class Newkeys(OpenSSHStruct):
  ''' kex.h:110 '''
  _fields_ = [
  ("enc",  Enc), 
  ("mac",  Mac), 
  ("comp",  Comp)
  ]

class Buffer(OpenSSHStruct):
  ''' buffer.h:19 '''
  _fields_ = [
  ("buf", ctypes.POINTER(ctypes.c_ubyte) ), 
  ("alloc", ctypes.c_uint ), 
  ("offset", ctypes.c_uint ), 
  ("end", ctypes.c_uint)
  ]


class packet_state(OpenSSHStruct):
  ''' packet.c:90 '''
  _fields_ = [
  ("seqnr", UINT32 ), 
  ("packets", UINT32 ), 
  ("blocks", UINT64 ), 
  ("bytes", UINT64 )
  ]

class packet(OpenSSHStruct):
  pass
  

class TAILQ_HEAD_PACKET(OpenSSHStruct):
  ''' sys/queue.h:382 '''
  _fields_ = [
  ("tqh_first", ctypes.POINTER(packet) ), 
  ("tqh_last", ctypes.POINTER(ctypes.POINTER(packet)) )
  ]

class TAILQ_ENTRY_PACKET(OpenSSHStruct):
  ''' sys/queue.h:382 '''
  _fields_ = [
  ("tqe_next", ctypes.POINTER(packet) ), 
  ("tqe_prev", ctypes.POINTER(ctypes.POINTER(packet)) )
  ]

''' packet.c:90 '''
packet._fields_ = [
  ("next", TAILQ_ENTRY_PACKET), 
  ("type", ctypes.c_ubyte ), #u_char
  ("payload", Buffer )
  ] 

packet.expectedValues={
    "next": IgnoreMember, 
}
'''
TAILQ_HEAD_PACKET.expectedValues={
    "next": IgnoreMember, 
}
.expectedValues={
    "next": IgnoreMember, 
}
'''
class session_state(OpenSSHStruct):
  ''' openssh/packet.c:103 '''
  _fields_ = [
  ("connection_in", ctypes.c_int ), 
  ("connection_out", ctypes.c_int ), 
  ("remote_protocol_flags", ctypes.c_uint ), 
  ("receive_context", CipherContext ), # used to cipher_crypt/receive
  ("send_context", CipherContext ),    # used to cipher_crypt/send
  ("input", Buffer ), 
  ("output", Buffer ), 
  ("outgoing_packet", Buffer ), 
  ("incoming_packet", Buffer ), 
  ("compression_buffer", Buffer ), 
  ("compression_buffer_ready", ctypes.c_int ), 
  ("packet_compression", ctypes.c_int ), 
  ("max_packet_size", ctypes.c_uint ), 
  ("initialized", ctypes.c_int ), 
  ("interactive_mode", ctypes.c_int ), 
  ("server_side", ctypes.c_int ), 
  ("after_authentication", ctypes.c_int ), 
  ("keep_alive_timeouts", ctypes.c_int ), 
  ("packet_timeout_ms", ctypes.c_int ), 
  ("newkeys", ctypes.POINTER(Newkeys)*MODE_MAX ), #Newkeys *newkeys[MODE_MAX]; XXX
  ("p_read", packet_state ), 
  ("p_send", packet_state ), 
  ("max_blocks_in", UINT64 ), 
  ("max_blocks_out", UINT64 ), 
  ("rekey_limit", UINT32 ), 
  ("ssh1_key", ctypes.c_ubyte * SSH_SESSION_KEY_LENGTH ), #	u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
  ("ssh1_keylen", ctypes.c_uint ), 
  ("extra_pad", ctypes.c_ubyte ), 
  ("packet_discard", ctypes.c_uint ), 
  ("packet_discard_mac", ctypes.POINTER(Mac) ), 
  ("packlen", ctypes.c_uint ), 
  ("rekeying", ctypes.c_int ), 
  ("set_interactive_called", ctypes.c_int ), 
  ("set_maxsize_called", ctypes.c_int ), 
  ("outgoing", TAILQ_HEAD_PACKET ) 
  ]
  expectedValues={
    "connection_in": RangeValue(-1,1024), # FD number
    "connection_out": RangeValue(-1,1024), # FD number
    "max_packet_size": RangeValue(4 * 1024,1024 * 1024), # packet.c:1781
    "packlen": RangeValue(0,1024 * 1024), # is 0 or < max_pack_size
    "initialized": [1], # mostly should be 1
    "interactive_mode": [0,1], 
    "server_side": [0,1] , 
    "after_authentication": [0,1], # mostly should be 1
    #"keep_alive_timeouts", [0], ## ?? 
    #"packet_timeout_ms", [], 
    #"max_blocks_in", UINT64 , #packet.c:794 1<<enc.block_size*2   ou si block_size < 16 (1<<30)/enc.block_size
    #"max_blocks_out", UINT64 , # ou si rekey_limit , max_blocks = MIN(max_block, rekey_limit/block_size )
    #"max_blocks_in": NotNull, #mmh # 0L values in sshd server
    #"max_blocks_out": NotNull # ) value in sshd server
  }
  def toPyObject(self):
    d=OpenSSHStruct.toPyObject(self)
    
    #log.info('self.send_context.evp.app_data: 0x%lx'%(self.send_context.evp.app_data))
    
    # populate AppData.
    if d.receive_context.evp.cipher.nid == 0:
      d.receive_context.evp.app_data = self.receive_context.getEvpAppData().toPyObject()
      d.send_context.evp.app_data = self.send_context.getEvpAppData().toPyObject()
    
    
    #log.debug('self.send_context.evp.app_data: %s'%(self.send_context.getEvpAppData()))
    #log.debug('d.send_context.evp.app_data: %s'%(d.send_context.evp.app_data))
    ## TODO find a better way to pass a void_p for that cipher data
    #d.receive_context.evp.cipher_data = self.receive_context.getEvpAppData().toPyObject()
    #d.send_context.evp.cipher_data = self.send_context.getEvpAppData().toPyObject()
    if (type(d.send_context.evp.cipher_data) == tuple 
        and d.send_context.evp.cipher_data[0] is not None
        and d.send_context.evp.cipher_data[1] is not None ):
      log.debug("cipher_data has %s"%(d.send_context.evp.cipher_data.toString()) )
    return d


def printSizeof():
  print 'Cipher:',ctypes.sizeof(Cipher)
  print 'CipherContext:',ctypes.sizeof(CipherContext)
  print 'Enc:',ctypes.sizeof(Enc)
  print 'nh_ctx:',ctypes.sizeof(nh_ctx)
  print 'uhash_ctx:',ctypes.sizeof(uhash_ctx)
  print 'pdf_ctx:',ctypes.sizeof(pdf_ctx)
  print 'umac_ctx:',ctypes.sizeof(umac_ctx)
  print 'Mac:',ctypes.sizeof(Mac)
  print 'Comp:',ctypes.sizeof(Comp)
  print 'Newkeys:',ctypes.sizeof(Newkeys)
  print 'Buffer:',ctypes.sizeof(Buffer)
  print 'packet:',ctypes.sizeof(packet)
  print 'packet_state:',ctypes.sizeof(packet_state)
  print 'TAILQ_HEAD_PACKET:',ctypes.sizeof(TAILQ_HEAD_PACKET)
  print 'TAILQ_ENTRY_PACKET:',ctypes.sizeof(TAILQ_ENTRY_PACKET)
  print 'session_state:',ctypes.sizeof(session_state)
  print 'UINT32:',ctypes.sizeof(UINT32)
  print 'UINT64:',ctypes.sizeof(UINT64)
  print 'UINT8:',ctypes.sizeof(UINT8)
  print 'AES_BLOCK_LEN:',AES_BLOCK_LEN
  print 'HASH_BUF_BYTES:',HASH_BUF_BYTES
  print 'UMAC_OUTPUT_LEN:',UMAC_OUTPUT_LEN
  print 'SSH_SESSION_KEY_LENGTH:',SSH_SESSION_KEY_LENGTH
  print 'L1_KEY_LEN:',L1_KEY_SHIFT
  print 'L1_KEY_SHIFT:',L1_KEY_SHIFT
  print 'MODE_MAX:',MODE_MAX
  print 'STREAMS:',STREAMS




# register all classes to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

if __name__ == '__main__':
  printSizeof()



