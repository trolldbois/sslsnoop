#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

'''

h2xml $PWD/myssh.h -o ssh.xml -I$PWD/ -I$PWD/unix/ -I$PWD/charset/  
 && xml2py ssh.xml -o ctypes_putty_generated.py 
 && cp ctypes_putty_generated.py ../../sslsnoop/

'''

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
import logging, sys

''' insure ctypes basic types are subverted '''
from haystack import model

from haystack.model import is_valid_address,is_valid_address_value,getaddress,array2bytes,bytes2array
from haystack.model import LoadableMembersStructure,RangeValue,NotNull,CString

import ctypes_putty_generated as gen

log=logging.getLogger('ctypes_putty')


# ============== Internal type defs ==============


class PuttyStruct(LoadableMembersStructure):
  ''' defines classRef '''
  pass


################ START copy generated classes ##########################

# copy generated classes (gen.*) to this module as wrapper
model.copyGeneratedClasses(gen, sys.modules[__name__])

# register all classes (gen.*, locally defines, and local duplicates) to haystack
# create plain old python object from ctypes.Structure's, to picke them
model.registerModule(sys.modules[__name__])

################ END   copy generated classes ##########################


BN_ULONG = ctypes.c_ulong

############# Start expectedValues and methods overrides #################
'''
NIDs = dict( [(getattr(gen, s), s) for s in gen.__dict__ if s.startswith('NID_') ])
def getCipherName(nid):
  if nid not in NIDs:
    return None
  nidname = NIDs[nid]
  LNattr = 'SN'+nidname[3:] # del prefix 'NID'
  return getattr(gen, LNattr)

def getCipherDataType(nid):
  name = getCipherName(nid)
  if name is None:
    return None
  for t in EVP_CIPHER.CIPHER_DATA:
    if name.startswith( t ):
      return EVP_CIPHER.CIPHER_DATA[t]
  return None
'''

''' rc4.h:71 '''
####### RC4_KEY #######
'''
def RC4_KEY_getData(self):
  return array2bytes(self.data)
def RC4_KEY_fromPyObj(self,pyobj):
  #copy P and S
  self.data = bytes2array(pyobj.data, ctypes.c_uint)
  self.x = pyobj.x
  self.y = pyobj.y
  return self
RC4_KEY.getData = RC4_KEY_getData
RC4_KEY.fromPyObj = RC4_KEY_fromPyObj
#######
'''

''' cast.h:80 '''
'''
####### CAST_KEY #######
def CAST_KEY_getData(self):
  return array2bytes(self.data)
def CAST_KEY_getShortKey(self):
  return self.short_key
def CAST_KEY_fromPyObj(self,pyobj):
  #copy P and S
  self.data = bytes2array(pyobj.data, ctypes.c_uint)
  self.short_key = pyobj.short_key
  return self
CAST_KEY.getData = CAST_KEY_getData
CAST_KEY.getShortKey = CAST_KEY_getShortKey
CAST_KEY.fromPyObj = CAST_KEY_fromPyObj
#######
'''


''' blowfish.h:101 '''
'''
####### BF_KEY #######
def BF_KEY_getP(self):
  return array2bytes(self.P)
  #return ','.join(["0x%lx"%key for key in self.rd_key])
def BF_KEY_getS(self):
  return array2bytes(self.S)
def BF_KEY_fromPyObj(self,pyobj):
  #copy P and S
  self.P = bytes2array(pyobj.P, ctypes.c_ulong)
  self.S = bytes2array(pyobj.S, ctypes.c_ulong)
  return self
BF_KEY.getP = BF_KEY_getP
BF_KEY.getS = BF_KEY_getS
BF_KEY.fromPyObj = BF_KEY_fromPyObj
#######
'''

''' aes.h:78 '''
'''
####### AES_KEY #######
def AES_KEY_getKey(self):
  #return array2bytes(self.rd_key)
  return ','.join(["0x%lx"%key for key in self.rd_key])
def AES_KEY_getRounds(self):
  return self.rounds
def AES_KEY_fromPyObj(self,pyobj):
  #copy rd_key
  self.rd_key=bytes2array(pyobj.rd_key,ctypes.c_ulong)
  #copy rounds
  self.rounds=pyobj.rounds
  return self
AES_KEY.getKey = AES_KEY_getKey
AES_KEY.getRounds = AES_KEY_getRounds
AES_KEY.fromPyObj = AES_KEY_fromPyObj
#######
'''

'''
############ BIGNUM
BIGNUM.expectedValues={
    "neg": [0,1]
  }
def BIGNUM_loadMembers(self, mappings, maxDepth):
  #self._d = process.readArray(attr_obj_address, ctypes.c_ulong, self.top) 
  ## or    
  #ulong_array= (ctypes.c_ulong * self.top)    
  if not self.isValid(mappings):
    log.debug('BigNUm tries to load members when its not validated')
    return False
  # Load and memcopy d / BN_ULONG *
  attr_obj_address=getaddress(self.d)
  if not bool(self.d):
    log.debug('BIGNUM has a Null pointer d')
    return True
  memoryMap = is_valid_address_value( attr_obj_address, mappings)
  contents=(BN_ULONG*self.top).from_buffer_copy(memoryMap.readArray(attr_obj_address, BN_ULONG, self.top))
  log.debug('contents acquired %d'%ctypes.sizeof(contents))
  self.d.contents=BN_ULONG.from_address(ctypes.addressof(contents))
  self.d=ctypes.cast(contents, ctypes.POINTER(BN_ULONG) ) 
  return True

def BIGNUM_isValid(self,mappings):
  if ( self.dmax < 0 or self.top < 0 or self.dmax < self.top ):
    return False
  return LoadableMembersStructure.isValid(self,mappings)

def BIGNUM___str__(self):
  d= getaddress(self.d)
  return ("BN { d=0x%lx, top=%d, dmax=%d, neg=%d, flags=%d }"%
              (d, self.top, self.dmax, self.neg, self.flags) )

BIGNUM.loadMembers = BIGNUM_loadMembers
BIGNUM.isValid     = BIGNUM_isValid
BIGNUM.__str__     = BIGNUM___str__
#################
'''


'''
# CRYPTO_EX_DATA crypto.h:158:
def CRYPTO_EX_DATA_loadMembers(self, mappings, maxDepth):
  return LoadableMembersStructure.loadMembers(self, mappings, maxDepth)
def CRYPTO_EX_DATA_isValid(self,mappings):
  return LoadableMembersStructure.isValid(self,mappings)

CRYPTO_EX_DATA.loadMembers = CRYPTO_EX_DATA_loadMembers 
CRYPTO_EX_DATA.isValid     = CRYPTO_EX_DATA_isValid 
#################
'''



######## RSA key
RSAKey.expectedValues={
    'bits': [1024,2048,4096],
    'bytes': [NotNull],
    'modulus': [NotNull],
    'exponent': [NotNull],
    'private_exponent': [NotNull],
    'p': [NotNull],
    'q': [NotNull],
    'iqmp': [NotNull]
  }
def RSAKey_loadMembers(self, mappings, maxDepth):
  #self.meth = 0 # from_address(0)
  # ignore bignum_data.
  #self.bignum_data = 0
  #self.bignum_data.ptr.value = 0
  #self.blinding = 0
  #self.mt_blinding = 0

  if not LoadableMembersStructure.loadMembers(self, mappings, maxDepth):
    log.debug('RSA not loaded')
    return False
  return True

RSAKey.loadMembers = RSAKey_loadMembers


config_tag.expectedValues={
  'sshprot': [ 0,2,3],
  #'version': [ 0,1,2], # mostly 1,2
  }

tree234_Tag.expectedValues={
  'root': [ NotNull],
  }
node234_Tag.expectedValues={
  'parent': [ NotNull],
  }


######## ssh_tag main context
ssh_tag.expectedValues={
#  'fn': [NotNull],
  'state': [	gen.SSH_STATE_PREPACKET,
              gen.SSH_STATE_BEFORE_SIZE,
              gen.SSH_STATE_INTERMED,
              gen.SSH_STATE_SESSION,
              gen.SSH_STATE_CLOSED
      ],
  'agentfwd_enabled': [0,1],
  'X11_fwd_enabled': [0,1],
  }

'''
    ('v_c', STRING),
    ('v_s', STRING),
    ('exhash', c_void_p),
    ('s', Socket),
    ('ldisc', c_void_p),
    ('logctx', c_void_p),
    ('session_key', c_ubyte * 32),
    ('v1_compressing', c_int),
    ('v1_remote_protoflags', c_int),
    ('v1_local_protoflags', c_int),
    ('remote_bugs', c_int),
    ('cipher', POINTER(ssh_cipher)),
    ('v1_cipher_ctx', c_void_p),
    ('crcda_ctx', c_void_p),
    ('cscipher', POINTER(ssh2_cipher)),
    ('sccipher', POINTER(ssh2_cipher)),
    ('cs_cipher_ctx', c_void_p),
    ('sc_cipher_ctx', c_void_p),
    ('csmac', POINTER(ssh_mac)),
    ('scmac', POINTER(ssh_mac)),
    ('cs_mac_ctx', c_void_p),
    ('sc_mac_ctx', c_void_p),
    ('cscomp', POINTER(ssh_compress)),
    ('sccomp', POINTER(ssh_compress)),
    ('cs_comp_ctx', c_void_p),
    ('sc_comp_ctx', c_void_p),
    ('kex', POINTER(ssh_kex)),
    ('hostkey', POINTER(ssh_signkey)),
    ('v2_session_id', c_ubyte * 32),
    ('v2_session_id_len', c_int),
    ('kex_ctx', c_void_p),
    ('savedhost', STRING),
    ('savedport', c_int),
    ('send_ok', c_int),
    ('echoing', c_int),
    ('editing', c_int),
    ('frontend', c_void_p),
    ('ospeed', c_int),
    ('ispeed', c_int),
    ('term_width', c_int),
    ('term_height', c_int),
    ('channels', POINTER(tree234)),
    ('mainchan', POINTER(ssh_channel)),
    ('ncmode', c_int),
    ('exitcode', c_int),
    ('close_expected', c_int),
    ('clean_exit', c_int),
    ('rportfwds', POINTER(tree234)),
    ('portfwds', POINTER(tree234)),
    
    
    ('size_needed', c_int),
    ('eof_needed', c_int),
    ('queue', POINTER(POINTER(Packet))),
    ('queuelen', c_int),
    ('queuesize', c_int),
    ('queueing', c_int),
    ('deferred_send_data', POINTER(c_ubyte)),
    ('deferred_len', c_int),
    ('deferred_size', c_int),
    ('fallback_cmd', c_int),
    ('banner', bufchain),
    ('pkt_kctx', Pkt_KCtx),
    ('pkt_actx', Pkt_ACtx),
    ('x11disp', POINTER(X11Display)),
    ('version', c_int),
    ('conn_throttle_count', c_int),
    ('overall_bufsize', c_int),
    ('throttled_all', c_int),
    ('v1_stdout_throttling', c_int),
    ('v2_outgoing_sequence', c_ulong),
    ('ssh1_rdpkt_crstate', c_int),
    ('ssh2_rdpkt_crstate', c_int),
    ('do_ssh_init_crstate', c_int),
    ('ssh_gotdata_crstate', c_int),
    ('do_ssh1_login_crstate', c_int),
    ('do_ssh1_connection_crstate', c_int),
    ('do_ssh2_transport_crstate', c_int),
    ('do_ssh2_authconn_crstate', c_int),
    ('do_ssh_init_state', c_void_p),
    ('do_ssh1_login_state', c_void_p),
    ('do_ssh2_transport_state', c_void_p),
    ('do_ssh2_authconn_state', c_void_p),
    ('rdpkt1_state', rdpkt1_state_tag),
    ('rdpkt2_state', rdpkt2_state_tag),
    ('protocol_initial_phase_done', c_int),
    ('protocol', CFUNCTYPE(None, Ssh, c_void_p, c_int, POINTER(Packet))),
    ('s_rdpkt', CFUNCTYPE(POINTER(Packet), Ssh, POINTER(POINTER(c_ubyte)), POINTER(c_int))),
    ('cfg', Config),
    ('agent_response', c_void_p),
    ('agent_response_len', c_int),
    ('user_response', c_int),
    ('frozen', c_int),
    ('queued_incoming_data', bufchain),
    ('packet_dispatch', handler_fn_t * 256),
    ('qhead', POINTER(queued_handler)),
    ('qtail', POINTER(queued_handler)),
    ('pinger', Pinger),
    ('incoming_data_size', c_ulong),
    ('outgoing_data_size', c_ulong),
    ('deferred_data_size', c_ulong),
    ('max_data_size', c_ulong),
    ('kex_in_progress', c_int),
    ('next_rekey', c_long),
    ('last_rekey', c_long),
    ('deferred_rekey_reason', STRING),
    ('fullhostname', STRING),
    ('gsslibs', POINTER(ssh_gss_liblist)),
    '''


'''
########## DSA Key
DSA.expectedValues={
    "pad": [0], 
    "version": [0], 
    "references": RangeValue(0,0xfff),
    "p": [NotNull],
    "q": [NotNull],
    "g": [NotNull],
    "pub_key": [NotNull],
    "priv_key": [NotNull]
  }
def DSA_printValid(self,mappings):
  log.debug( '----------------------- \npad: %d version %d ref %d'%(self.pad,self.version,self.write_params) )
  log.debug(is_valid_address( self.p, mappings)    )
  log.debug(is_valid_address( self.q, mappings)    )
  log.debug(is_valid_address( self.g, mappings)    )
  log.debug(is_valid_address( self.pub_key, mappings)    )
  log.debug(is_valid_address( self.priv_key, mappings)    )
  return
def DSA_loadMembers(self, mappings, maxDepth):
  # clean other structs
  # r and kinv can be null
  self.meth = None
  self._method_mod_p = None
  #self.engine = None
  
  if not LoadableMembersStructure.loadMembers(self, mappings, maxDepth):
    log.debug('DSA not loaded')
    return False

  return True

DSA.printValid  = DSA_printValid
DSA.loadMembers = DSA_loadMembers
'''

'''
######### EP_CIPHER
EVP_CIPHER.expectedValues={
    #crypto/objects/objects.h 0 is undef .. crypto cipher is a smaller subset :
    # 1-10 19 29-46 60-70 91-98 104 108-123 166
    # but for argument sake, we have to keep an open mind
    "nid": RangeValue( min(NIDs.keys()), max(NIDs.keys()) ), 
    "block_size": [1,2,4,6,8,16,24,32,48,64,128], # more or less
    "key_len": RangeValue(1,0xff), # key_len *8 bits ..2040 bits for a key is enought ? 
                                   # Default value for variable length ciphers 
    "iv_len": RangeValue(0,0xff), #  rc4 has no IV ?
    "init": [NotNull], 
    "do_cipher": [NotNull], 
    #"cleanup": [NotNull], # aes-cbc ?
    "ctx_size": RangeValue(0,0xffff), #  app_data struct should not be too big
  }
EVP_CIPHER.CIPHER_DATA = { 
	 "DES": DES_key_schedule,
	 "3DES": DES_key_schedule,
	 "BF": BF_KEY,
	 "CAST": CAST_KEY,
	 "RC4": RC4_KEY,
	 "ARCFOUR": RC4_KEY,
	 "AES": AES_KEY,
  }


########### EVP_CIPHER_CTX
EVP_CIPHER_CTX.expectedValues={
    "cipher": [NotNull], 
    "encrypt": [0,1], 
    "buf_len": RangeValue(0,EVP_MAX_BLOCK_LENGTH), ## number we have left, so must be less than buffer_size
    #"engine": , # can be null
    #"app_data": , # can be null if cipher_data is not
    #"cipher_data": , # can be null if app_data is not
    "key_len": RangeValue(1,0xff), # key_len *8 bits ..2040 bits for a key is enought ? 
  }

# loadMembers, if nid & cipher_data-> we can assess cipher_data format to be a XX_KEY
def EVP_CIPHER_CTX_loadMembers(self, mappings, maxDepth):
  if not super(EVP_CIPHER_CTX,self).loadMembers(mappings, maxDepth):
    return False
  log.debug('trying to load cipher_data Structs.')
  #
  #if bool(cipher) and bool(self.cipher.nid) and is_valid_address(cipher_data):
  #  memcopy( self.cipher_data, cipher_data_addr, self.cipher.ctx_size)
  #  # cast possible on cipher.nid -> cipherType
  
  if self.cipher.contents.nid == 0: # NID_undef, not openssl doing
    log.info('The cipher is home made - the cipher context data should be application dependant (app_data)')
    return True
    
  struct = getCipherDataType( self.cipher.contents.nid) 
  log.debug('cipher type is %s - loading %s'%( getCipherName(self.cipher.contents.nid), struct ))
  if(struct is None):
    log.warning("Unsupported cipher %s"%(self.cipher.contents.nid))
    return True
  
  # c_void_p is a basic type.
  attr_obj_address = self.cipher_data
  memoryMap = is_valid_address_value( attr_obj_address, mappings, struct)
  log.debug( "cipher_data CAST into : %s "%(struct) )
  if not memoryMap:
    log.warning('in CTX On second toughts, cipher_data seems to be at an invalid address. That should not happen (often).')
    log.warning('%s addr:0x%lx size:0x%lx addr+size:0x%lx '%(is_valid_address_value( attr_obj_address, mappings), 
                                attr_obj_address, ctypes.sizeof(struct), attr_obj_address+ctypes.sizeof(struct)))
    return True
  #ok
  st = memoryMap.readStruct(attr_obj_address, struct )
  model.keepRef(st, struct, attr_obj_address)
  self.cipher_data = ctypes.c_void_p(ctypes.addressof(st)) 
  # check debug
  attr=getattr(self, 'cipher_data')      
  log.debug('Copied 0x%lx into %s (0x%lx)'%(ctypes.addressof(st), 'cipher_data', attr))      
  log.debug('LOADED cipher_data as %s from 0x%lx (%s) into 0x%lx'%(struct, 
        attr_obj_address, is_valid_address_value(attr_obj_address, mappings, struct), attr ))
  log.debug('\t\t---------\n%s\t\t---------'%st.toString())
  return True

def EVP_CIPHER_CTX_toPyObject(self):
    d=super(EVP_CIPHER_CTX,self).toPyObject()
    log.debug('Cast a EVP_CIPHER_CTX into PyObj')
    # cast app_data or cipher_data to right struct
    if bool(self.cipher_data):
      struct = getCipherDataType( self.cipher.contents.nid)
      if struct is not None:
        # CAST c_void_p to struct
        d.cipher_data = struct.from_address(self.cipher_data).toPyObject()
    return d

def EVP_CIPHER_CTX_getOIV(self):
  return array2bytes(self.oiv)
def EVP_CIPHER_CTX_getIV(self):
  return array2bytes(self.iv)

EVP_CIPHER_CTX.loadMembers = EVP_CIPHER_CTX_loadMembers
EVP_CIPHER_CTX.toPyObject = EVP_CIPHER_CTX_toPyObject
EVP_CIPHER_CTX.getOIV = EVP_CIPHER_CTX_getOIV
EVP_CIPHER_CTX.getIV  = EVP_CIPHER_CTX_getIV

##########
'''

# checkks
#
#import sys,inspect
#src=sys.modules[__name__]
#for (name, klass) in inspect.getmembers(src, inspect.isclass):
#  #if klass.__module__ == src.__name__ or klass.__module__.endswith('%s_generated'%(src.__name__) ) :
#  #  #if not klass.__name__.endswith('_py'):
#  print klass, type(klass) #, len(klass.classRef)


def printSizeof(mini=-1):
  for (name,klass) in inspect.getmembers(sys.modules[__name__], inspect.isclass):
    if type(klass) == type(ctypes.Structure) and klass.__module__.endswith('%s_generated'%(__name__) ) :
      if ctypes.sizeof(klass) > mini:
        print '%s:'%name,ctypes.sizeof(klass)
  #print 'SSLCipherSuiteInfo:',ctypes.sizeof(SSLCipherSuiteInfo)
  #print 'SSLChannelInfo:',ctypes.sizeof(SSLChannelInfo)


if __name__ == '__main__':
  printSizeof()

