#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import ctypes
from ptrace.debugger.memory_mapping import readProcessMappings
import logging
log=logging.getLogger('openssh.model')

from model import is_valid_address,getaddress,sstr
from model import EVP_CIPHER_CTX, EVP_MD, HMAC_CTX, AES_KEY

MODE_MAX=2 #kex.h:62
AES_BLOCK_LEN=16 #umac.c:168
L1_KEY_LEN=1024 #umac.c:298
L1_KEY_SHIFT=16 #umac.c:316
UMAC_OUTPUT_LEN=8 #umac.c:55
STREAMS=(UMAC_OUTPUT_LEN / 4) #umac.c:310
HASH_BUF_BYTES=64 # umac.c:315
SSH_SESSION_KEY_LENGTH=32 # ssh.h:84

''' typedefs '''
UINT64=ctypes.c_ulonglong
UINT32=ctypes.c_ulong
UINT8=ctypes.c_ubyte


class Cipher(ctypes.Structure):
  ''' cipher.c:60 '''
  _fields_ = [
  ("name",  ctypes.c_char_p), 
  ("number",  ctypes.c_int), 
  ("block_size",  ctypes.c_uint), 
  ("key_len",  ctypes.c_uint), 
  ("discard_len",  ctypes.c_uint), 
  ("cbc_mode",  ctypes.c_uint), 
  ("evptype",  ctypes.POINTER(ctypes.c_int)) ## pointer function() 
  ]

class CipherContext(ctypes.Structure):
  ''' cipher.h:65 '''
  _fields_ = [
  ("plaintext",  ctypes.c_int), 
  ("evp",  EVP_CIPHER_CTX),
  ("cipher", ctypes.POINTER(Cipher))
  ]

class Enc(ctypes.Structure):
  ''' kex.h:84 '''
  _fields_ = [
  ("name",  ctypes.c_char_p), 
  ("cipher", ctypes.POINTER(Cipher)),
  ("enabled",  ctypes.c_int), 
  ("key_len",  ctypes.c_uint), 
  ("block_size",  ctypes.c_uint), 
  ("key",  ctypes.c_char_p), #u_char ? -> ctypes.c_byte_p ?
  ("iv",  ctypes.c_char_p)
  ]

class nh_ctx(ctypes.Structure):
  ''' umac.c:323 '''
  _fields_ = [
  ("nh_key",  UINT8 *(L1_KEY_LEN + L1_KEY_SHIFT * (STREAMS - 1)) ), 
  ("data",  UINT8 * HASH_BUF_BYTES), 
  ("next_data_empty",  ctypes.c_int), 
  ("bytes_hashed",  ctypes.c_int), 
  ("state",  UINT64 * STREAMS)
  ]

class uhash_ctx(ctypes.Structure):
  ''' umac.c:772 '''
  _fields_ = [
  ("hash",  nh_ctx), 
  ("poly_key_8",  UINT64 * STREAMS), 
  ("poly_accum",  UINT64 * STREAMS), 
  ("ip_keys",  UINT64 * STREAMS * 4), 
  ("ip_trans",  UINT32 * STREAMS), 
  ("msg_len",  UINT32)
  ]

#AES_KEY
class pdf_ctx(ctypes.Structure):
  ''' umac:221 '''
  _fields_ = [
  ("cache",  UINT8 * AES_BLOCK_LEN), #UINT8 
  ("nonce",  UINT8 * AES_BLOCK_LEN), #UINT8 
  ("prf_key",  AES_KEY * 1) #typedef AES_KEY aes_int_key[1];
  ]

class umac_ctx(ctypes.Structure):
  ''' umac:1179 '''
  _fields_ = [
  ("hash",  uhash_ctx), 
  ("pdf",  pdf_ctx), 
  ("free_ptr",  ctypes.c_void_p)
  ]

class Mac(ctypes.Structure):
  ''' kex.h:90 '''
  _fields_ = [
  ("name",  ctypes.c_char_p), 
  ("enabled",  ctypes.c_int), 
  ("mac_len",  ctypes.c_uint), 
  ("key",  ctypes.c_char_p), #u_char ? 
  ("key_len",  ctypes.c_uint), 
  ("type",  ctypes.c_int), 
  ("evp_md",  ctypes.POINTER(EVP_MD)),
  ("evp_ctx",  HMAC_CTX),
  ("umac_ctx",  ctypes.POINTER(umac_ctx)) 
  ]

class Comp(ctypes.Structure):
  ''' kex.h:100 '''
  _fields_ = [
  ("type",  ctypes.c_int), 
  ("enabled",  ctypes.c_int), 
  ("name",  ctypes.c_char_p)
  ]

class Newkeys(ctypes.Structure):
  ''' kex.h:110 '''
  _fields_ = [
  ("enc",  Enc), 
  ("mac",  Mac), 
  ("comp",  Comp)
  ]

class Buffer(ctypes.Structure):
  ''' buffer.h:19 '''
  _fields_ = [
  ("buf", ctypes.c_char_p ), 
  ("alloc", ctypes.c_uint ), 
  ("offset", ctypes.c_uint ), 
  ("end", ctypes.c_uint)
  ]


class packet_state(ctypes.Structure):
  ''' packet.c:90 '''
  _fields_ = [
  ("seqnr", UINT32 ), 
  ("packets", UINT32 ), 
  ("blocks", UINT64 ), 
  ("bytes", UINT64 )
  ]

class packet(ctypes.Structure):
  pass
  

class TAILQ_HEAD_PACKET(ctypes.Structure):
  ''' sys/queue.h:382 '''
  _fields_ = [
  ("tqh_first", ctypes.POINTER(packet) ), 
  ("tqh_last", ctypes.POINTER(ctypes.POINTER(packet)) )
  ]

class TAILQ_ENTRY_PACKET(ctypes.Structure):
  ''' sys/queue.h:382 '''
  _fields_ = [
  ("tqe_next", ctypes.POINTER(packet) ), 
  ("tqe_prev", ctypes.POINTER(ctypes.POINTER(packet)) )
  ]

class packet(ctypes.Structure):
  ''' packet.c:90 '''
  _fields_ = [
  ("next", TAILQ_ENTRY_PACKET), 
  ("type", ctypes.c_ubyte ), #u_char
  ("payload", Buffer )
  ] 

class session_state(ctypes.Structure):
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
  ("ssh1_key", ctypes.c_char * SSH_SESSION_KEY_LENGTH ), #	u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
  ("ssh1_keylen", ctypes.c_uint ), 
  ("extra_pad", ctypes.c_char ), 
  ("packet_discard", ctypes.c_uint ), 
  ("packet_discard_mac", ctypes.POINTER(Mac) ), 
  ("packlen", ctypes.c_uint ), 
  ("rekeying", ctypes.c_int ), 
  ("set_interactive_called", ctypes.c_int ), 
  ("set_maxsize_called", ctypes.c_int ), 
  ("outgoing", TAILQ_HEAD_PACKET ) 
  ]


def test():
  print 'session_state:',ctypes.sizeof(session_state)
  print 'Buffer:',ctypes.sizeof(Buffer)
  print 'CipherContext:',ctypes.sizeof(CipherContext)
  print 'Newkeys:',ctypes.sizeof(Newkeys)
  print 'Mac:',ctypes.sizeof(Mac)
  print 'Cipher:',ctypes.sizeof(Cipher)
  print 'Comp:',ctypes.sizeof(Comp)
  print 'EVP_CIPHER_CTX:',ctypes.sizeof(EVP_CIPHER_CTX)
  print 'EVP_MD:',ctypes.sizeof(EVP_MD)
  print 'Enc:',ctypes.sizeof(Enc)
  print 'nh_ctx:',ctypes.sizeof(nh_ctx)
  print 'packet:',ctypes.sizeof(packet)
  print 'packet_state:',ctypes.sizeof(packet_state)
  print 'pdf_ctx:',ctypes.sizeof(pdf_ctx)
  print 'AES_KEY:',ctypes.sizeof(AES_KEY)
  print 'uhash_ctx:',ctypes.sizeof(uhash_ctx)
  print 'umac_ctx:',ctypes.sizeof(umac_ctx)
  print 'HMAC_CTX:',ctypes.sizeof(HMAC_CTX)
  print 'TAILQ_ENTRY_PACKET:',ctypes.sizeof(TAILQ_ENTRY_PACKET)
  print 'TAILQ_HEAD_PACKET:',ctypes.sizeof(TAILQ_HEAD_PACKET)
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


test()






