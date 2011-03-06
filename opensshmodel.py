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
from model import EVP_CIPHER_CTX, EVP_MD, HMAC_CTX

''' kex.h:62 '''
MODE_MAX=2

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
  ("key",  ctypes.c_char_p), #u_char ? 
  ("iv",  ctypes.c_char_p)
  ]


class umac_ctx(ctypes.Structure):
  ''' umac:1179 '''
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    void *free_ptr;          /* Address to free this struct via          */
} umac_ctx;

#EVP_MD k
# HMAC_CTX
#struct umac_ctx *
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
  ("umac_ctx",  ctypes.POINTER(umac_ctx)) #struct umac_ctx
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

NewkeysModeMax=Newkeys*MODE_MAX

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
  ("max_blocks_in", ctypes.c_uint64 ), ## u_int64?
  ("max_blocks_out", ctypes.c_uint64 ), ## u_int64?
  ("rekey_limit", ctypes.c_uint32 ), ## u_int32?
  ("ssh1_key", ctypes.c_char ), #	u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
  ("ssh1_keylen", ctypes.c_uint ), 
  ("extra_pad", ctypes.c_char ), #u_char
  ("packet_discard", ctypes.c_uint ), 
  ("packet_discard_mac", ctypes.POINTER(Mac) ), 
  ("packlen", ctypes.c_uint ), 
  ("rekeying", ctypes.c_int ), 
  ("set_interactive_called", ctypes.c_int ), 
  ("set_maxsize_called", ctypes.c_int ), 
  ("outgoing", TAILQ_HEAD ) #	TAILQ_HEAD(, packet) outgoing;
  ]
  














