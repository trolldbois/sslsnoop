#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
#use volatility?

import abouchet
import ctypes, model, ctypes_openssh
from ctypes import cdll
from ctypes_openssh import AES_BLOCK_SIZE

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

from paramiko.packet import Packetizer, NeedRekeyException
from paramiko.transport import Transport
from paramiko import util
from paramiko.util import Counter
from paramiko.common import *


import socket_scapy
from threading import Thread

log=logging.getLogger('sslsnoop.openssh')

libopenssl=cdll.LoadLibrary('libssl.so')



def testDecrypt(packetizer):
  _expected_packet = tuple()
  while ( True ):
    try:
      ptype, m = packetizer.read_message()
    except NeedRekeyException:
      continue
    if ptype == MSG_IGNORE:
      continue
    elif ptype == MSG_DISCONNECT:
      print "DISCONNECT MESSAGE"
      print m
      packetizer.close()
      break
    elif ptype == MSG_DEBUG:
      always_display = m.get_boolean()
      msg = m.get_string()
      lang = m.get_string()
      log.debug('Debug msg: ' + util.safe_string(msg))
      continue
    if len(_expected_packet) > 0:
      if ptype not in _expected_packet:
        raise SSHException('Expecting packet from %r, got %d' % (_expected_packet, ptype))
      _expected_packet = tuple()
      if (ptype >= 30) and (ptype <= 39):
        print "KEX Message, we need to rekey"
        continue
  print 'Test descrypt Finished'  




class StatefulAESEngine():
  #ctx->cipher->do_cipher(ctx,out,in,inl);
  # -> openssl.AES_ctr128_encrypt(&in,&out,length,&aes_key, ivecArray, ecount_bufArray, &num )
  #AES_encrypt(ivec, ecount_buf, key); # aes_key is struct with cnt, key is really AES_KEY->aes_ctx
  #AES_ctr128_inc(ivec); #ssh_Ctr128_inc semble etre different, mais paramiko le fait non ?
  def __init__(self, context ):
    self.context= context
    self.aes_key = context.app_data 
    # we need nothing else
    self.key = self.aes_key.aes_ctx
    self._AES_encrypt=libopenssl.AES_encrypt
    print 'cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len)
  
  def decrypt(self,block):
    bLen=len(block)
    if bLen % AES_BLOCK_SIZE:
      log.error("Sugar, why do you give me a block the wrong size: %d not modulo of %d"%(bLen, AES_BLOCK_SIZE))
      return None
    dest=(ctypes.c_ubyte*bLen)()
    if not self.ssh_aes_ctr(self.aes_key, dest, block, bLen ) :
      return None
    return model.array2bytes(dest)
        
  def ssh_aes_ctr(self, aes_key, dest, src, srcLen ):
    # a la difference de ssh on ne prends pas l'EVP_context mais le ssh context
    #  parceque j'ai pas un evp_cipher_ctx_evp_app_data pour l'isntant
    n = 0
    buf=(ctypes.c_ubyte*AES_BLOCK_SIZE)()
    if srcLen==0:
      return True
    if not bool(aes_key):
      return False
    print 'src is a %s , dest is a %s and buf is a %s'%(type(src), dest, buf)
    print 'src[0] is a %s , dest[0] is a %s and buf[0] is a %s'%(type(src[0]), dest[0], buf[0])
    for i in range(0,srcLen):
      if (n == 0):
        # on ne bosse que sur le block_size ( ivec, dst, key )
        self._AES_encrypt(ctypes.byref(aes_key.aes_counter), ctypes.byref(buf), ctypes.byref(aes_key.aes_ctx))
        self.ssh_ctr_inc(aes_key.aes_counter, AES_BLOCK_SIZE)
      # on recopie le resultat pour chaque byte du block
      dest[i] = ord(src[i]) ^ buf[i]
      n = (n + 1) % AES_BLOCK_SIZE
    return True

  def ssh_ctr_inc(self, ctr, ctrLen):
    '''
    @param ctr: a ubyte array
        l'implementation ssh semble etre differente de l'implementation Openssl...
    int i=0;
    for (i = len - 1; i >= 0; i--)
      if (++ctr[i])  /* continue on overflow */
        return;
    '''
    for i in range(len(ctr)-1,-1,-1):
      ctr[i]+=1
      if ctr[i] != 0:
        return



def activate_cipher(packetizer, context):
  "switch on newly negotiated encryption parameters for inbound traffic"
  #packetizer.set_log(log)
  engine = StatefulAESEngine(context)
  print 'cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len )
  print engine, type(engine)

  mac = context.mac
  if mac is not None:
    mac_key    = mac.getKey()
    mac_engine = Transport._mac_info[mac.name.toString()]['class']
  # fix our engines in packetizer
  packetizer.set_inbound_cipher(engine, context.block_size, mac_engine, mac.mac_len , mac_key)
  '''  
  compress_in = self._compression_info[self.remote_compression][1]
  if (compress_in is not None) and ((self.remote_compression != 'zlib@openssh.com') or self.authenticated):
      self._log(DEBUG, 'Switching on inbound compression ...')
      self.packetizer.set_inbound_compressor(compress_in())
  '''
  return
  

def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.debug(argv)

  return -1


if __name__ == "__main__":
  main(sys.argv[1:])


