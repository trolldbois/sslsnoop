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


from paramiko.packet import Packetizer, NeedRekeyException
from paramiko.transport import Transport
from paramiko import util
from paramiko.util import Counter
from paramiko.common import *


import socket_scapy
from threading import Thread

log=logging.getLogger('engine')

libopenssl=cdll.LoadLibrary('libssl.so')


class Engine:

  def decrypt(self,block):
    ''' decrypts '''
    bLen=len(block)
    if bLen % AES_BLOCK_SIZE:
      log.error("Sugar, why do you give me a block the wrong size: %d not modulo of %d"%(bLen, AES_BLOCK_SIZE))
      return None
    data=(ctypes.c_ubyte*bLen )()
    for i in range(0, bLen ):
      #print i, block[i] 
      data[i]=ord(block[i])
    # no way....
    return self._decrypt(data,bLen)
  
  def _decrypt(self,data,bLen):
    raise NotImplementedError

class StatefulAESEngine(Engine):
  #ctx->cipher->do_cipher(ctx,out,in,inl);
  # -> openssl.AES_ctr128_encrypt(&in,&out,length,&aes_key, ivecArray, ecount_bufArray, &num )
  #AES_encrypt(ivec, ecount_buf, key); # aes_key is struct with cnt, key is really AES_KEY->aes_ctx
  #AES_ctr128_inc(ivec); #ssh_Ctr128_inc semble etre different, mais paramiko le fait non ?
  def __init__(self, context ):
    self.aes_key_ctx = type(context.app_data).from_buffer_copy(context.app_data)
    # we need nothing else
    self.key = self.aes_key_ctx.aes_ctx
    self._AES_ctr=libopenssl.AES_ctr128_encrypt
    print 'cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len)
  
  def _decrypt(self,block, bLen):
    buf=(ctypes.c_ubyte*AES_BLOCK_SIZE)()
    dest=(ctypes.c_ubyte*bLen)()
    num=ctypes.c_uint()
    #TODO test, openssl aes128_ctr_encrypt
    # in , out, lenght, key
    #void AES_ctr128_encrypt(
    #      const unsigned char *in, unsigned char *out, const unsigned long length, 
    #           const AES_KEY *key, unsigned char ivec[AES_BLOCK_SIZE],     
    #        	  unsigned char ecount_buf[AES_BLOCK_SIZE],  unsigned int *num)
    self._AES_ctr( ctypes.byref(block), ctypes.byref(dest), bLen, ctypes.byref(self.key), 
              ctypes.byref(self.aes_key_ctx.aes_counter), ctypes.byref(buf), ctypes.byref(num) ) 
    #self._AES_ctr( block, dest, bLen, ctypes.byref(self.key), 
    #          ctypes.byref(self.aes_key_ctx.aes_counter), (buf), ctypes.byref(num) ) 
    log.info(self.aes_key_ctx.toString())
    log.debug("Num ret: %d"%num.value)
    return model.array2bytes(dest)
        



class MyStatefulAESEngine(Engine):
  #ctx->cipher->do_cipher(ctx,out,in,inl);
  # -> openssl.AES_ctr128_encrypt(&in,&out,length,&aes_key, ivecArray, ecount_bufArray, &num )
  #AES_encrypt(ivec, ecount_buf, key); # aes_key is struct with cnt, key is really AES_KEY->aes_ctx
  #AES_ctr128_inc(ivec); #ssh_Ctr128_inc semble etre different, mais paramiko le fait non ?
  def __init__(self, context ):
    self.aes_key_ctx = type(context.app_data).from_buffer_copy(context.app_data)
    # we need nothing else
    self.key = self.aes_key_ctx.aes_ctx
    self._AES_encrypt=libopenssl.AES_encrypt
    print 'cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len)
  
  def _decrypt(self,block, bLen):
    dest=(ctypes.c_ubyte*bLen)()
    #TODO test, openssl aes128_ctr_encrypt
    if not self.ssh_aes_ctr(self.aes_key_ctx, dest, block, bLen ) :
      return None
    return model.array2bytes(dest)
        
  def ssh_aes_ctr(self, aes_key_ctx, dest, src, srcLen ):
    # a la difference de ssh on ne prends pas l'EVP_context mais le ssh context
    #  parceque j'ai pas un evp_cipher_ctx_evp_app_data pour l'isntant
    n = 0
    buf=(ctypes.c_ubyte*AES_BLOCK_SIZE)()
    if srcLen==0:
      return True
    if not bool(aes_key_ctx):
      return False
    print 'src is a %s , dest is a %s and buf is a %s'%(type(src), dest, buf)
    #print 'src[0] is a %s , dest[0] is a %s and buf[0] is a %s'%(type(src[0]), dest[0], buf[0])
    #print len(src),len(dest),len(buf)
    #print 'srcLen ',srcLen
    for i in range(0,srcLen):
      if (n == 0):
        # on ne bosse que sur le block_size ( ivec, dst, key )
        self._AES_encrypt(ctypes.byref(aes_key_ctx.aes_counter), ctypes.byref(buf), ctypes.byref(aes_key_ctx.aes_ctx))
        self.ssh_ctr_inc(aes_key_ctx.aes_counter, AES_BLOCK_SIZE)
      # on recopie le resultat pour chaque byte du block
      dest[i] = src[i] ^ buf[n]
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




def testDecrypt():
  buf='?A\xb7\ru\xc9\x08\xe2em\x16\x06\x1a\x18\xfb\x805,\xd8\x1f\x11\xa3\x1b )G\xe2\r`\xfaw\x87\xef\xfa\xa7\x95\xe1\x84>\xe1\x90\xec\xe1\xfa\xe5\x1e\x9c\xe3'



def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.debug(argv)

  testDecrypt()
  return -1


if __name__ == "__main__":
  main(sys.argv[1:])


