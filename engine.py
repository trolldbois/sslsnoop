#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys, copy

import ctypes, model
from ctypes import cdll
from ctypes_openssh import AES_BLOCK_SIZE, ssh_aes_ctr_ctx
from ctypes_openssl import AES_KEY, EVP_AES_KEY

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


def myhex(bstr):
  s=''
  for el in bstr:
    s+='\\'+hex(ord(el))[1:]
  return s


class StatefulAES_CBC_Engine(Engine):
  def __init__(self, context ):
    self.sync(context)
    self._AES_cbc=libopenssl.AES_cbc_encrypt
    log.debug('cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len))
  
  def _decrypt(self, src, bLen):
    buf=(ctypes.c_ubyte*AES_BLOCK_SIZE)()
    dest=(ctypes.c_ubyte*bLen)()
    enc=ctypes.c_uint(0)
    ##log.debug('BEFORE %s'%( myhex(self.aes_key_ctx.getCounter())) )
    #void AES_cbc_encrypt(
    #      const unsigned char *in, unsigned char *out, const unsigned long length, 
    #           const AES_KEY *key, unsigned char ivec[AES_BLOCK_SIZE], const int enc
    #        	  )
    self._AES_cbc( ctypes.byref(src), ctypes.byref(dest), bLen, ctypes.byref(self.key), 
              ctypes.byref(self.iv), enc ) 
    ##log.debug('AFTER  %s'%( myhex(self.aes_key_ctx.getCounter())) )
    return model.array2bytes(dest)
  
  def sync(self, context):
    ''' refresh the crypto state '''
    self.evp_aes_key = EVP_AES_KEY().fromPyObj(context.evpCtx.cipher_data) # 
    # we need nothing else
    self.key = self.evp_aes_key.ks
    # copy counter content
    self.iv = model.bytes2array(context.evpCtx.iv, ctypes.c_ubyte)
    log.info('IV value is %s'%(myhex(context.evpCtx.iv)) )



class StatefulAES_Ctr_Engine(Engine):
  #ctx->cipher->do_cipher(ctx,out,in,inl);
  # -> openssl.AES_ctr128_encrypt(&in,&out,length,&aes_key, ivecArray, ecount_bufArray, &num )
  #AES_encrypt(ivec, ecount_buf, key); # aes_key is struct with cnt, key is really AES_KEY->aes_ctx
  #AES_ctr128_inc(ivec); #ssh_Ctr128_inc semble etre different, mais paramiko le fait non ?
  def __init__(self, context ):
    self.sync(context)
    self._AES_ctr=libopenssl.AES_ctr128_encrypt
    log.debug('cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len))
  
  def _decrypt(self,block, bLen):
    buf=(ctypes.c_ubyte*AES_BLOCK_SIZE)()
    dest=(ctypes.c_ubyte*bLen)()
    num=ctypes.c_uint()
    ##log.debug('BEFORE %s'%( myhex(self.aes_key_ctx.getCounter())) )
    #void AES_ctr128_encrypt(
    #      const unsigned char *in, unsigned char *out, const unsigned long length, 
    #           const AES_KEY *key, unsigned char ivec[AES_BLOCK_SIZE],     
    #        	  unsigned char ecount_buf[AES_BLOCK_SIZE],  unsigned int *num)
    # debug counter overflow
    ###last=self.aes_key_ctx.getCounter()[-1]
    ###before=self.getCounter()
    self._AES_ctr( ctypes.byref(block), ctypes.byref(dest), bLen, ctypes.byref(self.key), 
              ctypes.byref(self.counter), ctypes.byref(buf), ctypes.byref(num) ) 
    '''
    newlast=self.aes_key_ctx.getCounter()[-1]
    if newlast < last :
      log.warning('Counter has overflown')
      after=self.getCounter()
      log.warning('Before %s'%(before))
      log.warning('After  %s'%(after))
    '''
    ##log.debug('AFTER  %s'%( myhex(self.aes_key_ctx.getCounter())) )
    return model.array2bytes(dest)
  
  def sync(self, context):
    ''' refresh the crypto state '''
    self.aes_key_ctx = ssh_aes_ctr_ctx().fromPyObj(context.app_data)
    # we need nothing else
    self.key = self.aes_key_ctx.aes_ctx
    # copy counter content
    self.counter = self.aes_key_ctx.aes_counter
    log.info('Counter value is %s'%(myhex(self.aes_key_ctx.getCounter())) )

  def getCounter(self):
    return myhex(self.aes_key_ctx.getCounter())

  def incCounter(self):
    ctr=self.counter
    for i in range(len(ctr)-1,-1,-1):
      ctr[i] += 1
      if ctr[i] != 0:
        return
    
  def decCounter(self):
    ctr=self.counter
    for i in range(len(ctr)-1,-1,-1):
      old = ctr[i]         
      ctr[i] -= 1
      if old != 0: # underflow
        return




CIPHERS = {
  "none": None, #(		SSH_CIPHER_NONE, 8, 0, 0, 0, EVP_enc_null ),
  "des": None, #(		SSH_CIPHER_DES, 8, 8, 0, 1, EVP_des_cbc ),
  "3des": None, #(		SSH_CIPHER_3DES, 8, 16, 0, 1, evp_ssh1_3des ),
  "blowfish": None, #(		SSH_CIPHER_BLOWFISH, 8, 32, 0, 1, evp_ssh1_bf ),
  "3des-cbc": None, #(		SSH_CIPHER_SSH2, 8, 24, 0, 1, EVP_des_ede3_cbc ),
  "blowfish-cbc": None, #(	SSH_CIPHER_SSH2, 8, 16, 0, 1, EVP_bf_cbc ),
  "cast128-cbc": None, #(	SSH_CIPHER_SSH2, 8, 16, 0, 1, EVP_cast5_cbc ),
  "arcfour": None, #(		SSH_CIPHER_SSH2, 8, 16, 0, 0, EVP_rc4 ),
  "arcfour128": None, #(		SSH_CIPHER_SSH2, 8, 16, 1536, 0, EVP_rc4 ),
  "arcfour256": None, #(		SSH_CIPHER_SSH2, 8, 32, 1536, 0, EVP_rc4 ),
  "aes128-cbc": StatefulAES_CBC_Engine, 
  "aes192-cbc": StatefulAES_CBC_Engine, 
  "aes256-cbc": StatefulAES_CBC_Engine, 
  "rijndael-cbc@lysator.liu.se": StatefulAES_CBC_Engine, 
  "aes128-ctr": StatefulAES_Ctr_Engine,
  "aes192-ctr": StatefulAES_Ctr_Engine,
  "aes256-ctr": StatefulAES_Ctr_Engine,
}



def testDecrypt():
  buf='?A\xb7\ru\xc9\x08\xe2em\x16\x06\x1a\x18\xfb\x805,\xd8\x1f\x11\xa3\x1b )G\xe2\r`\xfaw\x87\xef\xfa\xa7\x95\xe1\x84>\xe1\x90\xec\xe1\xfa\xe5\x1e\x9c\xe3'



def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.debug(argv)

  testDecrypt()
  return -1


if __name__ == "__main__":
  main(sys.argv[1:])


