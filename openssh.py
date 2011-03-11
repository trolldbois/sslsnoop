#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
#use volatility?

import abouchet
import ctypes_openssh

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

from paramiko.packet import Packetizer
from paramiko.transport import Transport
#from paramiko import util

log=logging.getLogger('sslsnoop.openssh')


def get_cipher(name, key, iv, counter=None):
  ''' paramiko _get_cipher in transport.py:1467 '''
  if name != "aes128-ctr":
    print 'UNKOWN CIPHER MEC'
    ##return self._cipher_info[name]['class'].new(key, self._cipher_info[name]['mode'], iv)
    return None
  # CTR modes, we need a counter
  #counter = Counter.new(nbits=Trasnport._cipher_info[name]['block-size'] * 8, initial_value=util.inflate_long(iv, True))
  return Transport._cipher_info[name]['class'].new(key, Transport._cipher_info[name]['mode'], iv, counter)

def activate_cipher(packetizer, cipher, mac=None):
  "switch on newly negotiated encryption parameters for inbound traffic"
  key=  cipher.key
  iv = cipher.iv
  ctr = cipher.ctr
  block_size = cipher.block_size
  print 'cipher:%s block_size: %d key_len: %d IV len:%d'%(cipher.name, block_size,len(key),len(iv) )
  engine = get_cipher(cipher.name, key, iv, ctr)
  print engine
  '''  
  mac_size = mac.mac_len 
  mac_engine = Transport._mac_info[mac.name.toString()]['class']
  # initial mac keys are done in the hash's natural size (not the potentially truncated
  # transmission size)
  if self.server_mode:
      mac_key = self._compute_key('E', mac_engine.digest_size)
  else:
      mac_key = self._compute_key('F', mac_engine.digest_size)
      
  self.packetizer.set_inbound_cipher(engine, block_size, mac_engine, mac_size, mac_key)
  compress_in = self._compression_info[self.remote_compression][1]
  if (compress_in is not None) and ((self.remote_compression != 'zlib@openssh.com') or self.authenticated):
      self._log(DEBUG, 'Switching on inbound compression ...')
      self.packetizer.set_inbound_compressor(compress_in())
  '''

  
def decryptSSHTraffic(scapySocket,ciphers):
  inEnc,outEnc=ciphers.getCiphers()
  # Inbound
  inbound=Packetizer(scapySocket.getInboundSocket())
  activate_cipher(inbound, inEnc )
  # out bound
  outbound=Packetizer(scapySocket.getOutboundSocket())
  activate_cipher(outbound, outEnc )
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


class EncryptionCipher:
  def __init__(self,cipher,key,iv,ctr=None):
    self.cipher=cipher
    self.name=self.cipher.name.toString()
    self.block_size=self.cipher.block_size
    self.key=key
    self.iv=iv
    self.ctr=ctr

class SessionCiphers():
  def __init__(self,session_state):
    self.sessions_state=session_state
    # read cipher MODE_IN == 0
    self.receiveEnc=self.sessions_state.newkeys[0].contents.enc
    self.receiveMac=self.sessions_state.newkeys[0].contents.mac
    self.receiveComp=self.sessions_state.newkeys[0].contents.comp
    self.receiveCtx=session_state.receive_context
    self.receiveCipherOpenSSH=self.receiveCtx.cipher.contents
    self.receiveCipherName=self.receiveCipherOpenSSH.name.toString()
    self.receiveCipherEVP=self.receiveCtx.evp.cipher.contents
    self.receiveKeyContext=ctypes_openssh.getEvpAppData(self.receiveCtx)
    self.receiveKey=self.receiveEnc.getKey()
    self.receiveIV=self.receiveEnc.getIV()
    self.receiveKeyCounter=None
    if self.receiveCipherName.endswith('-ctr') and self.receiveCipherName.startswith('aes') :
      self.receiveKeyCounter=self.receiveKeyContext.getCounter()
    # 
    self.receiveEncCipher=EncryptionCipher(self.receiveEnc, self.receiveKey, self.receiveIV, self.receiveKeyCounter)
    
    # write cipher MODE_IN == 1
    self.sendEnc=self.sessions_state.newkeys[1].contents.enc
    self.sendMac=self.sessions_state.newkeys[1].contents.mac
    self.sendComp=self.sessions_state.newkeys[1].contents.comp
    self.sendCtx=session_state.send_context
    self.sendCipherOpenSSH=self.sendCtx.cipher.contents
    self.sendCipherName=self.sendCipherOpenSSH.name.toString()
    self.sendCipherEVP=self.sendCtx.evp.cipher.contents
    self.sendKeyContext=ctypes_openssh.getEvpAppData(self.sendCtx)
    self.sendKey=self.sendEnc.getKey()
    self.sendIV=self.sendEnc.getIV()
    self.sendKeyCounter=None
    if self.sendCipherName.endswith('-ctr') and self.sendCipherName.startswith('aes') :
      self.sendKeyCounter=self.sendKeyContext.getCounter()
    # 
    self.sendEncCipher=EncryptionCipher(self.sendEnc, self.sendKey, self.sendIV, self.sendKeyCounter)
    return

  def getCiphers(self):
    return self.receiveEncCipher, self.sendEncCipher
 
  def getReceiveKey(self):
    return self.receiveKey, self.receiveIV , self.receiveKeyCounter

  def getSendKey(self):
    return self.sendKey, self.sendIV, self.sendKeyCounter
  
  def __str__(self):
    return "<SessionCiphers RECEIVE: '%s' SEND: '%s' >"%(self.receiveCipherName,self.sendCipherName)




def findActiveSession(pid):
  
  dbg=PtraceDebugger()
  process=dbg.addProcess(pid,is_attached=False)
  if process is None:
    log.error("Error initializing Process debugging for %d"% pid)
    return None
  # process is SIGSTOP-ed
  mappings=readProcessMappings(process)
  session_state=None  
  for m in mappings:
    ##debug, rsa is on head
    if m.pathname != '[heap]':
      continue
    if not abouchet.hasValidPermissions(m):
      continue
    ## method generic
    log.info('looking for struct session_state')
    outs=abouchet.find_struct(process, m, ctypes_openssh.session_state)
    # unstop() the process
    process.cont()
    if len(outs) == 0:
      log.error("The session_state has not been found. maybe it's not OpenSSH ?")
      return None
    elif len(outs) > 1:
      log.warning("Mmmh, multiple session_state. That is odd. I'll try with the first one.")
    #
    session_state=outs[0]
  return session_state
  
def findActiveKeys(pid):
  session_state=findActiveSession(pid)
  if session_state is None:
    return None # raise Exception ... 
  ciphers=SessionCiphers(session_state)
  log.info('Active state ciphers : %s'%(ciphers))
  return ciphers

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
  ciphers=findActiveKeys(pid)
  # process is running... sniffer is listening
  decryptSSHTraffic(soscapy,ciphers)
  log.info("done for pid %d"%pid)
  sys.exit(0)
  return -1


if __name__ == "__main__":
  main(sys.argv[1:])

