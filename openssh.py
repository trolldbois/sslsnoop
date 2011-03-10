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


log=logging.getLogger('sslsnoop.openssh')



def activate_cipher(packetizer,cipher):
  "switch on newly negotiated encryption parameters for inbound traffic"
  block_size = cipher.block_size
  print 'block_size:',block_size
  '''if self.server_mode:
      IV_in = self._compute_key('A', block_size)
      key_in = self._compute_key('C', self._cipher_info[self.remote_cipher]['key-size'])
  else:
      IV_in = self._compute_key('B', block_size)
      key_in = self._compute_key('D', self._cipher_info[self.remote_cipher]['key-size'])
  
  engine = self._get_cipher(self.remote_cipher, key_in, IV_in)
  mac_size = self._mac_info[self.remote_mac]['size']
  mac_engine = self._mac_info[self.remote_mac]['class']
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
  # 
  inC,outC=ciphers.getCiphers()
  # Inbound
  inbound=Packetizer(scapySocket.getInboundSocket())
  activate_cipher(inbound, inC )
  # out bound
  outbound=Packetizer(scapySocket.getOutboundSocket())
  activate_cipher(outbound, outC )
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


class SessionCiphers():
  def __init__(self,session_state):
    self.sessions_state=session_state
    # read cipher
    self.receiveCtx=session_state.receive_context
    self.receiveCipherOpenSSH=self.receiveCtx.cipher.contents
    self.receiveCipherName=self.receiveCipherOpenSSH.name.toString()
    self.receiveCipherEVP=self.receiveCtx.evp.cipher.contents
    self.receiveKey=ctypes_openssh.getEvpAppData(self.receiveCtx)
    # write cipher
    self.sendCtx=session_state.send_context
    self.sendCipherOpenSSH=self.sendCtx.cipher.contents
    self.sendCipherName=self.sendCipherOpenSSH.name.toString()
    self.sendCipherEVP=self.sendCtx.evp.cipher.contents
    self.sendKey=ctypes_openssh.getEvpAppData(self.sendCtx)
    return
  def getCiphers(self):
    return self.receiveCipherEVP, self.sendCipherEVP
 
  def getKeys(self):
    return self.receiveKey, self.sendKey
  
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

