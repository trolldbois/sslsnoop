#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
#use volatility?

import abouchet

import ctypes_openssl,ctypes_openssh
#from  model import DSA,RSA
import ctypes
from ctypes import *
from ptrace.ctypes_libc import libc

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings



log=logging.getLogger('abouchet')
MAX_KEYS=255

verbose = 0


def testScapyThread():
  import socket_scapy,select
  from threading import Thread
  port=22
  sshfilter="tcp and port %d"%(port)
  soscapy=socket_scapy.socket_scapy(sshfilter,packetCount=100)
  log.info('Please make some ssh  traffic')
  sniffer = Thread(target=soscapy.run)
  sniffer.start()
  # sniffer is strted, let's consume
  nbblocks=0
  data=''
  readso=soscapy.getReadSocket()
  while sniffer.isAlive():
    r,w,oo=select.select([readso],[],[],1)
    if len(r)>0:
      data+=readso.recv(16)
      nbblocks+=1
  # try to finish socket
  print 'sniffer is finished'
  r,w,oo=select.select([readso],[],[],0)
  while len(r)>0:
    data+=readso.recv(16)
    nbblocks+=1
    r,w,oo=select.select([readso],[],[],0)
  #end      
  print "received %d blocks/ %d bytes"%(nbblocks,len(data))
  print 'sniffer captured : ',soscapy


class SessionCiphers():
  def __init__(self,session_state):
    self.sessions_state=session_state
    # read cipher
    self.receiveCtx=session_state.receive_context
    self.receiveCipher=receiveCtx.cipher.contents
    self.receiveCipherName=receiveCipher.name
    self.receiveKey=ctypes_openssh.getEvpAppData(receiveCtx)
    # write cipher
    self.sendCtx=session_state.send_context
    self.sendCipher=sendCtx.cipher.contents
    self.sendCipherName=sendCipher.name
    self.sendKey=ctypes_openssh.getEvpAppData(sendCtx)
  def getReceiveKey(self):
    return self.receiveKey
  def getSendKey(self):
    return self.sendKey
  def __str__(self):
    return "<SessionCiphers RECEIVE: %s SEND: %s>"%(self.receiveCipherName,self.sendCipherName)

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
    if not hasValidPermissions(m):
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
    session_state=out[0]
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
  ciphers=findActiveKeys(pid)
      
  log.info("done for pid %d"%pid)

  return -1


if __name__ == "__main__":
  main(sys.argv[1:])

