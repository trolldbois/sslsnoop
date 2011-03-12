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
from engine import StatefulAESEngine,MyStatefulAESEngine

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

#our impl
from paramiko_packet import Packetizer, NeedRekeyException


from paramiko.transport import Transport
from paramiko import util
import paramiko
from paramiko.util import Counter
from paramiko.common import *


import socket_scapy,struct
from socket_scapy import hexify
from threading import Thread

log=logging.getLogger('sslsnoop.openssh')



def testSimpleDecrypt(readso,engine_in):
  block = readso.recv(16)
  print hexify(block)
  header = engine_in.decrypt(block)
  print 'First 4 char  data=',repr(header[:4])
  print 'p_size %d or %d'%(struct.unpack('>I', header[:4])[0], struct.unpack('<I', header[:4])[0])
  #print 'p_size %d or %d'%(struct.unpack('>I', header[:4])[3], struct.unpack('<I', header[:4])[3])
  packet_size = struct.unpack('>I', header[:4])[0]
  # leftover contains decrypted bytes from the first block (after the length field)
  leftover = header[4:]
  print 'packet_size=%d \nleftoverlen=%d'%(packet_size,len(leftover))
  if (packet_size - len(leftover)) % 16 != 0:
    print "SSHException('Invalid packet blocking')"
  print 'Test descrypt Finished\n\n\n'  
  return


def decrypt(packetizer):
  _expected_packet = tuple()
  while ( True ):
    try:
      ptype, m = packetizer.read_message()
    except NeedRekeyException:
      continue
    if ptype == MSG_IGNORE:
      continue
    elif ptype == MSG_DISCONNECT:
      log.info( "DISCONNECT MESSAGE")
      log.info( m)
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
        log.info("KEX Message, we need to rekey")
        continue
    #
    print m,
  log.info('Test descrypt Finished' )



def activate_cipher(packetizer, context):
  "switch on newly negotiated encryption parameters for inbound traffic"
  #packetizer.set_log(log)
  #packetizer.set_hexdump(True)
  
  engine = StatefulAESEngine(context)
  log.debug( 'cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len ) )
  #print engine, type(engine)


  mac = context.mac
  if mac is not None:
    mac_key    = mac.getKey()
    mac_engine = Transport._mac_info[mac.name.toString()]['class']
    mac_len = mac.mac_len
  # again , we need a stateful HMAC engine. 
  # we disable HMAC checking to get around.

  # fix our engines in packetizer
  packetizer.set_inbound_cipher(engine, context.block_size, mac_engine, mac_len , mac_key)
  
  if context.comp.enabled != 0:
    name = context.comp.name.toString()
    compress_in = Transport._compression_info[name][1]
    log.debug('Switching on inbound compression ...')
    packetizer.set_inbound_compressor(compress_in())
  #ok
  return engine
  
def decryptSSHTraffic(scapySocket,ciphers):
  receiveCtx,sendCtx = ciphers.getCiphers()
  # Inbound
  inbound = Packetizer(scapySocket.getInboundSocket())
  inEngine=activate_cipher(inbound, receiveCtx )
  # out bound
  outbound = Packetizer(scapySocket.getOutboundSocket())
  activate_cipher(outbound, sendCtx )

  # thread inbound reads and writes  
  while True:
    try :
      m=decrypt(inbound)
    except paramiko.SSHException,e:
      print 'Exception -> ',e
      #print inEngine.aes_key.toString()
  
  #testSimpleDecrypt(scapySocket.getInboundSocket(),inEngine)
  
  #return
  return

def launchScapyThread():
  # @ at param
  port=22
  sshfilter="tcp and port %d"%(port)
  #
  soscapy=socket_scapy.socket_scapy(sshfilter,packetCount=100)
  sniffer = Thread(target=soscapy.run)
  soscapy.setThread(sniffer)
  sniffer.start()
  return soscapy


class CipherContext:
  pass

class SessionCiphers():
  def __init__(self,session_state):
    self.sessions_state=session_state
    # two ciphers    
    self.receiveCtx=CipherContext()
    self.sendCtx=CipherContext()
    # read cipher MODE_IN == 0
    MODE=0
    #for ctx in [self.sendCtx, self.receiveCtx ]:
    for ctx in [self.receiveCtx, self.sendCtx ]:
      ctx.enc =  self.sessions_state.newkeys[MODE].contents.enc
      ctx.mac =  self.sessions_state.newkeys[MODE].contents.mac
      ctx.comp = self.sessions_state.newkeys[MODE].contents.comp
      ctx.sshCtx = session_state.receive_context
      ctx.sshCipher = ctx.sshCtx.cipher.contents
      ctx.evpCtx    = ctx.sshCtx.evp
      ctx.evpCipher = ctx.sshCtx.evp.cipher.contents
      # useful stuff
      ctx.name = ctx.sshCipher.name.toString()
      ctx.app_data  = ctx.sshCtx.getEvpAppData()
      # original key and IV are ctx.getKey() and ctx.getIV()
      # stateful AES_key key is at ctx.app_data.aes_ctx #&c->aes_ctx
      # stateful ctr counter is at ctx.app_data.aes_ctr
      ctx.key_len  = ctx.evpCipher.key_len
      ctx.block_size  = ctx.evpCipher.block_size
      MODE+=1
    # 
    return

  def getCiphers(self):
    return self.receiveCtx, self.sendCtx
  
  def __str__(self):
    return "<SessionCiphers RECEIVE: '%s/%s' SEND: '%s/%s' >"%(self.receiveCtx.name,self.receiveCtx.mac.name.toString(),
                                                  self.sendCtx.name,self.sendCtx.mac.name.toString() ) 




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
    outs=abouchet.find_struct(process, m, ctypes_openssh.session_state, maxNum=5)
    # unstop() the process
    process.cont()
    if len(outs) == 0:
      log.error("The session_state has not been found. maybe it's not OpenSSH ?")
      break
    elif len(outs) > 1:
      log.warning("Mmmh, we found multiple session_state(%d). That is odd. I'll try with the first one."%(len(outs)))
      
    #
    session_state,addr=outs[0]
  dbg.deleteProcess(process)
  dbg.quit()
  return session_state,addr
  
def findActiveKeys(pid):
  session_state,addr=findActiveSession(pid)
  if session_state is None:
    return None # raise Exception ... 
  ciphers=SessionCiphers(session_state)
  log.info('Active state ciphers : %s at 0x%lx'%(ciphers,addr))
  #log.debug(ciphers.receiveCtx.app_data.toString())
  return ciphers,addr


def testEncDec(pid):
  logging.basicConfig(level=logging.INFO)
  soscapy=launchScapyThread()
  ciphers,addr=findActiveKeys(pid)
  logging.basicConfig(level=logging.DEBUG)
  engine = StatefulAESEngine(ciphers.receiveCtx)
  engine2 = StatefulAESEngine(ciphers.receiveCtx)
  app_data=ciphers.receiveCtx.app_data
  key,rounds=app_data.getCtx()
  print "key=",repr(key)
  print len(key)
  print "rounds=",rounds
  print ''
  
  print "waiting for packet:"
  buf=b'1234567890ABCDEF1234567890ABCDEF'
  
  print '"aes_counter" : "%s"'%repr(engine.aes_key_ctx.getCounter())
  #encrypted=engine.decrypt(buf)
  encrypted=engine.decrypt(buf)
  print 'Encrypted len', len(encrypted)
  decrypted=engine2.decrypt(encrypted)
  print 'engine 1 "aes_counter" : "%s"'%repr(engine.aes_key_ctx.getCounter())
  print 'engine 2 "aes_counter" : "%s"'%repr(engine2.aes_key_ctx.getCounter())
  print 'decrypted=',decrypted
  return engine,key

def test(pid):
  logging.basicConfig(level=logging.INFO)
  soscapy=launchScapyThread()
  ciphers,addr=findActiveKeys(pid)
  logging.basicConfig(level=logging.DEBUG)
  
  readso=soscapy.getInboundSocket()
  engine = StatefulAESEngine(ciphers.receiveCtx)
  app_data=ciphers.receiveCtx.app_data
  key,rounds=app_data.getCtx()
  print "key=",repr(key)
  print len(key)
  print "rounds=",rounds
  print ''
  print "waiting for packet:"
  import time,select,struct
  start=time.time()
  while( True):
    r,w,o=select.select([readso],[],[],2)
    if len(r) > 0:
      if time.time()-start > 20:
        break
    else: 
      encrypted=readso.recv(1024)
      #print '"aes_counter" : "%s"'%repr(engine.aes_key.getCounter())
      #print 'Encrypted len', len(encrypted)
      print '"aes_counter" : "%s"'%repr(engine.aes_key.getCounter())
      decrypted=engine.decrypt(encrypted)
      print '"aes_counter" : "%s"'%repr(engine.aes_key.getCounter())
      print 'decrypted=',decrypted
      packet_size = struct.unpack('>I', decrypted[:4])[0]
      print 'packet_size BE',packet_size
      packet_size = struct.unpack('<I', decrypted[:4])[0]
      print 'packet_size LE',packet_size
  
  # find it again
  ciphers,addr=findActiveKeys(pid)
  app_data=ciphers.receiveCtx.app_data
  print 'our aes_counter : "%s"'%repr(engine.aes_key.getCounter())
  print 'its aes_counter : "%s"'%repr(app_data.aes_key.getCounter())

  #print "key=",repr(key)
  #buf=readso.recv(1024)
  #decrypted=engine.decrypt(encrypted[:AES_BLOCK_SIZE])
  
  return engine,key


def usage(txt):
  log.error("Usage : %s <pid of ssh>"% txt)
  sys.exit(-1)


def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  logging.getLogger('openssh.model').setLevel(logging.INFO)
  logging.getLogger('scapy').setLevel(logging.ERROR)
  logging.getLogger('socket.scapy').setLevel(logging.INFO)
  logging.getLogger('root').setLevel(logging.WARNING)
  logging.getLogger('sslnoop.openssh').setLevel(logging.INFO)
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

  #logging.getLogger('model').setLevel(logging.INFO)
  ###engine,key=openssh.test(16634)
  #engine,key=testEncDec(pid)
  #return 0
  
  soscapy=launchScapyThread()
  ciphers,addr=findActiveKeys(pid)
  # process is running... sniffer is listening
  log.info('Please make some ssh  traffic')  
  decryptSSHTraffic(soscapy,ciphers)
  log.info("done for pid %d, struct at 0x%lx"%(pid,addr))
  sys.exit(0)
  return -1


if __name__ == "__main__":
  main(sys.argv[1:])


'''  

import openssh,logging
logging.getLogger('model').setLevel(logging.INFO)
##engine,key=openssh.test(16634)
engine,key=openssh.testEncDec(16634)


'''

  
  
  
  