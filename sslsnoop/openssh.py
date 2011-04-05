#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse, os, logging, sys, time, pickle, struct, threading

import ctypes
import ctypes_openssh, ctypes_openssl
import output, socket_scapy

from engine import CIPHERS
import haystack 

#our impl
from paramiko_packet import Packetizer

# todo : replace by one empty shell of ours
from paramiko.transport import Transport

from output import FileWriter

log=logging.getLogger('sslsnoop.openssh')



CLIENT_STRUCTS=[ctypes_openssh.session_state]
SERVER_STRUCTS=[ctypes_openssh.session_state]
AGENT_STRUCTS=[ctypes_openssl.RSA, ctypes_openssl.DSA]



class SessionStateFileWriter(FileWriter):
  def __init__(self,pid,folder='outputs'):
    FileWriter.__init__(self,'session_state',pid,folder)
  def writeToFile(self,instance):
    prefix=self.prefix
    filename=self.get_valid_filename()
    f=open(filename,"w")
    pickle.dump(instance,f)
    f.close()
    log.info ("[X] SSH session_state saved to file %s"%filename)
    return True




class DumbCipherContext:
  pass

class SessionCiphers():
  def __init__(self,session_state):
    self.session_state=session_state
    # two ciphers    
    self.receiveCtx=DumbCipherContext()
    self.sendCtx=DumbCipherContext()
    # read cipher MODE_IN == 0
    MODE=0
    for ctx in [self.receiveCtx, self.sendCtx ]:
      ctx.enc =  self.session_state.newkeys[MODE].enc
      ctx.mac =  self.session_state.newkeys[MODE].mac
      ctx.comp = self.session_state.newkeys[MODE].comp
      if MODE == 0:
        ctx.sshCtx = session_state.receive_context
      else:
        ctx.sshCtx = session_state.send_context
      ctx.sshCipher = ctx.sshCtx.cipher
      ctx.evpCtx    = ctx.sshCtx.evp
      ctx.evpCipher = ctx.sshCtx.evp.cipher
      # useful stuff
      ctx.name = ctx.sshCipher.name
      ctx.app_data  = ctx.evpCtx.app_data  #TODO delete
      ctx.cipher_data  = ctx.evpCtx.cipher_data #TODO delete
      # original key and IV are ctx.getKey() and ctx.getIV()
      # stateful AES_key key is at ctx.app_data.aes_ctx #&c->aes_ctx
      # stateful ctr counter is at ctx.app_data.aes_ctr
      log.debug("ctx.evpCipher type : %s"%(type(ctx.evpCipher)) )
      ctx.key_len  = ctx.evpCipher.key_len
      ctx.block_size  = ctx.evpCipher.block_size
      MODE+=1
    # 
    return

  def getCiphers(self):
    return self.receiveCtx, self.sendCtx
  
  def __str__(self):
    return "<SessionCiphers RECEIVE: '%s/%s' SEND: '%s/%s' >"%(self.receiveCtx.name,self.receiveCtx.mac.name,
                                                  self.sendCtx.name,self.sendCtx.mac.name ) 



class OpenSSHKeysFinder():
  ''' wrapper around a fork/exec to abouchet StructFinder '''

  def __init__(self, pid, fullScan=False):
    self.pid = pid
    self.fullScan = fullScan
    return
  
  def find_struct(self, typ, maxNum):
    raise NotImplementedError()
    return

  def loadAt(self,offset, typ):
    raise NotImplementedError()
    return
  
  def findActiveSession(self, maxNum=1):
    ''' '''
    outs=haystack.findStruct(self.pid, ctypes_openssh.session_state, debug=False)
    if outs is None:
      log.error("The session_state has not been found. maybe it's not OpenSSH ?")
      return None,None
    elif len(outs) > 1:
      log.warning("Mmmh, we found multiple session_state(%d). That is odd. I'll try with the first one."%(len(outs)))
    #
    session_state,addr=outs[0]
    return session_state, addr

  def refreshActiveSession(self, offset):
    ''' '''
    instance,validated=haystack.refreshStruct(self.pid, ctypes_openssh.session_state, offset)
    if not validated:
      log.error("The session_state has not been re-validated. You should look for it again.")
      return None,None
    return instance,offset
    
  def findActiveKeys(self, maxNum=1, offset=None):
    ''' '''
    if offset is None:
      session_state,addr=self.findActiveSession(maxNum)
    else:
      session_state,addr=self.refreshActiveSession(offset)
    if session_state is None:
      return None,None # raise Exception ... 
    log.debug('received session_state %s'%(session_state))
    ciphers=SessionCiphers(session_state)
    log.info('Active state ciphers : %s at 0x%lx'%(ciphers,addr))
    #log.debug(ciphers.receiveCtx.app_data.__dict__)
    return ciphers,addr

  def save(self, instance):
    ssfw=SessionStateFileWriter(self.process.pid)
    ssfw.writeToFile(instance)
    return



def connectionToString(connection, reverse=False):
  log.debug('make a string for %s'%(repr(connection)))
  if reverse:
    return "%s:%d-%s:%d"%(connection.remote_address[0],connection.remote_address[1], connection.local_address[0],connection.local_address[1]) 
  else:
    return "%s:%d-%s:%d"%(connection.local_address[0],connection.local_address[1],connection.remote_address[0],connection.remote_address[1]) 



class OpenSSHLiveDecryptatator(OpenSSHKeysFinder):
  ''' Decrypt SSH traffic in live '''
  def __init__(self, pid, sessionStateAddr=None, stream = None, scapyThread = None, serverMode=None, fullScan=False, maxNum=1):
    OpenSSHKeysFinder. __init__(self, pid, fullScan=fullScan)
    self.stream = stream
    self.scapy = scapyThread
    #self.serverMode=serverMode
    self.maxNum = maxNum
    self.session_state_addr=sessionStateAddr
    self.inbound=dict()
    self.outbound=dict()
    return
  
  def run(self):
    ''' launch sniffer and decrypter threads '''
    if self.scapy is None:
      from finder import launchScapy, getConnectionForPID
      self.scapy=launchScapy()
      conn = getConnectionForPID(self.pid)
      self.stream = self.scapy.makeStream(conn)
    elif not self.scapy.thread.isAlive():
      self.scapy.thread.start()
    # ptrace ssh
    if self.session_state_addr is None:
      self.ciphers,self.session_state_addr=self.findActiveKeys(maxNum = self.maxNum)
    else:
      self.ciphers,self.session_state_addr=self.findActiveKeys(offset=self.session_state_addr)
    if self.ciphers is None:
      raise ValueError('Struct not found')
    # unstop() the process
    ### Forked no useful self.process.cont()
    # process is running... sniffer is listening
    log.info('Please make some ssh  traffic')  
    self.init()
    self.loop()
    log.info("done for pid %d, struct at 0x%lx"%(self.process.pid, self.session_state_addr))
    return
    
  def init(self):
    ''' plug sockets, packetizer and outputs together '''
    receiveCtx,sendCtx = self.ciphers.getCiphers()
    # Inbound
    log.info('activate INBOUND receive')
    self.inbound['context'] = receiveCtx
    self.inbound['socket'] = self.stream.getInbound().getSocket()
    self.inbound['packetizer'] = Packetizer( self.inbound['socket'] )
    self.inbound['packetizer'].set_log(logging.getLogger('inbound.packetizer'))
    self.inbound['engine'] = self.activate_cipher(self.inbound['packetizer'], receiveCtx )
    name = 'ssh-%s'%( connectionToString(self.stream.connection) )
    self.inbound['filewriter'] =  output.SSHStreamToFile(self.inbound['packetizer'], self.inbound, name)

    # out bound
    log.info('activate OUTBOUND send')
    self.outbound['context'] = sendCtx
    self.outbound['socket'] = self.stream.getOutbound().getSocket()
    self.outbound['packetizer'] = Packetizer(self.outbound['socket'])
    self.outbound['packetizer'].set_log(logging.getLogger('outbound.packetizer'))
    self.outbound['engine'] = self.activate_cipher(self.outbound['packetizer'], self.outbound['context'] )
    name = 'ssh-%s'%( connectionToString(self.stream.connection, reverse=True) )
    self.outbound['filewriter'] =  output.SSHStreamToFile(self.outbound['packetizer'], self.outbound, name)
    
    # worker to watch out for data for decryption
    self.worker = output.Supervisor()
    self.worker.add( self.inbound['socket'],  self.inbound['filewriter'].process  )
    self.worker.add( self.outbound['socket'], self.outbound['filewriter'].process )
    ## run streams
    self.stream.getInbound().setActiveMode()
    self.stream.getOutbound().setActiveMode()
    threading.Thread(target=self.stream.run).start()
    return
    
  def loop(self):
    self.worker.run()
    return

  def activate_cipher(self, packetizer, context):
    "switch on newly negotiated encryption parameters for inbound traffic"
    #packetizer.set_log(log)
    #packetizer.set_hexdump(True)
    # find Engine from engine.ciphers
    engine = CIPHERS[context.name](context) 
    log.debug( 'cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len ) )
    #print engine, type(engine)
    mac = context.mac
    if mac is not None:
      mac_key    = mac.key #XXX TODO
      mac_engine = Transport._mac_info[mac.name]['class']
      mac_len = mac.mac_len
    # again , we need a stateful HMAC engine. 
    # we disable HMAC checking to get around.
    # fix our engines in packetizer
    ## packetizer.set_hexdump(True)
    packetizer.set_inbound_cipher(engine, context.block_size, mac_engine, mac_len , mac_key)
    if context.comp.enabled != 0:
      name = context.comp.name
      compress_in = Transport._compression_info[name][1]
      log.debug('Switching on inbound compression ...')
      packetizer.set_inbound_compressor(compress_in())
    #ok
    return engine
  
  def refresh(self):
    log.warning('Refreshing Engine states')
    # ptrace ssh
    if self.session_state_addr is None:
      self.ciphers,self.session_state_addr=self.findActiveKeys(maxNum = self.maxNum)
    else:
      self.ciphers,self.session_state_addr=self.findActiveKeys(offset=self.session_state_addr)
    if self.ciphers is None:
      raise ValueError('Struct not found')
    # refresh both engine
    receiveCtx,sendCtx = self.ciphers.getCiphers()
    # Inbound
    log.info('activate INBOUND receive')
    self.inbound['context'] = receiveCtx
    self.outbound['context'] = sendCtx
    self.inbound['engine'].sync(self.inbound['context'])
    self.outbound['engine'].sync(self.outbound['context'])
    pass


def launchScapyThreadOld(serverMode):
  from threading import Thread
  # @ at param
  port=22
  sshfilter="tcp and port %d"%(port)
  #
  if serverMode:
    soscapy=socket_scapy.socket_scapy(sshfilter, isInboundPacketCallback=socket_scapy.isdestport22,
                                      isOutboundPacketCallback=socket_scapy.isNotdestport22)
    log.info(' --- SSHD SERVER MODE ---- ')
  else:
    soscapy=socket_scapy.socket_scapy(sshfilter)
    log.info(' --- SSH  CLIENT MODE ---- ')
  sniffer = Thread(target=soscapy.run)
  worker  = Thread(target=soscapy.run2)
  sniffer.worker = worker
  soscapy.setThread( sniffer )
  sniffer.start()
  worker.start()
  return soscapy


def parseSSHClient(proc, tcpstream, sniffer): 
  
  pid = proc.pid
  # sniffer is a running thread
  # when ready, will have to launch tcpstream as a Thread
  decryptatator=OpenSSHLiveDecryptatator(pid, scapyThread=sniffer, stream=tcpstream)
  decryptatator.run()
  log.info("done for pid %d, struct at 0x%lx"%(pid,decryptatator.session_state_addr))

  return 
  
  


def argparser():
  parser = argparse.ArgumentParser(prog='sshsnoop', description='Live decription of Openssh traffic.')
  parser.add_argument('pid', type=int, help='Target PID')
  parser.add_argument('--addr', type=str, help='active_context memory address')
  parser.add_argument('--server', dest='isServer', action='store_const', const=True, help='Use sshd server mode')
  parser.add_argument('--debug', action='store_const', const=True, default=False, help='debug mode')
  parser.set_defaults(func=search)
  return parser

def search(args):
  if args.debug:
    logging.basicConfig(level=logging.DEBUG)    
    log.debug("==================- DEBUG MODE -================== ")
  pid=int(args.pid)
  sessionStateAddr=None
  log.info("Target has pid %d"%pid)
  if args.addr != None:
    sessionStateAddr=int(args.addr,16)
  serverMode=args.isServer # True or None

  #logging.getLogger('model').setLevel(logging.INFO)
  ###engine,key=openssh.test(16634)
  #engine,key=testEncDec(pid)
  #return 0
  
  decryptatator=OpenSSHLiveDecryptatator(pid, sessionStateAddr=sessionStateAddr, serverMode=serverMode)
  decryptatator.run()
  log.info("done for pid %d, struct at 0x%lx"%(pid,decryptatator.session_state_addr))
  sys.exit(0)
  return -1


def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.getLogger('abouchet').setLevel(logging.INFO)
  logging.getLogger('model').setLevel(logging.INFO)
  ##logging.getLogger('openssh.model').setLevel(logging.INFO)
  ##logging.getLogger('scapy').setLevel(logging.ERROR)
  logging.getLogger('socket.scapy').setLevel(logging.INFO)
  logging.getLogger('engine').setLevel(logging.INFO)
  logging.getLogger('output').setLevel(logging.INFO)
  ##logging.getLogger('root').setLevel(logging.DEBUG)
  ##logging.getLogger('sslnoop.openssh').setLevel(logging.DEBUG)
  logging.getLogger("inbound.packetizer").setLevel(logging.INFO)
  logging.getLogger("outbound.packetizer").setLevel(logging.INFO)

  logging.debug(argv)
  # we must have big privileges...
  if os.getuid() + os.geteuid() != 0:
    log.error("You must be root/using sudo to read memory and sniff traffic.")
    return

  #sys.path.append('/home/jal/Compil/python-haystack/')
  #sys.path.append('/home/jal/Compil/sslsnoop/sslsnoop/')
  
  parser = argparser()
  opts = parser.parse_args(argv)
  try:
    opts.func(opts)
  except ImportError,e:
    log.error('Struct type does not exists.')
    print e

  #0xb9116268

  return 0
  



if __name__ == "__main__":
  main(sys.argv[1:])


