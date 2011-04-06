#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse, os, logging, sys, time, pickle, struct, threading

import ctypes
import ctypes_openssh, ctypes_openssl
import output

from engine import CIPHERS
import haystack 


from output import FileWriter

log=logging.getLogger('openvpn')





class OpenvpnKeysFinder():
  ''' wrapper around a fork/exec to abouchet StructFinder '''

  def __init__(self, pid, fullScan=False):
    self.pid = pid
    self.fullScan = fullScan
    return
  
  def findCipherCtx(self, maxNum=3):
    ''' '''
    outs=haystack.findStruct(self.pid, ctypes_openssl.EVP_CIPHER_CTX, maxNum=maxNum)
    if outs is None:
      log.error("The session_state has not been found. maybe it's not OpenSSH ?")
      return None,None
    #
    return outs

  def refreshCipherCtx(self, offset):
    ''' '''
    instance,validated=haystack.refreshStruct(self.pid, ctypes_openssl.EVP_CIPHER_CTX, offset)
    if not validated:
      log.error("The session_state has not been re-validated. You should look for it again.")
      return None,None
    return instance,offset
    
  def findKeys(self, maxNum=3):
    ''' '''
    contexts = self.findCipherCtx(maxNum)
    log.debug('received %d EVP context '%( len(contexts)))
    self.printCiphers(contexts)
    return contexts

  def printCiphers(self, cipherContexts):
    for ctx, addr in cipherContexts:
      print 'Cipher : %s-%d'%(ctypes_openssl.getCipherName(ctx.cipher.nid), 8*ctx.cipher.key_len)
    return 
    
  def save(self, instance):
    # pickle ?
    ssfw=FileWriter(self.process.pid)
    ssfw.writeToFile(instance)
    return



def connectionToString(connection, reverse=False):
  log.debug('make a string for %s'%(repr(connection)))
  if reverse:
    return "%s:%d-%s:%d"%(connection.remote_address[0],connection.remote_address[1], connection.local_address[0],connection.local_address[1]) 
  else:
    return "%s:%d-%s:%d"%(connection.local_address[0],connection.local_address[1],connection.remote_address[0],connection.remote_address[1]) 



class OpenvpnLiveDecryptatator(OpenvpnKeysFinder):
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



def argparser():
  parser = argparse.ArgumentParser(prog='sshsnoop', description='Live decription of Openssh traffic.')
  parser.add_argument('pid', type=int, help='Target PID')
  parser.add_argument('--addr', type=str, help='active_context memory address')
  parser.add_argument('--debug', action='store_const', const=True, default=False, help='debug mode')
  parser.set_defaults(func=search)
  return parser

def search(args):
  if args.debug:
    logging.basicConfig(level=logging.DEBUG)    
    log.debug("==================- DEBUG MODE -================== ")
  pid=int(args.pid)
  log.info("Target has pid %d"%pid)
  if args.addr != None:
    offset = int(args.addr,16)
  
  test = OpenvpnKeysFinder(args.pid, fullScan=True)
  test.findKeys()
  
  #decryptatator=OpenSSHLiveDecryptatator(pid, sessionStateAddr=sessionStateAddr, serverMode=serverMode)
  #decryptatator.run()
  #log.info("done for pid %d, struct at 0x%lx"%(pid,decryptatator.session_state_addr))
  sys.exit(0)
  return -1


def main(argv):
  logging.basicConfig(level=logging.INFO)

  # we must have big privileges...
  if os.getuid() + os.geteuid() != 0:
    log.error("You must be root/using sudo to read memory and sniff traffic.")
    return

  parser = argparser()
  opts = parser.parse_args(argv)
  try:
    opts.func(opts)
  except ImportError,e:
    log.error('Struct type does not exists.')
    print e

  return 0
  



if __name__ == "__main__":
  main(sys.argv[1:])


