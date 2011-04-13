#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse
import ctypes
import os
import logging
import pickle
import struct
import sys
import time
import threading

# todo : replace by one empty shell of ours
from paramiko.transport import Transport

import ctypes_openssl
import ctypes_openssh
import output
import haystack 
import network
import utils

from engine import CIPHERS
#our impl
from paramiko_packet import Packetizer

log=logging.getLogger('sslsnoop-openssh')


class SessionStateFileWriter(output.FileWriter):
  def __init__(self,pid,folder='outputs'):
    FileWriter.__init__(self,'session_state',pid,folder)
  def writeToFile(self,instance):
    prefix = self.prefix
    filename = self.get_valid_filename()
    f = open(filename,"w")
    pickle.dump(instance,f)
    f.close()
    log.info ("[X] SSH session_state saved to file %s"%filename)
    return True


class Dummy:
  pass

class SessionCiphers():
  def __init__(self,session_state):
    self.session_state = session_state
    # two ciphers    
    self.receiveCtx = Dummy()
    self.sendCtx = Dummy()
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
  ''' wrapper around a fork/exec to haystack StructFinder '''

  def __init__(self, pid, fullScan=False):
    self.pid = pid
    self.fullScan = fullScan
    return
  
  def findActiveSession(self, maxNum=1):
    ''' search for session_state '''
    outs = haystack.findStruct(self.pid, ctypes_openssh.session_state, debug=False)
    if outs is None:
      log.error("The session_state has not been found. maybe it's not OpenSSH ?")
      return None,None
    elif len(outs) > 1:
      log.warning("Mmmh, we found multiple session_state(%d). That is odd. I'll try with the first one."%(len(outs)))
    #
    session_state,addr = outs[0]
    return session_state, addr

  def refreshActiveSession(self, offset):
    ''' refresh session_state from a known address '''
    instance,validated = haystack.refreshStruct(self.pid, ctypes_openssh.session_state, offset)
    if not validated:
      log.error("The session_state has not been re-validated. You should look for it again.")
      return None,None
    return instance,offset
    
  def findActiveKeys(self, maxNum=1, offset=None):
    ''' wrap search or refresh and returns a session_state with pretty clothes'''
    if offset is None:
      session_state,addr = self.findActiveSession(maxNum)
    else:
      session_state,addr = self.refreshActiveSession(offset)
    if session_state is None:
      return None,None # raise Exception ... 
    log.debug('received session_state %s'%(session_state))
    ciphers = SessionCiphers(session_state)
    log.info('Active state ciphers : %s at 0x%lx'%(ciphers,addr))
    return ciphers,addr

  def save(self, instance):
    ssfw = SessionStateFileWriter(self.process.pid)
    ssfw.writeToFile(instance)
    return



class OpenSSHLiveDecryptatator(OpenSSHKeysFinder):
  ''' 
    Decrypt SSH traffic in live.
    This class only works on Live PID.
  '''
  def __init__(self, pid, sessionStateAddr=None, scapyThread = None):
    OpenSSHKeysFinder. __init__(self, pid)
    self.scapy = scapyThread
    self.session_state_addr = sessionStateAddr
    self.connection = utils.getConnectionForPID(self.pid)
    self.inbound = Dummy()
    self.outbound = Dummy()
    return
  
  def _initSniffer(self):
    ''' use existing sniffer or create a new one '''
    if self.scapy is None:
      self.scapy = utils.launchScapy()
    elif not self.scapy.thread.isAlive():
      self.scapy.thread.start()
    return
  
  def _initCiphers(self):
    ''' ptrace the ssh process to get sessions keys '''
    if self.session_state_addr is None:
      self.ciphers,self.session_state_addr = self.findActiveKeys()
    else:
      self.ciphers,self.session_state_addr = self.findActiveKeys(offset=self.session_state_addr)
    if self.ciphers is None:
      raise ValueError('Struct not found')
    return  
  
  def _initStream(self):
    ''' create a stream from scapy thread '''
    self.stream = self.scapy.makeStream(self.connection)
    return
  
  def _initSockets(self):
    self.inbound.socket = self.stream.getInbound().getSocket()
    self.outbound.socket = self.stream.getOutbound().getSocket()
    return
    
  def _initSSH(self):
    ''' plug sockets, packetizer and outputs together '''
    receiveCtx,sendCtx = self.ciphers.getCiphers()
    # Inbound
    log.debug('activate INBOUND packetizer')
    self.inbound.context = receiveCtx
    self.inbound.packetizer = Packetizer( self.inbound.socket )
    self.inbound.packetizer.set_log(logging.getLogger('inbound.packetizer'))
    self.inbound.engine = self.activate_cipher(self.inbound.packetizer, receiveCtx )
    # Outbound
    log.debug('activate OUTBOUND packetizer')
    self.outbound.context = sendCtx
    self.outbound.packetizer = Packetizer(self.outbound.socket)
    self.outbound.packetizer.set_log(logging.getLogger('outbound.packetizer'))
    self.outbound.engine = self.activate_cipher(self.outbound.packetizer, self.outbound.context )
    return 
  
  def _initOutputs(self):
    ''' init output engine. File Writers.'''
    name = 'ssh-%s'%( utils.connectionToString(self.stream.connection) )
    self.inbound.filewriter = output.SSHStreamToFile(self.inbound.packetizer, self.inbound, name)

    name = 'ssh-%s'%( utils.connectionToString(self.stream.connection, reverse=True) )
    self.outbound.filewriter =  output.SSHStreamToFile(self.outbound.packetizer, self.outbound, name)
    return 
  
  def _initWorker(self):
    ''' worker to poll on data for decryption '''
    self.worker = output.Supervisor()
    self.worker.add( self.inbound.socket,  self.inbound.filewriter.process  )
    self.worker.add( self.outbound.socket, self.outbound.filewriter.process )
    return
        
  def _launchStreamProcessing(self):
    ''' run streams '''
    self.stream.getInbound().setActiveMode()
    self.stream.getOutbound().setActiveMode()
    self.stream_t = threading.Thread(target=self.stream.run,name='stream' )
    self.stream_t.start()    
    return
    
  def run(self):
    ''' launch sniffer and decrypter threads '''
    self._initSniffer()
    self._initCiphers()
    self._initStream()
    self._initSockets()
    self._initSSH()
    self._initOutputs()
    self._initWorker()
    log.info('Ready to catch some ssh traffic - please try `ls -l` in ssh if your just playing around...')  
    self._launchStreamProcessing()
    self.loop()
    log.info("done %s"%(self))
    return
    
  def loop(self):
    self.worker.run()
    return

  def activate_cipher(self, packetizer, context):
    ''' activate the packetizer with a cipher engine '''
    # find Engine from engine.ciphers
    engine = CIPHERS[context.name](context) 
    log.debug( 'cipher:%s block_size: %d key_len: %d '%(context.name, context.block_size, context.key_len ) )
    mac = context.mac
    if mac is not None:
      mac_key    = mac.key 
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
    return engine
  
  def refresh(self):
    log.warning('Refreshing Engine states')
    self._initCiphers()
    # refresh both engine
    receiveCtx,sendCtx = self.ciphers.getCiphers()
    # Inbound
    log.info('activate INBOUND receive')
    self.inbound.context = receiveCtx
    self.outbound.context = sendCtx
    self.inbound.engine.sync(self.inbound.context)
    self.outbound.engine.sync(self.outbound.context)
    pass

  def __str__(self):
    return "Decryption for pid %d, struct at 0x%lx"%(self.process.pid, self.session_state_addr)

class OpenSSHPcapDecrypt(OpenSSHLiveDecryptatator):
  ''' 
  Decrypt ssh traffic from a dumped session_state and a pcap capture.
  '''
  def __init__(self, pcapfilename, connection, ssfile):
    self.scapy = None
    self.session_state_addr = None
    self.inbound = Dummy()
    self.outbound = Dummy()
    # now...
    self.ssfile = ssfile
    self.pcapfilename = pcapfilename
    self.connection = connection

  def _initSniffer(self):
    ''' use existing sniffer or create a new one '''
    self.scapy = network.PcapFileSniffer(self.pcapfilename)
    sniffer = threading.Thread(target=self.scapy.run, name='scapy')
    self.scapy.thread = sniffer
    # do not launch the scapy thread before having made the stream, 
    # otherwise we are gonna loose packets ...
    return
  
  def _initCiphers(self):
    ''' ptrace the ssh process to get sessions keys '''
    inst = pickle.load(self.ssfile)
    self.session_state,self.session_state_addr = inst[0]
    self.ciphers = SessionCiphers(self.session_state)
    if self.ciphers is None:
      raise ValueError('Struct not found')
    return  
  
  def _launchStreamProcessing(self):
    OpenSSHLiveDecryptatator._launchStreamProcessing(self)
    # we can start scapy now, stream are in place
    self.scapy.thread.start()
    return

  def __str__(self):
    return "Decryption of %s, struct at 0x%lx"%(self.pcapfilename, self.session_state_addr)


def launchLiveDecryption(pid, sniffer, addr=None): 
  ''' launch a live decryption '''
  # sniffer is a running thread
  # when ready, will have to launch tcpstream as a Thread
  decryptatator = OpenSSHLiveDecryptatator(pid, sessionStateAddr=addr, scapyThread=sniffer )
  decryptatator.run()
  return

def launchPcapDecryption(pcap, connection, ssfile): 
  ''' launch a decryption fro a pcap file and a session state '''
  decryptatator = OpenSSHPcapDecrypt(pcap, connection, ssfile)
  decryptatator.run()
  return



# ============== move to scripts/sslsnoop-openssh


def argparser():
  parser = argparse.ArgumentParser(prog='sshsnoop', description='Live decription of Openssh traffic.')
  parser.add_argument('--debug', action='store_const', const=True, default=False, help='debug mode')

  subparsers = parser.add_subparsers(help='sub-command help')
  live_parser = subparsers.add_parser('live', help='Decrypts traffic from a live PID.')
  live_parser.add_argument('pid', type=int, help='Target PID')
  live_parser.add_argument('--addr', type=str, help='active_context memory address')
  live_parser.set_defaults(func=search)

  offline_parser = subparsers.add_parser('offline', help='Decrypts traffic from a pcap file, given a pickled session state.')
  offline_parser.add_argument('sessionstatefile', type=argparse.FileType('r'), help='File containing a pickled sessionstate.')
  offline_parser.add_argument('pcapfile', type=argparse.FileType('r'), help='Pcap file containing ssh traffic.')
  offline_parser.add_argument('src', type=str, help='SSH local host ip.')
  offline_parser.add_argument('sport', type=int, help='SSH source port.')
  offline_parser.add_argument('dst', type=str, help='SSH remote host ip.')
  offline_parser.add_argument('dport', type=int, help='SSH destination port.')
  offline_parser.set_defaults(func=searchOffline)
  return parser

def search(args):
  pid = int(args.pid)
  log.debug("Target has pid %d"%pid)
  addr = None
  if args.addr != None:
    addr = int(args.addr,16)
  launchLiveDecryption(pid, None, addr=addr)
  sys.exit(0)
  return

def searchOffline(args):
  import utils 
  connection = utils.Connection(args.src,args.sport, args.dst,args.dport)
  launchPcapDecryption(args.pcapfile.name, connection, args.sessionstatefile)
  sys.exit(0)
  return


def main(argv):
  logging.basicConfig(level=logging.INFO)

  # we must have big privileges...
  if os.getuid() + os.geteuid() != 0:
    log.error("You must be root/using sudo to read memory and sniff traffic.")
    return
  
  parser = argparser()
  opts = parser.parse_args(argv)
  try:
    if opts.debug:
      logging.basicConfig(level=logging.DEBUG)    
      log.debug("==================- DEBUG MODE -================== ")  
    opts.func(opts)
  except ImportError,e:
    log.error('Struct type does not exists.')
    print e

  return 0
  
if __name__ == "__main__":
  main(sys.argv[1:])

