#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging,os,socket,sys

import scapy
from scapy.all import sniff
from paramiko import util

from lrucache import LRUCache

log=logging.getLogger('socket.scapy')


def isdestport22(packet):
  return  packet.dport == 22

def isNotdestport22(packet):
  return  not isdestport22(packet)


def hexify(data):
  s=''
  for i in range(0,len(data)):
    s+="%02x"% ord(data[i])
    if i%16==15:
      s+="\r\n"
    elif i%2==1:
      s+=" "
  #s+="\r\n"
  return s

class state:
  name=None
  packet_count=0
  byte_count=0
  start_seq=None
  max_seq=0
  expected_seq=None
  queue=None
  write_socket=None
  read_socket=None
  def __init__(self,name):
    self.name=name
    self.queue=LRUCache(128)
  def init(self, pair):
    read, write = pair
    self.read_socket=read
    self.write_socket=write
    return  
  def __str__(self):
    return "%s: %d bytes/%d packets max_seq:%d expected_seq:%d"%(self.name, self.byte_count,self.packet_count,
                self.max_seq,self.expected_seq)
  
class stack:
  def __init__(self):
    self.inbound=state('inbound')
    self.outbound=state('outbound')
  def __str__(self):
    return "%s %s"%(self.inbound,self.outbound)
  
class socket_scapy():
  ''' what you write in writeso, gets read in readso '''
  def __init__(self,filterRules, protocolName='TCP', packetCount=0, timeout=None,
            isInboundPacketCallback=None,isOutboundPacketCallback=None):
    ''' 
    @param filterRules: a pcap compatible filter string 
    @param protocolName: the name of the scapy proto layer 
    @param packetCount: 0/Unlimited or packet capture limit
    @param timeout: None/Unlimited or stop after
    '''
    self._cache_seqn = LRUCache(128)
    self.filterRules=filterRules
    self.protocolName=protocolName
    self.packetCount=packetCount
    self.timeout=timeout
    #
    self.stack=stack()

    self._running_thread=None
    # distinguish between incoming and outgoing packets // classic ssh client
    self.__is_inboundPacket=isInboundPacketCallback
    self.__is_outboundPacket=isOutboundPacketCallback
    if ( self.__is_inboundPacket is None):
      self.__is_inboundPacket=isNotdestport22 ## SSH CLIENT
      ##self.__is_inboundPacket=isdestport22  ## SSH SERVER
    if ( self.__is_outboundPacket is None):
      self.__is_outboundPacket=isdestport22  ## SSH CLIENT
      ##self.__is_outboundPacket=isNotdestport22 ## SSH SERVER
    # make socket
    try:
        isWindows = socket.AF_UNIX
        self.stack.inbound.init(  socket.socketpair() )
        self.stack.outbound.init( socket.socketpair() )
    except NameError:
        # yes || no socketpair support anyway
        self._initPipes()
    # scapy config
    # loopback
    #log.info('MTU is %d'%(scapy.data.MTU ))
    #scapy.data.MTU=0x7fff
    return
  
  def _initPipes(self):
    self.stack.inbound.pipe  = pipe_socketpair()
    self.stack.inbound.init(  self.stack.inbound.pipe.socketpair())
    self.stack.outbound.pipe = pipe_socketpair()
    self.stack.outbound.init( self.stack.outbound.pipe.socketpair() )
    return

  def getInboundSocket(self):
    return self.stack.inbound.read_socket
  def getOutboundSocket(self):
    return self.stack.outbound.read_socket

  def run(self):
    # scapy
    sniff(count=self.packetCount,timeout=self.timeout,store=0,filter=self.filterRules,prn=self.cbSSHPacket)
    log.warning('============ SNIFF Terminated ====================')
    return
  
  def checkState(self,state, packet):
    seq=packet.seq
    ## debug head initialisation
    if state.start_seq is None:
      state.start_seq=seq
      state.expected_seq=seq
    ## debug
    payloadLen=len(packet.payload)
    # DEDUPs..
    # yeah ok, we need an id... seqnum could be ok, but that's tcp
    # but we can hash the payload too... surely no SSL proto would send twice the same payload
    pkid=hash((packet.sport,packet.dport,  packet.seq, packet.ack, packet.flags))
    
    if pkid in self._cache_seqn:
      # dups. ignore. Happens when testing on ssh localhost & sshd localhost
      log.debug('Duplicate packet detected seq: %d'%(seq))
      '''
      log.debug('Duplicate packet ignored. seq: %d'%(seq))
      log.debug('orig packet : %s'%(repr(self._cache_seqn[pkid].underlayer ) ))
      log.debug('Duplicate packet : %s'%(repr(packet.underlayer) ))
      sys.exit()
      return False
    self._cache_seqn[pkid]=packet
    '''
    # always for wireshark, don't log ACKs
    if state.name == 'inbound' and  payloadLen > 0:
      log.debug('seqnum %d - %d len: %d %s'%(seq-state.start_seq, seq, payloadLen, state ))

    # now on tcp reassembly
    if seq == state.expected_seq: # JIT
      if payloadLen > 0: 
        state.max_seq = seq
        state.expected_seq = seq + payloadLen
        return True
      # ignore acks
      return False
    if seq > state.expected_seq: # future anterieur
      if payloadLen > 0: 
        # seq is in advance
        state.queue[seq]= packet
        if state.name == 'inbound':
          log.debug('Queuing packet seq: %d %s'%(seq, state))
      # ignore Acks
      return False
    if seq < state.max_seq:
      log.warning('We just received %d when we already processed %d'%(seq, state.max_seq))
      # we are screwed. ignore the packet
      return False
    # else, seq < expected_seq and seq >= state.max_seq. That's not possible... it's current packet.
    # it's a dup already dedupped ? partial fragment ?
    log.warning('received a bogus fragment seq: %d for %s'%(seq, self))
    return False

  def cbSSHPacket(self, obj):
    ''' callback function to pile packets in socket'''
    packet=obj[self.protocolName]
    pLen=len(packet.payload)
    if self.__is_inboundPacket(packet):
      if self.checkState(self.stack.inbound, packet) and pLen > 0:
        self.writePacket(self.stack.inbound, packet.payload.load )
    elif self.__is_outboundPacket(packet):
      if self.checkState(self.stack.outbound, packet) and pLen > 0:
        self.writePacket(self.stack.outbound, packet.payload.load )
    else:
      log.error('the packet is neither inbound nor outbound. You messed up your filter and callbacks.')
    return None
    
  def setThread(self,thread):
    ''' the thread using the pipes '''
    self._running_thread=thread
    return 
  
  def writePacket(self,state, payload):
    state.byte_count+=self.addPacket(payload,state.write_socket)
    state.packet_count+=1
    if state.name == 'inbound':
      log.debug("writePacket%s %d len: %d"%(state.name, state.byte_count, len(payload) ) )
    #log.debug("writePacket%s %d len: %d\n%s"%(state.name, state.byte_count, len(payload), hexify(payload) ) )
    #log.debug( (''.join(util.format_binary(payload, '\n '))).lower() )
    return 
    
  def addPacket(self,payload,so):
    cnt=so.send(payload)
    #log.debug("buffered %d/%d bytes"%(cnt, len(payload) ) )
    return cnt
  
  def __str__(self):
    return "<socket_scapy %s "%(self.stack) 

# if Linux use socket.socketpair()
class pipe_socketpair(object):
  def __init__(self):
    self.readfd,self.writefd=os.pipe()
    self.readso=socket.fromfd(self.readfd,socket.AF_UNIX,socket.SOCK_STREAM)
    self.writeso=socket.fromfd(self.writefd,socket.AF_UNIX,socket.SOCK_STREAM)
    return
  def socketpair(self):
    return (self.readso,self.writeso)

def test():
  '''
sniff(count=0, store=1, offline=None, prn=None, lfilter=None, L2socket=None, timeout=None, opened_socket=None, *arg, **karg)  
  '''
  port=22
  sshfilter="tcp and port %d"%(port)
  soscapy=socket_scapy(sshfilter,packetCount=10)
  log.info('Please make some ssh  traffic')
  soscapy.run()
  print 'sniff finished'
  # we get Ether()'s...
  print soscapy.stats()
  l=soscapy._inbound_cnt
  print 'trying to read'
  data=soscapy.getInboundSocket().recv(l)
  print 'recv %d bytes ->',len(data),repr(data)
  return soscapy

#test()

