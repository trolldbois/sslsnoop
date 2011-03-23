#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging,os,socket

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
    self._inbound_cnt=0
    self._outbound_cnt=0

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
        self._inbound_readso,self._inbound_writeso=socket.socketpair()
        self._outbound_readso,self._outbound_writeso=socket.socketpair()
    except NameError:
        # yes || no socketpair support anyway
        self._initPipes()
    # scapy config
    # loopback
    #log.info('MTU is %d'%(scapy.data.MTU ))
    #scapy.data.MTU=0x7fff
    return
  
  def _initPipes(self):
    self._inbound_pipe=pipe_socketpair()
    self._inbound_readso,self._inbound_writeso=self._inbound_pipe.socketpair()
    self._outbound_pipe=pipe_socketpair()
    self._outbound_readso,self._outbound_writeso=self._outbound_pipe.socketpair()
    return

  def getInboundSocket(self):
    return self._inbound_readso
  def getOutboundSocket(self):
    return self._outbound_readso

  def run(self):
    # scapy
    sniff(count=self.packetCount,timeout=self.timeout,store=0,filter=self.filterRules,prn=self.cbSSHPacket)
    log.warning('============ SNIFF Terminated ====================')
    return
  
  def cbSSHPacket(self, obj):
    ''' callback function to pile packets in socket'''
    packet=obj[self.protocolName]
    pLen=len(packet.payload)
    if pLen > 0:
      # DEDUPs..
      # yeah ok, we need an id... seqnum could be ok, but that's tcp
      # but we can hash the payload too... surely no SSL proto would send twice the same payload
      pkid=hash(packet.payload.load)
      if pkid in self._cache_seqn:
        # dups. ignore. Happens when testing on ssh localhost & sshd localhost
        log.debug('Duplicate packet ignored.')
        return None
      # Lru cache, should disappear.
      self._cache_seqn[pkid]=True
      # else, triage
      if self.__is_inboundPacket(packet):
        self.addInboundPacket( packet.payload.load )
      elif self.__is_outboundPacket(packet):
        self.addOutboundPacket( packet.payload.load )
      else:
        log.error('the packet is neither inbound nor outbound. You messed up your filter and callbacks.')
    else:
      log.debug("empty payload isInbound %s"%self.__is_inboundPacket(packet))
    return None
    
  def setThread(self,thread):
    ''' the thread using the pipes '''
    self._running_thread=thread
    return 
  
  def addInboundPacket(self,payload):
    log.debug("add inbound")
    self._inbound_cnt+=self.addPacket(payload,self._inbound_writeso)
    log.debug("addInboundPacket %d len: %d\n%s"%(self._inbound_cnt, len(payload), hexify(payload) ))
    #log.debug( (''.join(util.format_binary(payload, '\n '))).lower() )
    return 
    
  def addOutboundPacket(self,payload):
    self._outbound_cnt+=self.addPacket(payload,self._outbound_writeso)
    #log.info("addOutboundPacket %d len: %d"%(self._outbound_cnt, len(payload) ) )
    log.debug("addOutboundPacket %d len: %d\n%s"%(self._outbound_cnt, len(payload), hexify(payload)) )
    #log.debug( (''.join(util.format_binary(payload, '\n '))).lower() )
    return 
    
  def addPacket(self,payload,so):
    cnt=so.send(payload)
    #log.debug("buffered %d/%d bytes"%(cnt, len(payload) ) )
    return cnt
  
  def __str__(self):
    return "inbound: %d bytes, outbound: %d bytes"%(self._inbound_cnt,self._outbound_cnt)

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

