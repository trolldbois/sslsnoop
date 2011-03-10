#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging,os,socket
logging.basicConfig(level=logging.DEBUG)

from scapy.all import sniff

log=logging.getLogger('socket.scapy')


class socket_scapy():
  ''' what you write in writeso, gets read in readso '''
  def __init__(self,filterRules,protocolName='TCP',packetCount=0,timeout=None):
    ''' 
    @param filterRules: a pcap compatible filter string 
    @param protocolName: the name of the scapy proto layer 
    @param packetCount: 0/Unlimited or packet capture limit
    @param timeout: None/Unlimited or stop after
    '''
    self.filterRules=filterRules
    self.protocolName=protocolName
    self.packetCount=packetCount
    self.timeout=timeout
    self.wcnt=0
    try:
        isWindows = socket.AF_UNIX
        self._readso,self._writeso=socket.socketpair()
    except NameError:
        # yes || no socketpair support anyway
        self._initPipe()
    return
  def _initPipe(self):
    self.__pipe=pipe_socketpair()
    self._readso,self._writeso=self.__pipe.socketpair()
    return
  def getReadSocket(self):
    return self._readso
  def getWriteSocket(self):
    return self._writeso

  def run(self):
    # scapy
    sniff(count=self.packetCount,timeout=self.timeout,store=0,filter=self.filterRules,prn=self.cbSSHPacket)
    return
  
  def cbSSHPacket(self, obj):
    ''' callback function to pile packets in socket'''
    pLen=len(obj['TCP'].payload)
    if pLen > 0:
      self.addPacket( obj['TCP'].payload.load )
    return None
  def addPacket(self,payload):
    self.wcnt+=self._writeso.send(payload)
    return
  def __str__(self):
    return "'sent': %d "%(self.wcnt)

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
  l=soscapy.wcnt
  print 'trying to read'
  data=soscapy.getReadSocket().recv(l)
  print 'recv %d bytes ->',len(data),repr(data)
  return soscapy

#test()

