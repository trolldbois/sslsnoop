#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging,os,socket,select, sys,threading, time

import scapy.config

from lrucache import LRUCache
from ctypes_openssh import AES_BLOCK_SIZE

log=logging.getLogger('network')

QUEUE_SIZE = 1500

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

class Sniffer():
  worker=None
  def __init__(self,filterRules, packetCount=0, timeout=None, pcapFile=None):
    ''' 
    This sniffer can run in a thread. But it should be one of the few thread running (BPL) 
    
    @param filterRules: a pcap compatible filter string 
    @param packetCount: 0/Unlimited or packet capture limit
    @param timeout: None/Unlimited or stop after
    '''
    # set scapy to use native pcap instead of SOCK_RAW
    scapy.config.conf.use_pcap=True
    ## if using SOCK_RAW, we need to mess with filter to up the capture size higher than 1514/1600 bytes
    #maxSize="\' -s \'0xffff" # abusing scapy-to-tcpdump string format 
    #self.filterRules=filterRules + maxSize
    self.filterRules=filterRules
    self.packetCount=packetCount
    self.timeout=timeout
    #
    self.streams={}
    self._running_thread=None
    return
  

  def run(self):
    # scapy - with config initialised
    #scapy.sendrecv.sniff(count=self.packetCount,timeout=self.timeout,store=0,filter=self.filterRules,prn=self.cbSSHPacket)
    from scapy.all import sniff
    log.info('Using L2listen = %s'%(scapy.config.conf.L2listen)) 
    # XXX TODO, define iface from saddr and daddr // scapy.all.read_routes()
    sniff(count=self.packetCount, timeout=self.timeout, store=0, filter=self.filterRules, prn=self.enqueue, iface='any')
    log.warning('============ SNIFF Terminated ====================')
    return

  def getStream(self, packet):
    # whataboutipv6 ?
    shost  = packet['IP'].src
    sport  = packet['TCP'].sport
    dhost  = packet['IP'].dst
    dport  = packet['TCP'].dport
    if (shost,sport,dhost,dport) in self.streams:
      return self.streams[(shost,sport,dhost,dport)]
    return None

  def dropStream(self, packet):
    # whataboutipv6 ?
    shost  = packet['IP'].src
    sport  = packet['TCP'].sport
    dhost  = packet['IP'].dst
    dport  = packet['TCP'].dport
    if (shost,sport,dhost,dport) in self.streams:
      del self.streams[(shost,sport,dhost,dport)]
      log.info('Dropped %s,%s,%s,%s from valid connections.'%(shost,sport,dhost,dport))
    return None
    
  def enqueue(self, packet):
    q = self.getStream(packet)
    if q is None:
      return
    try:
      q.put_nowait(packet)
    except Queue.Full:
      log.warning('a Queue is Full. lost packet.')
      self.dropStream( packet )
    return

  def makeStream(self, connection):
    ''' create a TCP Stream recognized by socket_scapy 
      the Stream can be used to read captured data
      
      The Stream should be run is a thread or a subprocess (better because of GIL).
    '''
    shost,sport = connection.local_address
    dhost,dport = connection.remote_address
    q = multiprocessing.Queue(QUEUE_SIZE)
    self.streams[(shost,sport,dhost,dport)] = q
    tcpstream = stream.TCPStream(q, connection)
    return tcpstream





    
    
    










