#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging,os,socket,select, sys,time
import multiprocessing, Queue
import scapy.config

from lrucache import LRUCache

import stream

log = logging.getLogger('network')

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
  def __init__(self,filterRules='tcp', packetCount=0, timeout=None):
    ''' 
    This sniffer can run in a thread. But it should be one of the few thread running (BPL) 
    
    @param filterRules: a pcap compatible filter string 
    @param packetCount: 0/Unlimited or packet capture limit
    @param timeout: None/Unlimited or stop after
    '''
    # set scapy to use native pcap instead of SOCK_RAW
    scapy.config.conf.use_pcap = True
    ## if using SOCK_RAW, we need to mess with filter to up the capture size higher than 1514/1600 bytes
    #maxSize="\' -s \'0xffff" # abusing scapy-to-tcpdump string format 
    #self.filterRules=filterRules + maxSize
    self.filterRules = filterRules
    self.packetCount = packetCount
    self.timeout = timeout
    #
    self.streams = {}
    self._running_thread = None
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

  def hasStream(self, packet):
    ''' checks if the stream has a queue '''
    (shost,sport,dhost,dport) = getConnectionTuple(packet)
    return (shost,sport,dhost,dport) in self.streams

  def getStream(self, packet):
    ''' returns the queue for that stream '''
    if self.hasStream(packet):
      return self.streams[getConnectionTuple(packet)]
    return None,None

  def addStream(self, connection):
    ''' forget that stream '''
    shost,sport = connection.local_address
    dhost,dport = connection.remote_address
    if shost.startswith('127.') or shost.startswith('::1'):
      log.warning('=============================================================')
      log.warning('scapy is gonna truncate big packet on the loopback interface.')
      log.warning('please change your test params,or use offline mode with pcap.')
      log.warning('=============================================================')
    #q = multiprocessing.Queue(QUEUE_SIZE)
    q = Queue.Queue(QUEUE_SIZE)
    st = stream.TCPStream(q, connection)
    #save in both directions
    self.streams[(shost,sport,dhost,dport)] = (st,q)
    self.streams[(dhost,dport,shost,sport)] = (st,q)
    return st
  
  def dropStream(self, packet):
    ''' forget that stream '''
    if self.hasStream(packet):
      (shost,sport,dhost,dport) = getConnectionTuple(packet)
      if (shost,sport,dhost,dport) in self.streams:
        del self.streams[(shost,sport,dhost,dport)]
      if (dhost,dport,shost,sport) in self.streams:
        del self.streams[(dhost,dport,shost,sport)]
      log.info('Dropped %s,%s,%s,%s from valid connections.'%(shost,sport,dhost,dport))
    return None
    
  def enqueue(self, packet):
    st,q = self.getStream(packet)
    if q is None:
      return
    try:
      log.debug('Queuing a packet from %s:%s\t-> %s:%s'%(getConnectionTuple(packet)))
      q.put_nowait(packet)
    except Queue.Full:
      log.warning('a Queue is Full. lost packet.')
      self.dropStream( packet )
    except Exception,e:
      log.error(e)
    return

  def makeStream(self, connection):
    ''' create a TCP Stream recognized by sniffer 
      the Stream can be used to read captured data
      
      The Stream should be run is a thread or a subprocess (better because of GIL).
    '''
    shost,sport = connection.local_address
    dhost,dport = connection.remote_address
    if (shost,sport,dhost,dport) in self.streams:
      raise ValueError('Stream already exists')
    tcpstream = self.addStream(connection)
    log.debug('Created a TCPStream for %s'%(tcpstream))
    return tcpstream


def getConnectionTuple(packet):
  ''' Supposedly an IP/IPv6 model'''
  try:
    shost  = packet.payload.src
    sport  = packet.payload.payload.sport
    dhost  = packet.payload.dst
    dport  = packet.payload.payload.dport
  except Exception, e:
    log.debug("%s - %s"% (type(packet), packet.show2()))
    raise e
  return (shost,sport,dhost,dport)  
 


class PcapFileSniffer(Sniffer):
  ''' Use scapy's offline mode to simulate network by reading a pcap file.
  '''
  def __init__(self, pcapfile, filterRules='tcp', packetCount=0):
    Sniffer.__init__(self, filterRules=filterRules, packetCount=packetCount)
    self.pcapfile = pcapfile
  def run(self):
    from scapy.all import sniff
    sniff(store=0, prn=self.enqueue, offline=self.pcapfile)
    log.info('Finishing the pcap reading')
    for v, k in list(self.streams.items()):
      st,q = k
      if not q.empty():
        log.debug('waiting on %s'%(repr(v)))
        q.join()
      del self.streams[v]
      del q
      st.pleaseStop()

    log.info('============ SNIFF Terminated ====================')

    return


    
    
    










