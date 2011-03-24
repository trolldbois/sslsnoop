#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging,os,socket,sys,threading, time

import scapy.sendrecv
from scapy.all import sniff
#from scapy.sendrecv import sniff, send
from paramiko import util

from lrucache import LRUCache

log=logging.getLogger('socket.scapy')


WAIT_RETRANSMIT=5
MISSING_DATA_MESSAGE='[MISSINGDATA]'

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


class MissingDataException (Exception):
  def __init__(self,nb):
    self.nb=nb
 
class state:
  name=None
  packet_count=0
  byte_count=0
  start_seq=None
  max_seq=0
  expected_seq=0
  lastpacket=None
  queue=None
  write_socket=None
  read_socket=None
  read_socket_revc_func=None
  ts_missing=None
  def __init__(self,name):
    self.name=name
    self.queue={}
  def init(self, pair):
    read, write = pair
    self.read_socket=socket.socket(_sock=read)
    self.read_socket_revc_func=self.read_socket.recv
    self.write_socket=write
    self.lock=threading.Lock()
    return  
  def forget_missing_data(self):
    ''' switch recv() method on readsocket to alert reader()
     push missing data in socket to wakeup reader
    '''
    self.lock.acquire()
    if self.ts_missing is None: # naaa. it's good
      return
    self.ts_missing=None
    #
    if self.read_socket.recv != self._read_missing_data:
      self.read_socket.recv = self._read_missing_data
      nb=self.expected_seq-self.max_seq
      log.debug('%s: ***********888 Signaling about missing data %d bytes from %d to %d'%(self.name, nb, self.max_seq, self.expected_seq))
      self.write_socket.send(MISSING_DATA_MESSAGE)
    self.lock.release()
    return
    
  def _read_missing_data(self, n):
    ''' exception contains lenght of missing data '''
    self.lock.acquire()
    # repair socket for further use
    self.read_socket.recv = self.read_socket_revc_func
    nb = self.expected_seq - self.max_seq
    new_seq = min(self.queue.keys())
    log.debug('%s: Forgetting about %d bytes / %d pkts left, expected: %d, new_seq: %d'%(self.name, nb, len(self.queue), self.expected_seq ,new_seq ))
    # reinit counters with lowest value, and prequeue will naturally occur (supposedly)
    self.expected_seq = new_seq
    self.max_seq = self.expected_seq
    self.lock.release()
    raise MissingDataException(nb)
  def __str__(self):
    return "%s: %d bytes/%d packets max_seq:%d expected_seq:%d q:%d"%(self.name, self.byte_count,self.packet_count,
                self.max_seq,self.expected_seq, len(self.queue))
  
class stack:
  def __init__(self):
    self.inbound=state('inbound')
    self.outbound=state('outbound')
  def __str__(self):
    return "\n%s\n%s"%(self.inbound,self.outbound)
  
class socket_scapy():
  ''' what you write in writeso, gets read in readso '''
  worker=None
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
    self.lock=threading.Lock()
    self.stack=stack()
    self.packets={}
    self.bigqueue=[]

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
    #scapy.sendrecv.sniff(count=self.packetCount,timeout=self.timeout,store=0,filter=self.filterRules,prn=self.cbSSHPacket)
    sniff(count=self.packetCount,timeout=self.timeout,store=0,filter=self.filterRules,prn=self.enqueue)
    log.warning('============ SNIFF Terminated ====================')
    return

  def enqueue(self, obj):
    self.lock.acquire()
    self.bigqueue.append(obj)
    self.lock.release()
    return
  def dequeue(self):
    obj=None
    self.lock.acquire()
    if len(self.bigqueue) > 0:
      obj=self.bigqueue.pop(0)
    self.lock.release()
    return obj

  def prequeue(self, state):
    ''' get packets from queue and put them in processing bigqueue '''
    queue=state.queue.values()
    queue.sort(key=lambda p: p.seq)
    # add the first and the next that are in perfect suite.
    toadd=[queue.pop(0),]
    for i in xrange(1,len(queue)):
      log.debug('prequeue queue[0].seq: %d , toadd[-1].seq+len(toadd[-1].payload): %d'%(queue[0].seq, toadd[0].seq+len(toadd[0].payload)))
      if queue[0].seq == toadd[-1].seq+len(toadd[-1].payload):
        toadd.append(queue.pop(0))
      else:
        break
    # let remaining in state.queue
    state.queue=dict( [ (p.seq, p) for p in queue])
    self.lock.acquire()
    #preprend packets
    self.bigqueue = toadd + self.bigqueue
    self.lock.release()
    log.debug('Prequeued %d packets, remaining %d'%(len(toadd), len(state.queue)))
    # reset time counter
    if len(state.queue) > 0:
      state.ts_missing  = time.time()
    else:
      state.ts_missing  = None
    return
  
  def run2(self):
    while(True):
      # depile packets
      packet=self.dequeue()
      self.cbSSHPacket(packet)
      if packet is None:
        #log.debug('%s'%(self))
        time.sleep(0.5)          
    log.warning('============ SNIFF WORKER Terminated ====================')
    return
  
  def retransmit(self, state):
    ''' act like a buggy tcp stack, ask for a retransmit on state.
    but with processing delay, it won't work ... 
    ''' 
    return
    if state == self.stack.inbound:
      other = self.stack.outbound
    else:
      other = self.stack.inbound
    ip = other.lastpacket.underlayer.copy()
    ip.payload.payload=''
    ip.payload.seq = other.expected_seq+1000
    ip.payload.ack = state.expected_seq
    # IP might be nice with us
    start=ip.id+1000
    #ip.show2()
    del ip.chksum
    del ip.payload.chksum
    '''
    packets=[]
    for start in range(start,start+200,20):
      ip.id=start
      packets.append(ip.copy())
    '''
    ip2=ip.copy()
    ip2.payload.seq += 48 # try to guess next packet ( downstream )
    packets=[ip,ip2]
    scapy.sendrecv.send(packets, verbose=0)
    
    log.debug('======= send %d ack for %d'%(len(packets), state.expected_seq))
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
    pkid=hash((packet.sport,packet.dport,  packet.seq, packet.ack, packet.flags, len(packet)))
    
    if pkid in self._cache_seqn and payloadLen > 0:
      # dups. ignore. Happens when testing on ssh localhost & sshd localhost
      log.debug('seqnum %d -     %d len: %d %s  *** DUPLICATE IGNORED *** '%(seq-state.start_seq, seq, payloadLen, state ))
      return False # ignore it, we already got it
      '''
      log.debug('Duplicate packet ignored. seq: %d'%(seq))
      log.debug('orig packet : %s'%(repr(self._cache_seqn[pkid].underlayer ) ))
      log.debug('Duplicate packet : %s'%(repr(packet.underlayer) ))
      sys.exit()
      return False
      '''
    self._cache_seqn[pkid]=packet
    
    # always for wireshark, don't log ACKs
    #if state.name == 'inbound' : #and  payloadLen > 0:
    #  log.debug('seqnum %d -     %d len: %d %s'%(seq-state.start_seq, seq, payloadLen, state ))


    # debug, is that useful at all....?
    #return True


    # now on tcp reassembly
    if seq == state.expected_seq: # JIT
      ## if payloadLen > 0: ## get all packets
      if payloadLen > 0: 
        state.max_seq = seq
        state.expected_seq = seq + payloadLen
        self.packets[seq]=packet # debug the packets
        state.ts_missing = None
        # check if next is already in state.queue , if expected has changed
        if state.expected_seq in state.queue : 
          log.debug('seqnum %d - ok  %d len: %d %s'%(seq-state.start_seq, seq, payloadLen, state ))
          log.debug('we have next ones in buffer %d'%(state.expected_seq)) # prepend the queue to parse list.
          self.prequeue(state)
      return True
      # ignore acks
      #log.debug('IGNORE empty packet with expected_seq')
      #return False
    if seq > state.expected_seq: # future anterieur
      if payloadLen > 0: 
        # seq is in advance
        state.queue[seq]= packet
        #log.debug('Queuing packet seq: %d len: %d %s'%(seq, payloadLen, state))

        ## if ~5 sec, we will forget about missing data
        ## and inform reader of that fact
        if state.ts_missing is None:
          state.ts_missing = time.time()
        elif time.time() > ( state.ts_missing + WAIT_RETRANSMIT) : # waiting for too long
          state.forget_missing_data()
        else:
          pass

      # check if next is already in state.queue 
      if state.expected_seq in state.queue :
        log.debug('queuing, seqnum %d -  q  %d len: %d %s'%(seq-state.start_seq, seq, payloadLen, state ))
        log.debug('queuing, we have next ones in buffer %d'%(state.expected_seq)) # prepend the queue to parse list.
        self.prequeue(state)
        # reset time counter
        state.ts_missing  = None
      else:
        ## if ~5 sec, we will forget about missing data
        ## and inform reader of that fact
        if state.ts_missing is None:
          state.ts_missing = time.time()
        elif time.time() > ( state.ts_missing + WAIT_RETRANSMIT) : # waiting for too long
          state.forget_missing_data()
        else:
          pass

      ## ask for a retransmission of state.expected_seq
      if seq in self.packets:
        log.warning('packet seq %d has already been received'%(seq))
        log.warning('recent  packet : %s'%(repr(packet.underlayer) ))
        log.warning('first   packet : %s'%(repr(self.packets[seq].underlayer ) ))
        seq2=seq+len(self.packets[seq].payload)
        log.warning('first+1 packet : %s'%(repr(self.packets[seq2].underlayer ) ))
          
          ##
      # ignore Acks
      #log.debug('IGNORE empty packet with future seq')
      return False
    if seq < state.expected_seq:
      # TCP retransmission
      log.debug('TCP retransmit - We just received %d when we already processed %d'%(seq, state.max_seq))
      ## ignore it most of the time
      # check if restransmission from packets[-2]+packets[-1]
      #if seq in self.packets:
      #  log.warning('packet seq %d has already been received'%(seq))
      #  log.warning('recent  packet : %s'%(repr(packet.underlayer) ))
      #  log.warning('first   packet : %s'%(repr(self.packets[seq].underlayer ) ))
      #  seq2=seq+len(self.packets[seq].payload)
      #  log.warning('first+1 packet : %s'%(repr(self.packets[seq2].underlayer ) ))
      if seq+payloadLen > state.expected_seq :
        log.warning(' ***** EXTRA DATA FOUND ONT TCP RETRANSMISSION ')
        # we need to recover the extra data to put it in the stream
        nb=(seq+payloadLen) - state.expected_seq
        data=packet.payload.load[-nb:]
        log.warning('packet seq %d has already been received'%(seq))
        log.warning('recent  packet : %s'%(repr(packet.underlayer) ))
        log.warning('first   packet : %s'%(repr(self.packets[seq].underlayer ) ))
        seq2=seq+len(self.packets[seq].payload)
        log.warning('first+1 packet : %s'%(repr(self.packets[seq2].underlayer ) ))
        packet.payload.load=data
        log.warning('NEW     packet : %s'%(repr(packet.underlayer) ))
        # updates seq
        state.max_seq = seq
        state.expected_seq = seq2
        if payloadLen > 0: 
          self.packets[seq]=packet # debug the packets

        ##os.kill(os.getpid())
        
        return True
      # we are screwed. ignore the packet
      return False
    # else, seq < expected_seq and seq >= state.max_seq. That's not possible... it's current packet.
    # it's a dup already dedupped ? partial fragment ?
    log.warning('received a bogus fragment seq: %d for %s'%(seq, self))
    return True

  def cbSSHPacket(self, obj):
    ''' callback function to pile packets in socket'''
    if obj is None:
      for state in [self.stack.inbound,self.stack.outbound]:
        if state.expected_seq in state.queue : 
          self.prequeue(state)
        if state.ts_missing is not None and  time.time() > ( state.ts_missing + WAIT_RETRANSMIT) : # waiting for too long
            state.forget_missing_data()
      return None
    ###self.lock.acquire()
    packet=obj[self.protocolName]
    pLen=len(packet.payload)
    #if pLen == 0: # ignore acks and stuff // retransmit not working
    #  return None
    if self.__is_inboundPacket(packet):
      self.stack.inbound.lastpacket = packet
      if self.checkState(self.stack.inbound, packet) and pLen > 0:
        self.writePacket(self.stack.inbound, packet.payload.load )
    elif self.__is_outboundPacket(packet):
      self.stack.outbound.lastpacket = packet
      if self.checkState(self.stack.outbound, packet) and pLen > 0:
        self.writePacket(self.stack.outbound, packet.payload.load )
    else:
      log.error('the packet is neither inbound nor outbound. You messed up your filter and callbacks.')
    ##self.lock.release()
    return None
    
  def setThread(self,thread):
    ''' the thread using the pipes '''
    self._running_thread=thread
    return 
  
  def writePacket(self,state, payload):
    #if state.name == 'inbound':
    #  log.debug("writePacket%s %d + len: %d = %d"%(state.name, state.byte_count, len(payload), state.byte_count+ len(payload) ) )

    state.byte_count+=self.addPacket(payload,state.write_socket)
    state.packet_count+=1
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

