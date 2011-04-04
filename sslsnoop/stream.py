#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging, os, socket, sys, time
import multiprocessing

from lrucache import LRUCache

log=logging.getLogger('stream')


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
  ''' declare we are lost in translation '''
  def __init__(self,nb=0):
    self.nb=nb

class BadStateError (Exception):
  pass


class State:
  pass


class TCPState(State):
  ''' TCP state. 
    enqueueRaw is used by TCP Stream to triage packet in one direction.
    STATE SEARCH: packets are then ordered into orderedQueue following a simple TCP seq state machine
    STATE ACTIVE: packets payload are added to the socket in an ordered fashion following a simple TCP seq state machine
    orderedQueue contains ordered packets waiting to be processed
      - at some point, packets data from ordered Queue must be put in write_socket
      - a override can change condition of write.... (decryption testing ?) 
      - setSearchMode() set the state to queue packest
      - setActiveMode() set the state to write packets payload
    write_socket is used to put data from ordered TCP packets.
    read_socket is used by a reader ( Packetizer) to read data in active mode.

  '''
  name = None
  packet_count = 0
  byte_count = 0
  start_seq = None
  max_seq = 0
  expected_seq = 0
  rawQueue = None
  orderedQueue = None
  write_socket = None
  read_socket = None
  ts_missing = None
  # for variable size retransmission
  packets = None
  activeLock = None
  def __init__(self,name):
    self.name=name
    self.rawQueue = {}
    self.orderedQueue = []
    self.packets = LRUCache(1000)
    self.activeLock   = multiprocessing.Lock()
    # make socket UNIX way. non existent in Windows
    read, write = socket.socketpair()
    self.read_socket  = socket.socket(_sock=read) ## useless to get a python object we do not override after all?
    self.write_socket = write

  def _enqueueRaw(self, packet):
    ''' the rawQueue gets all unexpected packets. 
    reodering will happen before adding them to orderedQueue or socket '''
    self.rawQueue[packet.seq]= packet
    return

  def _isMissing(self):
    return not (self.ts_missing is None)
  def _resetMissing(self):
    self.ts_missing = None
  def _setMissing(self):
    self.ts_missing = time.time()


  def _requeue(self):
    ''' Internal func .
        get packets from rawQueue and put them in processing orderedQueue or in socket '''
    queue = self.rawQueue.values()
    queue.sort(key=lambda p: p.seq)
    # add the first and the next that are in perfect suite.
    toadd=[queue.pop(0),]
    for i in xrange(0,len(queue)):
      if toadd[-1].seq+len(toadd[-1].payload) == queue[0].seq :
        toadd.append(queue.pop(0))
      else:
        log.debug('Stop prequeuing  toadd[-1].seq+len(toadd[-1].payload): %d , queue[0].seq: %d'%(toadd[-1].seq+len(toadd[-1].payload) , queue[0].seq ))
        break
    # let remaining in state.queue
    self.rawQueue=dict( [ (p.seq, p) for p in queue])
    # add to output 
    for p in toadd:
      self.addPacket( p )
    log.debug('Prequeued %d packets, remaining %d, queued from %d to %d '%(
                        len(toadd), len(self.rawQueue), toadd[0].seq, (toadd[-1].seq + len(toadd[-1].payload)) 
                        ))
    # reset time counter
    if len(self.rawQueue) > 0:
      self._setMissing()
    else:
      self._resetMissing()
    return

  def _addPacketToOrderedQueue(self, packet ):
    ''' search mode '''
    ''' Ordered packet are added here before their contents gets to socket. '''
    self.orderedQueue.append(packet)
    return cnt

  def _addPacketToSocket(self, packet):
    ''' active mode '''
    self.activeLock.acquire()
    self.byte_count   += self.write_socket.send( packet.payload.load )
    self.packet_count += 1
    self.activeLock.release()
    return True

  def _checkState1(self, packet):
    ''' temp methods to get initial seqnum from first packet '''
    seq = packet.seq    
    ## debug head initialisation
    if self.start_seq is None:
      self.start_seq=seq
      self.expected_seq=seq
      # head done. switch to normal behaviour
      self.checkState = self._checkState
    return self._checkState( packet )
  
  def _checkState(self, packet):
    ''' if packet is expected return True.
        else, add it to queues and return False
    '''
    ## we should not processs empty packets
    payloadLen = len(packet.payload)
    if payloadLen == 0:
      return False

    # packet is expected 
    if seq == self.expected_seq: # JIT
      self.max_seq = seq
      self.expected_seq = seq + payloadLen
      ##self.packets[seq] = packet # debug the packets
      self._resetMissing()
      
      # check if next is already in self.queue , if expected has changed
      self.checkForExpectedPackets()
      return True

    # packet is future
    elif seq > self.expected_seq: 
      # seq is in advance, add it to queue
      self.enqueueRaw(packet)
      #log.debug('Queuing packet seq: %d len: %d %s'%(seq, payloadLen, state))

      # we are waiting for something...
      if not self._isMissing():
        self._setMissing()

      # check if next is already in self.queue 
      self.checkForExpectedPackets()
      #do not add this one, it's maybe already added anyway...
      return False

    # packet is a retranmission 
    elif seq < self.expected_seq:
      # TCP retransmission
      log.debug('TCP retransmit - We just received %d when we already processed %d'%(seq, self.max_seq))
      # never hitted
      if seq+payloadLen > self.expected_seq :
        log.warning(' ***** EXTRA DATA FOUND ON TCP RETRANSMISSION ')
        # we need to recover the extra data to put it in the stream
        nb   = (seq+payloadLen) - self.expected_seq
        data = packet.payload.load[-nb:]
        log.warning('packet seq %d has already been received'%(seq))
        log.warning('recent  packet : %s'%(repr(packet.underlayer) ))
        log.warning('first   packet : %s'%(repr(self.packets[seq].underlayer ) ))
        seq2 = seq+len(self.packets[seq].payload)
        log.warning('first+1 packet : %s'%(repr(self.packets[seq2].underlayer ) ))
        packet.payload.load = data
        log.warning('NEW     packet : %s'%(repr(packet.underlayer) ))
        # updates seq
        self.max_seq = seq
        self.expected_seq = seq2
        # save it
        self.packets[seq]=packet 
        # we can process this (new) one, it's containing only the non-used remains
        return True
      # ignore it, it's a retransmission
      return False
    # else, seq < expected_seq and seq >= self.max_seq. That's not possible... it's current packet.
    # it's a dup already dedupped ? partial fragment ?
    log.warning('received a bogus fragment seq: %d for %s'%(seq, self))
    return True
    
  ################ PUBLIC METHODS 
  ''' check the state of the packet.
  if packet is expected return True.
        else, add it to queues and return False 
  at first, we are expected to find our first seq '''
  checkState = _checkState1
  ''' at first, add to queue. When the state goes into active mode, switch to socket '''
  addPacket = _addPacketToOrderedQueue

  def checkForExpectedPackets(self):
    ''' check for some internal expectation. '''
    ret = False
    ''' time to check the raw queue for expected packets '''
    if self.expected_seq in self.rawQueue : 
      ''' requeue all expected packets to ordered queue '''
      self._requeue()
      ret = True
    # waiting for too long
    elif self._isMissing() and  time.time() > ( self.ts_missing + WAIT_RETRANSMIT) : 
        raise MissingDataException()
    return ret

  def getSocket(self):
    return self.read_socket

  def getFirstPacket(self):
    ''' pop the first packet '''
    if not self.searchMode:
      raise BadStateError('State %s is in Active Mode. Not poping allowed')
    if len(self.orderedQueue) == 0:
      return None
    return self.orderedQueue.pop(0)
  
  def setSearchMode(self):
    self.addPacket = self._addPacketToOrderedQueue
    self.searchMode = True

  def setActiveMode(self, data=None):
    ''' go in active mode.
      all ordered packets will be written to the socket for subsequent use...
      
      WARNING: you should have a thread running on read_socket, otherwise, 
      the socket buffer space will quickly be overflown and this will block on socket.send()
      
    @param data:  some data can be pre-written to the socket  .
    '''
    # stop any data from behing inserted in socket witouht proper timing
    self.activeLock.acquire()
    self.searchMode = False
    self.addPacket = self._addPacketToSocket
    if data is not None:
      log.debug('Prepended %d bytes of data before remaining packets'%(len(data) ) )
      self.byte_count   += self.write_socket.send( data )
      self.packet_count += 1
    # push data
    queue = self.orderedQueue
    self.orderedQueue = []
    for p in queue:
      self.byte_count   += self.write_socket.send( packet.payload.load )
      self.packet_count += 1
    self.activeLock.release()
    # operation can now resume. the socket is active
    return 
    
  def __str__(self):
    return "%s: %d bytes/%d packets max_seq:%d expected_seq:%d q:%d"%(self.name, self.byte_count,self.packet_count,
                self.max_seq,self.expected_seq, len(self.queue))
  
class stack:
  ''' A stream is duplex. '''
  def __init__(self):
    self.inbound=state('inbound')
    self.outbound=state('outbound')
  def __str__(self):
    return "\n%s\n%s"%(self.inbound,self.outbound)
  
class Stream:
  ''' 
    A Stream is a duplex communication.
    
    All packets coming from a scapy socket are triaged here, for both directions.
    
    If the TCPState is in active mode (setActiveMode()) data will be available in the socket.
    
  '''
  worker=None
  def __init__(self, inQueue, connectionTuple, protocolName):
    ''' 
    @param inQueue: packet Queue from socket_scapy   ## from multiprocessing import Process, Queue
    @param connectionTuple: connection Metadata to identify inbound/outbound
    '''
    self.inQueue = inQueue # triage must happen 
    self.connectionTuple = connectionTuple
    self.protocolName = protocolName
    # contains TCP state & packets queue before reordering    
    self.stack=stack()  # duplex context


  def getInbound(self):
    return self.stack.inbound
  
  def getOutbound(self):
    return self.stack.outbound

  def _isInbound(self, packet):
    raise NotImplementedError()
   
  def run(self):
    ''' loops on self.inQueue and calls triage '''
    for p in self.inQueue.get(block=True, timeout=1):
      if p is not None:
        self.triage(p)
      self.checkStop()
    pass

  def triage(self, obj):
    ''' pile packets in the right state machine and call the processing 
      @param obj: the packet
    '''
    # check queues only
    if obj is None:
      self.stack.inbound.checkForExpectedPackets()
      self.stack.outbound.checkForExpectedPackets()
      return None
    
    # triage
    packet=obj[self.protocolName]
    pLen=len(packet.payload)
    if pLen == 0: # ignore acks and stuff 
      return None
    # real triage
    if self._isInbound(packet):
      if self.stack.inbound.checkState( packet ) and pLen > 0:
        self.stack.inbound.addPacket(   packet )
    else:
      if self.stack.outbound.checkState( packet ) and pLen > 0:
        self.stack.outbound.addPacket(   packet )
    return



class TCPStream(Stream):
  ''' Simple subclass for TCP packets '''
  def __init__(self, inQueue, connection ):
    super(Stream).__init__(self, inQueue, connection, protocolName='TCP')

  def _isInbound(self, packet):
    ''' check if the connection metadata corrects '''
    shost,sport = connection.local_address
    return shost == packet.underlayer.src and sport == packet.sport
    

    
    
    
    
def test():
  q = multiprocessing.Queue()
  ct = [connection(fd=9, family=2, type=1, local_address=('192.168.1.100', 41220), remote_address=('74.125.53.125', 5222), status='ESTABLISHED'), connection(fd=8, family=2, type=1, local_address=('192.168.1.100', 33690), remote_address=('69.63.181.105', 5222), status='ESTABLISHED')]

  s = TCPStream(q, )
    
    
    
    
    
    
    
