#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse
import ctypes
import copy
import os
import logging
import pickle
import struct
import sys
import time
import threading
import Queue

# todo : replace by one empty shell of ours
#from paramiko.transport import Transport

import ctypes_openssl
import ctypes_openssh
import output
import haystack 
import network
import utils

from engine import CIPHERS
#our impl
from paramiko_packet import Packetizer, PACKET_MAX_SIZE

log=logging.getLogger('align')



def alignEncryption(way, data):
  '''
  # get data[] in input
  # try to get an offset
  # split to output previous, after
  # the index of the alignement
  '''
  log.debug('trying to align on data')
  blocksize = way.engine.block_size
  # try to find a packetlen
  read_offset = 1 # len(data) # check only start of packet
  #for i in range(0, len(data)-blocksize, len(data) ): # check only start of packet
  for i in range(0, len(data)-blocksize, read_offset ): # check all offsets
    # tests shows Message are often data[blocksize:] 
    log.debug('trying index %d'%(i))
    header = way.engine.decrypt( data[i:i+blocksize] )
    packet_size = struct.unpack('>I', header[:4])[0]
    # reset engine to initial state
    way.engine.sync(way.context)
    if  0 < packet_size <= PACKET_MAX_SIZE:
      log.debug('Auto align done: We found a acceptable packet size(%d) at %d '%(packet_size, i))
      if (packet_size - (blocksize-4)) % blocksize == 0 :
        log.debug('Auto align found : packet size(%d) at %d  '%(packet_size, i))
        # save previous data
        prev = data[:i]
        next = data[i:]
        return prev, next
      else:
        log.debug('bad blocking packetsize %d is not correct for blocksize'%((packet_size - (blocksize-4)) % blocksize))    
    # goto next byte
  return None


from network import Sniffer
from stream  import TCPStream
class PcapFileSniffer2(Sniffer):
  ''' Use scapy's offline mode to simulate network by reading a pcap file.
  '''
  def __init__(self, pcapfile, filterRules='tcp', packetCount=0):
    Sniffer.__init__(self, filterRules=filterRules, packetCount=packetCount)
    self.pcapfile = pcapfile
  def run(self):
    from scapy.all import sniff
    sniff(store=0, prn=self.enqueue, offline=self.pcapfile)
    return
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
    q = Queue.Queue(50000)
    st = TCPStream2(q, connection)
    #save in both directions
    self.streams[(shost,sport,dhost,dport)] = (st,q)
    self.streams[(dhost,dport,shost,sport)] = (st,q)
    return st

class TCPStream2(TCPStream):
  def run(self):
    ''' loops on self.inQueue and calls triage '''
    retry=1
    while self.check():
      try:
        for p in self.inQueue.get(block=True, timeout=1):
          self.triage(p)
          self.inQueue.task_done()
      except Queue.Empty,e:
        if retry > 2:
          break
        retry+=1
        log.debug('Empty queue')
        pass
    self.finish()
    pass


class RawFileDumper:
  def __init__(self, socket, filename):
    self.fout=file(filename,'w')
    self.socket = socket
  
  def process(self):
    #log.debug('Processing stuff')
    ok = True
    while ok:
      data = self.socket.recv(16)
      if data is None or len(data) <= 0:
        raise EOFError('end of stream')
      self.fout.write(data)  
      self.fout.flush()

from openssh import OpenSSHPcapDecrypt

class PrevDecrypt(OpenSSHPcapDecrypt):
  #def __init__(self, pcapfilename, connection, ssfile):
  def run(self):
    ''' launch sniffer and decrypter threads '''
    # capure network before keys
    self._initSniffer()
    self._initStream()
    self._launchStreamProcessing()
    # we can get keys now
    self._initCiphers()
    self._initSSH()
    self._initOutputs()
    self._initWorker()
    self.loop()
    log.info("[+] done %s"%(self))
    return

  def _initSniffer(self):
    self.scapy = PcapFileSniffer2(self.pcapfilename)
    self.scapy.thread = threading.Thread(target=self.scapy.run, )
    #self.scapy.thread.start()
    log.info('[+] read pcap online')

  def _initOutputs(self):
    self.inbound.state.setActiveMode()
    self.outbound.state.setActiveMode()
    self.inbound.filewriter = RawFileDumper(self.inbound.state.getSocket(), 'test1.inbound.raw')
    self.outbound.filewriter =  RawFileDumper(self.outbound.state.getSocket(), 'test1.outbound.raw')
    log.debug('Outputs created')
    return 


class Dummy:
  pass

ssfile=file('test1.ss')
pcapfile='test1.pcap'
connection = Dummy()
connection.local_address = ('::1', 44204)
connection.remote_address = ('::1', 22)


logging.basicConfig(level=logging.DEBUG)
decrypt = PrevDecrypt(pcapfile, connection, ssfile)

decrypt.run()























