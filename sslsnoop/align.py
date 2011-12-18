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

from sslsnoop import openssh
from sslsnoop import ctypes_openssl
from sslsnoop import ctypes_openssh
import output
import haystack 
import network
import utils
import openssh

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
  log.info('trying to align on data ')
  blocksize = way.engine.block_size
  # try to find a packetlen
  read_offset = 1 # len(data) # check only start of packet
  #for i in range(0, len(data)-blocksize, len(data) ): # check only start of packet
  for i in range(0, len(data)-blocksize, read_offset ): # check all offsets
    # tests shows Message are often data[blocksize:] 
    log.debug('trying index %d'%(i))
    header = way.engine.decrypt( data[i:i+blocksize] )
    #log.debug('after align  decrypt %s'%repr(way.engine.getCounter()))
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


def rfindAlign(way, data):
  ''' find alignement backwards
    we need to backtrack from  prev_i = (index-blocksize)-- # smallest packet is at least mac_len+int_size+padding
    with counter = counter-2 ( // block_size) // counter-1 is useless when > 16
        smallest case scenarios packet_size = 28, 12 for disconnects ? 
        And this is only to find a valid packet_size
    and find a value x for which  x+prev_i < index # packet_size is not in clear stoupid..
  '''
  log.debug('trying to backwards align on data ')
  blocksize = way.engine.block_size
  # try to find a packetlen
  read_offset = 1 # len(data) # check only start of packet

  # reset engine to initial state
  way.engine.sync(way.context)
  # save current counter
  lastGoodCounter = way.engine.counter
  lastGoodIndex = len(data)

  log.debug('orig counter:')
  log.debug(repr(way.engine.getCounter()))
  log.debug('backwards counters:')
  
  #for i in range(0, len(data)-blocksize, len(data) ): # check only start of packet
  #for i in range(len(data)-blocksize, -1 , -1 ): # check all offsets
  i = len(data)
  while i>0:

    ## STEP 1 : prepare counter backwards 2 (packet_size+) 
    ## # possible corner case, if no packet payload, only one decCounter should be needed ( disconnections ?? )
    ## # test1 : if index-prev_i < mac_len + 4 + 12(padding), test with simple decCounter
    ## # lets ignore that for now

    # reset engine ctr to previous iteration and decrease counter 2 times
    way.engine.counter = (ctypes.c_ubyte*blocksize).from_buffer_copy( lastGoodCounter )
    way.engine.decCounter()
    way.engine.decCounter()
    log.debug('after decCounter %s'%repr(way.engine.getCounter()))
    counter = (ctypes.c_ubyte*blocksize).from_buffer_copy( way.engine.counter )

    ## STEP 2 : test all offset for a valid packet_size
    for i in range(lastGoodIndex-blocksize, -1 , -1 ): # check all offsets ( -blocksize+4 ?)
      header = way.engine.decrypt( data[i:i+blocksize] ) # read from end to start
      #log.debug('after    decrypt %s'%repr(way.engine.getCounter()))
      packet_size = struct.unpack('>I', header[:4])[0]
      if  0 < packet_size <= PACKET_MAX_SIZE:
        log.debug('Auto align done: We found a acceptable packet size(%d) at %d '%(packet_size, i))
        if (packet_size - (blocksize-4)) % blocksize == 0 :
          log.debug('Auto align found : packet size(%d) at %d  '%(packet_size, i))
          # save previous data
          lastGoodIndex = i
          lastGoodCounter = (ctypes.c_ubyte*blocksize).from_buffer_copy(counter)     # save current counter for next iteration
          break # go to search the previous packet
        else:
          log.debug('bad blocking packetsize %d is not correct for blocksize'%((packet_size - (blocksize-4)) % blocksize))    
      ##
      #if i < len(data) - 200:
      #  log.warning('breaking out')
      #  return -1
      # clean and reset
      way.engine.counter = (ctypes.c_ubyte*blocksize).from_buffer_copy( counter )

  if lastGoodIndex == len(data):
    return -1, None
  return lastGoodIndex, lastGoodCounter



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
    self.worker.pleaseStop()
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
    self.inbound.filewriter = RawFileDumper(self.inbound.state.getSocket(), '%s.inbound.raw'%(self.pcapfilename))
    self.outbound.filewriter =  RawFileDumper(self.outbound.state.getSocket(), '%s.outbound.raw'%(self.pcapfilename))
    log.debug('Outputs created')
    return 


class Dummy:
  pass



BUFSIZE = 4096
class SimpleBufferSocket():
  def __init__(self, buf):
    self.buf = buf
    self.offset = 0
    self.closed = False

  def recv(self, n = BUFSIZE):
    if self.closed:
      raise IOError()
    ret = self.buf[self.offset:self.offset+n]
    self.offset += len(ret)
    return ret

  def close(self):
    self.closed = True

class FakeState():
  def __init__(self, buf):
    self.socket = SimpleBufferSocket(buf)

  def getSocket(self):
    return self.socket


def decrypt(engine, data, block_size, mac_len):
  #logging.getLogger('align').setLevel(logging.DEBUG)
  #logging.getLogger('engine').setLevel(logging.DEBUG)
  i = 0
  ret = ''
  remainder=''
  while i < len(data):

    #log.debug('read %d i:%d : \n header = %s'%(block_size,i, repr(data[i:i+block_size])))
    tmp = engine.decrypt( data[i:i+block_size] )
    i += block_size
    packet_size = struct.unpack('>I', tmp[:4])[0]
    if packet_size > 35000:
      raise ValueError(packet_size)

    ret += tmp[:4]

    #log.debug('read packet_size %d i:%d'%(packet_size,i))
    leftover = tmp[4:]

    #log.debug('read packet (%d+%d-%d)=%d i:%d \n body = %s'%(packet_size, mac_len, len(leftover), 
    #          packet_size+mac_len-len(leftover), i , repr(data[i:i+packet_size+mac_len-len(leftover)]) ))
    packet = engine.decrypt( data[i:i+packet_size-len(leftover)] ) # do not decrypt +mac_len
    i += packet_size+mac_len-len(leftover)  # but we read +mac_len

    packet = leftover+packet
    padding = ord(packet[0])
    #log.debug('padding %d'%(padding))
    #payload = packet[1:packet_size - padding]
    #ret += packet[1+4+4+1:-padding]  # content only

    log.debug('read packet_size:%d padding:%d mac:%d total:%d'%(packet_size,padding, mac_len, packet_size+mac_len+padding ))

    ret += packet
  return ret


def parseProtocol(way, data_clear, outfilename):
  way.state = FakeState(data_clear)
  way.packetizer = Packetizer( way.state.getSocket() )
  way.packetizer.set_log(logging.getLogger('packetizer'))
  logging.getLogger('packetizer').setLevel(logging.DEBUG)
  #use a null block_engine
  way.packetizer.set_inbound_cipher(None, way.context.block_size, None, way.context.mac.mac_len , None)
  if way.context.comp.enabled != 0:
    from paramiko.transport import Transport
    name = way.context.comp.name
    compress_in = Transport._compression_info[name][1]
    way.packetizer.set_inbound_compressor(compress_in())
  # use output stream
  ssh_decrypt = output.SSHStreamToFile(way.packetizer, way, '%s.clear'%outfilename, folder=".", fmt='%Y')
  try:
    way.engine.sync(way.context)
    while True:
      ssh_decrypt.process()
  except EOFError,e:
    log.warning('offset in socket %d'%(way.state.getSocket().offset))
    pass

def dec(way, basename):
  rawfilename = '%s.raw'%(basename)
  postfilename = '%s.post.dec'%(basename)
  prevfilename = '%s.prev.dec'%(basename)

  attachEngine(way)

  # open the raw file
  prev, post = alignEncryption(way, file(rawfilename).read())
  index = len(prev)
  log.info('Memdump was done at index %d with cipher %s'%(index, way.context.name))

  # decrypt the next part to file
  way.engine.sync(way.context)
  fout = file('%s.raw'%postfilename,'w')
  data_clear = decrypt( way.engine, post , way.context.block_size, way.context.mac.mac_len )
  fout.write(data_clear)
  fout.close()
  log.info('POST memdump - decryption completed in %s'%(fout.name))
  packet_size = struct.unpack('>I', data_clear[:4])[0]
  padding_l = struct.unpack('>b', data_clear[4:5])[0]
  cmd = struct.unpack('>b', data_clear[5:6])[0]
  log.info('after decrypt packet_size:%d padding_l:%d cmd:%d'%(packet_size,padding_l,cmd) )
  
  # parse the ssh protocol
  parseProtocol(way, data_clear, postfilename)  


  # rfind backwards alignement with counter in the prev part
  prev_index, prev_counter = rfindAlign(way, prev)
  if prev_index == -1:
    log.info('could not go backwards')
  else:
    log.info('Last good index is %d'%(prev_index))
    fakecontext = Dummy()
    fakecontext.__dict__ = dict(way.context.__dict__)
    way.engine.sync(fakecontext)
    way.engine.counter = prev_counter
    fout = file('%s.raw'%prevfilename,'w')
    data_clear = decrypt( way.engine, prev[prev_index:] , way.context.block_size, way.context.mac.mac_len )
    fout.write(data_clear)
    fout.close()
    log.info('PREV memdump - decryption completed in %s'%(fout.name))

  logging.getLogger('align').setLevel(logging.DEBUG)
  logging.getLogger('engine').setLevel(logging.DEBUG)

  # parse the ssh protocol
  parseProtocol(way, data_clear, prevfilename)  

  return

def attachEngine(way):
  way.engine = openssh.CIPHERS[way.context.name](way.context) 



logging.basicConfig(level=logging.INFO)
logging.getLogger('align').setLevel(logging.INFO)
logging.getLogger('engine').setLevel(logging.INFO)

ssfilename='test1.ss'
pcapfilename='test1.pcap'
connection = Dummy()
connection.remote_address = ('::1', 44204)
connection.local_address = ('::1', 22)

## work for separating streams
##decryptor = PrevDecrypt(pcapfilename, connection, file(ssfilename))
##decryptor.run()

#import sys
#sys.exit()

inbound = Dummy()
outbound = Dummy()

ss = openssh.SessionCiphers(pickle.load( file(ssfilename))[0][0])
inbound.context, outbound.context = ss.getCiphers()

base_in = '%s.inbound'%(pcapfilename)
base_out = '%s.outbound'%(pcapfilename)



dec(inbound, base_in)

#dec(decrypt.outbound, base_out)

















