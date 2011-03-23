#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys,time,io,select
import threading
from threading import Thread

from paramiko_packet import NeedRekeyException
from paramiko.ssh_exception import SSHException
from paramiko.common import *

log=logging.getLogger('output')



class SSHStreamToFile():
  ''' Pipes the data from a (ssh) socket into a different file for each packet type. 
    supposedly, this would demux channels into files.
    We still need to differenciate at higher level, with two SSHStreamFile
     between upload and download.
  '''
  BUFSIZE=4096
  def __init__(self, packetizer, engine, basename, folder='outputs', fmt="%Y%m%d-%H%M%S"):
    self.packetizer = packetizer
    #self.refresher = refresher
    self.datename = "%s"%time.strftime(fmt,time.gmtime())
    self.fname=os.path.sep.join([folder,basename])
    self.outs=dict()
    self.engine=engine
    ##
    self.lastMessage=None
    return

  def process(self):
    data=self._in.read(self.BUFSIZE)
    self._out.write(data2)
  
  def _outputStream(self, channel):
    name="%s.%s.%d"%(self.fname, self.datename, channel )
    if name in self.outs:
      return self.outs[name]
    else:
      self.outs[name] = io.FileIO(name , 'w' )
      log.info("New Output Filename is %s"%(name))
    log.debug("Output Filename is %s"%(name))
    return self.outs[name]

  def process(self):
    ''' m can be rewind()-ed , __str__ ()-ed or others...
  '''
    _expected_packet = tuple()
    try:
      ptype, m = self.packetizer.read_message()
      self.lastMessage=m
      #log.error("now  message was (%d) : %s"%(len(str(m)),repr(str(m))) )
      self.lastCounter=self.engine.getCounter()
      if ptype != 94:
        log.warning("===================== ptype:%d len:%d "%(ptype, len(str(m)) ) )
    except NeedRekeyException:
      log.warning('=============================== Please refresh keys for rekey')
      return
    except SSHException,e:
      log.warning('SSH exception catched on %s - %s'%(self.fname,e))
      ## doesn't work, it's not that...
      ## drop block, decrement counter, and get next one...
      #self.engine.decCounter()
      ##return # drop block
      
      print self.packetizer
      m=self.lastMessage
      c=self.lastCounter
      log.error("last counter was : %s"%(c) )
      log.error("last message was (%d) : %s"%(len(str(m)),repr(str(m))) )
      log.error("last counter was : %s"%( self.engine.getCounter() ) )
      os.kill(os.getpid())
      sys.exit()
      raise e
      #self.refresher.refresh()
      return
    except OverflowError,e:
      log.warning('SSH exception catched/bad packet size on %s'%(self.fname))
      #self.refresher.refresh()
      return
    if ptype == MSG_IGNORE:
      log.warning('================================== MSG_IGNORE')
      return
    elif ptype == MSG_DISCONNECT:
      log.info( "==================================== DISCONNECT MESSAGE")
      log.info( m)
      self.packetizer.close()
      return
    elif ptype == MSG_DEBUG:
      always_display = m.get_boolean()
      msg = m.get_string()
      lang = m.get_string()
      log.warning('Debug msg: ' + util.safe_string(msg))
      return
    if len(_expected_packet) > 0:
      if ptype not in _expected_packet:
        raise SSHException('Expecting packet from %r, got %d' % (_expected_packet, ptype))
      _expected_packet = tuple()
      if (ptype >= 30) and (ptype <= 39):
        log.info("KEX Message, we need to rekey")
        return
    #
    out=self._outputStream(ptype)
    ret=out.write( str(m) )
    out.flush() # beuahhh
    log.debug("%d bytes written for channel %d"%(ret, ptype))
    return

  
class Supervisor(threading.Thread):
  def __init__(self ):
    self.stopSwitch=threading.Event()
    self.readables=dict()
    self.selectables=set()
    self._readables=dict()
    self._selectables=set()
    self.lock=threading.Lock()
    self.todo=False
    return
  
  def add(self, socket, handler):
    '''
      @param soket: the socket to select() onto  
      @param handler: the callable to run when data arrives.
    '''
    self.lock.acquire()
    self.readables[socket] = handler
    self.selectables.add(socket)
    self.todo=True
    self.lock.release()
    return 

  def _syncme(self):
    self.lock.acquire()
    self._readables = dict(self.readables)
    self._selectables = set(self.selectables)
    self.todo=False
    self.lock.release()
    return 

  def run(self):
     # thread inbound reads and writes  
    while not self.stopSwitch.isSet():
      # check
      if self.todo:
        self._syncme
      r,w,o=select.select(self.selectables,[],[],2)
      if len(r) == 0:
        log.debug("select waked up without anything to read... going back to select()")
        continue
      # read them and write them
      for soket in r:
        self.readables[soket]()
        log.debug("read and write done for %s"%(soket))
      #loop
    log.info('Supervisor finished running') 
    return


