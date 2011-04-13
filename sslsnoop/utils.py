#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging
import pickle
import sys
import socket
import threading

import argparse
import psutil

import output
import network
import openssh #OpenSSHLiveDecryptatator
from paramiko_packet import Packetizer

log = logging.getLogger('utils')



def connectionToString(connection, reverse=False):
  log.debug('make a string for %s'%(repr(connection)))
  if reverse:
    return "%s:%d-%s:%d"%(connection.remote_address[0],connection.remote_address[1], connection.local_address[0],connection.local_address[1]) 
  else:
    return "%s:%d-%s:%d"%(connection.local_address[0],connection.local_address[1],connection.remote_address[0],connection.remote_address[1]) 

def getConnectionForPID(pid):
  proc = psutil.Process(pid)
  return checkConnections(proc)

def checkConnections(proc):
  conns=proc.get_connections()
  conns = [ c for c in conns if c.status == 'ESTABLISHED']
  if len(conns) == 0 :
    return False
  elif len(conns) > 1 :
    log.warning(' %s has more than 1 connection ?'%(proc.name))
    return False
  elif conns[0].status != 'ESTABLISHED' :
    log.warning(' %s has no ESTABLISHED connections (1 %s)'%(conn[0].status))
    return False
  log.info('Found connection %s for %s'%(conns[0], proc.name))
  return conns[0]

class Connection:
  ''' Mimic psutils connection class '''
  def __init__(self, src, sport, dst, dport):
    self.local_address = (src,sport)
    self.remote_address = (dst, dport)
    self.status = 'ESTABLISHED'
  def __str__(self):
    return "%s:%d-%s:%d"%(self.local_address[0],self.local_address[1],self.remote_address[0],self.remote_address[1]) 



def launchScapy():
  from threading import Thread
  sshfilter = "tcp "
  soscapy = network.Sniffer(sshfilter)
  sniffer = Thread(target=soscapy.run)
  soscapy.thread = sniffer
  sniffer.start()
  return soscapy





def dumpPcapToFiles(pcapfile, connection, fname='raw'):
  # create the pcap reader
  soscapy = network.PcapFileSniffer(pcapfile)
  sniffer = threading.Thread(target=soscapy.run, name='scapy')
  soscapy.thread = sniffer
  # create output engines
  stream = soscapy.makeStream( connection ) 
  # prepare them
  stream.getInbound().setActiveMode()
  stream.getOutbound().setActiveMode()
  in_s = stream.getInbound().getSocket()
  out_s = stream.getOutbound().getSocket()
  win = output.RawPacketsToFile(in_s, fname+'-in.raw')
  wout = output.RawPacketsToFile(out_s, fname+'-out.raw')
  # make thread for all that
  st = threading.Thread(target=stream.run, name='stream')
  st.start()
  win_th = threading.Thread(target=win.run, name='inbound data writer')
  wout_th = threading.Thread(target=wout.run, name='outbound data writer')
  win_th.start()
  wout_th.start()
  # launch scapy and start the dumping
  sniffer.start()
  # wait for them
  for t in [sniffer, st, win_th, wout_th]:
    log.debug('waiting for %s'%(t.name))
    t.join()
    in_s.close()  
  return (fname+'-in.raw', fname+'-out.raw')


def rawFilesFromPcap(pcapfile, connection, fname='raw'):
  fin,fout = dumpPcapToFiles(pcapfile, connection, fname='raw')
  return file(fin), file(fout)


def writeToSocket(socket_,file_):
  while True:
    data = file_.read(4096)
    if len(data) == 0:
      break
    socket_.send(data)



def dump(args):
  connection = Connection(args.src,args.sport, args.dst,args.dport)
  fname = 'raw-%s'%(connection)
  args.pcapfile.close()
  dumpPcapToFiles(args.pcapfile.name, connection, fname)


def offline(args):
  connection = Connection(args.src,args.sport, args.dst,args.dport)
  fname = 'raw-%s'%(connection)
  args.pcapfile.close()
  decrypt = openssh.OpenSSHPcapDecrypt(args.pcapfile.name, connection, args.sessionstatefile)
  decrypt.run()
  log.info('Decrypt done -- ')




