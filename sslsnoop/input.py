#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse
import logging
import pickle
import sys
import socket
import threading

import output
import network
import openssh #OpenSSHLiveDecryptatator
from paramiko_packet import Packetizer

log = logging.getLogger('input')


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

class C:
  def __init__(self, src, sport, dst, dport):
    self.local_address = (src,sport)
    self.remote_address = (dst, dport)
    self.status = 'ESTABLISHED'
  def __str__(self):
    return "%s:%d-%s:%d"%(self.local_address[0],self.local_address[1],self.remote_address[0],self.remote_address[1]) 

def writeToSocket(socket_,file_):
  while True:
    data = file_.read(4096)
    if len(data) == 0:
      break
    socket_.send(data)

class sshPcapDecrypt(openssh.OpenSSHLiveDecryptatator):
  ''' decrypt ssh traffic from a dumped session_state and a pcap capture '''
  def __init__(self, pcapfile, connection, ssfile):
    self.ssfile = ssfile
    self.pcapfile = pcapfile
    self.connection = connection
    self.inbound=dict()
    self.outbound=dict()
    self.in_rsocket,self.in_wsocket = socket.socketpair()
    self.out_rsocket,self.out_wsocket = socket.socketpair()
    
  def run(self):
    inst = pickle.load(self.ssfile)
    self.session_state,self.session_state_addr = inst[0]
    self.ciphers = openssh.SessionCiphers(self.session_state)

    if self.ciphers is None:
      raise ValueError('Struct not found')
    # make raw data file and sockets
    self.fin, self.fout = rawFilesFromPcap(self.pcapfile, self.connection, 'raw-%s'%(self.connection))
    # write data fro raw file in socket, using threads..
    self.tin = threading.Thread(target=writeToSocket, args=(self.in_wsocket, self.fin))
    self.tout = threading.Thread(target=writeToSocket, args=(self.out_wsocket, self.fout))
    self.tin.start()
    self.tout.start()
    
    self.init()
    self.loop()
    log.info("done ")
    return

  def init(self):
    ''' plug sockets, packetizer and outputs together '''
    receiveCtx,sendCtx = self.ciphers.getCiphers()
    # Inbound
    log.info('activate INBOUND receive')
    self.inbound['context'] = receiveCtx
    self.inbound['socket'] = self.in_rsocket
    self.inbound['packetizer'] = Packetizer( self.inbound['socket'] )
    self.inbound['packetizer'].set_log(logging.getLogger('inbound.packetizer'))
    self.inbound['engine'] = self.activate_cipher(self.inbound['packetizer'], receiveCtx )
    name = 'ssh-%s'%( openssh.connectionToString(self.connection) )
    self.inbound['filewriter'] =  output.SSHStreamToFile(self.inbound['packetizer'], self.inbound, name)

    # out bound
    log.info('activate OUTBOUND send')
    self.outbound['context'] = sendCtx
    self.outbound['socket'] = self.out_rsocket
    self.outbound['packetizer'] = Packetizer(self.outbound['socket'])
    self.outbound['packetizer'].set_log(logging.getLogger('outbound.packetizer'))
    self.outbound['engine'] = self.activate_cipher(self.outbound['packetizer'], self.outbound['context'] )
    name = 'ssh-%s'%( openssh.connectionToString(self.connection, reverse=True) )
    self.outbound['filewriter'] =  output.SSHStreamToFile(self.outbound['packetizer'], self.outbound, name)
    
    # worker to watch out for data for decryption
    self.worker = output.Supervisor()
    self.worker.add( self.inbound['socket'],  self.inbound['filewriter'].process  )
    self.worker.add( self.outbound['socket'], self.outbound['filewriter'].process )
    return


def dump(args):
  connection = C(args.src,args.sport, args.dst,args.dport)
  fname = 'raw-%s'%(connection)
  args.pcapfile.close()
  dumpPcapToFiles(args.pcapfile.name, connection, fname)


def offline(args):
  connection = C(args.src,args.sport, args.dst,args.dport)
  fname = 'raw-%s'%(connection)
  args.pcapfile.close()
  decrypt = sshPcapDecrypt(args.pcapfile.name, connection, args.sessionstatefile)
  decrypt.run()
  log.info('Decrypt done -- ')

def argparser():
  parser = argparse.ArgumentParser(prog='input', description='Reads a pcapfile to dumps ssh traffic.')
  parser.add_argument('pcapfile', type=argparse.FileType('r'), help='Pcap source file')
  parser.add_argument('src', type=str, help='local host ip')
  parser.add_argument('sport', type=int, help='Source port')
  parser.add_argument('dst', type=str, help='remote host ip')
  parser.add_argument('dport', type=int, help='Destination port')
  parser.add_argument('sessionstatefile', type=argparse.FileType('r'), help='File containing a pickled sessionstate.')
  parser.set_defaults(func=offline)
  return parser


def main(argv):
  logging.basicConfig(level=logging.INFO)
  parser = argparser()
  opts = parser.parse_args(argv)
  try:
    opts.func(opts)
  except ImportError,e:
    log.error('Struct type does not exists.')
    print e

  return 0
  
if __name__ == "__main__":
  main(sys.argv[1:])

