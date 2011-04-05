#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,psutil,sys, time
import openssh, openssl, network
import subprocess

log=logging.getLogger('finder')


class Args:
  pid=None
  memfile=None
  memdump=None
  debug=None

def parseSSL(proc, tcpstream, sniffer):
  args=Args()
  args.pid = proc.pid
  return openssl.search(args)
  



_targets={
    'ssh': openssh.parseSSHClient,
    'ssh-agent': parseSSL,
    'sshd': parseSSL, # sshd a SSL keys too
    #'firefox': []
    }

Processes = []

def buildTuples(targets):
  rets=[]
  for proc in psutil.process_iter():
    if proc.name in targets:
      rets.append( (proc.pid,proc) )
  return rets

    
def pgrep(name):
  pids=[]
  for proc in psutil.process_iter():
    if proc.name == name:
      pids.append(name)
  return pids

def makeFilter(conn):
  # [connection(fd=3, family=2, type=1, local_address=('192.168.1.101', 36386), remote_address=('213.186.33.2', 22), status='ESTABLISHED')]
  pcap_filter = "host %s and port %s and host %s and port %s" %(conn.local_address[0],conn.local_address[1] ,
                            conn.remote_address[0],conn.remote_address[1]  )
  return pcap_filter

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

def getConnectionForPID(pid):
  proc = psutil.Process(pid)
  return checkConnections(proc)

    
def runthread(callable, sniffer, proc,conn):
  if not conn : # ssh-agent
    s1 = None
  else:
    s1 = sniffer.makeStream(conn)
  
  ##from multiprocessing import Process
  ##p = Process(target=s1.run)
  from threading import Thread
  args = (proc, s1, sniffer)
  p = Thread(target=callable, args=args)
  
  p.start()
  Processes.append(p)
  log.info('Thread launched')
  return 
    
def launchScapy():
  from threading import Thread
  sshfilter = "tcp "
  soscapy = network.Sniffer(sshfilter)
  sniffer = Thread(target=soscapy.run)
  soscapy.thread = sniffer
  sniffer.start()
  return soscapy






def main(argv):
  logging.basicConfig(level=logging.INFO)
  #logging.getLogger('model').setLevel(logging.INFO)


  # we must have big privileges...
  if os.getuid() + os.geteuid() != 0:
    log.error("You must be root/using sudo to read memory and sniff traffic. So there's no point in going further")
    return
  
  if not os.access('outputs', os.X_OK) :
    os.mkdir('outputs/')
  
  options=buildTuples(_targets)
  threads=[]
  forked=0
  # get sniffer up
  sniffer = launchScapy()  
  for pid,proc in options:
    log.info("Searching in %s/%d memory"%(proc.name,proc.pid))
    conn = checkConnections(proc)
    if not conn and 'ssh-agent' != proc.name:
      continue
    log.info('Adding this pid to watch list')
    runthread(_targets[proc.name], sniffer, proc,conn)
    
    forked+=1
    log.info('Subprocess launched on pid %d'%(proc.pid))

  for p in Processes:
    p.join()
  time.sleep(5)
  log.info(' ============== %d process forked. look into outputs/ for data '%(forked))
  sys.exit(0)
  return 0


if __name__ == "__main__":
  main(sys.argv[1:])


  
  
  
