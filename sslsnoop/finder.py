#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,psutil,sys, time
import openssh
import subprocess

log=logging.getLogger('finder')

_targets={
    'ssh': openssh.parseSSHClient,
    'sshd': openssh.parseSSHServer,
    'ssh-agent': openssh.parseSSHAgent,
    #'firefox': []
    }


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
  if len(conns) == 0 :
    return False
  elif len(conns) > 1 :
    if proc.name == 'sshd':
      estab = [ c for c in conns if c.status == 'ESTABLISHED'] 
      log.info('Found %d connections for %s'%(len(estab), proc.name))
      return ' or '.join(makeFilter(estab))
    log.warning(' %s has more than 1 connection ?'%(proc.name))
    return False
  elif conns[0].status != 'ESTABLISHED' :
    log.warning(' %s has noESTABLISHED connections (1 %s)'%(conn[0].status))
    return False
  # else ok for ssh
  f=makeFilter(conns[0])
  log.info('Found connection %s for %s'%(conns[0], proc.name))
  return f

def usage(txt):
  log.error("Usage : %s "% txt)
  sys.exit(-1)


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
  for pid,proc in options:
    log.info("Searching in %s/%d memory"%(proc.name,proc.pid))
    pcap_filter = checkConnections(proc)
    if not pcap_filter and not 'ssh-agent' == proc.name:
      continue
    # call cb
    if (os.fork() == 0):
      _targets[proc.name](proc, pcap_filter)
      sys.exit(0)
      break
    forked+=1
    log.info('Subprocess launched on pid %d'%(proc.pid))

  time.sleep(5)
  log.info(' ============== %d process forked. look into outputs/ for data '%(forked))
  sys.exit(0)
  return 0


if __name__ == "__main__":
  main(sys.argv[1:])


  
  
  
