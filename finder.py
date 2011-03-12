#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,psutil

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
      rets.append( (proc.pid,proc.name,targets[proc.name]) )
  return rets

    
def pgrep(name):
  pids=[]
  for proc in psutil.process_iter():
    if proc.name == name:
      pids.append(name)
  return pids


def usage(txt):
  log.error("Usage : %s <pid of ssh>"% txt)
  sys.exit(-1)


def main(argv):
  logging.basicConfig(level=logging.INFO)
  #logging.getLogger('model').setLevel(logging.INFO)

  if ( len(argv) != 1 ):
    usage(argv[0])
    return

  # we must have big privileges...
  if os.getuid() + os.geteuid() != 0:
    log.error("You must be root/using sudo to read memory and sniff traffic. So there's no point in going further")
    return
    
  options=buildTuples(_targets)

  for pid,name,func in options:
    status=func(pid,name) 
    lof.info(status)

  sys.exit(0)
  return 0


if __name__ == "__main__":
  main(sys.argv[1:])


  
  
  
