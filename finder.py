#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,psutil,sys
import openssh
import ptrace

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
      rets.append( (proc.pid,proc.name,targets[proc.name]) )
  return rets

    
def pgrep(name):
  pids=[]
  for proc in psutil.process_iter():
    if proc.name == name:
      pids.append(name)
  return pids


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
    
  options=buildTuples(_targets)

  for pid,name,func in options:
    try:
      log.info("Searching in %s/%d memory"%(name,pid))
      status=func(pid,name) 
      log.info(status)
    except ptrace.error.PtraceError,e:
      log.warning("%s/%d not ptraceable"%(name,pid))
      continue      

  sys.exit(0)
  return 0


if __name__ == "__main__":
  main(sys.argv[1:])


  
  
  
