#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

__doc__ = '''
  Drop OpenSSH session_state.
  
  python code Ready to be freezed by :
  /usr/share/doc/python2.7/examples/Tools/freeze/freeze.py 
     -X apport -X apt -X distutils -X doctest -X pydoc -X paramiko -X scapy -X email 
     -X xml -X unittest -X urllib -X urllib2 -X ssl -X threading -X meliae  -X readline 
     sslsnoop-openssh-dump.py
'''

import sslsnoop
from sslsnoop import ctypes_openssh
import pickle,os, sys, argparse

def argparser():
  parser = argparse.ArgumentParser(prog='sshsnoop', description='Live decription of Openssh traffic.')
  parser.add_argument('--debug', action='store_const', const=True, default=False, help='debug mode')
  parser.add_argument('--quiet', action='store_const', const=True, default=False, help='quiet mode')

  subparsers = parser.add_subparsers(help='sub-command help')
  dump_parser = subparsers.add_parser('dump', help='Dump openssh session_state to a file for later use by offline mode.')
  dump_parser.add_argument('pid', type=int, help='Target PID')
  dump_parser.add_argument('sessionstatefile', type=argparse.FileType('w'), help='Output File for the pickled session_state.')
  dump_parser.set_defaults(func=dumpToFile)
  return parser

def dumpToFile(args):
  from haystack import memory_mapper, abouchet, model
  mappings = memory_mapper.MemoryMapper(args).getMappings() #args.pid /args.memfile
  targetMapping = [m for m in mappings if m.pathname == '[heap]']
  if len(targetMapping) == 0:
    log.warning('No [heap] memorymapping found. Searching everywhere.')
    targetMapping = mappings
  finder = abouchet.StructFinder(mappings, targetMapping)
  outs = finder.find_struct( ctypes_openssh.session_state, maxNum=1) # 1 is awaited
  if len(outs) == 0 :
    log.error('openssh session_state not found')
    return
  ss, addr = outs[0]
  res = ss.toPyObject()
  if model.findCtypesInPyObj(res):
    log.error('=========************======= CTYPES STILL IN pyOBJ !!!! ')
  args.sessionstatefile.write(pickle.dumps(res))
  return
  openssh.main(sys.argv[1:])


def main(argv):
  parser = argparser()
  opts = parser.parse_args(argv)
  opts.func(opts)
  return  

if __name__ == "__main__":
  sys.path.append(os.getcwd())
  main(sys.argv[1:])

