#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
#use volatility?

import ctypes_openssh
import ctypes
#from ctypes import *
from ptrace.ctypes_libc import libc

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

import argparse


log=logging.getLogger('abouchet')
MAX_KEYS=255

verbose = 0


class FileWriter:
  def __init__(self,prefix,suffix,folder):
    self.prefix=prefix
    self.suffix=suffix
    self.folder=folder
  def get_valid_filename(self):
    filename_FMT="%s-%d.%s"
    for i in range(1,MAX_KEYS):
      filename=filename_FMT%(self.prefix,i,self.suffix)
      afilename=os.path.normpath(os.path.sep.join([self.folder,filename]))
      if not os.access(afilename,os.F_OK):
        return afilename
    #
    log.error("Too many file keys extracted in %s directory"%(self.folder))
    return None    
  def writeToFile(self,instance):
    raise NotImplementedError



class StructFinder:
  ''' Generic tructure mapping '''
  def __init__(self, pid, fullScan=False):
    self.fullScan=fullScan
    self.dbg = PtraceDebugger()
    self.process = self.dbg.addProcess(pid,is_attached=False)
    if self.process is None:
      log.error("Error initializing Process debugging for %d"% pid)
      raise IOError
      # ptrace exception is raised before that
    tmp = readProcessMappings(self.process)
    self.mappings=[]
    for i in range(0,len(tmp)):
      if tmp[i].pathname == '[heap]':
        self.mappings.append(tmp.pop(i))
        break
    self.mappings.extend(tmp)

  def find_struct(self, struct, hintOffset=None, maxNum = 10, maxDepth=99 ):
    if not self.fullScan:
      log.warning("Restricting search to heap.")
    outputs=[]
    for m in self.mappings:
      ##debug, most structures are on head
      if not self.fullScan and m.pathname != '[heap]':
        continue
      if not hasValidPermissions(m):
        log.warning("Invalid permission for memory %s"%m)
        continue
      if self.fullScan:
        log.info("Looking at %s"%(m))
      else:
        log.debug("%s,%s"%(m,m.permissions))
      log.debug('look for %s'%(struct))
      outputs.extend(self.find_struct_in( m, struct, maxNum))
      # check out
      if len(outputs) >= maxNum:
        log.info('Found enough instance. returning results.')
        break
    # if we mmap, we could yield
    return outputs

  def find_struct_in(self, memoryMap, struct, hintOffset=None, maxNum=10, maxDepth=99 ):
    '''
      Looks for struct in memory, using :
        hints from struct (default values, and such)
        guessing validation with instance(struct)().isValid()
        and confirming with instance(struct)().loadMembers()
      
      returns POINTERS to struct.
    '''

    # update process mappings
    log.debug("scanning 0x%lx --> 0x%lx %s"%(memoryMap.start,memoryMap.end,memoryMap.pathname) )

    # where do we look  
    start=memoryMap.start  
    end=memoryMap.end
    plen=ctypes.sizeof(ctypes.c_char_p) # use aligned words only
    structlen=ctypes.sizeof(struct)
    #ret vals
    outputs=[]
    # alignement
    if hintOffset in memoryMap:
      align=hintOffset%plen
      start=hintOffset-plen
     
    # parse for struct on each aligned word
    log.debug("checking 0x%lx-0x%lx by increment of %d"%(start, (end-structlen), plen))
    instance=None
    for offset in range(start, end-structlen, plen):
      instance,validated=self.loadAt( offset, struct, maxDepth)
      if validated:
        log.debug( "found instance @ 0x%lx"%(offset) )
        # do stuff with it.
        outputs.append( (instance,offset) )
      if len(outputs) >= maxNum:
        log.info('Found enough instance. returning results.')
        break
    return outputs

  def loadAt(self, offset, struct, depth=99 ):
    log.debug("Loading %s from 0x%lx "%(struct,offset))
    instance=struct.from_buffer_copy(self.process.readStruct(offset,struct))
    # check if data matches
    if ( instance.loadMembers(self.process, self.mappings, depth) ):
      log.info( "found instance %s @ 0x%lx"%(struct,offset) )
      # do stuff with it.
      validated=True
    else:
      log.debug("Address not validated")
      validated=False
    return instance,validated

def hasValidPermissions(memmap):
  ''' memmap must be 'rw..' or shared '...s' '''
  perms=memmap.permissions
  return (perms[0] == 'r' and perms[1] == 'w') or (perms[3] == 's')

def usage(parser):
  parser.print_help()
  sys.exit(-1)


def argparser():
  rootparser = argparse.ArgumentParser(prog='StructFinder', description='Parse memory structs.')
  subparsers = rootparser.add_subparsers(help='sub-command help')
  search_parser = subparsers.add_parser('search', help='search help')
  search_parser.add_argument('pid', type=int, help='Target PID')
  search_parser.add_argument('structType', type=str, help='Structure type name')
  search_parser.set_defaults(func=search)
  #
  refresh_parser = subparsers.add_parser('refresh', help='refresh help')
  refresh_parser.add_argument('pid', type=int, help='Target PID')
  refresh_parser.add_argument('structType', type=str, help='Structure type name')
  refresh_parser.add_argument('addr', type=str, help='Structure memory address')
  refresh_parser.set_defaults(func=refresh)
  #
  return rootparser


def getKlass(name):
  module,sep,kname=name.rpartition('.')
  mod = __import__(module, globals(), locals(), [kname])
  klass = getattr(mod, kname)
  return klass

def search(args):
  pid=int(args.pid)
  structType=getKlass(args.structType)

  finder = StructFinder(pid)  
  outs=finder.find_struct( structType, maxNum=1)
  for ss, addr in outs:
    pass
  #s=['0x%lx,'.join()
  return


def refresh(args):
  pid=int(args.pid)
  addr=int(args.addr,16)
  structType=getKlass(args.structType)

  finder = StructFinder(pid)  
  instance,validated = finder.loadAt(addr, structType)
  print instance.toString()
  return

def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.debug(argv)
  
  parser = argparser()
  opts = parser.parse_args(argv)
  try:
    opts.func(opts)
  except ImportError,e:
    log.error('Struct type does not exists.')
    print e
  
  log.info("done for pid %d"%opts.pid)
  return 0


if __name__ == "__main__":
  main(sys.argv[1:])

