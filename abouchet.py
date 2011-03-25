#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
import subprocess

import ctypes_openssh
import ctypes
#from ctypes import *
from ptrace.ctypes_libc import libc

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings

import argparse,pickle


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
  def __init__(self, pid):
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

  def find_struct(self, struct, hintOffset=None, maxNum = 10, maxDepth=99 , fullScan=False):
    if not fullScan:
      log.warning("Restricting search to heap.")
    outputs=[]
    for m in self.mappings:
      ##debug, most structures are on head
      if not fullScan and m.pathname != '[heap]':
        continue
      if not hasValidPermissions(m):
        log.warning("Invalid permission for memory %s"%m)
        continue
      if fullScan:
        log.info("Looking at %s"%(m))
      else:
        log.debug("%s,%s"%(m,m.permissions))
      log.debug('look for %s'%(struct))
      outputs.extend(self.find_struct_in( m, struct, maxNum=maxNum))
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
        log.info('Found enough instance. returning results. find_struct_in')
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


def _callFinder(cmd_line):
  p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, close_fds=True )
  p.wait()
  instance=p.stdout.read()
  instance=pickle.loads(instance)
  return instance

def findStruct(pid, struct, maxNum=1, fullScan=False):
  ''' '''
  cmd_line=['python', 'abouchet.py', 'search', "%d"%pid, "%s"%struct]
  if fullScan:
    cmd_line.append('--fullscan')
  cmd_line.append('--maxnum')
  cmd_line.append(str(int(maxNum)))
  outs=_callFinder(cmd_line)
  if len(outs) == 0:
    log.error("The %s has not been found."%(struct))
    return None
  #
  return outs

def refreshStruct(pid, struct, offset):
  ''' '''
  cmd_line=['python', 'abouchet.py', 'refresh', "%d"%pid , '%s'%struct, "0x%lx"%offset ]
  instance,validated=_callFinder(cmd_line)
  if not validated:
    log.error("The session_state has not been re-validated. You should look for it again.")
    return None,None
  return instance,offset


def usage(parser):
  parser.print_help()
  sys.exit(-1)


def argparser():
  rootparser = argparse.ArgumentParser(prog='StructFinder', description='Parse memory structs and pickle them.')
  rootparser.add_argument('--string', dest='human', action='store_const', const=True, help='Print results as human readable string')
  
  subparsers = rootparser.add_subparsers(help='sub-command help')
  search_parser = subparsers.add_parser('search', help='search help')
  search_parser.add_argument('pid', type=int, help='Target PID')
  search_parser.add_argument('structType', type=str, help='Structure type name')
  search_parser.add_argument('--fullscan', action='store_const', const=True, default=False, help='do a full memory scan, otherwise, restrict to the heap')
  search_parser.add_argument('--maxnum', type=int, action='store', default=1, help='Limit to maxnum numbers of results')
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
  outs=finder.find_struct( structType, maxNum=args.maxnum, fullScan=args.fullscan)
  if args.human:
    print '[',
    for ss, addr in outs:
      print "# --------------- 0x%lx \n"% addr, ss.toString()
      pass
    print ']'
  else:
    ret=[ (ss.toPyObject(),addr) for ss, addr in outs]
    print pickle.dumps(ret)
  return outs


def refresh(args):
  pid=int(args.pid)
  addr=int(args.addr,16)
  structType=getKlass(args.structType)

  finder = StructFinder(pid)  
  instance,validated = finder.loadAt(addr, structType)
  if validated:
    if args.human:
       print '( %s, %s )'%(instance.toString(),validated)
    else:
      d=(instance.toPyObject(),validated)
      print pickle.dumps(d)
  else:
    if args.human:
      #Unloaded datastruct, printing safe __str__
      print '( %s, %s )'%(instance,validated)
    else:
      d=None
      print pickle.dumps(d)
  return instance,validated

def test():
  import subprocess
  cmd_line=['python', 'abouchet.py', 'refresh', '2442', 'ctypes_openssh.session_state', '0xb822a268']
  p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, close_fds=True )
  p.wait()
  instance=p.stdout.read()
  instance=eval(instance)
  return instance


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

def a():
  argv=[ 'refresh', '28573', 'ctypes_openssh.session_state', '0xb9116268']
  parser = argparser()
  opts = parser.parse_args(argv)
  ret=opts.func(opts)
  return ret

