#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import argparse, logging, os, pickle, sys, time, ctypes
import subprocess

import model

# linux only ?
from ptrace.debugger.debugger import PtraceDebugger
# ptrace fork
from memory_mapping import readProcessMappings, MemoryDumpMemoryMapping

log=logging.getLogger('haystack')



class StructFinder:
  ''' Generic tructure mapping '''
  def __init__(self, pid=None, mmap=False, memdump=None):
    if pid is None and memdump is None:
      raise ValueError('You have to choose pid or dumpfile')
    if not (pid is None) and not (memdump is None):
      raise ValueError('You have to choose pid or dumpfile')
    if not (pid is None):
      self.initPid(pid,mmap)
    elif not (memdump is None):
      self.initMemdump(memdump)

  def initMemdump(self,memdump):
    mem = MemoryDumpMemoryMapping(memdump, 0, os.fstat(memdump.fileno()).st_size) ## is that valid ?
    self.mappings=[mem]
  
  def initPid(self,pid, mmap):
    self.dbg = PtraceDebugger()
    self.process = self.dbg.addProcess(pid,is_attached=False)
    if self.process is None:
      log.error("Error initializing Process debugging for %d"% pid)
      raise IOError
      # ptrace exception is raised before that
    tmp = readProcessMappings(self.process)
    self.mappings=[]
    remains=[]
    t0=time.time()
    for m in tmp :
      if mmap:
        ### mmap memory in local space
        m.mmap()
        #log.warning('mmap() : %d'%(len(m.local_mmap)))
      if ( m.pathname == '[heap]' or 
           m.pathname == '[vdso]' or
           m.pathname == '[stack]' or
           m.pathname is None ):
        self.mappings.append(m)
        continue
      remains.append(m)
    #tmp = [x for x in remains if not x.pathname.startswith('/')] # delete memmapped dll
    tmp=remains
    tmp.sort(key=lambda x: x.start )
    tmp.reverse()
    self.mappings.extend(tmp)
    self.mappings.reverse()
    if mmap:
      ### mmap done, we can release process...
      self.process.cont()
      log.info('Memory mmaped, process released after %02.02f secs'%(time.time()-t0))

  def find_struct(self, struct, hintOffset=0, maxNum = 10, maxDepth=10 , fullScan=False):
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
        log.info("Looking at %s (%d bytes)"%(m, m.end-m.start))
      else:
        log.debug("%s,%s"%(m,m.permissions))
      log.debug('look for %s'%(struct))
      outputs.extend(self.find_struct_in( m, struct, hintOffset=hintOffset, maxNum=maxNum, maxDepth=maxDepth))
      # check out
      if len(outputs) >= maxNum:
        log.info('Found enough instance. returning results.')
        break
    # if we mmap, we could yield
    return outputs

  def find_struct_in(self, memoryMap, struct, hintOffset=0, maxNum=10, maxDepth=99 ):
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
    plen=ctypes.sizeof(ctypes.c_void_p) # use aligned words only
    structlen=ctypes.sizeof(struct)
    #ret vals
    outputs=[]
    # alignement
    if hintOffset in memoryMap: # absolute offset
      align=hintOffset%plen
      start=hintOffset-align
    elif hintOffset != 0 and hintOffset  < end-start: # relative offset
      align=hintOffset%plen
      start=start+ (hintOffset-align)
     
    # parse for struct on each aligned word
    log.debug("checking 0x%lx-0x%lx by increment of %d"%(start, (end-structlen), plen))
    instance=None
    import time
    t0=time.time()
    p=0
    for offset in xrange(start, end-structlen, plen):
      if offset % (1024<<6) == 0:
        p2=offset-start
        log.info('processed %d bytes  - %02.02f test/sec'%(p2, (p2-p)/(plen*(time.time()-t0)) ))
        t0=time.time()
        p=p2
      instance,validated= self.loadAt( memoryMap, offset, struct, maxDepth) 
      if validated:
        log.debug( "found instance @ 0x%lx"%(offset) )
        # do stuff with it.
        outputs.append( (instance,offset) )
      if len(outputs) >= maxNum:
        log.info('Found enough instance. returning results. find_struct_in')
        break
    return outputs


  def loadAt(self, memoryMap, offset, struct, depth=99 ):
    log.debug("Loading %s from 0x%lx "%(struct,offset))
    instance=struct.from_buffer_copy(memoryMap.readStruct(offset,struct))
    # check if data matches
    if ( instance.loadMembers(self.mappings, depth) ):
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

def getMainFile():
  return os.path.abspath(sys.modules[__name__].__file__)


def findStruct(pid, struct, maxNum=1, fullScan=False, nommap=False):
  ''' '''
  if type(struct) != str:
    struct = '.'.join([struct.__module__,struct.__name__])
  cmd_line=[sys.executable, getMainFile(), "%s"%struct, "--pid", "%d"%pid, 'search',  '--maxnum', str(int(maxNum))] #, '--nommap'
  if fullScan:
    cmd_line.append('--fullscan')
  if nommap:
    cmd_line.append('--nommap')
  outs=_callFinder(cmd_line)
  if len(outs) == 0:
    log.error("The %s has not been found."%(struct))
    return None
  #
  return outs

def findStructInFile(filename, struct, hint=None, maxNum=1, fullScan=False):
  ''' '''
  if type(struct) != str:
    struct = '.'.join([struct.__module__,struct.__name__])
  cmd_line=[sys.executable, getMainFile(), "--debug", "%s"%struct, "--fromdump", filename, 'search',  '--maxnum', str(int(maxNum))] #, '--nommap'
  if fullScan:
    cmd_line.append('--fullscan')
  if hint:
    cmd_line.extend(['--hint', str(hex(hint))])
  outs=_callFinder(cmd_line)
  if len(outs) == 0:
    log.error("The %s has not been found."%(struct))
    return None
  #
  return outs

def refreshStruct(pid, struct, offset):
  ''' '''
  if type(struct) != str:
    struct = '.'.join([struct.__module__,struct.__name__])
  cmd_line=[sys.executable, getMainFile(),  '%s'%struct, '--pid', "%d"%pid ,'refresh',  "0x%lx"%offset ]
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
  rootparser.add_argument('--debug', dest='debug', action='store_const', const=True, help='setLevel to DEBUG')
  rootparser.add_argument('structType', type=str, help='Structure type name')
  
  target = rootparser.add_mutually_exclusive_group(required=True)
  target.add_argument('--pid', type=int, help='Target PID')
  target.add_argument('--fromdump', type=argparse.FileType('r'), dest='memdump', action='store', default=None, help='Use a memory dump instead of a live process ID')
  
  subparsers = rootparser.add_subparsers(help='sub-command help')
  search_parser = subparsers.add_parser('search', help='search help')
  search_parser.add_argument('--fullscan', action='store_const', const=True, default=False, help='do a full memory scan, otherwise, restrict to the heap')
  search_parser.add_argument('--maxnum', type=int, action='store', default=1, help='Limit to maxnum numbers of results')
  search_parser.add_argument('--hint', type=int, action='store', default=1, help='hintOffset to start at')
  search_parser.add_argument('--nommap', action='store_const', const=True, default=False, help='disable mmap()-ing')
  search_parser.set_defaults(func=search)
  #
  refresh_parser = subparsers.add_parser('refresh', help='refresh help')
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
  structType=getKlass(args.structType)
  if args.pid :
    finder = StructFinder(pid=args.pid, mmap=(not args.nommap))
  else : # from dump
    finder = StructFinder(memdump=args.memdump)
    log.debug('starting a memory file dump search')
  
  outs=finder.find_struct( structType, hintOffset=args.hint ,maxNum=args.maxnum, fullScan=args.fullscan)
  #return
  if args.human:
    print '[',
    for ss, addr in outs:
      print "# --------------- 0x%lx \n"% addr, ss.toString()
      pass
    print ']'
  else:
    ret=[ (ss.toPyObject(),addr) for ss, addr in outs]
    log.info("%s %s"%(ret[0], type(ret[0]) )   )
    #model.findCtypesInPyObj(ret)
    print pickle.dumps(ret)
  return outs


def refresh(args):
  addr=int(args.addr,16)
  structType=getKlass(args.structType)

  if args.pid :
    finder = StructFinder(pid=args.pid, mmap=(not args.nommap))
  else : # from dump
    finder = StructFinder(memdump=args.memdump)
    log.debug('starting a memory file dump search')

  instance,validated = finder.loadAt( model.is_valid_address_value(addr, finder.mappings), 
          addr, structType)
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

def devnull(arg, **args):
  return

def main(argv):
  #log.debug = devnull
  #model.log.debug = devnull
  #logging.debug(argv)
  
  parser = argparser()
  opts = parser.parse_args(argv)
  if opts.debug:
    logging.basicConfig(level=logging.DEBUG)
  else:
    logging.basicConfig(level=logging.INFO)
  try:
    opts.func(opts)
  except ImportError,e:
    log.error('Struct type does not exists.')
    print e

  if opts.pid:  
    log.info("done for pid %d"%opts.pid)
  else:
    log.info("done for file %s"%opts.memdump.name)
  return 0


if __name__ == "__main__":
  main(sys.argv[1:])


