
#test read memory

#import ptrace
#f=file('/proc/8902/maps')
#lines=f.readlines()

import logging,sys,os
logging.basicConfig(level=logging.DEBUG)

import abouchet,model
import ctypes
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings



def printBytes(data):
  for i in range(0,len(data)/8,8):
    print "0x%lx"%data[i],
    

pid=8902
dbg=PtraceDebugger()
process=dbg.addProcess(pid,is_attached=False)
if process is None:
  log.error("Error initializing Process debugging for %d"% pid)
  sys.exit(-1)

maps=readProcessMappings(process)


stack=process.findStack()

abouchet.find_keys(process,stack)

addr=0xb8da74e8
rsa=process.readStruct(addr,model.RSA)

data=process.readBytes(addr,ctypes.sizeof(model.RSA))

#print rsa
#print hex(data)
#printBytes(data)


