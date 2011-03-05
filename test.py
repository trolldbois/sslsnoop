
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
from ctypes import *
from ptrace.ctypes_libc import libc



def printBytes(data):
  for i in range(0,len(data)/8,8):
    print "0x%lx"%data[i],
    

pid=27477
addr=0xb835b4e8


dbg=PtraceDebugger()
process=dbg.addProcess(pid,is_attached=False)
if process is None:
  log.error("Error initializing Process debugging for %d"% pid)
  sys.exit(-1)

maps=readProcessMappings(process)
stack=process.findStack()




def dbg_read(addr):
  from ptrace.cpu_info import CPU_64BITS, CPU_WORD_SIZE, CPU_POWERPC
  for a in range(addr,addr+88,CPU_WORD_SIZE):
    print "0x%lx"%process.readWord(a)


def readRsa(addr):
  rsa=process.readStruct(addr,model.RSA)
  print "isValid : ", rsa.isValid(maps)
  #rsa.printValid(maps)
  #print rsa
  #print rsa.n
  #print rsa.n.contents
  #print ctypes.byref(rsa.n.contents)
  #print rsa
  rsa.loadMembers(process)
  return rsa

def readDsa(addr):
  dsa=process.readStruct(addr,model.DSA)
  print "isValid : ", dsa.isValid(maps)
  dsa.printValid(maps)
  print 'DSA1 -> ', dsa
  print '------------'
  print 'DSA1.q -> ', dsa.q
  #print '------------ === '
  dsa.loadMembers(process)
  #print '------------  ===== ==== '
  print 'DSA2.q -> ', dsa.q
  print 'DSA2.q.contents -> ', dsa.q.contents
  #print ctypes.byref(rsa.n.contents)
  #print dsa
  return dsa

def writeWithLib(addr):
  ssl=cdll.LoadLibrary("libssl.so")
  # need original data struct
  #rsa=process.readBytes(addr, ctypes.sizeof(model.RSA) )
  #rsa=ctypes.addressof(process.readStruct(addr,model.RSA))
  rsa=readRsa(addr)
  rsa_p=ctypes.addressof(rsa)
  print 'rsa acquired 0x%lx copied to 0x%lx'%(addr,rsa_p)
  f=libc.fopen("test.out","w")
  print 'file opened',f  
  ret=ssl.PEM_write_RSAPrivateKey(f, rsa_p, None, None, 0, None, None)
  print 'key written'  
  print ret,f

def withM2(addr):
  import M2Crypto
  from M2Crypto.BIO import MemoryBuffer
  from M2Crypto import RSA as mRSA
  rsa=process.readBytes(addr, ctypes.sizeof(model.RSA) )
  bio=MemoryBuffer(rsa)
  # tsssi need PEM
  myrsa=mRSA.load_key_bio(bio)
  return myrsa

#rsa=readRsa(addr)

#writeWithLib(addr)
#print '---------------'
#abouchet.find_keys(process,stack)

dsa=readDsa(addr)

