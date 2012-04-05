
#test read memory

#import ptrace
#f=file('/proc/8902/maps')
#lines=f.readlines()

import logging,sys,os
logging.basicConfig(level=logging.INFO)

import haystack
from haystack.reverse import reversers

import math 

log=logging.getLogger('test')

#context = reversers.getContext('skype.1.i')
#heap = context.heap
#bytes = heap.mmap().getByteBuffer()

def H(data):
  if not data:
    return 0
  entropy = 0
  for x in range(256):
    p_x = float(data.count(chr(x)))/len(data)
    if p_x > 0:
      entropy += - p_x*math.log(p_x, 2)
  return entropy

def entropy_scan (data, block_size) :
  # creates blocks of block_size for all possible offsets ('x'):
  blocks = (data[x : block_size + x] for x in range (len (data) - block_size))
  i = 0
  for block in (blocks) :
    i += 1
    yield H (block)


results = []
if False:
  for vaddr,s in zip(context._malloc_addresses, context._malloc_sizes):
    #print vaddr,
    vals = heap.readBytes(int(vaddr), int(s))
    ent = H(vals)
    results.append( (ent, vaddr) )
else:
  from haystack.reverse.win32 import win7heapwalker
  from haystack import dump_loader
  mappings = dump_loader.load('test/dumps/putty/putty.1.dump')
  for vaddr,s in win7heapwalker.getUserAllocations(mappings, mappings.getMmapForAddr(0x5c0000) ):
    #print vaddr,
    heap = mappings.getMmapForAddr(vaddr)
    vals = heap.readBytes(int(vaddr), int(s))
    ent = H(vals)
    results.append( (ent, int(vaddr), int(s)) )
  
results.sort()
#print results
  
for i in range(1,6):
  ent,addr,size = results[-i]
  print '%2.2f @%x size:%d'%(results[-i])
  heap = mappings.getMmapForAddr(addr)
  vals = heap.readBytes(int(addr), int(size))
  print repr(vals)
  continue # need fscking context
  ent,addr = results[-i]
  st = context.getStructureForAddr(addr)
  st.decodeFields()
  print st.toString()
  print '## # ', ent
  print '----------------'

# it actually works....
# so multiple previous work on google.












def printBytes(data):
  for i in range(0,len(data)/8,8):
    print "0x%lx"%data[i],
    




def dbg_read(addr):
  from ptrace.cpu_info import CPU_64BITS, CPU_WORD_SIZE, CPU_POWERPC
  for a in range(addr,addr+88,CPU_WORD_SIZE):
    print "0x%lx"%process.readWord(a)


def readRsa(addr):
  dbg=PtraceDebugger()
  process=dbg.addProcess(PID, is_attached=False)
  if process is None:
    log.error("Error initializing Process debugging for %d"% PID)
    sys.exit(-1)
  # read where it is
  ######################### RAAAAAAAAAAAAH
  rsa=ctypes_openssl.RSA.from_buffer_copy(process.readStruct(addr,ctypes_openssl.RSA))
  mappings=readProcessMappings(process)
  print "isValid : ", rsa.isValid(mappings)
  #rsa.printValid(maps)
  print rsa
  #print rsa.n
  #print rsa.n.contents
  #print ctypes.byref(rsa.n.contents)
  #print rsa
  print '------------ === Loading members'
  ret=rsa.loadMembers(process,mappings)
  print '------------ === Loading members finished'
  print ret,rsa
  return rsa

def readDsa(addr):
  dbg=PtraceDebugger()
  process=dbg.addProcess(PID, is_attached=False)
  if process is None:
    log.error("Error initializing Process debugging for %d"% pid)
    sys.exit(-1)
  # read where it is
  dsa=ctypes_openssl.DSA.from_buffer_copy(process.readStruct(addr,ctypes_openssl.DSA))
  mappings=readProcessMappings(process)
  print "isValid : ", dsa.isValid(mappings)
  #dsa.printValid(maps)
  #print 'DSA1 -> ', dsa
  #print '------------'
  #print 'DSA1.q -> ', dsa.q
  print '------------ === Loading members'
  dsa.loadMembers(process,mappings)
  #print '------------  ===== ==== '
  #print 'DSA2.q -> ', dsa.q
  #print 'DSA2.q.contents -> ', dsa.q.contents
  #print ctypes.byref(rsa.n.contents)
  #print dsa
  return dsa

def writeWithLibRSA(addr):
  ssl=cdll.LoadLibrary("libssl.so")
  # need original data struct
  #rsa=process.readBytes(addr, ctypes.sizeof(ctypes_openssl.RSA) )
  #rsa=ctypes.addressof(process.readStruct(addr,ctypes_openssl.RSA))
  rsa=readRsa(addr)
  rsa_p=ctypes.addressof(rsa)
  print 'rsa acquired 0x%lx copied to 0x%lx'%(addr,rsa_p)
  f=libc.fopen("test.out","w")
  print 'file opened',f  
  ret=ssl.PEM_write_RSAPrivateKey(f, rsa_p, None, None, 0, None, None)
  print 'key written'  
  print ret,f

def writeWithLibDSA(addr):
  ssl=cdll.LoadLibrary("libssl.so")
  dsa=readDsa(addr)
  dsa_p=ctypes.addressof(dsa)
  print 'dsa acquired 0x%lx copied to 0x%lx'%(addr,dsa_p)
  f=libc.fopen("test.out","w")
  print 'file opened',f  
  ret=ssl.PEM_write_DSAPrivateKey(f, dsa_p, None, None, 0, None, None)
  print 'key written'  
  print ret,f

def withM2(addr):
  import M2Crypto
  from M2Crypto.BIO import MemoryBuffer
  from M2Crypto import RSA as mRSA
  rsa=process.readBytes(addr, ctypes.sizeof(ctypes_openssl.RSA) )
  bio=MemoryBuffer(rsa)
  # tsssi need PEM
  myrsa=mRSA.load_key_bio(bio)
  return myrsa

def printSize():
  ctypes_openssl.printSizeof()
  ctypes_openssh.printSizeof()

def printme(obj):
  log.info(obj)

def findCipherContext():
  dbg=PtraceDebugger()
  process=dbg.addProcess(pid,is_attached=False)
  if process is None:
    log.error("Error initializing Process debugging for %d"% pid)
    sys.exit(-1)
  mappings=readProcessMappings(process)
  stack=process.findStack()
  for m in mappings:
    #if m.pathname != '[heap]':
    #  continue
    if not abouchet.hasValidPermissions(m):
      continue    
    print m,m.permissions
    abouchet.find_struct(process, m, ctypes_openssh.CipherContext, printme)

def isMemOf(addr,mpid):
  class p:
    pid=mpid
  myP=p()
  for m in readProcessMappings(myP):
    if addr in m:
      print myP, m
      return True
  return False

def testScapy():
  import socket_scapy
  socket_scapy.test()

def testScapyThread():
  import socket_scapy,select
  from threading import Thread
  port=22
  sshfilter="tcp and port %d"%(port)
  soscapy=socket_scapy.socket_scapy(sshfilter,packetCount=100)
  log.info('Please make some ssh  traffic')
  sniffer = Thread(target=soscapy.run)
  sniffer.start()
  # sniffer is strted, let's consume
  nbblocks=0
  data=''
  readso=soscapy.getInboundSocket()
  while sniffer.isAlive():
    r,w,oo=select.select([readso],[],[],1)
    if len(r)>0:
      data+=readso.recv(16)
      nbblocks+=1
  # try to finish socket
  print 'sniffer is finished'
  r,w,oo=select.select([readso],[],[],0)
  while len(r)>0:
    data+=readso.recv(16)
    nbblocks+=1
    r,w,oo=select.select([readso],[],[],0)
  #end      
  print "received %d blocks/ %d bytes"%(nbblocks,len(data))
  print 'sniffer captured : ',soscapy



def testwatwever():
  #rsa=readRsa(addr)

  #writeWithLibRSA(addr)
  #print '---------------'
  #abouchet.find_keys(process,stack)

  #dsa=readDsa(0xb835b4e8)
  #print dsa
  #rsa=readRsa(0xb835c9a0)
  #writeWithLibDSA(addr)

  #printSize()

  #x pourPEM_write_RSAPrivateKey

  class B(ctypes.Structure):
    _fields_=[("b1",ctypes.c_ulong),('b2',ctypes.c_ulonglong)]

  class A(ctypes.Structure):
    _fields_=[("a1",ctypes.c_ulong),('b',ctypes.POINTER(B)),('a2',ctypes.c_ulonglong)]

  myaddr=0xb7c16884
  # rsa-> n
  myaddr=0xb8359148
  pid=12563
  if len(sys.argv) == 2:
    myaddr=int(sys.argv[1],16)
    if isMemOf(myaddr, pid ):
      print "isMemOf(0x%lx, 8831) - python"%myaddr
    if isMemOf(myaddr, PID):
      print "isMemOf(0x%lx, 27477) - ssh-agent"%myaddr

  #findCipherContext()


  soscapy=testScapyThread()





