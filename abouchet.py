#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
#use volatility?

import ctypes_openssl
#from  model import DSA,RSA
import ctypes
from ctypes import *
from ptrace.ctypes_libc import libc

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings



log=logging.getLogger('abouchet')
MAX_KEYS=255

verbose = 0



'''
int extract_rsa_key(RSA *rsa, proc_t *p) {


   switch ( RSA_check_key( rsa )) {
     case 1 :
       return 0;
     case 0 :
       if (verbose > 1)
         fprintf(stderr, "warn: invalid RSA key found.\n");
       break;
     case -1 :
       if (verbose > 1)
         fprintf(stderr, "warn: unable to check key.\n");
       break;
   }
'''

'''
int extract_dsa_key( DSA * dsa, proc_t *p ) {

  dsa->method_mont_p = NULL;
  dsa->meth = NULL;
  dsa->engine = NULL;

  /* in DSA, we should have :
   * pub_key = g^priv_key mod p
   */
  BIGNUM * res = BN_new();
  if ( res == NULL )
    err(p, "failed to allocate result BN");

  BN_CTX * ctx = BN_CTX_new();
  if ( ctx == NULL ) {
    fprintf(stderr, "[-] error allocating BN_CTX ctx\n");
    goto free_res;
  }
  /* a ^ p % m
    int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
    */
  error = BN_mod_exp(res, dsa->g, dsa->priv_key, dsa->p, ctx);
  if ( error == 0 ) {
    if (verbose > 0)
      fprintf(stderr, "warn: failed to check DSA key.\n");
    goto free_ctx;
  }
  if ( BN_cmp(res, dsa->pub_key) != 0 ) {
    if (verbose > 0)
      fprintf(stderr, "warn: invalid DSA key.\n");
    goto free_ctx;
  }
  BN_clear_free(res);
  BN_CTX_free(ctx);

  fprintf(stderr, "[X] Valid DSA key found.\n");

  return 0;

'''




def extract_rsa_key(rsa,process):
  return rsa.loadMembers(process)
  
def extract_dsa_key(dsa,process):
  return dsa.loadMembers(process)


def get_valid_filename(prefix):
  filename_FMT="%s-%d.key"
  for i in range(1,MAX_KEYS):
    filename=filename_FMT%(prefix,i)
    if not os.access(filename,os.F_OK):
      return filename
  #
  log.error("Too many file keys extracted in current directory")
  return None

class FileWriter:
  def __init__(self,prefix):
    self.prefix=prefix
  def writeToFile(self,instance):
    raise NotImplementedError

class RSAFileWriter(FileWriter):
  def __init__(self):
    self.prefix='id_rsa'
  def writeToFile(self,instance):
    write_rsa_key(instance,self.prefix)
class DSAFileWriter(FileWriter):
  def __init__(self):
    self.prefix='id_dsa'
  def writeToFile(self,instance):
    write_dsa_key(instance,self.prefix)
    

def write_rsa_key(rsa,prefix):
  '''
  PEM_write_RSAPrivateKey(f, rsa_p, None, None, 0, None, None)
  PEM_write_RSAPrivateKey(fp,x, [enc,kstr,klen,cb,u]) 
   -> PEM_ASN1_write((int (*)())i2d_RSAPrivateKey,PEM_STRING_RSA,fp, (char *)x, [enc,kstr,klen,cb,u])
  int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp, char *x, [const EVP_CIPHER *, unsigned char *kstr,int , pem_password_cb *, void *])
   -> PEM_ASN1_write_bio(i2d, name, b, x  [,enc,kstr,klen,callback,u] );
  int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp, char *x ,  [..]
   -> i2d_RSAPrivateKey( sur x )
    -> ASN1_item_i2d_bio(ASN1_ITEM_rptr(RSAPrivateKey), bp, rsa);
     -> i=BIO_write(out,&(b[j]),n);
   -> i=PEM_write_bio(bp,name,buf,data,i);
   
  en gros, c'est ctypes_openssl.RSA().writeASN1(file)
  '''
  filename=get_valid_filename(prefix)
  ssl=cdll.LoadLibrary("libssl.so")
  # need original data struct, loaded in our memory
  #rsa_p=ctypes.addressof(rsa)
  rsa_p=ctypes.pointer(rsa)
  print 'in rsa_p',rsa_p
  #print 'in rsa',rsa
  f=libc.fopen(filename,"w")
  
  ret=ssl.PEM_write_RSAPrivateKey(f, rsa_p, None, None, 0, None, None)
  libc.fclose(f)

  if ret < 1:
    log.error("Error saving key to file %s"% filename)
    return False
  log.info ("[X] Key saved to file %s"%filename)
  return True

def write_dsa_key(dsa,prefix):
  filename=get_valid_filename(prefix)
  ssl=cdll.LoadLibrary("libssl.so")
  # need original data struct
  dsa_p=ctypes.addressof(dsa)
  f=libc.fopen(filename,"w")
  ret=ssl.PEM_write_DSAPrivateKey(f, dsa_p, None, None, 0, None, None)
  if ret < 1:
    log.error("Error saving key to file %s"% filename)
    return False
  log.info ("[X] Key saved to file %s"%filename)
  return True
  


def find_struct(process, memoryMap, struct, callback, hint=None, hintOffset=None):
  '''
    Looks for struct in memory, using :
      hints from struct (default values, and such)
      guessing validation with instance(struct)().isValid()
      and confirming with instance(struct)().loadMembers()
    
    returns POINTERS to struct.
  '''
  
  # update process mappings
  mappings= readProcessMappings(process)
  log.debug("scanning 0x%lx --> 0x%lx %s"%(memoryMap.start,memoryMap.end,memoryMap.pathname) )

  # where do we look  
  start=memoryMap.start  
  end=memoryMap.end
  plen=ctypes.sizeof(ctypes.c_char_p) # use aligned words only
  structlen=ctypes.sizeof(struct)
  
  ## hinted search
  if not (hint is None or hintOffset is None ):
    # search map for hint
    results=memoryMap.search( bytes(hint) )
    if results is not None:
      ## Boundary check, don't try too far in mapping
      solutions=[offset for offset in results if (( (offset-hintOffset) + structlen ) <= end) ]
      log.debug('Found %d offsets possible with the hint'%(len(solutions)) )
      for offset in solutions:
        instance=try_to_map(process, mappings, struct, offset-hintOffset )
        if instance is not None:
          callback(instance)
          # XXX memory issues :the memory region is gonna die now.
          pass
    else:
      log.debug('Found no possible offsets for the hint')
    # get out
    return
  
  ## search without hint
  # parse for struct on each aligned word
  log.debug("checking 0x%lx-0x%lx by increment of %d"%(start, (end-structlen), plen))
  instance=None
  for j in range(start, end-structlen, plen):
    instance=try_to_map(process,mappings,struct,j)
    if instance is not None:
      # do stuff with it.
      callback(instance)
      # XXX memory issues : the memory region is gonna die now.
  # XXX memory issues : la structure dies here. end of life for try_tomap returns
  return 

def try_to_map(process,mappings,struct,offset):
  ''' '''
  instance=process.readStruct(offset,struct)
  # check if data matches
  if instance.isValid(mappings): # refreshing would be better
    log.debug('possible instance at 0x%lx'%(offset))
    if ( instance.loadMembers(process) ):
      log.info( "found instance @ 0x%lx"%(offset) )
      #print 'before write', instance
      #write_rsa_key(instance, "id_rsa",process)
      #print 'after write', instance
      return instance
  return None



def hasValidPermissions(memmap):
  ''' memmap must be 'rw..' or shared '...s' '''
  perms=memmap.permissions
  return (perms[0] == 'r' and perms[1] == 'w') or (perms[3] == 's')

def usage(txt):
  log.error("Usage : %s [-v] [-a from[-to]] pid"% txt)
  sys.exit(-1)


def main(argv):
  logging.basicConfig(level=logging.INFO)
  logging.debug(argv)
  if ( len(argv) < 1 ):
    usage(argv[0])
    return
  #
  verbose = 0
  start = 0
  to = 0
  #min_key_size = (sizeof(RSA) < sizeof(DSA)) ? sizeof(RSA) : sizeof(DSA);

  # use optarg on v, a and to
  pid = int(argv[0])
  log.error("Target has pid %d"%pid)

  dbg=PtraceDebugger()
  process=dbg.addProcess(pid,is_attached=False)
  if process is None:
    log.error("Error initializing Process debugging for %d"% pid)
    return
  
  if (False):
    #When we have args ...
    stack=process.findStack()
    # if ( dbg_get_memory(&p) )
    # check memory access ?
    ## check args -a and -to
    ##  check if -a and -to is in process.
    if start !=0 and not process.contains(start):
      log.error("0x%lx not mapped into process %d"%( start, pid) )
    if to != 0 and   not process.contains(to):
      log.error("0x%lx not mapped into process %d"%( to, pid) )
    if start !=0 and (to <= start) :
      log.error("bad memory range")
    off_end = stack.end - stack.start

  #cache it .. yeah... sometime
  #if (dbg_map_cache(map) < 0)
  ### t-t-t-t, search in all MemoryMap
  mappings= readProcessMappings(process)
  rsaw=RSAFileWriter()
  dsaw=DSAFileWriter()
  for m in mappings:
    ##debug, rsa is on head
    if m.pathname != '[heap]':
      continue
    if not hasValidPermissions(m):
      continue
    
    print m,m.permissions
    ## method generic
    print 'look for RSA'
    find_struct(process, m, ctypes_openssl.RSA, rsaw.writeToFile)
    print 'look for DSA'
    find_struct(process, m, ctypes_openssl.DSA, dsaw.writeToFile)

  log.info("done for pid %d"%pid)

  return -1


if __name__ == "__main__":
  main(sys.argv[1:])

