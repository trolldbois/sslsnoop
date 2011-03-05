#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
#use volatility?

import model
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

#ko
def write_rsa_key(rsa,prefix):
  filename=get_valid_filename(prefix)
  #f=open(filename,"w")    
  ssl=cdll.LoadLibrary("libssl.so")
  # need original data struct, loaded in our memory
  rsa_p=ctypes.addressof(rsa)
  f=libc.fopen(filename,"w")
  ret=ssl.PEM_write_RSAPrivateKey(f, rsa_p, None, None, 0, None, None)
  if ret < 1:
    log.error("Error saving key to file %s"% filename)
    return False
  log.info ("[X] Key saved to file %s"%filename)
  return True

#ko
def write_dsa_key(dsa,prefix):
  filename=get_valid_filename(prefix)
  #f=open(filename,"w")    
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
  
def find_keys(process,stackmap):

  mappings= readProcessMappings(process)
  log.debug("scanning 0x%lx --> 0x%lx %s"%(stackmap.start,stackmap.end,stackmap.pathname) )
  #openssl=cdll.LoadLibrary("libssl.so")
  #rsa=model.RSA()
  #dsa=model.DSA()
  
  ## stackmap.search(bytestr) // won't cut it.
  ## process.readBytes() is ok
  ### copy data in rsa struct
  #### test if rsa struct is ok ?
  ##### extract rsa key
  ###### save it

  ### do the same for dsa.

  data=stackmap.start  
  ## todo change 4 by len char *
  ##if ( j <= map->size - sizeof(RSA) ) {
  plen=ctypes.sizeof(ctypes.c_char_p)
  rsalen=ctypes.sizeof(model.RSA)
  dsalen=ctypes.sizeof(model.DSA)
  '''
  # parse for rsa
  for j in range(stackmap.start, stackmap.end-rsalen, plen):
    #log.debug("checking 0x%lx"% j)
    rsa=process.readStruct(j,model.RSA)
    # check if data matches
    if rsa.isValid(mappings): # refreshing would be better
      log.debug('possible valid rsa key at 0x%lx'%(j))
      if ( extract_rsa_key(rsa, process) ):
        log.info( "found RSA key @ 0x%lx"%(j) )
        write_rsa_key(rsa, "id_rsa")
        continue
  '''
  #do the same with dsa
  for j in range(stackmap.start, stackmap.end-dsalen, plen):
    #log.debug("checking 0x%lx"% j)
    dsa=process.readStruct(j,model.DSA)
    # check if data matches
    if dsa.isValid(mappings): # refreshing would be better
      log.info('Found valid dsa at 0x%lx'%(j))
      #print ' dsa isValid -----------'
      #dsa.printValid(mappings)
      #print '--------------------------- \nextract :'
      if ( extract_dsa_key(dsa, process) ):
        log.info( "found DSA key @ 0x%lx"%(j) )
        write_dsa_key(dsa, "id_dsa")
        continue
  
  return

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
  for m in mappings:
    if hasValidPermissions(m):
      print m,m.permissions
      find_keys(process, m)
    

  # dbg_map_for_each(&p, map)  ????

  log.info("done for pid %d"%pid)

  return -1


if __name__ == "__main__":
  main(sys.argv[1:])

