#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys

import ctypes_openssl,ctypes_openssh
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

from abouchet import FileWriter,StructFinder

_libssl = ctypes.cdll.LoadLibrary("libssl.so")




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





class RSAFileWriter(FileWriter):
  def __init__(self,folder='outputs'):
    FileWriter.__init__(self,'id_rsa','key',folder)
  def writeToFile(self,instance):
    prefix=self.prefix
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
    filename=self.get_valid_filename()
    f=libc.fopen(filename,"w")  
    ret=_libssl.PEM_write_RSAPrivateKey(f, ctypes.byref(instance), None, None, 0, None, None)
    libc.fclose(f)
    if ret < 1:
      log.error("Error saving key to file %s"% filename)
      return False
    log.info ("[X] Key saved to file %s"%filename)
    return True

class DSAFileWriter(FileWriter):
  def __init__(self,folder='outputs'):
    FileWriter.__init__(self,'id_dsa','key',folder)
  def writeToFile(self,instance):
    prefix=self.prefix
    filename=self.get_valid_filename()
    f=libc.fopen(filename,"w")
    ret=_libssl.PEM_write_DSAPrivateKey(f, ctypes.byref(instance), None, None, 0, None, None)
    if ret < 1:
      log.error("Error saving key to file %s"% filename)
      return False
    log.info ("[X] Key saved to file %s"%filename)
    return True
  

class OpenSSLStructFinder(StructFinder):
  ''' '''
  # interesting structs
  rsaw=RSAFileWriter()
  dsaw=DSAFileWriter()  
  def __init__(self,pid, fullScan=False):
    StructFinder.__init__(self,pid, fullScan=False)
    self.OPENSSL_STRUCTS={     # name, ( struct, callback)
      'RSA': (ctypes_openssl.RSA, self.rsaw.writeToFile ),
      'DSA': (ctypes_openssl.DSA, self.dsaw.writeToFile )
      }
  #'BIGNUM':   'RSA': (ctypes_openssl.BIGNUM, )
  def save(self,instance):
    if type(instance) == ctypes_openssl.RSA:
      self.rsaw.writeToFile(instance)
    elif type(instance) == ctypes_openssl.DSA:
      self.dsaw.writeToFile(instance)
    else:
      log.error('I dont know how to save that')

def usage(txt):
  log.error("Usage : %s <pid> [offset] # find SSL Structs in process"% txt)
  sys.exit(-1)


def main(argv):
  logging.basicConfig(level=logging.INFO)

  if ( len(argv) < 1 ):
    usage(sys.argv[0])
    return

  # use optarg on v, a and to
  pid = int(argv[0])
  log.info("Target has pid %d"%pid)

  finder = OpenSSLStructFinder(pid, fullScan=False )
  
  addr=None  
  #### force offset
  if len(argv) == 2:
    addr=int(argv[1],16)
    instance,validated = finder.loadAt(addr, ctypes_openssl.DSA)
    if validated:
      finder.save(instance)    
    instance,validated = finder.loadAt(addr, ctypes_openssl.RSA)
    if validated:
      finder.save(instance)    
    return

  log.debug('look for RSA keys')
  outs=finder.find_struct(ctypes_openssl.RSA)
  for rsa,addr in outs:
    finder.save(rsa)    
  log.debug('look for DSA keys')
  outs=finder.find_struct(ctypes_openssl.DSA)
  for dsa,addr in outs:
    finder.save(dsa)    
        
  log.info("done for pid %d"%pid)

  return -1


if __name__ == "__main__":
  main(sys.argv[1:])

