#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,sys
#use volatility?

import model 
import ctypes
from ctypes import memmove,byref

# linux only
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.memory_mapping import readProcessMappings



log=logging.getLogger('abouchet')
MAX_KEYS=255

verbose = 0


'''
static void *extract_from_mem(void *addr, unsigned int size, proc_t *proc) {
  mapping_t *map;
  unsigned int off;

  map = dbg_map_lookup_by_address(proc, (xaddr_t)addr, &off);
  if (!map || !map->data)
    return NULL;

  return map->data + off;
}

static int is_valid_BN(BIGNUM *bn) {
    
    printf("BN { d=%p, top=%i, dmax=%i, neg=%i, flags=%i }\n",
    bn->d, bn->top, bn->dmax, bn->neg, bn->flags);
    if ( bn->dmax < 0 || bn->top < 0 || bn->dmax < bn->top )
        return -1;

    if ( !(bn->neg == 1 || bn->neg == 0 ) ) {
        return -1;
    }
    return 0;
}
/*
   struct bignum_st
   {
   BN_ULONG *d;     Pointer to an array of 'BN_BITS2' bit chunks. 
   int top;     Index of last used d +1. 
   The next are internal book keeping for bn_expand. 
   int dmax;    Size of the d array. 
   int neg;     one if the number is negative 
   int flags;
   };

   Extract a BIGNUM structure from memory.
   Set error to 1 if an error occured, else set it to 0.
   */

BIGNUM * BN_extract_from_mem(void * bn_addr, proc_t * proc, int * error) {
  BIGNUM *bn_tmp;

  *error = 0;
//printf("=a= %p\n", bn_addr);
  bn_tmp = extract_from_mem( bn_addr, sizeof(BIGNUM), proc);
  if (!bn_tmp) {
//printf("=z=\n");
    *error = 1;
    return NULL;
  }
  BIGNUM *bn = malloc(sizeof(BIGNUM));
  if ( bn == NULL ) {
    exit(EXIT_FAILURE);
  }
  memcpy(bn, bn_tmp, sizeof(BIGNUM));
  /* tests heuristiques */
  if ( is_valid_BN(bn) == -1 ) { 
      *error = 1;
      free(bn);
      return NULL;
  }

//printf("=b=\n");
  bn->d = extract_from_mem( bn->d, bn->top * sizeof(BN_ULONG), proc);
  if (!bn->d) {
    *error = 1;
    free(bn);
    return NULL;
  }
//printf("=c=\n");
  return bn;
}
/* }}} */

/* key saving {{{ */

/* returns 0 if file does not exist
           1 if file exists */
static int file_exists(char *filename) {
    struct stat stat_st;
    return !stat(filename, &stat_st);
}

char * get_valid_filename(char *string) {
    int i = 0 ;
    char filename[128] ;
    sprintf(filename, "%s-%d.key", string, i);
    while ( file_exists(filename) && i < MAX_KEYS ) {
        i++;
        sprintf(filename, "%s-%d.key", string, i);
    } 
    if ( i >= MAX_KEYS )
        return NULL ;
    
    
    return strdup(filename);
}

int write_rsa_key(RSA * rsa, char *prefix) {

    char *filename = get_valid_filename(prefix) ;
    
    FILE *f = fopen(filename, "w");
    if ( f == NULL ) {
        perror("fopen");
        return -1;
    }
    if ( ! PEM_write_RSAPrivateKey(f, rsa, NULL,
            NULL, 0, NULL, NULL) ) {
        fprintf(stderr, "Error saving key to file %s\n", filename);
        return -1;
    }
    fclose(f);
    printf("[X] Key saved to file %s\n", filename);
    free(filename);
    return 0;
}


int write_dsa_key(DSA * dsa, char *prefix) {

    char *filename = get_valid_filename(prefix) ;
    
    FILE *f = fopen(filename, "w");
    if ( f == NULL ) {
        perror("fopen");
        return -1;
    }
    if ( ! PEM_write_DSAPrivateKey(f, dsa, NULL,
            NULL, 0, NULL, NULL) ) {
        fprintf(stderr, "Error saving key to file %s\n", filename);
        return -1;
    }
    fclose(f);
    printf("[X] Key saved to file %s\n", filename);
    free(filename);
    return 0;
}


/* key saving }}} */

/* key extraction {{{ */

int extract_rsa_key(RSA *rsa, proc_t *p) {

    int error = 0;

    if ( verbose > 1 ) {
        printf("RSA { pad=%i, ver=%li, ref=%i, flags=%i, engine=%p\n"
                "      n=%p, e=%p, d=%p, p=%p, q=%p\n"    
                "      dmp1=%p, dmq1=%p, iqmp=%p, bn_data=%p\n"
                "      blinding=%p, mont_bn=%p/%p/%p }\n",
                rsa->pad, rsa->version, rsa->references, rsa->flags, rsa->engine,
                rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->dmp1, rsa->dmq1,
                rsa->iqmp, rsa->bignum_data, rsa->blinding,
                rsa->_method_mod_n, rsa->_method_mod_p, rsa->_method_mod_q);
    }

    rsa->n =    BN_extract_from_mem(rsa->n, p, &error);
    if ( error ) return -1;
    rsa->e =    BN_extract_from_mem(rsa->e, p, &error);
    if ( error ) { goto free_n; }
    rsa->d =    BN_extract_from_mem(rsa->d, p, &error);
    if ( error ) { goto free_e; }
    rsa->p =    BN_extract_from_mem(rsa->p, p, &error);
    if ( error ) { goto free_d; }
    rsa->q =    BN_extract_from_mem(rsa->q, p, &error);
    if ( error ) { goto free_p; }
    rsa->dmp1 = BN_extract_from_mem(rsa->dmp1, p, &error);
    if ( error ) { goto free_q; }
    rsa->dmq1 = BN_extract_from_mem(rsa->dmq1, p, &error);
    if ( error ) { goto free_dmp1; }
    rsa->iqmp = BN_extract_from_mem(rsa->iqmp, p, &error);
    if ( error ) { goto free_dmq1; }

  rsa->meth = NULL;
  rsa->_method_mod_n = NULL;
  rsa->_method_mod_p = NULL;
  rsa->_method_mod_q = NULL;
  rsa->bignum_data = NULL;
  rsa->blinding = NULL;
//#if OPENSSL_VERSION_NUMBER >
  //rsa->mt_blinding = NULL;
//#endif

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

    free(rsa->iqmp);
free_dmq1 :
    free(rsa->dmq1);
free_dmp1 :
    free(rsa->dmp1);
free_q :
    free(rsa->q);
free_p :
    free(rsa->p);
free_d :
    free(rsa->d);
free_e :
    free(rsa->e);
free_n :
    free(rsa->n);

    return -1 ;
}


int extract_dsa_key( DSA * dsa, proc_t *p ) {
  int error;

  if ( verbose > 1 ) {
      printf("DSA { pad=%i, ver=%li, ref=%i, flags=%i, engine=%p\n"
              "      p=%p, q=%p, g=%p, pubkey=%p, pvkey=%p\n"    
              "      kinv=%p, r=%p, mont_p=%p, meth=%p }\n",
              dsa->pad, dsa->version, dsa->references, dsa->flags, dsa->engine,
              dsa->p, dsa->q, dsa->g, dsa->pub_key, dsa->priv_key, dsa->kinv,
              dsa->r, dsa->method_mont_p, dsa->meth);
  }

  dsa->priv_key = BN_extract_from_mem(dsa->priv_key, p, &error);
  if ( error ) return -1;

  dsa->pub_key = BN_extract_from_mem(dsa->pub_key, p, &error);
  if ( error ) goto free_priv_key;
  dsa->p = BN_extract_from_mem(dsa->p, p, &error);
  if ( error ) goto free_pub_key;
  dsa->q = BN_extract_from_mem(dsa->q, p, &error);
  if ( error ) goto free_p;
  dsa->g = BN_extract_from_mem(dsa->g, p, &error);
  if ( error ) goto free_q;
  dsa->kinv = BN_extract_from_mem(dsa->kinv, p, &error);
  if ( error ) dsa->kinv = NULL;
  dsa->r = BN_extract_from_mem(dsa->r, p, &error);
  if ( error ) dsa->r = NULL;

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
def extract_rsa_key(rsa):
  return ""
def extract_dsa_key(dsa):
  return ""

def write_rsa_key(rsa,suffix):
  return ""
def write_dsa_key(dsa,suffix):
  return ""


def find_keys(process,stackmap):

  mappings= readProcessMappings(process)
  log.info("scanning 0x%lx --> 0x%lx %s"%(stackmap.start,stackmap.end,stackmap.pathname) )
  #openssl=cdll.LoadLibrary("libssl.so")
  rsa=model.RSA()
  dsa=model.DSA()
  
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
  rsalen=ctypes.sizeof(rsa)
  dsalen=ctypes.sizeof(dsa)
  # parse for rsa
  for j in range(stackmap.start, stackmap.end-rsalen, plen):
    log.debug("checking 0x%lx"% j)
    log.debug("coping 0x%lx to 0x%lx for %d bytes"% (j,ctypes.addressof(rsa),rsalen))
    ctypes.memmove(ctypes.addressof(rsa),j,rsalen)
    log.debug("copied 0x%lx to 0x%lx for %d bytes"% (j,ctypes.addressof(rsa),rsalen))
    # check if data matches
    if rsa.isValid(mappings): # refreshing would be better
      data=extract_rsa_key(rsa)
      if ( data is not None):
        print "found RSA key @ 0x%lx"%(j)
        write_rsa_key(rsa, "id_rsa")
        continue

  #do the same with dsa
  for j in range(stackmap.start, stackmap.end-dsalen, plen):
    log.debug("checking 0x%lx"% j)
    log.debug("coping 0x%lx to 0x%lx for %d bytes"% (j,ctypes.addressof(dsa),dsalen))
    ctypes.memmove(ctypes.addressof(dsa),j,dsalen)
    log.debug("copied 0x%lx to 0x%lx for %d bytes"% (j,ctypes.addressof(dsa),dsalen))
    # check if data matches
    if dsa.isValid(mappings): # refreshing would be better
      data=extract_dsa_key(dsa)
      if ( data is not None):
        print "found DSA key @ 0x%lx"%(j)
        write_dsa_key(dsa, "id_dsa")
        continue
  
  return

def usage(txt):
  log.error("Usage : %s [-v] [-a from[-to]] pid"% txt)
  sys.exit(-1)


def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  logging.debug(argv)
  if ( len(argv) < 1 ):
    usage(argv[0])
    print 'aa'
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
  find_keys(process,stack)

  # dbg_map_for_each(&p, map)  ????

  log.info("done for pid %d"%pid)

  return -1


if __name__ == "__main__":
  main(sys.argv[1:])

