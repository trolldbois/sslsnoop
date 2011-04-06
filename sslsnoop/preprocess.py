#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging, os, subprocess

log=logging.getLogger('preprocess')

'''
OPENSSL_ARGS= ['-DOPENSSL_THREADS', '-D_REENTRANT', '-DDSO_DLFCN', '-DHAVE_DLFCN_H', 
    '-DL_ENDIAN', '-DTERMIO', '-O3', '-fomit-frame-pointer', '-Wall', '-DOPENSSL_BN_ASM_PART_WORDS',
    '-DOPENSSL_IA32_SSE2', '-DSHA1_ASM', '-DMD5_ASM', '-nostdinc++', '-DRMD160_ASM', '-DAES_ASM' ]
'''
OPENSSL_ARGS= [
  '-I.', 
  '-I/usr/include/', 
  '-I/usr/include/openssl', 
#  '-I/home/jal/Compil/sslsnoop/biblio//include', 
]

'''
NSS_ARGS= ['-Wall', '-pipe', '-O2', '-fno-strict-aliasing', '-g', '-ansi', '-D_POSIX_SOURCE', 
  '-D_BSD_SOURCE', '-D_XOPEN_SOURCE', '-fPIC', '-D_XOPEN_SOURCE', '-DLINUX1_2', '-Di386', '-DLINUX2_1', 
  '-Wno-switch', '-pipe', '-DLINUX', '-Dlinux', '-DHAVE_STRERROR', 
  '-DXP_UNIX', '-DSHLIB_SUFFIX="so"', '-DSHLIB_PREFIX="lib"', '-DSHLIB_VERSION="3"', '-DSOFTOKEN_SHLIB_VERSION="3"', 
  '-UDEBUG', '-DNDEBUG', '-D_REENTRANT', '-DNSS_ENABLE_ECC', '-DUSE_UTIL_DIRECTLY', 
'''
NSS_ARGS= [
  '-I.', 
  '-I/usr/include/', 
  '-I/usr/include/nspr', 
  '-I/home/jal/Compil/sslsnoop/biblio/nss-3.12.8/mozilla/dist/include', 
  '-I/home/jal/Compil/sslsnoop/biblio/nss-3.12.8/mozilla/dist/public/nss', 
  '-I/home/jal/Compil/sslsnoop/biblio/nss-3.12.8/mozilla/dist/private/nss',
  '-I/home/jal/Compil/sslsnoop/biblio/nss-3.12.8/mozilla/dist/public/dbm',
  '-I/home/jal/Compil/sslsnoop/biblio/nss-3.12.8/mozilla/security/nss/lib/ssl/'
  ]

class Preprocess:
  '''
    Make a Preprocessed File from a C file
    
    @param cfile: the desired input c file name
    @param preprocessed: the preprocessed file name
  '''
  #sslInc#export INCLUDES="-I$PWD/biblio/openssl-0.9.8o/crypto/ -I$PWD/biblio/openssl-0.9.8o/"

  def __init__(self, cfile, preprocessed, cppargs=None, gcc='gcc'):
    self.cfile = cfile
    self.preprocessed = preprocessed
    self.cppargs = cppargs
    self.gcc = 'gcc'
  
  def run(self):
    cmd_line = [self.gcc,  '-x', 'c++', self.cfile, '-E', '-P']
    cmd_line.extend(self.cppargs)
    cmd_line.extend(['-o', self.preprocessed])
    print ' '.join(cmd_line)
    p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, close_fds=True)
    p.wait()
    build = p.stdout.read().strip()
    if len(build) == 0:
      log.info("GENERATED %s - please correct source code gccxml if next step fails"%(self.preprocessed))
    else:
      log.info(build)
    return len(build)



def process(cfile, preprocessed):
  #p = Preprocess(cfile, preprocessed, OPENSSL_ARGS)
  p = Preprocess(cfile, preprocessed, NSS_ARGS)
  return p.run()


