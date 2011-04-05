#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging, os, subprocess

log=logging.getLogger('preprocess')

class Preprocess:
  '''
    Make a Preprocessed File from a C file
    
    @param cfile: the desired input c file name
    @param preprocessed: the preprocessed file name
  '''
  #sslInc#export INCLUDES="-I$PWD/biblio/openssl-0.9.8o/crypto/ -I$PWD/biblio/openssl-0.9.8o/"

  def __init__(self, cfile, preprocessed, gcc='gcc'):
    self.cfile = cfile
    self.preprocessed = preprocessed
    self.gcc = 'gcc'
  
  def getOpensslHeaders(self):
    self.opensslHeaders = "/usr/include/openssl/"
    return self.opensslHeaders 

  def run(self):
    self.getOpensslHeaders()    
    cmd_line = [self.gcc,  '-x', 'c++', self.cfile, '-E', '-P', '-DOPENSSL_THREADS', '-D_REENTRANT',
     '-DDSO_DLFCN', '-DHAVE_DLFCN_H', '-DL_ENDIAN', '-DTERMIO', '-O3', '-fomit-frame-pointer', '-Wall',
     '-DOPENSSL_BN_ASM_PART_WORDS', '-DOPENSSL_IA32_SSE2', '-DSHA1_ASM', '-DMD5_ASM', '-nostdinc++',
     '-DRMD160_ASM', '-DAES_ASM', '-o', self.preprocessed]
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
  p = Preprocess(cfile, preprocessed)
  return p.run()

#clean('ctypes_openssl_generated.c','ctypes_openssl_generated_clean.c')
