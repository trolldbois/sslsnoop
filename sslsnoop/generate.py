#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging, os, subprocess, sys

import cleaner, preprocess

log=logging.getLogger('generate')

class Generator:
  '''
    Wrapper around Ctypeslib
    Make python objects out of structures from C headers
    
    @param cleaned: the desired input c file name, preprocessed and cleaned
    @param pymodulename: the desired output module name
  '''
  def __init__(self, cleaned, pymodulename='ctypes_linux_generated'):
    if not os.access(cleaned, os.F_OK):
      raise IOError('The cleaned file %s does not exist'%(cleaned))
    self.cleaned = cleaned
    self.py = pymodulename
    self.xmlfile = '%s.%s'%(self.py, 'xml')
    self.pyfile = '%s.%s'%(self.py, 'py')
    self.gccxml = 'gccxml'
    self.h2xml = 'h2xml'
    self.xml2py = 'xml2py'
  
  def makeXml(self):
    cmd_line = [ self.gccxml, self.cleaned, '-fxml=%s'%(self.xmlfile), '-fextended-identifiers', '-fpreprocessed']
    p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    p.wait()
    build = p.stderr.read().strip()
    #print 'makexml', build
    if len(build) == 0:
      log.info( "GENERATED XML %s"%(self.xmlfile))
    else:
      log.error('Please clean %s\n%s'%(self.cleaned, build))
    return len(build)

  def makeH2Xml(self, args):
    cmd_line = [ self.h2xml, '-c', self.cleaned, '-o', self.xmlfile ]
    cmd_line.extend(args)
    p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    p.wait()
    build = p.stderr.read().strip()
    print 'makexml', build
    if len(build) == 0:
      log.info( "GENERATED XML %s"%(self.xmlfile))
    else:
      log.error('Please clean %s\n%s'%(self.cleaned, build))
    return len(build)

  def makePy(self):
    if not os.access(self.xmlfile, os.F_OK):
      log.error('The XML file %s has not been generated'%(self.xml))
      return -1
    cmd_line = [self.xml2py, self.xmlfile, '-o', self.pyfile] 
    # we need define's
    # '-k', 'd', '-k', 'e', '-k', 's', '-k', 't']
    p = subprocess.Popen(cmd_line, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    p.wait()
    build = p.stderr.read().strip()
    if len(build) == 0:
      log.warning('\n%s'%build)
    log.info( "GENERATED PY module %s"%(self.pyfile))
    return 0

  def run(self):
    ret = self.makeXml()
    if  ret > 0:
      return ret
    ret = self.makePy()
    if ret > 0:
      return ret
    log.info('GENERATION Done. Enjoy %s'%(self.pyfile))
    return 0

def gen( cleaned, modulename):
  p = Generator(cleaned, modulename)
  return p.run()

def gen2( cleaned, modulename, args):
  p = Generator(cleaned, modulename)
  p.makeH2Xml(args)
  p.makePy()
  return 0


def make(sourcefile, modulename, target=False):
  ''' using gccxml directly distort ctypeslib performances
  but on some libraries, we don't have a choice.
  '''
  if not os.access(sourcefile, os.F_OK):
    raise IOError(sourcefile)
  #sourcefile
  basename = os.path.basename(sourcefile)
  preprocessed = "%s.c"%(modulename)
  cleaned = "%s_clean.c"%(modulename)
  xml = "%s.xml"%(modulename)
  pyfinal = "%s.py"%(modulename)
  if target:
    gen2(sourcefile, modulename, target)
    log.info('PYFINAL - OK')
  else:
    if not os.access(pyfinal, os.F_OK):
      if not os.access(cleaned, os.F_OK):
        if not os.access(preprocessed, os.F_OK):
          # preprocess the file
          if preprocess.process(sourcefile, preprocessed) > 0:
            return
        log.info('PREPROCESS - OK')
        # clean it
        if cleaner.clean(preprocessed, cleaned) > 0:
          return
      log.info('CLEAN - OK')
      # generate yfinal
      if gen(cleaned, modulename) > 0:
        return
    log.info('PYFINAL - OK')
  __import__(modulename)
  import inspect
  nbClass = len(inspect.getmembers(sys.modules[modulename], inspect.isclass))
  nbMembers = len(inspect.getmembers(sys.modules[modulename], inspect.isclass))
  log.info("module %s has %d members for %d class"%(modulename, nbMembers, nbClass))

logging.basicConfig(level=logging.INFO)

#generate.gen('ctypes_linux_generated_clean.c','ctypes_linux_generated')

# generate.make('ctypes_linux.c','ctypes_linux_generated')
#make('ctypes_openssl.c','ctypes_openssl_generated')

make('ctypes_nss.c','ctypes_nss_generated', preprocess.NSS_ARGS)

