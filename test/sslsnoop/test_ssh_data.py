#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests end results data on ssh dump."""

import logging
import unittest
import sys

import sslsnoop
from sslsnoop import ctypes_openssh as cssh

from haystack import dump_loader
from haystack import model
from haystack import abouchet
from haystack import memory_mapper

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"

log = logging.getLogger('test_ssh_data')


class Test_SSH_1_Data_pickled(unittest.TestCase):
  '''
  ssh.1
  session_state is at 0xb84ee318
  '''
  
  @classmethod
  def setUpClass(self):
    d = {'pickled': True, 
        'dumpname': 'test/dumps/ssh/ssh.1/', 
        'structName': 'sslsnoop.ctypes_openssh.session_state',
        'addr': '0xb84ee318',
        'pid': None,
        'memfile': None,
        'interactive': None,
        'human': None,
        'json': None,
        }
    args = type('args', ( object,), d)
    #
    addr = int(args.addr,16)
    structType = abouchet.getKlass(args.structName)
    self.mappings = memory_mapper.MemoryMapper(args).getMappings()
    self.finder = abouchet.StructFinder(self.mappings)
    memoryMap = model.is_valid_address_value(addr, self.finder.mappings)
    # done          
    self.session_state, self.found = self.finder.loadAt( memoryMap, addr, structType)
    # if both None, that dies.
    #self.mappings = None
    #self.finder = None
        
         
  @classmethod
  def tearDownClass(self):
    self.mappings = None
    self.finder = None
    self.found = None
    self.session_state = None
    model.reset()
    pass
  
  def test_session_state(self):
    self.assertTrue(self.found)
    log.info('hey')
    log.info(type(self.session_state) )
    log.info( self.session_state._fields_ )
    import ctypes
    log.info( ctypes.addressof(self.session_state) )
    log.info( self.session_state.connection_in )
    log.info( self.session_state.incoming_packet )
    
    log.info(str(self.session_state) )
    
    d=(self.session_state.toPyObject(), self.found)
    print 'd ok '

  def test_session_state2(self):
    self.assertTrue(self.found)


if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  unittest.main(verbosity=2)

