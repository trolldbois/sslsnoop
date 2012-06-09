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
    mappings = memory_mapper.MemoryMapper(args).getMappings()
    finder = abouchet.StructFinder(mappings)
    memoryMap = model.is_valid_address_value(addr, finder.mappings)
    # done          
    self.session_state, self.found = finder.loadAt( memoryMap, addr, structType)
        
         
  @classmethod
  def tearDownClass(self):
    model.reset()
    pass
  
  def test_session_state(self):
    self.assertTrue(self.found)

  def test_session_state2(self):
    self.assertTrue(self.found)


if __name__ == '__main__':
  unittest.main(verbosity=2)

