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
  pass


def get_dict_value(root, attrlist):
  tmp = root
  for member in attrlist:
    tmp = tmp[member]
  return tmp

def get_member_value(root, attrlist):
  tmp = root
  for member in attrlist:
    tmp = getattr(tmp, member)
  return tmp

def test_tpl(self, attr):
  expected = get_dict_value( self.expected, attr)
  found    = get_member_value( self.session_state, attr)
  print expected
  print found
  self.assertEquals( expected, found, '.'.join(attr) )
  
#def _gen_attr_tests(cls):
#  import functools
#  def action( k, v, attr):
#    # create class def dynamically
#    name = 'test_%s'%('_'.join(attr+k))
#    setattr(cls, name, functools.partial( test_tpl, attr) )
#  
#  _gen_recurse_dict( self.expected, action, [] )

def _gen_recurse_dict( d, cb, attr ):
  for k,v in d:
    next = attr+k
    if type(v) == dict:
      self._gen_recurse_dict( v, fn, next )
    else:
      cb(k, v, next)

# generate dynamic value-tests
#_gen_attr_tests(Test_SSH_1_Data_pickled)


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
    
    self.expected = {        
"connection_in": 3, 
"connection_out": 3, 
"remote_protocol_flags": 0L, 
"receive_context": {		 # <CipherContext at @???>
	"plaintext": 0, 
	"evp": {			 # <evp_cipher_ctx_st at @???>
		"cipher": 0xb7832b20, #(FIELD NOT LOADED)
		"engine": 0x0,
		"encrypt": 0, 
		"buf_len": 0, 
		"oiv": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
		"iv": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
		"buf": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
		"num": 0, 
		"app_data": 0xb84f3910, #Void pointer NOT LOADED 
		"key_len": 16, 
		"flags": 0L, 
		"cipher_data": 0x0,
		"final_used": 0, 
		"block_mask": 15, 
		"final": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
	},
	"cipher": 0xb7832288, #(FIELD NOT LOADED)
},
"send_context": {		 # <CipherContext at @???>
	"plaintext": 0, 
	"evp": {			 # <evp_cipher_ctx_st at @???>
		"cipher": 0xb7832b20, #(FIELD NOT LOADED)
		"engine": 0x0,
		"encrypt": 1, 
		"buf_len": 0, 
		"oiv": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
		"iv": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
		"buf": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
		"num": 0, 
		"app_data": 0xb84f4068, #Void pointer NOT LOADED 
		"key_len": 16, 
		"flags": 0L, 
		"cipher_data": 0x0,
		"final_used": 0, 
		"block_mask": 15, 
		"final": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
	},
	"cipher": 0xb7832288, #(FIELD NOT LOADED)
},
"input": {		 # <Buffer at @???>
	"buf": 0xb84ee558, #(FIELD NOT LOADED)
	"alloc": 4096L, 
	"offset": 48L, 
	"end": 48L, 
},
"output": {		 # <Buffer at @???>
	"buf": 0xb84ef560, #(FIELD NOT LOADED)
	"alloc": 4096L, 
	"offset": 448L, 
	"end": 448L, 
},
"outgoing_packet": {		 # <Buffer at @???>
	"buf": 0xb84f0568, #(FIELD NOT LOADED)
	"alloc": 4096L, 
	"offset": 0L, 
	"end": 0L, 
},
"incoming_packet": {		 # <Buffer at @???>
	"buf": 0xb84f1570, #(FIELD NOT LOADED)
	"alloc": 4096L, 
	"offset": 28L, 
	"end": 28L, 
},
"compression_buffer": {		 # <Buffer at @???>
	"buf": 0x0,
	"alloc": 0L, 
	"offset": 0L, 
	"end": 0L, 
},
"compression_buffer_ready": 0, 
"packet_compression": 0, 
"max_packet_size": 32768L, 
"initialized": 1, 
"interactive_mode": 1, 
"server_side": 0, 
"after_authentication": 1, 
"keep_alive_timeouts": 0, 
"packet_timeout_ms": -1, 
"newkeys" :{"0": 0xb84f4240, #(FIELD NOT LOADED)
"1": 0xb84f4360, #(FIELD NOT LOADED)
},
"p_read": {		 # <packet_state at @???>
	"seqnr": 12L, 
	"packets": 9L, 
	"blocks": 33L, 
	"bytes": 2024L, 
},
"p_send": {		 # <packet_state at @???>
	"seqnr": 12L, 
	"packets": 9L, 
	"blocks": 97L, 
	"bytes": 2792L, 
},
"max_blocks_in": 4294967296L, 
"max_blocks_out": 4294967296L, 
"rekey_limit": 0L, 
"ssh1_key": b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
"ssh1_keylen": 0L, 
"extra_pad": 0, 
"packet_discard": 0L, 
"packet_discard_mac": 0x0,
"packlen": 0L, 
"rekeying": 0, 
"set_interactive_called": 1, 
"set_maxsize_called": 0, 
"outgoing": {		 # <TAILQ_HEAD_PACKET at @???>
	"tqh_first": 0x0,
	"tqh_last": 0xb84ee54c, #(FIELD NOT LOADED)
},
}
  
  
  @classmethod
  def tearDownClass(self):
    self.mappings = None
    self.finder = None
    self.found = None
    self.session_state = None
    model.reset()
    pass
  
  def test_session_state(self):
    ''' test session_state against expected values'''
    self.assertTrue(self.found)
    
    obj = self.session_state.toPyObject()
    self._recurse_expect( obj, self.expected, [])
    
    log.debug(obj.connection_in)

  def _recurse_expect(self, foundRoot, expectedRoot, attr ):
    ''' gro through the exepected values and compare results '''
    for k,v in expectedRoot.items():
      next = attr+[k] # attrname list
      foundNext = getattr(foundRoot, k)
      if type(v) == dict:
        self._recurse_expect( foundNext, v, next )
      else:
        test_tpl(self, next)


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  log.setLevel(level=logging.DEBUG)
  unittest.main(verbosity=4)

