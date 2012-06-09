#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit test module."""

import sys
if sys.version_info < (2, 7):
  import unittest2 as unittest
else:
  import unittest

__author__ = "Loic Jaquemet"
__copyright__ = "Copyright (C) 2012 Loic Jaquemet"
__email__ = "loic.jaquemet+python@gmail.com"
__license__ = "GPL"
__maintainer__ = "Loic Jaquemet"
__status__ = "Production"



def alltests():
  ret = unittest.TestLoader().discover('test/sslsnoop/')
  return ret


#alltests = suite()

if __name__ == '__main__':
  unittest.main(verbosity=0)
  #suite = unittest.TestLoader().loadTestsFromTestCase(TestFunctions)
  #unittest.TextTestRunner(verbosity=2).run(suite)
