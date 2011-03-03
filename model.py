#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"


class mapping:
  '''	struct _mapping *next;
  unsigned long address;
  unsigned int size;
  int flags;
  const char *name;
  proc_t *proc;
  char * data;
  '''
  next=None
  address=0
  size=0
  flags=0
  name=None
  proc=0
  data=None
  def __init__(self,address,size,flags,name):
    self.address=address
    self.size=size
    self.flags=flags
    self.name=name
      
class proc:
  pid=None
  maps=None
