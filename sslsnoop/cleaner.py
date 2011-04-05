#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import logging, re

log=logging.getLogger('preprocess')

class HeaderCleaner:
  '''
    Cleans a Preprocessed File for gccxml comsumption.
    Strips off static functions and extern references.
    
    @param preprocessed: the preprocessed file name
    @param out: the desired output file
  '''
  functionsReOneLine = r"""  # static inline bool kernel_page_present(struct page *page) { return true; } 
  ^ ((static\ (inline|__inline__)) 
         (\s+__attribute__\(\(always_inline\)\))*  (?P<sig> \s+\w+)* (\s*[*]\s*)* 
                (?P<funcname>  \w+ ) (?P<args> \s*\([^{;]+?\)\s* ) 
        ( { }$ |{ .*? }$  )
    )     
   """
  functionsRe = r"""  # nice - ok for pointers
  ^ ((static\ (inline|__inline__)) 
         (\s+__attribute__\(\(always_inline\)\))*  (?P<sig> \s+\w+)* (\s*[*]\s*)* 
                (?P<funcname>  \w+ ) (?P<args> \s*\([^{;]+?\)\s* ) 
        ( { }$ |{ . }$ | {  .*?  ^}$  )
    )     
   """
  functionsRe2 = r"""  # nice - ok for pointers
  ^ ( (__extension__\s+)*   (extern\ (inline|__inline__|__inline)) 
         (\s+__attribute__\(\((always_inline|__gnu_inline__)\)\))*  (?P<sig> \s+\w+)* (\s*[*]\s*)* 
                (?P<funcname>  \w+ ) (?P<args> \s*\([^{;]+?\)\s* ) 
        ( { }$ |{ . }$ | {  .*?  ^}$  )
    )     
   """
  externsRe = r"""  # extern functions sig.
  ^((extern) \s+ (?!struct|enum) [^{]*? ;$  ) 
   """
  externsRe2 = r"""  # functions sig. on one line
  ^((void|unsigned|long|int) \s+ (?!struct|enum) .*? ;$  ) 
   """
  def __init__(self, preprocessed, out):
    self.preprocessed = file(preprocessed).read()
    self.out = out
    
  def stripFunctions(self, data):
    # delete oneliner
    REGEX_OBJ = re.compile( self.functionsReOneLine, re.MULTILINE| re.VERBOSE)
    data1 = REGEX_OBJ.sub(r'/** // supprimed function a:  */',data)

    REGEX_OBJ = re.compile( self.functionsRe, re.MULTILINE| re.VERBOSE | re.DOTALL)
    data2 = REGEX_OBJ.sub(r'/** // supprimed function b:  */',data1)

    REGEX_OBJ = re.compile( self.functionsRe2, re.MULTILINE| re.VERBOSE | re.DOTALL)
    data3 = REGEX_OBJ.sub(r'/** // supprimed function c:  */',data2)
    return data3


  def stripExterns(self, data):
    REGEX_OBJ2 = re.compile( self.externsRe, re.MULTILINE| re.VERBOSE | re.DOTALL)
    data1 = REGEX_OBJ2.sub(r'/** // supprimed extern  */', data)

    REGEX_OBJ2 = re.compile( self.externsRe2, re.MULTILINE| re.VERBOSE | re.DOTALL)
    data2 = REGEX_OBJ2.sub(r'/** // supprimed function sig  */', data1)
    return data2

  def changeReservedWords(self, data):
    data1 = data.replace('*new);','*new1);')
    data1 = data1.replace('*proc_handler;','*proc_handler1;')
    mre = re.compile(r'\bprivate;')
    data2 = mre.sub('private1;',data1)
    mre = re.compile(r'\bnamespace\b')
    data3 = mre.sub('namespace1',data2)
    return data3

  def clean(self):
    data2 = self.stripFunctions(self.preprocessed)
    data3 = self.stripExterns(data2)
    #data3 = data2
    data4 = self.changeReservedWords(data3)
    self.fout = file(self.out,'w')
    return self.fout.write(data4)



def clean(prepro, out):
  clean = HeaderCleaner(prepro, out)
  return clean.clean()

#clean('ctypes_linux_generated.c','ctypes_linux_generated_clean.c')


data='''
typedef int (*pte_fn_t)(pte_t *pte, pgtable_t token, unsigned long addr,
   void *data);
extern int apply_to_page_range(struct mm_struct *mm, unsigned long address,
          unsigned long size, pte_fn_t fn, void *data);
void vm_stat_account(struct mm_struct *, unsigned long, struct file *, long);
static inline void
kernel_map_pages(struct page *page, int numpages, int enable) {}
static inline void enable_debug_pagealloc(void)
{
}
static inline bool kernel_page_present(struct page *page) { return true; }
extern struct vm_area_struct *get_gate_vma(struct task_struct *tsk);
int in_gate_area_no_task(unsigned long addr);
int in_gate_area(struct task_struct *task, unsigned long addr);
'''

from cleaner import HeaderCleaner
import re
def testF(data):
  obj = re.compile( HeaderCleaner.functionsRe, re.MULTILINE| re.VERBOSE | re.DOTALL)
  for p in obj.findall(data):
    print p[0]
    print '----------------------'
  return

def testF2(data):
  obj = re.compile( HeaderCleaner.functionsRe2, re.MULTILINE| re.VERBOSE | re.DOTALL)
  for p in obj.findall(data):
    print p[0]
    print '----------------------'
  return

def testE(data):
  obj = re.compile( HeaderCleaner.externsRe, re.MULTILINE| re.VERBOSE | re.DOTALL)
  for p in obj.findall(data):
    print p[0]
    print '----------------------'
  return

def testE2(data):
  obj = re.compile( HeaderCleaner.externsRe2, re.MULTILINE| re.VERBOSE | re.DOTALL)
  for p in obj.findall(data):
    print p[0]
    print '----------------------'
  return

'''
HeaderCleaner.externsRe = r"""  # extern functions sig.
  ^((extern) \s+ (?!struct|enum) .*? ;$  ) 
   """
HeaderCleaner.externsRe2 = r"""  # functions sig. on one line
  ^((void|unisgned|long|int) \s+ (?!struct|enum) .*? ;$  ) 
   """


c = HeaderCleaner('/dev/null','/dev/null')
data1 = c.stripFunctions( data )
data2 = c.stripExterns( data1 )

print data1


'mf_flags' in data
'mf_flags' in data1
'mf_flags' in data2


testE(data)


'''








