
from haystack import model
import ctypes, mmap, os, sys
#from structures import ctypes_linux_generated as kernel
import ctypes_linux as kernel
from haystack.memory_mapping import MemoryDumpMemoryMapping

systemmap = file('System.map-2.6.26-2-686')
for l in systemmap.readlines():
  addr,t,name=l.split(' ')
  if name == 'init_task':
    break

addr=int(addr,16)

print "System.map gives init_task @%lx"%addr

ctypes.sizeof(kernel.task_struct)
memdump = file('victoria-v8.memdump.img')
dumpsize = os.fstat(memdump.fileno()).st_size
memoryMap=MemoryDumpMemoryMapping(memdump,0, dumpsize )
#memoryMap.readStruct(addr, kernel.task_struct)

m2=mmap.mmap(memdump.fileno(), dumpsize, access=mmap.ACCESS_READ)

task1 = 0xf42f9d4
t1 = memoryMap.readStruct(task1, kernel.task_struct)
#print t1, t1.toString()

t1_comm_addr = 0xf42fb29
print repr(memoryMap.local_mmap[t1_comm_addr:t1_comm_addr+16])
'''
list_ptr 0xcf45cdf4 task_struct tasks 212 so task is @0xcf45cd20
fileaddrspace, read addr 0xe979b94 for 4 bytes
fileaddrspace, read addr 0xf45ce30 for 4 bytes   # pid
fileaddrspace, read addr 0xf45cef4 for 4 bytes   # uid ? /cred.uid
fileaddrspace, read addr 0xf45cf49 for 16 bytes  # comm
exim4                1942            101
'''
exim_pid = 0xf45ce30
print memoryMap.readWord(exim_pid)  # offset of pid is 272
exim_addr = exim_pid - 272
#exim_addr = memoryMap.readWord(p_exim)
print hex(exim_addr) #0xf45cd20
t1 = memoryMap.readStruct(exim_addr, kernel.task_struct)
#print t1.toString()

def offset(typ, name):
  ''' more or less '''
  i=0
  for f in typ._fields_:
    if f[0] == name:
      return i
    i+= ctypes.sizeof(f[1])

print offset(kernel.task_struct, 'pid') # 517 .. yeah.. compilation flags matters ...
# so, how do you translate init_task_addr 0xcf45cd20 into 0xf45cd20 ... chop 0xc ?

sys.exit() 


import re
fulldata=file('ctypes_linux_generated.c').read()

#__attribute__((no_instrument_function)) 

def stripFunctions(data):
  REGEX_STR = r"""  # nice - ok for pointers
  ^ (__attribute__\(\(no_instrument_function\)\)\s+)* ((static\ (inline|__inline__)) 
         (\s+__attribute__\(\(always_inline\)\))*  (?P<sig> \s+\w+)* (\s*[*]\s*)* 
                (?P<funcname>  \w+ ) (?P<args> \([^{;]+?\)\s* ) 
        ( { . }$ | {  .*?  ^}$  )
    )     
   """
  REGEX_OBJ = re.compile(REGEX_STR, re.MULTILINE| re.VERBOSE | re.DOTALL)
  data2 = REGEX_OBJ.sub('// supprimed function',data)
  '''
for p in REGEX_OBJ.findall(data):
  print p[0]
  print '--------'
fout = file('out.c','w')
for p in REGEX_OBJ.findall(fulldata):
  fout.write(p[0])
fout.close()
'''
  return data2


def stripExterns(data):
  REGEX_STR2 = r"""  # 
^((extern) \s+ (?!struct|enum) .*? ;$  ) 
 """
  REGEX_OBJ2 = re.compile(REGEX_STR2, re.MULTILINE| re.VERBOSE | re.DOTALL)
  '''
  for p in REGEX_OBJ2.findall(data):
  print p[0]
  print '--------'
fout = file('out.c','w')
for p in REGEX_OBJ2.findall(fulldata):
  fout.write(p[0]+'\n')
  
fout.close()
  '''
  data3 = REGEX_OBJ2.sub('// supprimed extern', data)
  return data3

data2 = stripFunctions(fulldata)
data3 = stripExterns(data2)

file('out.c','w').write(data3)





data='''
extern __attribute__((section(".data..percpu" ""))) __typeof__(u16) x86_cpu_to_apicid; extern __typeof__(u16) *x86_cpu_to_apicid_early_ptr; extern __typeof__(u16) x86_cpu_to_apicid_early_map[];
extern __attribute__((section(".data..percpu" ""))) __typeof__(u16) x86_bios_cpu_apicid; extern __typeof__(u16) *x86_bios_cpu_apicid_early_ptr; extern __typeof__(u16) x86_bios_cpu_apicid_early_map[];
extern struct {
 void *sp;
 unsigned short ss;
} stack_start;
extern struct tvec_base boot_tvec_bases;
'''
stripExterns(data)


REGEX_STR2 = r"""  # 
^((extern) \s+ (?!struct|enum) .*? ;$  )     
"""
REGEX_OBJ2 = re.compile(REGEX_STR2, re.MULTILINE| re.VERBOSE | re.DOTALL)
for p in REGEX_OBJ2.findall(data):
  print p[0]
  print '--------'


REGEX_OBJ = re.compile(REGEX_STR, re.MULTILINE| re.VERBOSE | re.DOTALL)
for p in REGEX_OBJ.findall(data):
  print p[0]
  print '--------'


fout = file('out.c','w')
for p in REGEX_OBJ.findall(fulldata):
  fout.write(p[0])
fout.close()




'''
python abouchet.py --string --debug --fromdump victoria-v8.kcore.img ctypes_linux.task_struct search --maxnum 10 --fullscan

import abouchet
struct = 'ctypes_linux.task_struct'
filename = 'victoria-v8.kcore.img'
insts = abouchet.findStructInFile(filename, struct, maxNum=1, fullScan=True)
instance = insts[0][0]

print instance.toString()

import debian_2_6_26_2_vtypes
debian_2_6_26_2_vtypes.linux_types['task_struct']
## listes des offset de la structures


debian_2_6_26_2_vtypes.linux_gvars['init_task']
#  [3224687360L, ['task_struct']]
len(debian_2_6_26_2_vtypes.linux_types['VOLATILITY_MAGIC'])
# 2
debian_2_6_26_2_vtypes.linux_types['VOLATILITY_MAGIC'][1].keys()
# ['DTB', 'system_map']
debian_2_6_26_2_vtypes.linux_types['VOLATILITY_MAGIC'][1]['DTB'][1]
['VolatilityMagic', {'value': 3915776}]








'''



