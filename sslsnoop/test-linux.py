
import model, ctypes, mmap, os
from structures import ctypes_linux_generated as kernel
from memory_mapping import MemoryDumpMemoryMapping

systemmap = file('System.map-2.6.26-2-686')
for l in systemmap.readlines():
  addr,t,name=l.split(' ')
  if name == 'init_task':
    break

addr=int(addr,16)

print "%lx"%addr

ctypes.sizeof(kernel.task_struct)
memdump = file('victoria-v8.kcore.img')
dumpsize = os.fstat(memdump.fileno()).st_size
memoryMap=MemoryDumpMemoryMapping(memdump,0, dumpsize )
memoryMap.readStruct(addr, kernel.task_struct)

m2=mmap.mmap(memdump.fileno(), dumpsize, access=mmap.ACCESS_READ)


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












