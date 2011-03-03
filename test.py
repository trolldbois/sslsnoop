
#test read memory

import ptrace
f=file('/proc/8902/maps')
lines=f.readlines()

