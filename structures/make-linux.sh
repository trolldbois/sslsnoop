#!/bin/sh


build=`uname -r`
#KHEADERS="/usr/src/linux-headers-2.6.35-28/"
KHEADERS="/usr/src/linux-headers-$build/"
CCFLAGS="-D__KERNEL__ " #-D__ASSEMBLY__"
INCLUDES="-I$PWD -I$KHEADERS/include/ -I$KHEADERS/include/linux/ " #-I$KHEADERS/arch/x86/include/"


#h2xml -k  $CCFLAGS $INCLUDES  ctypes_linux.h -o ctypes_linux.xml \
# && xml2py ctypes_linux.xml -o ctypes_linux_generated.py

#gccxml ctypes_linux.c -E -nostdinc++ -fxml=ctypes_linux.xml -D __KERNEL__ -I /home/jal/Security/honeynet/victoria/ctypes -I /usr/src/linux-headers-2.6.35-28//include/ -I /usr/src/linux-headers-2.6.35-28//include/linux/ -I /usr/src/linux-headers-2.6.35-28//arch/x86/include/ -I /usr/src/linux-headers-2.6.35-23-generic-pae//include/ -nostdinc -isystem /usr/lib/gcc/i686-linux-gnu/4.4.5/include -I/usr/src/linux-headers-lbm- -include $KHEADERS/include/generated/autoconf.h -Iubuntu/include -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -m32 -msoft-float -mregparm=3 -freg-struct-return -mpreferred-stack-boundary=2 -march=i686 -mtune=generic -maccumulate-outgoing-args -ffreestanding -fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -fno-omit-frame-pointer -fno-optimize-sibling-calls -g -fno-inline-functions-called-once -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow | grep -v ^\# > ctypes_linux_generated.c && echo "GENERATED ctypes_linux_generated.c - please correct source code gccxml is gonna choke on kernel source code"


gccxml ctypes_linux_generated.c -fxml=ctypes_linux_generated.xml && echo "GENERATED ctypes_linux_generated.xml" \
  && xml2py ctypes_linux_generated.xml -o ctypes_linux_generated.py -k d -k e -k s -k t && echo "GENERATED ctypes_linux_generated.py - DONE"



