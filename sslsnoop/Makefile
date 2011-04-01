#!/bin/sh
#
#
#
#
#


#export INCLUDES="-I$PWD/biblio/openssh-5.5p1/ -I$PWD/biblio/openssh-5.5p1/build-deb/ -I$PWD/biblio/openssl-0.9.8o/crypto/ -I$PWD/biblio/openssl-0.9.8o/"

#gcc -g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wno-pointer-sign -Wformat-security -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -Os -DSSH_EXTRAVERSION=\"Debian-4ubuntu5\"  $INCLUDES  -DSSHDIR=\"/etc/ssh\" -D_PATH_SSH_PROGRAM=\"/usr/bin/ssh\" -D_PATH_SSH_ASKPASS_DEFAULT=\"/usr/bin/ssh-askpass\" -D_PATH_SFTP_SERVER=\"/usr/lib/openssh/sftp-server\" -D_PATH_SSH_KEY_SIGN=\"/usr/lib/openssh/ssh-keysign\" -D_PATH_SSH_PKCS11_HELPER=\"/usr/lib/openssh/ssh-pkcs11-helper\" -D_PATH_SSH_PIDDIR=\"/var/run\" -D_PATH_PRIVSEP_CHROOT_DIR=\"/var/run/sshd\" -DSSH_RAND_HELPER=\"/usr/lib/openssh/ssh-rand-helper\" -D_PATH_SSH_DATADIR=\"/usr/share/ssh\" -DHAVE_CONFIG_H  -D__SIZE_SSH ssh-types.c -o ssh-types

#gcc -g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wno-pointer-sign -Wformat-security -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -Os -DSSH_EXTRAVERSION=\"Debian-4ubuntu5\"  $INCLUDES  -DSSHDIR=\"/etc/ssh\" -D_PATH_SSH_PROGRAM=\"/usr/bin/ssh\" -D_PATH_SSH_ASKPASS_DEFAULT=\"/usr/bin/ssh-askpass\" -D_PATH_SFTP_SERVER=\"/usr/lib/openssh/sftp-server\" -D_PATH_SSH_KEY_SIGN=\"/usr/lib/openssh/ssh-keysign\" -D_PATH_SSH_PKCS11_HELPER=\"/usr/lib/openssh/ssh-pkcs11-helper\" -D_PATH_SSH_PIDDIR=\"/var/run\" -D_PATH_PRIVSEP_CHROOT_DIR=\"/var/run/sshd\" -DSSH_RAND_HELPER=\"/usr/lib/openssh/ssh-rand-helper\" -D_PATH_SSH_DATADIR=\"/usr/share/ssh\" -DHAVE_CONFIG_H  -D__SIZE_SSL ssh-types.c -o ssl-types



# make headers
MOZSOURCE="$PWD/biblio//firefox-3.6.15+build1+nobinonly/mozilla/"
#./ipc/chromium/src/base/third_party/nspr/
INCLUDES="-I. -I$MOZSOURCE/nsprpub/pr/include/ -I$MOZSOURCE/security/nss/lib/ssl/ "
INCLUDES="$INCLUDES -I$MOZSOURCE/ipc/chromium/src/base/third_party/nspr/ -I$MOZSOURCE/ipc/chromium/src/"
INCLUDES="$INCLUDES -I$MOZSOURCE/security/nss/lib/ -I$MOZSOURCE/security/nss/lib/util/"
INCLUDES="$INCLUDES -I$MOZSOURCE/security/nss/lib/certdb/ -I$MOZSOURCE/security/nss/lib/freebl/"
INCLUDES="$INCLUDES -I$MOZSOURCE/security/nss/lib/softoken/ -I$MOZSOURCE/security/nss/lib/cryptohi/"
INCLUDES="$INCLUDES -I$MOZSOURCE/nsprpub/lib/libc/include/ -I$MOZSOURCE/nsprpub/lib/ds/"


####h2xml $INCLUDES -c ctypes_nss.h -o ctypes_nss.xml \
#### && xml2py ctypes_nss.xml -o ctypes_nss_generated.py

INCLUDES="-I$PWD -I/usr/include/openssl/"
#h2xml $INCLUDES -c ctypes_openssl.h -o ctypes_openssl.xml \
# && xml2py ctypes_openssl.xml -o ctypes_openssl_generated.py

clean:
	rm -f ctypes_openssl_generated.c ctypes_openssl_generated_clean.c ctypes_openssl_generated.py ctypes_openssl_generated.pyc


