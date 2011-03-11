#!/bin/sh
#
#
#
#
#

export INCLUDES="-I./biblio/openssh-5.5p1/ -I./biblio/openssh-5.5p1/build-deb/ -I./biblio/openssl-0.9.8o/crypto/ -I./biblio/openssl-0.9.8o/"

gcc -g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wno-pointer-sign -Wformat-security -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -Os -DSSH_EXTRAVERSION=\"Debian-4ubuntu5\"  $INCLUDES  -DSSHDIR=\"/etc/ssh\" -D_PATH_SSH_PROGRAM=\"/usr/bin/ssh\" -D_PATH_SSH_ASKPASS_DEFAULT=\"/usr/bin/ssh-askpass\" -D_PATH_SFTP_SERVER=\"/usr/lib/openssh/sftp-server\" -D_PATH_SSH_KEY_SIGN=\"/usr/lib/openssh/ssh-keysign\" -D_PATH_SSH_PKCS11_HELPER=\"/usr/lib/openssh/ssh-pkcs11-helper\" -D_PATH_SSH_PIDDIR=\"/var/run\" -D_PATH_PRIVSEP_CHROOT_DIR=\"/var/run/sshd\" -DSSH_RAND_HELPER=\"/usr/lib/openssh/ssh-rand-helper\" -D_PATH_SSH_DATADIR=\"/usr/share/ssh\" -DHAVE_CONFIG_H  -D__SIZE_SSH ssh-types.c -o ssh-types

gcc -g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wno-pointer-sign -Wformat-security -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -Os -DSSH_EXTRAVERSION=\"Debian-4ubuntu5\"  $INCLUDES  -DSSHDIR=\"/etc/ssh\" -D_PATH_SSH_PROGRAM=\"/usr/bin/ssh\" -D_PATH_SSH_ASKPASS_DEFAULT=\"/usr/bin/ssh-askpass\" -D_PATH_SFTP_SERVER=\"/usr/lib/openssh/sftp-server\" -D_PATH_SSH_KEY_SIGN=\"/usr/lib/openssh/ssh-keysign\" -D_PATH_SSH_PKCS11_HELPER=\"/usr/lib/openssh/ssh-pkcs11-helper\" -D_PATH_SSH_PIDDIR=\"/var/run\" -D_PATH_PRIVSEP_CHROOT_DIR=\"/var/run/sshd\" -DSSH_RAND_HELPER=\"/usr/lib/openssh/ssh-rand-helper\" -D_PATH_SSH_DATADIR=\"/usr/share/ssh\" -DHAVE_CONFIG_H  -D__SIZE_SSL ssh-types.c -o ssl-types

