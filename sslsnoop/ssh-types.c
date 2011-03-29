/* $OpenBSD: packet.c,v 1.166 2009/06/27 09:29:06 andreas Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains code implementing the packet protocol and communication
 * with the other side.  This same code is used both on client and server side.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * SSH2 packet format added by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS"" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <includes.h>
 
#include <sys/types.h>
#include "openbsd-compat/sys-queue.h"
#include <sys/param.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "xmalloc.h"
#include "buffer.h"
#include "packet.h"
#include "crc32.h"
#include "compress.h"
#include "deattack.h"
#include "channels.h"
#include "compat.h"
#include "ssh1.h"
#include "ssh2.h"
#include "cipher.h"
#include "key.h"
#include "kex.h"
#include "mac.h"
#include "log.h"
#include "canohost.h"
#include "misc.h"
#include "ssh.h"
#include "roaming.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

#define PACKET_MAX_SIZE (256 * 1024)

struct packet_state {
	u_int32_t seqnr;
	u_int32_t packets;
	u_int64_t blocks;
	u_int64_t bytes;
};

struct packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	Buffer payload;
};

struct session_state {
	/*
	 * This variable contains the file descriptors used for
	 * communicating with the other side.  connection_in is used for
	 * reading; connection_out for writing.  These can be the same
	 * descriptor, in which case it is assumed to be a socket.
	 */
	int connection_in;
	int connection_out;

	/* Protocol flags for the remote side. */
	u_int remote_protocol_flags;

	/* Encryption context for receiving data.  Only used for decryption. */
	CipherContext receive_context;

	/* Encryption context for sending data.  Only used for encryption. */
	CipherContext send_context;

	/* Buffer for raw input data from the socket. */
	Buffer input;

	/* Buffer for raw output data going to the socket. */
	Buffer output;

	/* Buffer for the partial outgoing packet being constructed. */
	Buffer outgoing_packet;

	/* Buffer for the incoming packet currently being processed. */
	Buffer incoming_packet;

	/* Scratch buffer for packet compression/decompression. */
	Buffer compression_buffer;
	int compression_buffer_ready;

	/*
	 * Flag indicating whether packet compression/decompression is
	 * enabled.
	 */
	int packet_compression;

	/* default maximum packet size */
	u_int max_packet_size;

	/* Flag indicating whether this module has been initialized. */
	int initialized;

	/* Set to true if the connection is interactive. */
	int interactive_mode;

	/* Set to true if we are the server side. */
	int server_side;

	/* Set to true if we are authenticated. */
	int after_authentication;

	int keep_alive_timeouts;

	/* The maximum time that we will wait to send or receive a packet */
	int packet_timeout_ms;

	/* Session key information for Encryption and MAC */
	Newkeys *newkeys[MODE_MAX];
	struct packet_state p_read, p_send;

	u_int64_t max_blocks_in, max_blocks_out;
	u_int32_t rekey_limit;

	/* Session key for protocol v1 */
	u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
	u_int ssh1_keylen;

	/* roundup current message to extra_pad bytes */
	u_char extra_pad;

	/* XXX discard incoming data after MAC error */
	u_int packet_discard;
	Mac *packet_discard_mac;

	/* Used in packet_read_poll2() */
	u_int packlen;

	/* Used in packet_send2 */
	int rekeying;

	/* Used in packet_set_interactive */
	int set_interactive_called;

	/* Used in packet_set_maxsize */
	int set_maxsize_called;

	TAILQ_HEAD(, packet) outgoing;
};

static struct session_state *active_state, *backup_state;

static struct session_state *
alloc_session_state(void)
{
    struct session_state *s = xcalloc(1, sizeof(*s));

    s->connection_in = -1;
    s->connection_out = -1;
    s->max_packet_size = 32768;
    s->packet_timeout_ms = -1;
    return s;
}
#include "includes.h"

#include <sys/types.h>

#include <openssl/md5.h>

#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "log.h"
#include "cipher.h"

/* compatibility with old or broken OpenSSL versions */
#include "openbsd-compat/openssl-compat.h"


struct Cipher {
	char	*name;
	int	number;		/* for ssh1 only */
	u_int	block_size;
	u_int	key_len;
	u_int	discard_len;
	u_int	cbc_mode;
	const EVP_CIPHER	*(*evptype)(void);
};

/** umac */

typedef u_int8_t	UINT8;  /* 1 byte   */
typedef u_int16_t	UINT16; /* 2 byte   */
typedef u_int32_t	UINT32; /* 4 byte   */
typedef u_int64_t	UINT64; /* 8 bytes  */
typedef unsigned int	UWORD;  /* Register */

#define AES_BLOCK_LEN  16
#define UMAC_OUTPUT_LEN     8  /* Alowable: 4, 8, 12, 16                  */

/* OpenSSL's AES */
//#include "openbsd-compat/openssl-compat.h"
//#ifndef USE_BUILTIN_RIJNDAEL
# include <openssl/aes.h>
//#endif
typedef AES_KEY aes_int_key[1];

//#include <aes/aes.h>

typedef struct pdf_ctx {
    UINT8 cache[AES_BLOCK_LEN];  /* Previous AES output is saved      */
    UINT8 nonce[AES_BLOCK_LEN];  /* The AES input making above cache  */
    aes_int_key prf_key;         /* Expanded AES key for PDF          */
} pdf_ctx;


#define STREAMS (UMAC_OUTPUT_LEN / 4) /* Number of times hash is applied  */
#define L1_KEY_LEN         1024     /* Internal key bytes                 */
#define L1_KEY_SHIFT         16     /* Toeplitz key shift between streams */
#define L1_PAD_BOUNDARY      32     /* pad message to boundary multiple   */
#define ALLOC_BOUNDARY       16     /* Keep buffers aligned to this       */
#define HASH_BUF_BYTES       64     /* nh_aux_hb buffer multiple          */

typedef struct nh_ctx{
    UINT8  nh_key [L1_KEY_LEN + L1_KEY_SHIFT * (STREAMS - 1)]; /* NH Key */
    UINT8  data   [HASH_BUF_BYTES];    /* Incomming data buffer           */
    int next_data_empty;    /* Bookeeping variable for data buffer.       */
    int bytes_hashed;        /* Bytes (out of L1_KEY_LEN) incorperated.   */
    UINT64 state[STREAMS];               /* on-line state     */
} nh_ctx;

typedef struct uhash_ctx {
    nh_ctx hash;                          /* Hash context for L1 NH hash  */
    UINT64 poly_key_8[STREAMS];           /* p64 poly keys                */
    UINT64 poly_accum[STREAMS];           /* poly hash result             */
    UINT64 ip_keys[STREAMS*4];            /* Inner-product keys           */
    UINT32 ip_trans[STREAMS];             /* Inner-product translation    */
    UINT32 msg_len;                       /* Total length of data passed  */
                                          /* to uhash */
} uhash_ctx;


typedef struct umac_ctx {
    uhash_ctx hash;          /* Hash function for message compression    */
    pdf_ctx pdf;             /* PDF for hashed output                    */
    void *free_ptr;          /* Address to free this struct via          */
} umac_ctx;



//#include <engine/engine.h>
#include <engine/eng_int.h>



/**
INCLUDES="-I./biblio/openssh-5.5p1/ -I./biblio/openssh-5.5p1/build-deb/ -I./biblio/openssl-0.9.8o/crypto/ -I./biblio/openssl-0.9.8o/"
gcc -g -O2 -Wall -Wpointer-arith -Wuninitialized -Wsign-compare -Wno-pointer-sign -Wformat-security -fno-strict-aliasing -fno-builtin-memset -fstack-protector-all -Os -DSSH_EXTRAVERSION=\"Debian-4ubuntu5\"  $INCLUDES  -DSSHDIR=\"/etc/ssh\" -D_PATH_SSH_PROGRAM=\"/usr/bin/ssh\" -D_PATH_SSH_ASKPASS_DEFAULT=\"/usr/bin/ssh-askpass\" -D_PATH_SFTP_SERVER=\"/usr/lib/openssh/sftp-server\" -D_PATH_SSH_KEY_SIGN=\"/usr/lib/openssh/ssh-keysign\" -D_PATH_SSH_PKCS11_HELPER=\"/usr/lib/openssh/ssh-pkcs11-helper\" -D_PATH_SSH_PIDDIR=\"/var/run\" -D_PATH_PRIVSEP_CHROOT_DIR=\"/var/run/sshd\" -DSSH_RAND_HELPER=\"/usr/lib/openssh/ssh-rand-helper\" -D_PATH_SSH_DATADIR=\"/usr/share/ssh\" -DHAVE_CONFIG_H  ssh-types.c -o ssh-types

*/

#define MAX_PACKETS	(1U<<31)

int main(){

#ifdef __SIZE_SSL
  printf("BIGNUM: %d\n",sizeof(BIGNUM));
  printf("STACK: %d\n",sizeof(STACK));
  printf("CRYPTO_EX_DATA: %d\n",sizeof(CRYPTO_EX_DATA));
  printf("BN_MONT_CTX: %d\n",sizeof(BN_MONT_CTX));
  printf("EVP_PKEY: %d\n",sizeof(EVP_PKEY));
  printf("ENGINE_CMD_DEFN: %d\n",sizeof(ENGINE_CMD_DEFN));
  printf("ENGINE: %d\n",sizeof(ENGINE));
  printf("RSA: %d\n",sizeof(RSA));
  printf("DSA: %d\n",sizeof(DSA));
  printf("EVP_CIPHER: %d\n",sizeof(EVP_CIPHER));
  printf("EVP_CIPHER_CTX: %d\n",sizeof(EVP_CIPHER_CTX));
  printf("EVP_MD: %d\n",sizeof(EVP_MD));
  printf("EVP_MD_CTX: %d\n",sizeof(EVP_MD_CTX));
  printf("HMAC_CTX: %d\n",sizeof(HMAC_CTX));
  printf("AES_KEY: %d\n",sizeof(AES_KEY));
  printf("HMAC_MAX_MD_CBLOCK: %d\n", HMAC_MAX_MD_CBLOCK);
  printf("EVP_MAX_BLOCK_LENGTH: %d\n", EVP_MAX_BLOCK_LENGTH);
  printf("EVP_MAX_IV_LENGTH: %d\n",EVP_MAX_IV_LENGTH);
  printf("AES_MAXNR: %d\n",AES_MAXNR);
#else
  printf("Cipher: %d\n",sizeof(Cipher));
  printf("CipherContext: %d\n",sizeof(CipherContext));
  printf("Enc: %d\n",sizeof(Enc));
  printf("nh_ctx: %d\n",sizeof(struct nh_ctx));
  printf("uhash_ctx: %d\n",sizeof(struct uhash_ctx));
  printf("pdf_ctx: %d\n",sizeof(struct pdf_ctx));
  printf("umac_ctx: %d\n",sizeof(struct umac_ctx));
  printf("Mac: %d\n",sizeof(Mac));
  printf("Comp: %d\n",sizeof(Comp));
  printf("Newkeys: %d\n",sizeof(Newkeys));
  printf("Buffer: %d\n",sizeof(Buffer));
  printf("packet: %d\n",sizeof(struct packet));
  printf("packet_state: %d\n",sizeof(struct packet_state));
  printf("TAILQ_HEAD_PACKET: %d\n",sizeof(TAILQ_HEAD(,packet)));
  printf("TAILQ_ENTRY_PACKET: %d\n",sizeof(TAILQ_ENTRY(packet)));
  printf("session_state: %d\n",sizeof(struct session_state));
  printf("UINT32: %d\n",sizeof(UINT32));
  printf("UINT64: %d\n",sizeof(UINT64));
  printf("UINT8: %d\n",sizeof(UINT8));
  printf("AES_BLOCK_LEN: %d\n",AES_BLOCK_LEN);
  printf("HASH_BUF_BYTES: %d\n",HASH_BUF_BYTES);
  printf("UMAC_OUTPUT_LEN: %d\n",UMAC_OUTPUT_LEN);
  printf("SSH_SESSION_KEY_LENGTH: %d\n",SSH_SESSION_KEY_LENGTH);
  printf("L1_KEY_LEN: %d\n",L1_KEY_SHIFT);
  printf("L1_KEY_SHIFT: %d\n",L1_KEY_SHIFT);
  printf("MODE_MAX: %d\n",MODE_MAX);
  printf("STREAMS: %d\n",STREAMS);
#endif
}



