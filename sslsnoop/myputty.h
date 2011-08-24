/*
 * SSH backend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <signal.h>

#include "putty.h"
#include "tree234.h"
#include "ssh.h"
#ifndef NO_GSSAPI
#include "sshgssc.h"
#include "sshgss.h"
#endif

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define SSH1_MSG_DISCONNECT                       1	/* 0x1 */
#define SSH1_SMSG_PUBLIC_KEY                      2	/* 0x2 */
#define SSH1_CMSG_SESSION_KEY                     3	/* 0x3 */
#define SSH1_CMSG_USER                            4	/* 0x4 */
#define SSH1_CMSG_AUTH_RSA                        6	/* 0x6 */
#define SSH1_SMSG_AUTH_RSA_CHALLENGE              7	/* 0x7 */
#define SSH1_CMSG_AUTH_RSA_RESPONSE               8	/* 0x8 */
#define SSH1_CMSG_AUTH_PASSWORD                   9	/* 0x9 */
#define SSH1_CMSG_REQUEST_PTY                     10	/* 0xa */
#define SSH1_CMSG_WINDOW_SIZE                     11	/* 0xb */
#define SSH1_CMSG_EXEC_SHELL                      12	/* 0xc */
#define SSH1_CMSG_EXEC_CMD                        13	/* 0xd */
#define SSH1_SMSG_SUCCESS                         14	/* 0xe */
#define SSH1_SMSG_FAILURE                         15	/* 0xf */
#define SSH1_CMSG_STDIN_DATA                      16	/* 0x10 */
#define SSH1_SMSG_STDOUT_DATA                     17	/* 0x11 */
#define SSH1_SMSG_STDERR_DATA                     18	/* 0x12 */
#define SSH1_CMSG_EOF                             19	/* 0x13 */
#define SSH1_SMSG_EXIT_STATUS                     20	/* 0x14 */
#define SSH1_MSG_CHANNEL_OPEN_CONFIRMATION        21	/* 0x15 */
#define SSH1_MSG_CHANNEL_OPEN_FAILURE             22	/* 0x16 */
#define SSH1_MSG_CHANNEL_DATA                     23	/* 0x17 */
#define SSH1_MSG_CHANNEL_CLOSE                    24	/* 0x18 */
#define SSH1_MSG_CHANNEL_CLOSE_CONFIRMATION       25	/* 0x19 */
#define SSH1_SMSG_X11_OPEN                        27	/* 0x1b */
#define SSH1_CMSG_PORT_FORWARD_REQUEST            28	/* 0x1c */
#define SSH1_MSG_PORT_OPEN                        29	/* 0x1d */
#define SSH1_CMSG_AGENT_REQUEST_FORWARDING        30	/* 0x1e */
#define SSH1_SMSG_AGENT_OPEN                      31	/* 0x1f */
#define SSH1_MSG_IGNORE                           32	/* 0x20 */
#define SSH1_CMSG_EXIT_CONFIRMATION               33	/* 0x21 */
#define SSH1_CMSG_X11_REQUEST_FORWARDING          34	/* 0x22 */
#define SSH1_CMSG_AUTH_RHOSTS_RSA                 35	/* 0x23 */
#define SSH1_MSG_DEBUG                            36	/* 0x24 */
#define SSH1_CMSG_REQUEST_COMPRESSION             37	/* 0x25 */
#define SSH1_CMSG_AUTH_TIS                        39	/* 0x27 */
#define SSH1_SMSG_AUTH_TIS_CHALLENGE              40	/* 0x28 */
#define SSH1_CMSG_AUTH_TIS_RESPONSE               41	/* 0x29 */
#define SSH1_CMSG_AUTH_CCARD                      70	/* 0x46 */
#define SSH1_SMSG_AUTH_CCARD_CHALLENGE            71	/* 0x47 */
#define SSH1_CMSG_AUTH_CCARD_RESPONSE             72	/* 0x48 */

#define SSH1_AUTH_RHOSTS                          1	/* 0x1 */
#define SSH1_AUTH_RSA                             2	/* 0x2 */
#define SSH1_AUTH_PASSWORD                        3	/* 0x3 */
#define SSH1_AUTH_RHOSTS_RSA                      4	/* 0x4 */
#define SSH1_AUTH_TIS                             5	/* 0x5 */
#define SSH1_AUTH_CCARD                           16	/* 0x10 */

#define SSH1_PROTOFLAG_SCREEN_NUMBER              1	/* 0x1 */
/* Mask for protoflags we will echo back to server if seen */
#define SSH1_PROTOFLAGS_SUPPORTED                 0	/* 0x1 */

#define SSH2_MSG_DISCONNECT                       1	/* 0x1 */
#define SSH2_MSG_IGNORE                           2	/* 0x2 */
#define SSH2_MSG_UNIMPLEMENTED                    3	/* 0x3 */
#define SSH2_MSG_DEBUG                            4	/* 0x4 */
#define SSH2_MSG_SERVICE_REQUEST                  5	/* 0x5 */
#define SSH2_MSG_SERVICE_ACCEPT                   6	/* 0x6 */
#define SSH2_MSG_KEXINIT                          20	/* 0x14 */
#define SSH2_MSG_NEWKEYS                          21	/* 0x15 */
#define SSH2_MSG_KEXDH_INIT                       30	/* 0x1e */
#define SSH2_MSG_KEXDH_REPLY                      31	/* 0x1f */
#define SSH2_MSG_KEX_DH_GEX_REQUEST               30	/* 0x1e */
#define SSH2_MSG_KEX_DH_GEX_GROUP                 31	/* 0x1f */
#define SSH2_MSG_KEX_DH_GEX_INIT                  32	/* 0x20 */
#define SSH2_MSG_KEX_DH_GEX_REPLY                 33	/* 0x21 */
#define SSH2_MSG_KEXRSA_PUBKEY                    30    /* 0x1e */
#define SSH2_MSG_KEXRSA_SECRET                    31    /* 0x1f */
#define SSH2_MSG_KEXRSA_DONE                      32    /* 0x20 */
#define SSH2_MSG_USERAUTH_REQUEST                 50	/* 0x32 */
#define SSH2_MSG_USERAUTH_FAILURE                 51	/* 0x33 */
#define SSH2_MSG_USERAUTH_SUCCESS                 52	/* 0x34 */
#define SSH2_MSG_USERAUTH_BANNER                  53	/* 0x35 */
#define SSH2_MSG_USERAUTH_PK_OK                   60	/* 0x3c */
#define SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ        60	/* 0x3c */
#define SSH2_MSG_USERAUTH_INFO_REQUEST            60	/* 0x3c */
#define SSH2_MSG_USERAUTH_INFO_RESPONSE           61	/* 0x3d */
#define SSH2_MSG_GLOBAL_REQUEST                   80	/* 0x50 */
#define SSH2_MSG_REQUEST_SUCCESS                  81	/* 0x51 */
#define SSH2_MSG_REQUEST_FAILURE                  82	/* 0x52 */
#define SSH2_MSG_CHANNEL_OPEN                     90	/* 0x5a */
#define SSH2_MSG_CHANNEL_OPEN_CONFIRMATION        91	/* 0x5b */
#define SSH2_MSG_CHANNEL_OPEN_FAILURE             92	/* 0x5c */
#define SSH2_MSG_CHANNEL_WINDOW_ADJUST            93	/* 0x5d */
#define SSH2_MSG_CHANNEL_DATA                     94	/* 0x5e */
#define SSH2_MSG_CHANNEL_EXTENDED_DATA            95	/* 0x5f */
#define SSH2_MSG_CHANNEL_EOF                      96	/* 0x60 */
#define SSH2_MSG_CHANNEL_CLOSE                    97	/* 0x61 */
#define SSH2_MSG_CHANNEL_REQUEST                  98	/* 0x62 */
#define SSH2_MSG_CHANNEL_SUCCESS                  99	/* 0x63 */
#define SSH2_MSG_CHANNEL_FAILURE                  100	/* 0x64 */
#define SSH2_MSG_USERAUTH_GSSAPI_RESPONSE               60
#define SSH2_MSG_USERAUTH_GSSAPI_TOKEN                  61
#define SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE      63
#define SSH2_MSG_USERAUTH_GSSAPI_ERROR                  64
#define SSH2_MSG_USERAUTH_GSSAPI_ERRTOK                 65
#define SSH2_MSG_USERAUTH_GSSAPI_MIC                    66

/*
 * Packet type contexts, so that ssh2_pkt_type can correctly decode
 * the ambiguous type numbers back into the correct type strings.
 */
typedef enum {
    SSH2_PKTCTX_NOKEX,
    SSH2_PKTCTX_DHGROUP,
    SSH2_PKTCTX_DHGEX,
    SSH2_PKTCTX_RSAKEX
} Pkt_KCtx;
typedef enum {
    SSH2_PKTCTX_NOAUTH,
    SSH2_PKTCTX_PUBLICKEY,
    SSH2_PKTCTX_PASSWORD,
    SSH2_PKTCTX_GSSAPI,
    SSH2_PKTCTX_KBDINTER
} Pkt_ACtx;

#define SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT 1	/* 0x1 */
#define SSH2_DISCONNECT_PROTOCOL_ERROR            2	/* 0x2 */
#define SSH2_DISCONNECT_KEY_EXCHANGE_FAILED       3	/* 0x3 */
#define SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED 4	/* 0x4 */
#define SSH2_DISCONNECT_MAC_ERROR                 5	/* 0x5 */
#define SSH2_DISCONNECT_COMPRESSION_ERROR         6	/* 0x6 */
#define SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE     7	/* 0x7 */
#define SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED 8	/* 0x8 */
#define SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE   9	/* 0x9 */
#define SSH2_DISCONNECT_CONNECTION_LOST           10	/* 0xa */
#define SSH2_DISCONNECT_BY_APPLICATION            11	/* 0xb */
#define SSH2_DISCONNECT_TOO_MANY_CONNECTIONS      12	/* 0xc */
#define SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER    13	/* 0xd */
#define SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE 14	/* 0xe */
#define SSH2_DISCONNECT_ILLEGAL_USER_NAME         15	/* 0xf */

static const char *const ssh2_disconnect_reasons[] = {
    NULL,
    "host not allowed to connect",
    "protocol error",
    "key exchange failed",
    "host authentication failed",
    "MAC error",
    "compression error",
    "service not available",
    "protocol version not supported",
    "host key not verifiable",
    "connection lost",
    "by application",
    "too many connections",
    "auth cancelled by user",
    "no more auth methods available",
    "illegal user name",
};

#define SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED     1	/* 0x1 */
#define SSH2_OPEN_CONNECT_FAILED                  2	/* 0x2 */
#define SSH2_OPEN_UNKNOWN_CHANNEL_TYPE            3	/* 0x3 */
#define SSH2_OPEN_RESOURCE_SHORTAGE               4	/* 0x4 */

#define SSH2_EXTENDED_DATA_STDERR                 1	/* 0x1 */

/*
 * Various remote-bug flags.
 */
#define BUG_CHOKES_ON_SSH1_IGNORE                 1
#define BUG_SSH2_HMAC                             2
#define BUG_NEEDS_SSH1_PLAIN_PASSWORD        	  4
#define BUG_CHOKES_ON_RSA	        	  8
#define BUG_SSH2_RSA_PADDING	        	 16
#define BUG_SSH2_DERIVEKEY                       32
#define BUG_SSH2_REKEY                           64
#define BUG_SSH2_PK_SESSIONID                   128
#define BUG_SSH2_MAXPKT				256
#define BUG_CHOKES_ON_SSH2_IGNORE               512

/*
 * Codes for terminal modes.
 * Most of these are the same in SSH-1 and SSH-2.
 * This list is derived from RFC 4254 and
 * SSH-1 RFC-1.2.31.
 */
typedef enum { TTY_OP_CHAR, TTY_OP_BOOL } 
TTYModeType;

static const struct {
    const char* const mode;
    int opcode;
    TTYModeType type;
} ssh_ttymodes[] = {
    /* "V" prefix discarded for special characters relative to SSH specs */
    { "INTR",	      1, TTY_OP_CHAR },
    { "QUIT",	      2, TTY_OP_CHAR },
    { "ERASE",	      3, TTY_OP_CHAR },
    { "KILL",	      4, TTY_OP_CHAR },
    { "EOF",	      5, TTY_OP_CHAR },
    { "EOL",	      6, TTY_OP_CHAR },
    { "EOL2",	      7, TTY_OP_CHAR },
    { "START",	      8, TTY_OP_CHAR },
    { "STOP",	      9, TTY_OP_CHAR },
    { "SUSP",	     10, TTY_OP_CHAR },
    { "DSUSP",	     11, TTY_OP_CHAR },
    { "REPRINT",     12, TTY_OP_CHAR },
    { "WERASE",	     13, TTY_OP_CHAR },
    { "LNEXT",	     14, TTY_OP_CHAR },
    { "FLUSH",	     15, TTY_OP_CHAR },
    { "SWTCH",	     16, TTY_OP_CHAR },
    { "STATUS",	     17, TTY_OP_CHAR },
    { "DISCARD",     18, TTY_OP_CHAR },
    { "IGNPAR",	     30, TTY_OP_BOOL },
    { "PARMRK",	     31, TTY_OP_BOOL },
    { "INPCK",	     32, TTY_OP_BOOL },
    { "ISTRIP",	     33, TTY_OP_BOOL },
    { "INLCR",	     34, TTY_OP_BOOL },
    { "IGNCR",	     35, TTY_OP_BOOL },
    { "ICRNL",	     36, TTY_OP_BOOL },
    { "IUCLC",	     37, TTY_OP_BOOL },
    { "IXON",	     38, TTY_OP_BOOL },
    { "IXANY",	     39, TTY_OP_BOOL },
    { "IXOFF",	     40, TTY_OP_BOOL },
    { "IMAXBEL",     41, TTY_OP_BOOL },
    { "ISIG",	     50, TTY_OP_BOOL },
    { "ICANON",	     51, TTY_OP_BOOL },
    { "XCASE",	     52, TTY_OP_BOOL },
    { "ECHO",	     53, TTY_OP_BOOL },
    { "ECHOE",	     54, TTY_OP_BOOL },
    { "ECHOK",	     55, TTY_OP_BOOL },
    { "ECHONL",	     56, TTY_OP_BOOL },
    { "NOFLSH",	     57, TTY_OP_BOOL },
    { "TOSTOP",	     58, TTY_OP_BOOL },
    { "IEXTEN",	     59, TTY_OP_BOOL },
    { "ECHOCTL",     60, TTY_OP_BOOL },
    { "ECHOKE",	     61, TTY_OP_BOOL },
    { "PENDIN",	     62, TTY_OP_BOOL }, /* XXX is this a real mode? */
    { "OPOST",	     70, TTY_OP_BOOL },
    { "OLCUC",	     71, TTY_OP_BOOL },
    { "ONLCR",	     72, TTY_OP_BOOL },
    { "OCRNL",	     73, TTY_OP_BOOL },
    { "ONOCR",	     74, TTY_OP_BOOL },
    { "ONLRET",	     75, TTY_OP_BOOL },
    { "CS7",	     90, TTY_OP_BOOL },
    { "CS8",	     91, TTY_OP_BOOL },
    { "PARENB",	     92, TTY_OP_BOOL },
    { "PARODD",	     93, TTY_OP_BOOL }
};

/* Miscellaneous other tty-related constants. */
#define SSH_TTY_OP_END		  0
/* The opcodes for ISPEED/OSPEED differ between SSH-1 and SSH-2. */
#define SSH1_TTY_OP_ISPEED	192
#define SSH1_TTY_OP_OSPEED	193
#define SSH2_TTY_OP_ISPEED	128
#define SSH2_TTY_OP_OSPEED	129




/* Enumeration values for fields in SSH-1 packets */
enum {
    PKT_END, PKT_INT, PKT_CHAR, PKT_DATA, PKT_STR, PKT_BIGNUM,
    /* These values are for communicating relevant semantics of

     * fields to the packet logging code. */
    PKTT_OTHER, PKTT_PASSWORD, PKTT_DATA
};

/*

 * Coroutine mechanics for the sillier bits of the code. If these

 * macros look impenetrable to you, you might find it helpful to

 * read

 * 

 *   http://www.chiark.greenend.org.uk/~sgtatham/coroutines.html

 * 
 * which explains the theory behind these macros.

 * 

 * In particular, if you are getting `case expression not constant'

 * errors when building with MS Visual Studio, this is because MS's

 * Edit and Continue debugging feature causes their compiler to

 * violate ANSI C. To disable Edit and Continue debugging:

 * 
 *  - right-click ssh.c in the FileView
 *  - click Settings
 *  - select the C/C++ tab and the General category
 *  - under `Debug info:', select anything _other_ than `Program
 *    Database for Edit and Continue'.
 */
#define crBegin(v)	{ int *crLine = &v; switch(v) { case 0:;
#define crState(t) \
    struct t *s; \
    if (!ssh->t) ssh->t = snew(struct t); \
    s = ssh->t;
#define crFinish(z)	} *crLine = 0; return (z); }
#define crFinishV	} *crLine = 0; return; }
#define crReturn(z)	\
	do {\
	    *crLine =__LINE__; return (z); case __LINE__:;\
	} while (0)
#define crReturnV	\
	do {\
	    *crLine=__LINE__; return; case __LINE__:;\
	} while (0)
#define crStop(z)	do{ *crLine = 0; return (z); }while(0)
#define crStopV		do{ *crLine = 0; return; }while(0)
#define crWaitUntil(c)	do { crReturn(0); } while (!(c))
#define crWaitUntilV(c)	do { crReturnV; } while (!(c))

typedef struct ssh_tag *Ssh;
struct Packet;


#define SSH1_BUFFER_LIMIT 32768
#define SSH_MAX_BACKLOG 32768
#define OUR_V2_WINSIZE 16384
#define OUR_V2_BIGWIN 0x7fffffff
#define OUR_V2_MAXPKT 0x4000UL
#define OUR_V2_PACKETLIMIT 0x9000UL

/* Maximum length of passwords/passphrases (arbitrary) */
#define SSH_MAX_PASSWORD_LEN 100


enum {				       /* channel types */
    CHAN_MAINSESSION,
    CHAN_X11,
    CHAN_AGENT,
    CHAN_SOCKDATA,
    CHAN_SOCKDATA_DORMANT	       /* one the remote hasn't confirmed */
};

/*

 * little structure to keep track of outstanding WINDOW_ADJUSTs

 */
struct winadj {
    struct winadj *next;
    unsigned size;
};

/*

 * 2-3-4 tree storing channels.

 */
struct ssh_channel {
    Ssh ssh;			       /* pointer back to main context */
    unsigned remoteid, localid;
    int type;
    /* True if we opened this channel but server hasn't confirmed. */
    int halfopen;
    /*
     * In SSH-1, this value contains four bits:
     * 
     *   1   We have sent SSH1_MSG_CHANNEL_CLOSE.
     *   2   We have sent SSH1_MSG_CHANNEL_CLOSE_CONFIRMATION.
     *   4   We have received SSH1_MSG_CHANNEL_CLOSE.
     *   8   We have received SSH1_MSG_CHANNEL_CLOSE_CONFIRMATION.
     * 
     * A channel is completely finished with when all four bits are set.
     */
    int closes;

    /*
     * This flag indicates that a close is pending on the outgoing

     * side of the channel: that is, wherever we're getting the data

     * for this channel has sent us some data followed by EOF. We
     * can't actually close the channel until we've finished sending
     * the data, so we set this flag instead to remind us to
     * initiate the closing process once our buffer is clear.
     */
    int pending_close;

    /*
     * True if this channel is causing the underlying connection to be
     * throttled.
     */
    int throttling_conn;
    union {
	struct ssh2_data_channel {
	    bufchain outbuffer;
	    unsigned remwindow, remmaxpkt;
	    /* locwindow is signed so we can cope with excess data. */
	    int locwindow, locmaxwin;
	    /*
	     * remlocwin is the amount of local window that we think
	     * the remote end had available to it after it sent the
	     * last data packet or window adjust ack.
	     */
	    int remlocwin;
	    /*
	     * These store the list of window adjusts that haven't
	     * been acked.
	     */
	    struct winadj *winadj_head, *winadj_tail;
	    enum { THROTTLED, UNTHROTTLING, UNTHROTTLED } throttle_state;
	} v2;
    } v;
    union {
	struct ssh_agent_channel {
	    unsigned char *message;
	    unsigned char msglen[4];
	    unsigned lensofar, totallen;
	} a;
	struct ssh_x11_channel {
	    Socket s;
	} x11;
	struct ssh_pfd_channel {
	    Socket s;
	} pfd;
    } u;
};

/*
 * 2-3-4 tree storing remote->local port forwardings. SSH-1 and SSH-2
 * use this structure in different ways, reflecting SSH-2's
 * altogether saner approach to port forwarding.
 * 
 * In SSH-1, you arrange a remote forwarding by sending the server
 * the remote port number, and the local destination host:port.
 * When a connection comes in, the server sends you back that
 * host:port pair, and you connect to it. This is a ready-made
 * security hole if you're not on the ball: a malicious server
 * could send you back _any_ host:port pair, so if you trustingly
 * connect to the address it gives you then you've just opened the
 * entire inside of your corporate network just by connecting
 * through it to a dodgy SSH server. Hence, we must store a list of
 * host:port pairs we _are_ trying to forward to, and reject a
 * connection request from the server if it's not in the list.
 * 
 * In SSH-2, each side of the connection minds its own business and
 * doesn't send unnecessary information to the other. You arrange a
 * remote forwarding by sending the server just the remote port

 * number. When a connection comes in, the server tells you which
 * of its ports was connected to; and _you_ have to remember what
 * local host:port pair went with that port number.
 * 
 * Hence, in SSH-1 this structure is indexed by destination
 * host:port pair, whereas in SSH-2 it is indexed by source port.
 */
struct ssh_portfwd; /* forward declaration */

struct ssh_rportfwd {
    unsigned sport, dport;
    char dhost[256];
    char *sportdesc;
    struct ssh_portfwd *pfrec;
};
#define free_rportfwd(pf) ( \
    ((pf) ? (sfree((pf)->sportdesc)) : (void)0 ), sfree(pf) )

/*
 * Separately to the rportfwd tree (which is for looking up port
 * open requests from the server), a tree of _these_ structures is
 * used to keep track of all the currently open port forwardings,
 * so that we can reconfigure in mid-session if the user requests
 * it.
 */
struct ssh_portfwd {
    enum { DESTROY, KEEP, CREATE } status;
    int type;
    unsigned sport, dport;
    char *saddr, *daddr;
    char *sserv, *dserv;
    struct ssh_rportfwd *remote;
    int addressfamily;
    void *local;
};
#define free_portfwd(pf) ( \
    ((pf) ? (sfree((pf)->saddr), sfree((pf)->daddr), \
	     sfree((pf)->sserv), sfree((pf)->dserv)) : (void)0 ), sfree(pf) )

struct Packet {
    long length;	    /* length of `data' actually used */
    long forcepad;	    /* SSH-2: force padding to at least this length */
    int type;		    /* only used for incoming packets */
    unsigned long sequence; /* SSH-2 incoming sequence number */
    unsigned char *data;    /* allocated storage */
    unsigned char *body;    /* offset of payload within `data' */
    long savedpos;	    /* temporary index into `data' (for strings) */
    long maxlen;	    /* amount of storage allocated for `data' */
    long encrypted_len;	    /* for SSH-2 total-size counting */

    /*
     * State associated with packet logging
     */
    int logmode;
    int nblanks;
    struct logblank_t *blanks;
};


struct rdpkt1_state_tag {
    long len, pad, biglen, to_read;
    unsigned long realcrc, gotcrc;
    unsigned char *p;
    int i;
    int chunk;
    struct Packet *pktin;
};

struct rdpkt2_state_tag {
    long len, pad, payload, packetlen, maclen;
    int i;
    int cipherblk;
    unsigned long incoming_sequence;
    struct Packet *pktin;
};

typedef void (*handler_fn_t)(Ssh ssh, struct Packet *pktin);
typedef void (*chandler_fn_t)(Ssh ssh, struct Packet *pktin, void *ctx);

struct queued_handler;
struct queued_handler {
    int msg1, msg2;
    chandler_fn_t handler;
    void *ctx;
    struct queued_handler *next;
};

struct ssh_tag {
    const struct plug_function_table *fn;
    /* the above field _must_ be first in the structure */

    char *v_c, *v_s;
    void *exhash;

    Socket s;

    void *ldisc;
    void *logctx;

    unsigned char session_key[32];
    int v1_compressing;
    int v1_remote_protoflags;
    int v1_local_protoflags;
    int agentfwd_enabled;
    int X11_fwd_enabled;
    int remote_bugs;
    const struct ssh_cipher *cipher;
    void *v1_cipher_ctx;
    void *crcda_ctx;
    const struct ssh2_cipher *cscipher, *sccipher;
    void *cs_cipher_ctx, *sc_cipher_ctx;
    const struct ssh_mac *csmac, *scmac;
    void *cs_mac_ctx, *sc_mac_ctx;
    const struct ssh_compress *cscomp, *sccomp;
    void *cs_comp_ctx, *sc_comp_ctx;
    const struct ssh_kex *kex;
    const struct ssh_signkey *hostkey;
    unsigned char v2_session_id[SSH2_KEX_MAX_HASH_LEN];
    int v2_session_id_len;
    void *kex_ctx;

    char *savedhost;
    int savedport;
    int send_ok;
    int echoing, editing;

    void *frontend;

    int ospeed, ispeed;		       /* temporaries */
    int term_width, term_height;

    tree234 *channels;		       /* indexed by local id */
    struct ssh_channel *mainchan;      /* primary session channel */
    int ncmode;			       /* is primary channel direct-tcpip? */
    int exitcode;
    int close_expected;
    int clean_exit;

    tree234 *rportfwds, *portfwds;

    enum {
	SSH_STATE_PREPACKET,
	SSH_STATE_BEFORE_SIZE,
	SSH_STATE_INTERMED,
	SSH_STATE_SESSION,
	SSH_STATE_CLOSED
    } state;

    int size_needed, eof_needed;

    struct Packet **queue;
    int queuelen, queuesize;
    int queueing;
    unsigned char *deferred_send_data;
    int deferred_len, deferred_size;

    /*
     * Gross hack: pscp will try to start SFTP but fall back to
     * scp1 if that fails. This variable is the means by which
     * scp.c can reach into the SSH code and find out which one it
     * got.
     */
    int fallback_cmd;

    bufchain banner;	/* accumulates banners during do_ssh2_authconn */

    Pkt_KCtx pkt_kctx;
    Pkt_ACtx pkt_actx;

    struct X11Display *x11disp;

    int version;
    int conn_throttle_count;
    int overall_bufsize;
    int throttled_all;
    int v1_stdout_throttling;
    unsigned long v2_outgoing_sequence;

    int ssh1_rdpkt_crstate;
    int ssh2_rdpkt_crstate;
    int do_ssh_init_crstate;
    int ssh_gotdata_crstate;
    int do_ssh1_login_crstate;
    int do_ssh1_connection_crstate;
    int do_ssh2_transport_crstate;
    int do_ssh2_authconn_crstate;

    void *do_ssh_init_state;
    void *do_ssh1_login_state;
    void *do_ssh2_transport_state;
    void *do_ssh2_authconn_state;

    struct rdpkt1_state_tag rdpkt1_state;
    struct rdpkt2_state_tag rdpkt2_state;

    /* SSH-1 and SSH-2 use this for different things, but both use it */
    int protocol_initial_phase_done;

    void (*protocol) (Ssh ssh, void *vin, int inlen,
		      struct Packet *pkt);
    struct Packet *(*s_rdpkt) (Ssh ssh, unsigned char **data, int *datalen);

    /*
     * We maintain a full _copy_ of a Config structure here, not
     * merely a pointer to it. That way, when we're passed a new
     * one for reconfiguration, we can check the differences and
     * potentially reconfigure port forwardings etc in mid-session.
     */
    Config cfg;

    /*
     * Used to transfer data back from async callbacks.
     */
    void *agent_response;
    int agent_response_len;
    int user_response;

    /*

     * The SSH connection can be set as `frozen', meaning we are
     * not currently accepting incoming data from the network. This
     * is slightly more serious than setting the _socket_ as
     * frozen, because we may already have had data passed to us
     * from the network which we need to delay processing until
     * after the freeze is lifted, so we also need a bufchain to
     * store that data.
     */
    int frozen;
    bufchain queued_incoming_data;

    /*
     * Dispatch table for packet types that we may have to deal
     * with at any time.
     */
    handler_fn_t packet_dispatch[256];

    /*
     * Queues of one-off handler functions for success/failure
     * indications from a request.
     */
    struct queued_handler *qhead, *qtail;

    /*
     * This module deals with sending keepalives.
     */
    Pinger pinger;

    /*
     * Track incoming and outgoing data sizes and time, for
     * size-based rekeys.
     */
    unsigned long incoming_data_size, outgoing_data_size, deferred_data_size;
    unsigned long max_data_size;
    int kex_in_progress;
    long next_rekey, last_rekey;
    char *deferred_rekey_reason;    /* points to STATIC string; don't free */

    /*
     * Fully qualified host name, which we need if doing GSSAPI.
     */
    char *fullhostname;

#ifndef NO_GSSAPI
    /*
     * GSSAPI libraries for this session.
     */
    struct ssh_gss_liblist *gsslibs;
#endif
};

/** from tree234 - the passphrases */

typedef struct node234_Tag node234;

struct tree234_Tag {
    node234 *root;
    cmpfn234 cmp;
};

struct node234_Tag {
    node234 *parent;
    node234 *kids[4];
    int counts[4];
    void *elems[3];
};





