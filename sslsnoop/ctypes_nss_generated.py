from ctypes import *

STRING = c_char_p


ssl_calg_3des = 4
calg_3des = ssl_calg_3des # alias
SSL_ERROR_TX_RECORD_TOO_LONG = -12262
_CS_V7_ENV = 1149
_CS_V7_ENV = _CS_V7_ENV # alias
IPPORT_ECHO = 7
SOCK_SEQPACKET = 5
SOCK_SEQPACKET = SOCK_SEQPACKET # alias
# __WCHAR_MAX = __WCHAR_MAX__ # alias
# def __LDBL_REDIR_NTH(name,proto): return name proto __THROW # macro
SEC_OID_PKCS1_RSA_PSS_SIGNATURE = 307
SEC_ERROR_BAD_DATA = -8190
PF_WANPIPE = 25 # Variable c_int '25'
AF_WANPIPE = PF_WANPIPE # alias
def _G_ARGS(ARGLIST): return ARGLIST # macro
__off_t = c_long
_G_off_t = __off_t # alias
_IO_off_t = _G_off_t # alias
_SC_TTY_NAME_MAX = 72
_SC_TTY_NAME_MAX = _SC_TTY_NAME_MAX # alias
SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT = 149
# WORDS_PER_DWORD_LOG2 = PR_WORDS_PER_DWORD_LOG2 # alias
SSL_ERROR_CERTIFICATE_UNKNOWN_ALERT = -12224
__LITTLE_ENDIAN = 1234 # Variable c_int '1234'
LITTLE_ENDIAN = __LITTLE_ENDIAN # alias
# PORT_Memcmp = memcmp # alias
_SC_XOPEN_XPG3 = 99
SIGEV_NONE = 1
SIGEV_NONE = SIGEV_NONE # alias
SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO = -12245
_SC_V6_LP64_OFF64 = 178
_SC_V6_LP64_OFF64 = _SC_V6_LP64_OFF64 # alias
SEC_OID_PKIX_USER_NOTICE_QUALIFIER = 129
SEC_OID_NS_CERT_EXT_HOMEPAGE_URL = 71
__POSIX2_THIS_VERSION = 200809 # Variable c_long '200809l'
_POSIX2_LOCALEDEF = __POSIX2_THIS_VERSION # alias
SEC_OID_PKCS12_V1_SECRET_BAG_ID = 166
PR_SockOpt_McastTimeToLive = 11
_SC_V6_ILP32_OFFBIG = 177
def PR_BITMASK(n): return (PR_BIT(n) - 1) # macro
PRTraceResume = 4
def PR_INSERT_LINK(_e,_l): return PR_INSERT_AFTER(_e,_l) # macro
PK11_DIS_COULD_NOT_INIT_TOKEN = 2
# def ssl_GetSpecWriteLock(ss): return { if (!ss->opt.noLocks) NSSRWLock_LockWrite((ss)->specLock); } # macro
dhKey = 4
_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = 1147
_CS_POSIX_V7_ILP32_OFFBIG_LIBS = 1138
_CS_POSIX_V7_ILP32_OFFBIG_LIBS = _CS_POSIX_V7_ILP32_OFFBIG_LIBS # alias
# def __u_intN_t(N,MODE): return typedef unsigned int u_int ##N ##_t __attribute__ ((__mode__ (MODE))) # macro
certX400Address = 4
IPPORT_ROUTESERVER = 520
SSL_ERROR_SESSION_KEY_GEN_FAILURE = -12207
def __va_arg_pack(): return __builtin_va_arg_pack () # macro
SEC_OID_NS_CERT_EXT_ISSUER_LOGO = 61
nssILockSSL = 8
_SC_TRACE_EVENT_FILTER = 182
_SC_TRACE_EVENT_FILTER = _SC_TRACE_EVENT_FILTER # alias
_SC_LEVEL3_CACHE_SIZE = 194
# def _ISbit(bit): return ((bit) < 8 ? ((1 << (bit)) << 8) : ((1 << (bit)) >> 8)) # macro
def PZ_NewLock(t): return PR_NewLock() # macro
_SC_FD_MGMT = 143
_SC_THREAD_ATTR_STACKSIZE = 78
# __S32_TYPE = int # alias
# __DADDR_T_TYPE = __S32_TYPE # alias
_SC_NL_ARGMAX = 119
_SC_NL_ARGMAX = _SC_NL_ARGMAX # alias
SEC_OID_SECG_EC_SECP128R2 = 212
# def CMSG_SPACE(len): return (CMSG_ALIGN (len) + CMSG_ALIGN (sizeof (struct cmsghdr))) # macro
PR_MW_SUCCESS = 0
_SC_MQ_PRIO_MAX = 28
_SC_MQ_PRIO_MAX = _SC_MQ_PRIO_MAX # alias
SEC_ERROR_UNRECOGNIZED_OID = -8049
crlEntryReasonKeyCompromise = 1
SEC_ERROR_OCSP_BAD_SIGNATURE = -8035
SEC_OID_RFC1274_UID = 98
_SC_CHAR_MIN = 103
SEC_OID_MD4 = 2
PF_INET6 = 10 # Variable c_int '10'
AF_INET6 = PF_INET6 # alias
cipher_camellia_256 = 13
def toascii_l(c,l): return __toascii_l ((c), (l)) # macro
def __WIFSTOPPED(status): return (((status) & 0xff) == 0x7f) # macro
_SC_THREAD_KEYS_MAX = 74
PR_BYTES_PER_DWORD = 8 # Variable c_int '8'
BYTES_PER_DWORD = PR_BYTES_PER_DWORD # alias
_SC_THREAD_STACK_MIN = 75
_SC_THREAD_STACK_MIN = _SC_THREAD_STACK_MIN # alias
# PR_FinishArenaPool = PL_FinishArenaPool # alias
_SC_CLOCK_SELECTION = 137
_SC_CLOCK_SELECTION = _SC_CLOCK_SELECTION # alias
cert_po_certList = 3
MSG_DONTROUTE = 4
MSG_DONTROUTE = MSG_DONTROUTE # alias
# def LL_SHR(r,a,b): return ((r) = (PRInt64)(a) >> (b)) # macro
SEC_ERROR_READ_ONLY = -8126
kea_dhe_rsa_export = 11
SSL_ERROR_BAD_CLIENT = -12282
_SC_FSYNC = 15
# PR_HashTableRawLookup = PL_HashTableRawLookup # alias
_SC_LEVEL1_ICACHE_SIZE = 185
_SC_LEVEL1_ICACHE_SIZE = _SC_LEVEL1_ICACHE_SIZE # alias
SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE = -8051
# PORT_Strpbrk = strpbrk # alias
MSG_CONFIRM = 2048
MSG_CONFIRM = MSG_CONFIRM # alias
__u_quad_t = c_ulonglong
__U64_TYPE = __u_quad_t # alias
SEC_OID_DES_OFB = 11
SCM_RIGHTS = 1
SCM_RIGHTS = SCM_RIGHTS # alias
_SC_XOPEN_REALTIME_THREADS = 131
_SC_XOPEN_REALTIME_THREADS = _SC_XOPEN_REALTIME_THREADS # alias
# _G_MMAP64 = __mmap64 # alias
cert_pi_nbioContext = 1
IPPROTO_ENCAP = 98
# __SUSECONDS_T_TYPE = __SLONGWORD_TYPE # alias
ssl_kea_null = 0
def __toascii_l(c,l): return ((l), __toascii (c)) # macro
SEC_OID_AVA_POSTAL_CODE = 266
PR_IpAddrLoopback = 2
ssl_calg_rc2 = 2
calg_rc2 = ssl_calg_rc2 # alias
SSL_ERROR_BAD_BLOCK_PADDING = -12264
_SC_OPEN_MAX = 4
PF_ECONET = 19 # Variable c_int '19'
AF_ECONET = PF_ECONET # alias
SEC_ERROR_NEED_RANDOM = -8129
_PC_PRIO_IO = 11
# def __exctype_l(name): return extern int name (int, __locale_t) __THROW # macro
_SC_SHELL = 157
_SC_SHELL = _SC_SHELL # alias
def PR_UPTRDIFF(p,q): return ((PRUword)(p) - (PRUword)(q)) # macro
SEC_ERROR_UNTRUSTED_CERT = -8171
_ISblank = 1
SEC_OID_NS_CERT_EXT_ENTITY_LOGO = 72
def IN_CLASSA(a): return ((((in_addr_t)(a)) & 0x80000000) == 0) # macro
_SC_THREAD_ROBUST_PRIO_INHERIT = 247
PR_SockOpt_MaxSegment = 14
SEC_OID_X509_BASIC_CONSTRAINTS = 85
IPPROTO_SCTP = 132
IPPROTO_IDP = 22
IPPROTO_IDP = IPPROTO_IDP # alias
PK11CertListUserUnique = 5
_SC_SS_REPL_MAX = 241
# PR_HashTableDestroy = PL_HashTableDestroy # alias
SEC_ERROR_KEY_NICKNAME_COLLISION = -8123
_CS_V7_WIDTH_RESTRICTED_ENVS = 5
_CS_V7_WIDTH_RESTRICTED_ENVS = _CS_V7_WIDTH_RESTRICTED_ENVS # alias
# def PORT_ZNewArray(type,num): return (type*) PORT_ZAlloc (sizeof(type)*(num)) # macro
SSL_ERROR_USER_CANCELED_ALERT = -12187
def PZ_WaitCondVar(v,t): return PR_WaitCondVar((v),(t)) # macro
# PORT_Tolower = tolower # alias
_CS_LFS_LINTFLAGS = 1003
_SC_UIO_MAXIOV = 60
SOCK_DCCP = 6
SEC_ERROR_JS_INVALID_DLL = -8085
crlEntryReasonRemoveFromCRL = 8
SEC_ERROR_PKCS12_CERT_COLLISION = -8106
PK11CertListCA = 3
_CS_XBS5_LP64_OFF64_LIBS = 1110
def __WEXITSTATUS(status): return (((status) & 0xff00) >> 8) # macro
def LL_GE_ZERO(a): return ((a) >= 0) # macro
SEC_OID_ANSIX962_EC_C2TNB239V3 = 234
SEC_OID_NS_CERT_EXT_CA_POLICY_URL = 70
siClearDataBuffer = 1
SEC_OID_RC4 = 6
def PZ_DestroyCondVar(v): return PR_DestroyCondVar((v)) # macro
crlEntryReasonUnspecified = 0
PRIntn = c_int
PLHashComparator = CFUNCTYPE(PRIntn, c_void_p, c_void_p)
PRHashComparator = PLHashComparator # alias
_SC_TIMERS = 11
_SC_TIMERS = _SC_TIMERS # alias
_CS_XBS5_ILP32_OFF32_LIBS = 1102
_SC_SCHAR_MIN = 112
_SC_SCHAR_MIN = _SC_SCHAR_MIN # alias
SEC_ERROR_OCSP_UNAUTHORIZED_REQUEST = -8068
_CS_LFS64_LIBS = 1006
_IScntrl = 2
PR_ACCESS_WRITE_OK = 2
_SC_PII_XTI = 54
_SC_PII_XTI = _SC_PII_XTI # alias
PR_SI_SYSNAME = 1
_SC_PASS_MAX = 88
_SC_PASS_MAX = _SC_PASS_MAX # alias
PK11_OriginDerive = 1
# PR_CompareValues = PL_CompareValues # alias
_SC_BARRIERS = 133
_SC_CLK_TCK = 2
_SC_CLK_TCK = _SC_CLK_TCK # alias
cert_po_policyOID = 4
certUsageUserCertImport = 7
PR_LOG_ERROR = 2
SEC_OID_HMAC_SHA1 = 294
def WIFCONTINUED(status): return __WIFCONTINUED (__WAIT_INT (status)) # macro
SEC_OID_X509_ANY_POLICY = 303
SEC_OID_X509_AUTH_KEY_ID = 91
SSL_ERROR_WRONG_CERTIFICATE = -12277
def __GNUC_PREREQ(maj,min): return ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min)) # macro
# def TEMP_FAILURE_RETRY(expression): return (__extension__ ({ long int __result; do __result = (long int) (expression); while (__result == -1L && errno == EINTR); __result; })) # macro
MSG_FIN = 512
MSG_FIN = MSG_FIN # alias
SCM_CREDENTIALS = 2
SCM_CREDENTIALS = SCM_CREDENTIALS # alias
SEC_OID_ANSIX9_DSA_SIGNATURE = 124
kea_ecdh_anon = 19
_ISdigit = 2048
# def SSL_LOCK_READER(ss): return if (ss->recvLock) PZ_Lock(ss->recvLock) # macro
_SC_MQ_OPEN_MAX = 27
cert_pi_nbioAbort = 2
ssl_auth_ecdsa = 4
PF_SECURITY = 14 # Variable c_int '14'
AF_SECURITY = PF_SECURITY # alias
MSG_MORE = 32768
MSG_MORE = MSG_MORE # alias
_ISlower = 512
# SEC_OID_SHA = SEC_OID_MISS_DSS # alias
SSL_ERROR_RX_MALFORMED_CERT_VERIFY = -12254
CKT_NSS_UNTRUSTED = 3461563219L # Variable c_uint '-833404077u'
CKT_NETSCAPE_UNTRUSTED = CKT_NSS_UNTRUSTED # alias
idle_handshake = 12
server_hello_done = 14
_SC_TZNAME_MAX = 6
__quad_t = c_longlong
__off64_t = __quad_t
_G_off64_t = __off64_t # alias
_IO_off64_t = _G_off64_t # alias
# def __tobody(c,f,a,args): return (__extension__ ({ int __res; if (sizeof (c) > 1) { if (__builtin_constant_p (c)) { int __c = (c); __res = __c < -128 || __c > 255 ? __c : (a)[__c]; } else __res = f args; } else __res = (a)[(int) (c)]; __res; })) # macro
SEC_OID_X509_CERT_ISSUER = 284
# def PR_MAX(x,y): return ((x)>(y)?(x):(y)) # macro
# __GID_T_TYPE = __U32_TYPE # alias
certPackageNSCertWrap = 4
def le32toh(x): return (x) # macro
ssl_calg_seed = 9
calg_seed = ssl_calg_seed # alias
# def CERT_LIST_NEXT(n): return ((CERTCertListNode *)n->links.next) # macro
# def IN6_IS_ADDR_MC_ORGLOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x8)) # macro
# def PL_ARENA_MARK(pool): return ((void *) (pool)->current->avail) # macro
# PR_ARENA_MARK = PL_ARENA_MARK # alias
certificate_request = 13
IPPORT_FINGER = 79
SSL_ERROR_SOCKET_WRITE_FAILURE = -12216
# def __FD_SET(d,set): return (__FDS_BITS (set)[__FDELT (d)] |= __FDMASK (d)) # macro
_CS_POSIX_V6_LP64_OFF64_LINTFLAGS = 1127
_CS_POSIX_V6_LP64_OFF64_LINTFLAGS = _CS_POSIX_V6_LP64_OFF64_LINTFLAGS # alias
SSL_ERROR_RX_UNEXPECTED_CHANGE_CIPHER = -12237
IPPROTO_ICMPV6 = 58
IPPROTO_ICMPV6 = IPPROTO_ICMPV6 # alias
INADDR_BROADCAST = 4294967295L # Variable c_uint '-1u'
PR_INADDR_BROADCAST = INADDR_BROADCAST # alias
_SC_2_UPE = 97
PR_SockOpt_Keepalive = 3
# def strndupa(s,n): return (__extension__ ({ __const char *__old = (s); size_t __len = strnlen (__old, (n)); char *__new = (char *) __builtin_alloca (__len + 1); __new[__len] = '\0'; (char *) memcpy (__new, __old, __len); })) # macro
HASH_AlgMD5 = 2
HASH_AlgNULL = 0
_CS_POSIX_V7_LP64_OFF64_LIBS = 1142
_CS_POSIX_V7_LP64_OFF64_LIBS = _CS_POSIX_V7_LP64_OFF64_LIBS # alias
_SC_THREAD_ATTR_STACKADDR = 77
SEC_ERROR_CRL_UNKNOWN_CRITICAL_EXTENSION = -8043
SEC_OID_PKCS12_PKCS8_KEY_SHROUDING = 109
SEC_ERROR_BAD_LDAP_RESPONSE = -8029
_SC_THREAD_PRIO_PROTECT = 81
_SC_THREAD_PRIO_PROTECT = _SC_THREAD_PRIO_PROTECT # alias
# def SSL_LOCK_WRITER(ss): return if (ss->sendLock) PZ_Lock(ss->sendLock) # macro
SEC_OID_ANSIX962_EC_C2ONB239V4 = 235
CKO_NSS_DELSLOT = 3461563222L # Variable c_uint '-833404074u'
CKO_NETSCAPE_DELSLOT = CKO_NSS_DELSLOT # alias
class PLHashAllocOps(Structure):
    pass
PRHashAllocOps = PLHashAllocOps # alias
SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID = 163
MSG_PROXY = 16
MSG_PROXY = MSG_PROXY # alias
_SC_SCHAR_MAX = 111
_SC_SCHAR_MAX = _SC_SCHAR_MAX # alias
__codecvt_partial = 1
SEC_OID_NS_CERT_EXT_SUBJECT_LOGO = 62
SEC_OID_PKCS9_EMAIL_ADDRESS = 31
CKM_NSS_AES_KEY_WRAP_PAD = 3461563218L # Variable c_uint '-833404078u'
CKM_NETSCAPE_AES_KEY_WRAP_PAD = CKM_NSS_AES_KEY_WRAP_PAD # alias
NO_DATA = 4 # Variable c_int '4'
NO_ADDRESS = NO_DATA # alias
_CS_XBS5_ILP32_OFFBIG_LDFLAGS = 1105
_CS_XBS5_ILP32_OFFBIG_LDFLAGS = _CS_XBS5_ILP32_OFFBIG_LDFLAGS # alias
_SC_PRIORITIZED_IO = 13
_SC_PRIORITIZED_IO = _SC_PRIORITIZED_IO # alias
SEC_OID_NS_KEY_USAGE_GOVT_APPROVED = 78
def be64toh(x): return __bswap_64 (x) # macro
_CS_POSIX_V7_LP64_OFF64_LINTFLAGS = 1143
# __MODE_T_TYPE = __U32_TYPE # alias
PF_TIPC = 30 # Variable c_int '30'
AF_TIPC = PF_TIPC # alias
def alloca(size): return __builtin_alloca (size) # macro
_SC_CHILD_MAX = 1
_SC_CHILD_MAX = _SC_CHILD_MAX # alias
_SC_GETGR_R_SIZE_MAX = 69
certUsageObjectSigner = 6
# __USECONDS_T_TYPE = __U32_TYPE # alias
wait_cert_verify = 3
_SC_2_CHAR_TERM = 95
_SC_MEMLOCK_RANGE = 18
_SC_XOPEN_XPG4 = 100
cert_pi_max = 13
_SC_LEVEL1_ICACHE_ASSOC = 186
_SC_LEVEL1_ICACHE_ASSOC = _SC_LEVEL1_ICACHE_ASSOC # alias
certificate_revoked = 44
SSL_ERROR_RX_MALFORMED_ALERT = -12250
CKR_NSS_CERTDB_FAILED = 3461563217L # Variable c_uint '-833404079u'
CKR_NETSCAPE_CERTDB_FAILED = CKR_NSS_CERTDB_FAILED # alias
_SC_DEVICE_SPECIFIC_R = 142
PK11_OriginGenerated = 2
# _G_LSEEK64 = __lseek64 # alias
XP_SEC_FORTEZZA_PERSON_NOT_FOUND = -8138
MSG_NOSIGNAL = 16384
MSG_NOSIGNAL = MSG_NOSIGNAL # alias
siUnsignedInteger = 10
SEC_OID_ANSIX962_EC_PRIME256V1 = 208
SEC_OID_SECG_EC_SECP256R1 = SEC_OID_ANSIX962_EC_PRIME256V1 # alias
CKT_NSS_TRUST_UNKNOWN = 3461563221L # Variable c_uint '-833404075u'
CKT_NETSCAPE_TRUST_UNKNOWN = CKT_NSS_TRUST_UNKNOWN # alias
_CS_XBS5_ILP32_OFF32_CFLAGS = 1100
_CS_XBS5_ILP32_OFF32_CFLAGS = _CS_XBS5_ILP32_OFF32_CFLAGS # alias
SEC_ERROR_REVOKED_CERTIFICATE = -8180
SEC_OID_AVA_STREET_ADDRESS = 263
_SC_NL_TEXTMAX = 124
_SC_JOB_CONTROL = 7
_SC_XOPEN_REALTIME = 130
_SC_XOPEN_REALTIME = _SC_XOPEN_REALTIME # alias
_PC_ASYNC_IO = 10
cert_po_max = 9
IPPROTO_ESP = 50
ssl_mac_sha = 2
mac_sha = ssl_mac_sha # alias
_PC_VDISABLE = 8
_PC_VDISABLE = _PC_VDISABLE # alias
PR_SockOpt_NoDelay = 13
MSG_DONTWAIT = 64
fortezzaKey = 3
ssl_sign_null = 0
sign_null = ssl_sign_null # alias
_SC_SHRT_MIN = 114
_SC_SHRT_MIN = _SC_SHRT_MIN # alias
_PC_SYNC_IO = 9
_SC_XOPEN_VERSION = 89
_SC_SHRT_MAX = 113
_SC_SHRT_MAX = _SC_SHRT_MAX # alias
PF_INET = 2 # Variable c_int '2'
AF_INET = PF_INET # alias
PR_AF_INET = AF_INET # alias
SEC_ERROR_IMPORTING_CERTIFICATES = -8115
# def __bswap_32(x): return (__extension__ ({ register unsigned int __v, __x = (x); if (__builtin_constant_p (__x)) __v = __bswap_constant_32 (__x); else __asm__ ("bswap %0" : "=r" (__v) : "0" (__x)); __v; })) # macro
certEDIPartyName = 6
# def PL_ARENA_RELEASE(pool,mark): return PR_BEGIN_MACRO char *_m = (char *)(mark); PLArena *_a = (pool)->current; if (PR_UPTRDIFF(_m, _a->base) <= PR_UPTRDIFF(_a->avail, _a->base)) { _a->avail = (PRUword)PL_ARENA_ALIGN(pool, _m); PL_CLEAR_UNUSED(_a); PL_ArenaCountRetract(pool, _m); } else { PL_ArenaRelease(pool, _m); } PL_ArenaCountRelease(pool, _m); PR_END_MACRO # macro
def PR_CurrentThread(): return PR_GetCurrentThread() # macro
PK11_TypeGeneric = 0
PR_FAILURE = -1
_SC_TYPED_MEMORY_OBJECTS = 165
# __KEY_T_TYPE = __S32_TYPE # alias
_SC_NL_LANGMAX = 120
_SC_NL_LANGMAX = _SC_NL_LANGMAX # alias
PR_BYTES_PER_INT = 4 # Variable c_int '4'
BYTES_PER_INT = PR_BYTES_PER_INT # alias
CKA_NSS_URL = 3461563217L # Variable c_uint '-833404079u'
CKA_NETSCAPE_URL = CKA_NSS_URL # alias
SEC_ERROR_UNKNOWN_CERT = -8077
# __FSBLKCNT_T_TYPE = __ULONGWORD_TYPE # alias
CKO_NSS_SMIME = 3461563218L # Variable c_uint '-833404078u'
CKO_NETSCAPE_SMIME = CKO_NSS_SMIME # alias
SEC_ERROR_REUSED_ISSUER_AND_SERIAL = -8054
PR_MW_FAILURE = -1
SSL_ERROR_RX_UNEXPECTED_NEW_SESSION_TICKET = -12179
# PORT_Strncmp = strncmp # alias
PR_BITS_PER_WORD = 32 # Variable c_int '32'
BITS_PER_WORD = PR_BITS_PER_WORD # alias
SEC_ERROR_LOCKED_PASSWORD = -8019
_SC_READER_WRITER_LOCKS = 153
_SC_READER_WRITER_LOCKS = _SC_READER_WRITER_LOCKS # alias
ssl_calg_aes = 7
_CS_POSIX_V7_ILP32_OFF32_CFLAGS = 1132
_CS_POSIX_V7_ILP32_OFF32_CFLAGS = _CS_POSIX_V7_ILP32_OFF32_CFLAGS # alias
__ssize_t = c_int
_G_ssize_t = __ssize_t # alias
_IO_ssize_t = _G_ssize_t # alias
# __CLOCK_T_TYPE = __SLONGWORD_TYPE # alias
_SC_USER_GROUPS = 166
_SC_TIMEOUTS = 164
_SC_TIMEOUTS = _SC_TIMEOUTS # alias
SSL_ERROR_SYM_KEY_CONTEXT_FAILURE = -12212
_SC_SSIZE_MAX = 110
_SC_SSIZE_MAX = _SC_SSIZE_MAX # alias
_SC_EQUIV_CLASS_MAX = 41
_SC_XOPEN_VERSION = _SC_XOPEN_VERSION # alias
_SC_CHAR_MIN = _SC_CHAR_MIN # alias
_SC_GETPW_R_SIZE_MAX = 70
# def __bswap_64(x): return (__extension__ ({ union { __extension__ unsigned long long int __ll; unsigned int __l[2]; } __w, __r; if (__builtin_constant_p (x)) __r.__ll = __bswap_constant_64 (x); else { __w.__ll = (x); __r.__l[0] = __bswap_32 (__w.__l[1]); __r.__l[1] = __bswap_32 (__w.__l[0]); } __r.__ll; })) # macro
_SC_STREAM_MAX = 5
_SC_STREAM_MAX = _SC_STREAM_MAX # alias
# def LL_UDIVMOD(qp,rp,a,b): return (*(qp) = ((PRUint64)(a) / (b)), *(rp) = ((PRUint64)(a) % (b))) # macro
_CS_POSIX_V7_LP64_OFF64_LDFLAGS = 1141
_CS_POSIX_V7_LP64_OFF64_LDFLAGS = _CS_POSIX_V7_LP64_OFF64_LDFLAGS # alias
_SC_LEVEL1_DCACHE_SIZE = 188
_SC_LEVEL1_DCACHE_SIZE = _SC_LEVEL1_DCACHE_SIZE # alias
unsupported_extension = 110
_SC_PII_OSI_COTS = 63
SSL_ERROR_RX_RECORD_TOO_LONG = -12263
SEC_OID_PKCS9_FRIENDLY_NAME = 171
def IN_CLASSD(a): return ((((in_addr_t)(a)) & 0xf0000000) == 0xe0000000) # macro
# _EXTERN_INLINE = __extern_inline # alias
SEC_OID_NS_CERT_EXT_CERT_TYPE = 63
IPPROTO_UDP = 17
SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE = 15
_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = 1137
PR_IpAddrAny = 1
_SC_TRACE_SYS_MAX = 244
_SC_TRACE_SYS_MAX = _SC_TRACE_SYS_MAX # alias
content_application_data = 23
_SC_XOPEN_CRYPT = 92
_SC_XOPEN_CRYPT = _SC_XOPEN_CRYPT # alias
class _G_fpos_t(Structure):
    pass
class __mbstate_t(Structure):
    pass
class N11__mbstate_t4DOT_28E(Union):
    pass
N11__mbstate_t4DOT_28E._fields_ = [
    ('__wch', c_uint),
    ('__wchb', c_char * 4),
]
__mbstate_t._fields_ = [
    ('__count', c_int),
    ('__value', N11__mbstate_t4DOT_28E),
]
_G_fpos_t._fields_ = [
    ('__pos', __off_t),
    ('__state', __mbstate_t),
]
_IO_fpos_t = _G_fpos_t # alias
__SQUAD_TYPE = __quad_t # alias
__BLKCNT64_T_TYPE = __SQUAD_TYPE # alias
MSG_RST = 4096
_SC_SYNCHRONIZED_IO = 14
_SC_SYNCHRONIZED_IO = _SC_SYNCHRONIZED_IO # alias
SSL_ERROR_UNSUPPORTED_CERT_ALERT = -12225
SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO = -12246
IPPROTO_ROUTING = 43
IPPROTO_ROUTING = IPPROTO_ROUTING # alias
def __warnattr(msg): return __attribute__((__warning__ (msg))) # macro
_SC_IPV6 = 235
_SC_IPV6 = _SC_IPV6 # alias
ssl_hmac_md5 = 3
hmac_md5 = ssl_hmac_md5 # alias
relativeDistinguishedName = 2
PR_SockOpt_McastLoopback = 12
_SC_V6_ILP32_OFF32 = 176
def PR_CALLOC(_size): return (PR_Calloc(1, (_size))) # macro
SSL_ERROR_UNSAFE_NEGOTIATION = -12175
IPPROTO_UDPLITE = 136
IPPROTO_UDPLITE = IPPROTO_UDPLITE # alias
_PC_ASYNC_IO = _PC_ASYNC_IO # alias
# def LL_NOT(r,a): return ((r) = ~(a)) # macro
SEC_ERROR_EXTENSION_NOT_FOUND = -8157
_PC_PIPE_BUF = 5
# def ssl_GetSSL3HandshakeLock(ss): return { if (!ss->opt.noLocks) PZ_EnterMonitor((ss)->ssl3HandshakeLock); } # macro
_ISgraph = 32768
# def ssl_HaveRecvBufLock(ss): return (PZ_InMonitor((ss)->recvBufLock)) # macro
_SC_BASE = 134
_SC_BASE = _SC_BASE # alias
_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = 1120
_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS # alias
SSL_ERROR_INIT_CIPHER_SUITE_FAILURE = -12208
SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION = 194
SEC_ERROR_PKCS11_DEVICE_ERROR = -8023
def __isupper_l(c,l): return __isctype_l((c), _ISupper, (l)) # macro
_SC_LEVEL2_CACHE_LINESIZE = 193
# def PL_CLEAR_UNUSED_PATTERN(a,pattern): return (PR_ASSERT((a)->avail <= (a)->limit), memset((void*)(a)->avail, (pattern), (a)->limit - (a)->avail)) # macro
# def LL_USHR(r,a,b): return ((r) = (PRUint64)(a) >> (b)) # macro
SEC_OID_SECG_EC_SECT163R2 = 248
# def PR_DEFINE_TRACE(name): return PRTraceHandle name # macro
def PZ_NewMonitor(t): return PR_NewMonitor() # macro
CKA_NSS_PQG_SEED_BITS = 3461563239L # Variable c_uint '-833404057u'
CKA_NETSCAPE_PQG_SEED_BITS = CKA_NSS_PQG_SEED_BITS # alias
calg_aes = ssl_calg_aes # alias
crlEntryReasonPrivilegeWithdrawn = 9
_SC_FIFO = 144
def CK_CALLBACK_FUNCTION(rtype,func): return rtype (PR_CALLBACK * func) # macro
_SC_SELECT = 59
def _IO_BE(expr,res): return __builtin_expect ((expr), res) # macro
kea_dhe_dss_export = 9
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC = 117
# PORT_Strcpy = strcpy # alias
cipher_des = 6
_SC_SIGNALS = 158
SEC_OID_PKIX_OCSP_NO_CHECK = 135
PF_NETBEUI = 13 # Variable c_int '13'
AF_NETBEUI = PF_NETBEUI # alias
_SC_V6_ILP32_OFF32 = _SC_V6_ILP32_OFF32 # alias
SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION = 195
_SC_RAW_SOCKETS = 236
_SC_RAW_SOCKETS = _SC_RAW_SOCKETS # alias
ssl_server_name_xtn = 0
certUsageAnyCA = 11
# def PR_REMOVE_LINK(_e): return PR_BEGIN_MACRO (_e)->prev->next = (_e)->next; (_e)->next->prev = (_e)->prev; PR_END_MACRO # macro
nssILockCertDB = 5
_SC_EXPR_NEST_MAX = 42
_CS_V6_WIDTH_RESTRICTED_ENVS = 1
_CS_POSIX_V6_WIDTH_RESTRICTED_ENVS = _CS_V6_WIDTH_RESTRICTED_ENVS # alias
_SC_CHAR_MAX = 102
_SC_CHAR_MAX = _SC_CHAR_MAX # alias
kea_ecdhe_rsa = 18
PR_PRIORITY_URGENT = 3
kea_dhe_rsa = 10
certValidityChooseA = 3
_SC_MEMORY_PROTECTION = 19
def htobe16(x): return __bswap_16 (x) # macro
def __isdigit_l(c,l): return __isctype_l((c), _ISdigit, (l)) # macro
SEC_OID_AVA_INITIALS = 269
SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_TRIPLE_DES = 122
SECSuccess = 0
_SC_PAGESIZE = 30
_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = 1115
_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS # alias
_CS_V6_WIDTH_RESTRICTED_ENVS = _CS_V6_WIDTH_RESTRICTED_ENVS # alias
SEC_OID_X509_SUBJECT_ALT_NAME = 83
# def LL_L2D(d,l): return ((d) = (PRFloat64)(l)) # macro
# __SWBLK_T_TYPE = __SLONGWORD_TYPE # alias
# def LL_XOR(r,a,b): return ((r) = (a) ^ (b)) # macro
SSL_ERROR_NO_CIPHERS_SUPPORTED = -12265
_SC_SAVED_IDS = 8
class _G_fpos64_t(Structure):
    pass
_G_fpos64_t._pack_ = 4
_G_fpos64_t._fields_ = [
    ('__pos', __off64_t),
    ('__state', __mbstate_t),
]
_IO_fpos64_t = _G_fpos64_t # alias
PF_ATMSVC = 20 # Variable c_int '20'
AF_ATMSVC = PF_ATMSVC # alias
# __BLKCNT_T_TYPE = __SLONGWORD_TYPE # alias
SEC_ERROR_KRL_INVALID = -8130
def IN_MULTICAST(a): return IN_CLASSD(a) # macro
_SC_THREAD_KEYS_MAX = _SC_THREAD_KEYS_MAX # alias
# def LSB(x): return ((unsigned char) ((x) & 0xff)) # macro
_PC_SYMLINK_MAX = 19
_PC_SYMLINK_MAX = _PC_SYMLINK_MAX # alias
PRTraceStopRecording = 9
_CS_LFS_LIBS = 1002
_CS_LFS_LIBS = _CS_LFS_LIBS # alias
ecKey = 6
IPPROTO_COMP = 108
# def __FD_CLR(d,set): return (__FDS_BITS (set)[__FDELT (d)] &= ~__FDMASK (d)) # macro
def WIFSTOPPED(status): return __WIFSTOPPED (__WAIT_INT (status)) # macro
IPV6_JOIN_GROUP = 20 # Variable c_int '20'
IPV6_ADD_MEMBERSHIP = IPV6_JOIN_GROUP # alias
_SC_XBS5_ILP32_OFF32 = 125
SEC_ERROR_CERT_NICKNAME_COLLISION = -8124
_SC_SIGNALS = _SC_SIGNALS # alias
_CS_XBS5_LPBIG_OFFBIG_LDFLAGS = 1113
# def PR_ABS(x): return ((x)<0?-(x):(x)) # macro
SSL_ERROR_SERVER_CACHE_NOT_CONFIGURED = -12185
# def PR_STATIC_ASSERT(condition): return extern void pr_static_assert(int arg[(condition) ? 1 : -1]) # macro
# _IO_iconv_t = _G_iconv_t # alias
_SC_OPEN_MAX = _SC_OPEN_MAX # alias
# def strdupa(s): return (__extension__ ({ __const char *__old = (s); size_t __len = strlen (__old) + 1; char *__new = (char *) __builtin_alloca (__len); (char *) memcpy (__new, __old, __len); })) # macro
_CS_V6_ENV = 1148
PF_LOCAL = 1 # Variable c_int '1'
PF_UNIX = PF_LOCAL # alias
AF_UNIX = PF_UNIX # alias
PR_AF_LOCAL = AF_UNIX # alias
CKA_NSS_PQG_SEED = 3461563237L # Variable c_uint '-833404059u'
CKA_NETSCAPE_PQG_SEED = CKA_NSS_PQG_SEED # alias
SEC_ERROR_JS_INVALID_MODULE_NAME = -8086
def CERT_LIST_EMPTY(l): return CERT_LIST_END(CERT_LIST_HEAD(l), l) # macro
_SC_TRACE_INHERIT = 183
_SC_TRACE_INHERIT = _SC_TRACE_INHERIT # alias
cipher_null = 0
SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT = -8107
# def SECKEY_HAS_ATTRIBUTE_SET(key,attribute): return (0 != (key->staticflags & SECKEY_Attributes_Cached)) ? (0 != (key->staticflags & SECKEY_ ##attribute)) : PK11_HasAttributeSet(key->pkcs11Slot,key->pkcs11ID,attribute) # macro
_CS_XBS5_LP64_OFF64_CFLAGS = 1108
# def MSB(x): return ((unsigned char) (((unsigned)(x)) >> 8)) # macro
# def _IO_PENDING_OUTPUT_COUNT(_fp): return ((_fp)->_IO_write_ptr - (_fp)->_IO_write_base) # macro
SEC_OID_ANSIX962_EC_C2ONB239V5 = 236
PR_FALSE = 0 # Variable c_int '0'
PR_BETA = PR_FALSE # alias
def PZ_DestroyLock(k): return PR_DestroyLock((k)) # macro
SEC_ERROR_OCSP_INVALID_SIGNING_CERT = -8048
SEC_ERROR_OUT_OF_SEARCH_LIMITS = -8034
SEC_OID_SHA256 = 191
_CS_XBS5_ILP32_OFF32_LINTFLAGS = 1103
_SC_2_C_VERSION = 96
_SC_2_C_VERSION = _SC_2_C_VERSION # alias
SEC_ERROR_OCSP_REQUEST_NEEDS_SIG = -8069
_SC_2_C_BIND = 47
_SC_PRIORITY_SCHEDULING = 10
_SC_PRIORITY_SCHEDULING = _SC_PRIORITY_SCHEDULING # alias
SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC = 21
cert_po_keyUsage = 7
SEEK_SET = 0 # Variable c_int '0'
L_SET = SEEK_SET # alias
# def LL_ADD(r,a,b): return ((r) = (a) + (b)) # macro
_SC_THREAD_CPUTIME = 139
def CMSG_NXTHDR(mhdr,cmsg): return __cmsg_nxthdr (mhdr, cmsg) # macro
PR_ACCESS_EXISTS = 1
_SC_CHAR_BIT = 101
_SC_CHAR_BIT = _SC_CHAR_BIT # alias
unexpected_message = 10
SEC_OID_PKCS12_V1_KEY_BAG_ID = 162
SSL_ERROR_BAD_CERTIFICATE = -12284
_SC_LEVEL1_DCACHE_ASSOC = 189
_SC_LEVEL1_DCACHE_ASSOC = _SC_LEVEL1_DCACHE_ASSOC # alias
PK11TokenRemovedOrChangedEvent = 0
_SC_VERSION = 29
_CS_XBS5_LPBIG_OFFBIG_LIBS = 1114
_CS_XBS5_LPBIG_OFFBIG_LIBS = _CS_XBS5_LPBIG_OFFBIG_LIBS # alias
_CS_V6_ENV = _CS_V6_ENV # alias
# def IP_MSFILTER_SIZE(numsrc): return (sizeof (struct ip_msfilter) - sizeof (struct in_addr) + (numsrc) * sizeof (struct in_addr)) # macro
IPPORT_TTYLINK = 87
SSL_ERROR_RX_MALFORMED_HELLO_DONE = -12255
ssl_calg_camellia = 8
SEC_OID_PKIX_TIMESTAMPING = 299
SHUT_RD = 0
# def LL_AND(r,a,b): return ((r) = (a) & (b)) # macro
PR_BITS_PER_BYTE_LOG2 = 3 # Variable c_int '3'
BITS_PER_BYTE_LOG2 = PR_BITS_PER_BYTE_LOG2 # alias
_SC_XOPEN_XCU_VERSION = 90
_SC_XOPEN_XCU_VERSION = _SC_XOPEN_XCU_VERSION # alias
SEC_ERROR_UNKNOWN_OBJECT_TYPE = -8042
SHUT_WR = 1
SHUT_WR = SHUT_WR # alias
IPPROTO_RSVP = 46
IPPROTO_RSVP = IPPROTO_RSVP # alias
SSLAppOpRead = 0
_SC_USER_GROUPS_R = 167
_SC_USER_GROUPS_R = _SC_USER_GROUPS_R # alias
PR_LibSpec_MacIndexedFragment = 2
PR_BITS_PER_INT = 32 # Variable c_int '32'
BITS_PER_INT = PR_BITS_PER_INT # alias
_PC_SOCK_MAXBUF = 12
_PC_SOCK_MAXBUF = _PC_SOCK_MAXBUF # alias
SEC_ERROR_NO_KRL = -8134
server_key_exchange = 12
IPPORT_RJE = 77
_CS_LFS_LDFLAGS = 1001
_CS_LFS_LDFLAGS = _CS_LFS_LDFLAGS # alias
PF_RDS = 21 # Variable c_int '21'
AF_RDS = PF_RDS # alias
_SC_PAGESIZE = _SC_PAGESIZE # alias
SSL_ERROR_RX_UNEXPECTED_FINISHED = -12238
IPPROTO_ICMP = 1
IPPROTO_ICMP = IPPROTO_ICMP # alias
SEC_ERROR_CERT_NOT_VALID = -8164
# def ssl_GetRecvBufLock(ss): return { if (!ss->opt.noLocks) PZ_EnterMonitor((ss)->recvBufLock); } # macro
_SC_TRACE_LOG = 184
PF_PPPOX = 24 # Variable c_int '24'
AF_PPPOX = PF_PPPOX # alias
IPPORT_WHOIS = 43
SEC_OID_SECG_EC_SECT283K1 = 254
# def PR_IMPLEMENT_DATA(__type): return PR_VISIBILITY_DEFAULT __type # macro
_SC_PII = 53
_SC_PII = _SC_PII # alias
protocol_version = 70
SEC_OID_X509_SUBJECT_INFO_ACCESS = 287
_SC_TZNAME_MAX = _SC_TZNAME_MAX # alias
HASH_AlgSHA512 = 6
_POSIX2_C_DEV = __POSIX2_THIS_VERSION # alias
SEC_OID_PKCS12_BAG_IDS = 103
# PRArenaStats = PLArenaStats # alias
# def __exctype(name): return extern int name (int) __THROW # macro
PF_MAX = 37 # Variable c_int '37'
AF_MAX = PF_MAX # alias
cipher_camellia_128 = 12
_SC_NETWORKING = 152
kea_rsa_export = 2
MSG_RST = MSG_RST # alias
SEC_OID_X509_ISSUER_ALT_NAME = 84
def PZ_Lock(k): return PR_Lock((k)) # macro
_CS_LFS64_LDFLAGS = 1005
SEC_OID_X509_NAME_CONSTRAINTS = 86
SEC_ERROR_CA_CERT_INVALID = -8156
dsaKey = 2
# def SEC_ASN1_CHOOSER_IMPLEMENT(x): return const SEC_ASN1Template * NSS_Get_ ##x(void * arg, PRBool enc) { return x; } # macro
SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST = 275
# PR_HashTableRawAdd = PL_HashTableRawAdd # alias
# def __SOCKADDR_COMMON(sa_prefix): return sa_family_t sa_prefix ##family # macro
SEC_OID_MISSI_KEA_DSS = 56
# def LL_UI2L(l,ui): return ((l) = (PRInt64)(ui)) # macro
def offsetof(TYPE,MEMBER): return __builtin_offsetof (TYPE, MEMBER) # macro
_CS_XBS5_LPBIG_OFFBIG_LDFLAGS = _CS_XBS5_LPBIG_OFFBIG_LDFLAGS # alias
XP_SEC_FORTEZZA_MORE_INFO = -8139
SOCK_CLOEXEC = 524288
SEC_ERROR_EXPIRED_CERTIFICATE = -8181
# def DER_ConvertBitString(item): return { (item)->len = ((item)->len + 7) >> 3; } # macro
PR_BITS_PER_BYTE = 8 # Variable c_int '8'
BITS_PER_BYTE = PR_BITS_PER_BYTE # alias
cert_pi_keyusage = 6
IPPROTO_GRE = 47
IPPROTO_SCTP = IPPROTO_SCTP # alias
SEC_OID_HMAC_SHA384 = 297
client_key_exchange = 16
SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE = 279
def PR_INT32(x): return x # macro
# PR_ArenaCountRetract = PL_ArenaCountRetract # alias
ssl_mac_null = 0
MSG_PEEK = 2
def __isalpha_l(c,l): return __isctype_l((c), _ISalpha, (l)) # macro
_SC_HOST_NAME_MAX = 180
PF_IPX = 4 # Variable c_int '4'
AF_IPX = PF_IPX # alias
_SC_PII_INTERNET = 56
_SC_PII_INTERNET = _SC_PII_INTERNET # alias
_SC_THREAD_ROBUST_PRIO_PROTECT = 248
SEC_ERROR_EXPORTING_CERTIFICATES = -8116
PF_NETROM = 6 # Variable c_int '6'
AF_NETROM = PF_NETROM # alias
_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = 1144
_PC_REC_MIN_XFER_SIZE = 16
_PC_REC_MIN_XFER_SIZE = _PC_REC_MIN_XFER_SIZE # alias
SEC_ERROR_FAILED_TO_ENCODE_DATA = -8028
_CS_XBS5_LP64_OFF64_LDFLAGS = 1109
SEC_ERROR_PKCS7_KEYALG_MISMATCH = -8146
SEC_OID_MISSI_DSS_OLD = 55
crlEntryReasonCaCompromise = 2
class PLArenaPool(Structure):
    pass
PRArenaPool = PLArenaPool # alias
# def LL_UCMP(a,op,b): return ((PRUint64)(a) op (PRUint64)(b)) # macro
SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY = -8099
def PZ_NotifyAllCondVar(v): return PR_NotifyAllCondVar((v)) # macro
SEC_OID_SECG_EC_SECP384R1 = 220
implicit = 0
def WIFEXITED(status): return __WIFEXITED (__WAIT_INT (status)) # macro
def FD_ISSET(fd,fdsetp): return __FD_ISSET (fd, fdsetp) # macro
# PR_ArenaCountAllocation = PL_ArenaCountAllocation # alias
_SC_LOGIN_NAME_MAX = 71
nssILockFreelist = 11
# PR_CompareStrings = PL_CompareStrings # alias
nssILockRWLock = 15
def PZ_Unlock(k): return PR_Unlock((k)) # macro
def __WIFCONTINUED(status): return ((status) == __W_CONTINUED) # macro
certValidityEqual = 2
# __CLOCKID_T_TYPE = __S32_TYPE # alias
# PR_HashTableLookup = PL_HashTableLookup # alias
certificate_unobtainable = 111
SEC_ERROR_OLD_KRL = -8082
# __UID_T_TYPE = __U32_TYPE # alias
# PR_ARENA_RELEASE = PL_ARENA_RELEASE # alias
# PORT_Memmove = memmove # alias
def __bswap_constant_32(x): return ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >> 8) | (((x) & 0x0000ff00) << 8) | (((x) & 0x000000ff) << 24)) # macro
SEC_OID_PKCS1_RSA_ENCRYPTION = 16
SEC_OID_ANSIX962_EC_PRIME192V1 = 202
SEC_OID_SECG_EC_SECP192R1 = SEC_OID_ANSIX962_EC_PRIME192V1 # alias
_G_HAVE_SYS_WAIT = 1 # Variable c_int '1'
_IO_HAVE_SYS_WAIT = _G_HAVE_SYS_WAIT # alias
PF_CAN = 29 # Variable c_int '29'
AF_CAN = PF_CAN # alias
SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH = 147
SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST = -12247
IPPROTO_PUP = 12
IPPROTO_PUP = IPPROTO_PUP # alias
PF_IUCV = 32 # Variable c_int '32'
AF_IUCV = PF_IUCV # alias
SEC_OID_AES_256_ECB = 187
PR_LibSpec_PathnameU = 3
_SC_SPORADIC_SERVER = 160
_SC_SPORADIC_SERVER = _SC_SPORADIC_SERVER # alias
_SC_2_PBS_CHECKPOINT = 175
# def PR_CEILING_LOG2(_log2,_n): return PR_BEGIN_MACRO PRUint32 j_ = (PRUint32)(_n); (_log2) = (j_ <= 1 ? 0 : 32 - pr_bitscan_clz32(j_ - 1)); PR_END_MACRO # macro
_SC_NL_SETMAX = 123
# def ssl_Get1stHandshakeLock(ss): return { if (!ss->opt.noLocks) PZ_EnterMonitor((ss)->firstHandshakeLock); } # macro
_SC_TRACE = 181
_SC_TRACE = _SC_TRACE # alias
_SC_AVPHYS_PAGES = 86
_SC_AVPHYS_PAGES = _SC_AVPHYS_PAGES # alias
IPPORT_BIFFUDP = 512
SSL_ERROR_IV_PARAM_FAILURE = -12209
# PR_ArenaGrow = PL_ArenaGrow # alias
SEC_OID_SHA512 = 193
_SC_PII_INTERNET_STREAM = 61
_SC_PII_INTERNET_STREAM = _SC_PII_INTERNET_STREAM # alias
# def PL_ARENA_ALIGN(pool,n): return (((PRUword)(n) + (pool)->mask) & ~(pool)->mask) # macro
# PR_ARENA_ALIGN = PL_ARENA_ALIGN # alias
_SC_V7_LP64_OFF64 = 239
_SC_V7_LP64_OFF64 = _SC_V7_LP64_OFF64 # alias
_SC_LEVEL2_CACHE_ASSOC = 192
SSL_ERROR_CERT_KEA_MISMATCH = -12200
def PZ_Notify(m): return PR_Notify((m)) # macro
def htobe32(x): return __bswap_32 (x) # macro
_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = 1128
_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS # alias
SEC_OID_SECG_EC_SECP112R2 = 210
crlEntryReasonCessationOfOperation = 5
PR_PROT_READWRITE = 1
SEC_OID_SECG_EC_SECP521R1 = 221
PR_PRIORITY_HIGH = 2
SEC_OID_SHA1 = 4
bad_record_mac = 20
trustEmail = 1
__NFDBITS = 32 # Variable c_int '32'
NFDBITS = __NFDBITS # alias
ssl_kea_dh = 2
kt_dh = ssl_kea_dh # alias
nssILockList = 9
PR_BYTES_PER_WORD = 4 # Variable c_int '4'
BYTES_PER_WORD = PR_BYTES_PER_WORD # alias
MSG_WAITFORONE = 65536
MSG_WAITFORONE = MSG_WAITFORONE # alias
SEC_OID_PKCS12_ESPVK_IDS = 102
# PORT_Strstr = strstr # alias
wait_new_session_ticket = 11
# def __warndecl(name,msg): return extern void name (void) __attribute__((__warning__ (msg))) # macro
ssl_calg_rc4 = 1
_SC_BC_SCALE_MAX = 38
_SC_BC_SCALE_MAX = _SC_BC_SCALE_MAX # alias
PK11TokenRemoved = 3
_SC_THREAD_PRIORITY_SCHEDULING = 79
_SC_THREAD_PRIORITY_SCHEDULING = _SC_THREAD_PRIORITY_SCHEDULING # alias
ssl_calg_null = 0
SEC_ERROR_NO_RECIPIENT_CERTS_QUERY = -8148
_CS_POSIX_V6_LP64_OFF64_CFLAGS = 1124
_CS_POSIX_V6_LP64_OFF64_CFLAGS = _CS_POSIX_V6_LP64_OFF64_CFLAGS # alias
# def _IO_getc_unlocked(_fp): return (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) ? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++) # macro
_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = 1123
_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS # alias
_CS_XBS5_LP64_OFF64_LINTFLAGS = 1111
_CS_XBS5_LP64_OFF64_LINTFLAGS = _CS_XBS5_LP64_OFF64_LINTFLAGS # alias
SEC_OID_PKIX_OCSP = 130
SEC_OID_X509_DELTA_CRL_INDICATOR = 282
SECLessThan = -1
def htons(x): return __bswap_16 (x) # macro
kt_null = ssl_kea_null # alias
_SC_ASYNCHRONOUS_IO = 12
# _IO_HAVE_ST_BLKSIZE = _G_HAVE_ST_BLKSIZE # alias
PF_DECnet = 12 # Variable c_int '12'
AF_DECnet = PF_DECnet # alias
SEC_ERROR_REVOKED_KEY = -8131
# def PR_MIN(x,y): return ((x)<(y)?(x):(y)) # macro
SEC_ERROR_NO_MEMORY = -8173
wait_client_hello = 0
_SC_XBS5_LP64_OFF64 = 127
_SC_XBS5_LP64_OFF64 = _SC_XBS5_LP64_OFF64 # alias
ssl_kea_ecdh = 4
kt_ecdh = ssl_kea_ecdh # alias
_CS_POSIX_V6_ILP32_OFFBIG_LIBS = 1122
_CS_POSIX_V6_ILP32_OFFBIG_LIBS = _CS_POSIX_V6_ILP32_OFFBIG_LIBS # alias
_PC_REC_MAX_XFER_SIZE = 15
_PC_REC_MAX_XFER_SIZE = _PC_REC_MAX_XFER_SIZE # alias
_CS_POSIX_V6_ILP32_OFF32_CFLAGS = 1116
_SC_LEVEL1_ICACHE_LINESIZE = 187
_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = 1121
_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS # alias
IP_ORIGDSTADDR = 20 # Variable c_int '20'
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR # alias
_PC_ALLOC_SIZE_MIN = 18
_PC_ALLOC_SIZE_MIN = _PC_ALLOC_SIZE_MIN # alias
IPPROTO_PIM = 103
SEC_OID_AVA_TITLE = 264
_SC_T_IOV_MAX = 66
_SC_T_IOV_MAX = _SC_T_IOV_MAX # alias
_ISprint = 16384
SEC_OID_X509_ISSUING_DISTRIBUTION_POINT = 283
_SC_ATEXIT_MAX = 87
_SC_ATEXIT_MAX = _SC_ATEXIT_MAX # alias
def PR_APPEND_LINK(_e,_l): return PR_INSERT_BEFORE(_e,_l) # macro
_SC_PHYS_PAGES = 85
SEC_OID_PKCS1_SHA224_WITH_RSA_ENCRYPTION = 308
# def PL_ARENA_ALLOCATE(p,pool,nb): return PR_BEGIN_MACRO PLArena *_a = (pool)->current; PRUint32 _nb = PL_ARENA_ALIGN(pool, nb); PRUword _p = _a->avail; PRUword _q = _p + _nb; if (_q > _a->limit) _p = (PRUword)PL_ArenaAllocate(pool, _nb); else _a->avail = _q; p = (void *)_p; PL_ArenaCountAllocation(pool, nb); PR_END_MACRO # macro
# PR_ARENA_ALLOCATE = PL_ARENA_ALLOCATE # alias
SEC_ERROR_BAD_INFO_ACCESS_METHOD = -8022
SEC_ERROR_EXTENSION_VALUE_INVALID = -8158
SOCK_RDM = 4
_SC_REALTIME_SIGNALS = 9
_SC_REALTIME_SIGNALS = _SC_REALTIME_SIGNALS # alias
SEC_OID_PKCS9_MESSAGE_DIGEST = 34
SEC_ERROR_CANNOT_MOVE_SENSITIVE_KEY = -8087
SEC_ERROR_PKCS12_UNSUPPORTED_VERSION = -8108
certIPAddress = 8
HASH_AlgSHA384 = 5
IPPORT_NETSTAT = 15
SEC_OID_EXT_KEY_USAGE_CODE_SIGN = 148
SEC_OID_ANSIX962_EC_C2PNB304W1 = 238
def PZ_DestroyMonitor(m): return PR_DestroyMonitor((m)) # macro
_SC_SHARED_MEMORY_OBJECTS = 22
_SC_SHARED_MEMORY_OBJECTS = _SC_SHARED_MEMORY_OBJECTS # alias
crlEntryReasonSuperseded = 4
_SC_NL_MSGMAX = 121
cipher_rc2_40 = 5
_SC_SPAWN = 159
ssl_sign_rsa = 1
PF_LLC = 26 # Variable c_int '26'
AF_LLC = PF_LLC # alias
SEC_ERROR_OCSP_TRY_SERVER_LATER = -8070
# __INO_T_TYPE = __ULONGWORD_TYPE # alias
SSL_ERROR_SHA_DIGEST_FAILURE = -12214
PF_RXRPC = 33 # Variable c_int '33'
AF_RXRPC = PF_RXRPC # alias
_SC_V6_ILP32_OFFBIG = _SC_V6_ILP32_OFFBIG # alias
SEC_OID_SECG_EC_SECT239K1 = 253
# PR_ArenaFinish = PL_ArenaFinish # alias
SEC_ERROR_OCSP_FUTURE_RESPONSE = -8061
SEC_OID_ANSIX962_EC_C2PNB208W1 = 231
SSL_ERROR_HANDSHAKE_NOT_COMPLETED = -12202
change_cipher_spec_choice = 1
cert_po_usages = 6
certUsageProtectedObjectSigner = 9
MSG_DONTWAIT = MSG_DONTWAIT # alias
SEC_OID_PKCS12_PKCS8_SHROUDED_KEY_BAG_ID = 161
kea_dhe_dss = 8
ct_RSA_ephemeral_DH = 5
_CS_LFS_CFLAGS = 1000
SSL_ERROR_NO_CERTIFICATE = -12285
_SC_BC_BASE_MAX = 36
_CS_POSIX_V7_LP64_OFF64_CFLAGS = 1140
_CS_POSIX_V7_LP64_OFF64_CFLAGS = _CS_POSIX_V7_LP64_OFF64_CFLAGS # alias
SEC_OID_PKIX_REGINFO_CERT_REQUEST = 145
bad_certificate = 42
cert_revocation_method_crl = 0
PR_LOG_WARNING = 3
nssILockPK11cxt = 14
SEC_OID_AVA_GENERATION_QUALIFIER = 270
SEC_OID_ISO_SHA1_WITH_RSA_SIGNATURE = 301
SECFailure = -1
_CS_XBS5_LP64_OFF64_LIBS = _CS_XBS5_LP64_OFF64_LIBS # alias
cert_pi_extendedKeyusage = 7
def htole16(x): return (x) # macro
decrypt_error = 51
# PORT_Strrchr = strrchr # alias
# def __LDBL_REDIR1_NTH(name,proto,alias): return name proto __THROW # macro
SSL_ERROR_RX_MALFORMED_CERT_REQUEST = -12256
def __bos(ptr): return __builtin_object_size (ptr, __USE_FORTIFY_LEVEL > 1) # macro
PF_SNA = 22 # Variable c_int '22'
AF_SNA = PF_SNA # alias
SEC_OID_NS_CERT_EXT_SCOPE_OF_USE = 178
calg_null = ssl_calg_null # alias
PK11CertListUnique = 0
_G_BUFSIZ = 8192 # Variable c_int '8192'
_IO_BUFSIZ = _G_BUFSIZ # alias
def __va_arg_pack_len(): return __builtin_va_arg_pack_len () # macro
MSG_ERRQUEUE = 8192
IPV6_HOPOPTS = 54 # Variable c_int '54'
IPV6_RXHOPOPTS = IPV6_HOPOPTS # alias
_SC_SAVED_IDS = _SC_SAVED_IDS # alias
SEC_ERROR_OUTPUT_LEN = -8189
# def _IO_ferror_unlocked(__fp): return (((__fp)->_flags & _IO_ERR_SEEN) != 0) # macro
def isxdigit_l(c,l): return __isxdigit_l ((c), (l)) # macro
_SC_SEMAPHORES = 21
_SC_SEMAPHORES = _SC_SEMAPHORES # alias
# def ssl_GetSpecReadLock(ss): return { if (!ss->opt.noLocks) NSSRWLock_LockRead((ss)->specLock); } # macro
SSL_ERROR_RECORD_OVERFLOW_ALERT = -12196
def __W_STOPCODE(sig): return ((sig) << 8 | 0x7f) # macro
_PC_REC_INCR_XFER_SIZE = 14
_PC_REC_INCR_XFER_SIZE = _PC_REC_INCR_XFER_SIZE # alias
IPPORT_TFTP = 69
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4 = 155
SSL_ERROR_ENCRYPTION_FAILURE = -12218
PR_DESC_SOCKET_TCP = 2
SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH = -12239
SEC_OID_PKCS9_SIGNING_TIME = 35
SEC_OID_X942_DIFFIE_HELMAN_KEY = 174
_SC_ASYNCHRONOUS_IO = _SC_ASYNCHRONOUS_IO # alias
certOwnerPeer = 1
PR_SockOpt_SendBufferSize = 5
SSL_ERROR_UNRECOGNIZED_NAME_ALERT = -12182
SEC_ERROR_INPUT_LEN = -8188
# def PR_IMPORT(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
# def IN6_IS_ADDR_UNSPECIFIED(a): return (((__const uint32_t *) (a))[0] == 0 && ((__const uint32_t *) (a))[1] == 0 && ((__const uint32_t *) (a))[2] == 0 && ((__const uint32_t *) (a))[3] == 0) # macro
xplicit = 1
SEC_OID_MISSI_DSS = 57
SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE = -12201
SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE = 201
SEC_OID_PKIX_REGCTRL_PKI_ARCH_OPTIONS = 141
sslHandshakingAsServer = 2
SEC_OID_CAMELLIA_192_CBC = 289
PR_PRIORITY_FIRST = 0
ssl_auth_null = 0
# def LL_D2L(l,d): return ((l) = (PRInt64)(d)) # macro
SEC_OID_ANSIX962_EC_C2TNB359V1 = 239
# def PR_IMPLEMENT(__type): return PR_VISIBILITY_DEFAULT __type # macro
SEC_OID_NS_CERT_EXT_LOST_PASSWORD_URL = 76
SEC_OID_PKCS9_LOCAL_KEY_ID = 172
crlEntryReasonAffiliationChanged = 3
SEC_OID_PKIX_REGCTRL_PKIPUBINFO = 140
_SC_SEM_VALUE_MAX = 33
_SC_SEM_VALUE_MAX = _SC_SEM_VALUE_MAX # alias
SEC_OID_SECG_EC_SECP224R1 = 218
SEC_OID_MD5 = 3
SEC_ERROR_BUSY = -8053
PK11CertListUser = 1
def FD_ZERO(fdsetp): return __FD_ZERO (fdsetp) # macro
SEC_OID_NS_CERT_EXT_CERT_RENEWAL_URL = 69
# PR_CLEAR_ARENA = PL_CLEAR_ARENA # alias
# PR_CompactArenaPool = PL_CompactArenaPool # alias
SEC_OID_PKCS9_X509_CRL = 170
MSG_EOR = 128
MSG_EOR = MSG_EOR # alias
_CS_LFS64_LINTFLAGS = 1007
_CS_LFS64_LINTFLAGS = _CS_LFS64_LINTFLAGS # alias
PR_BYTES_PER_LONG = 4 # Variable c_int '4'
BYTES_PER_LONG = PR_BYTES_PER_LONG # alias
def __W_EXITCODE(ret,sig): return ((ret) << 8 | (sig)) # macro
nssILockSession = 1
_SC_IOV_MAX = 60
_SC_IOV_MAX = _SC_IOV_MAX # alias
type_block = 1
SEC_OID_X509_KEY_USAGE = 81
SEC_OID_PKCS12_KEY_USAGE = SEC_OID_X509_KEY_USAGE # alias
__UQUAD_TYPE = __u_quad_t # alias
CKA_NSS_EXPIRES = 3461563223L # Variable c_uint '-833404073u'
CKA_NETSCAPE_EXPIRES = CKA_NSS_EXPIRES # alias
SEC_OID_PKIX_CA_REPOSITORY = 300
kea_ecdh_rsa = 17
SEC_OID_NS_CERT_EXT_NETSCAPE_OK = 60
_SC_SEM_NSEMS_MAX = 32
_CS_XBS5_LP64_OFF64_LDFLAGS = _CS_XBS5_LP64_OFF64_LDFLAGS # alias
# def __WAIT_INT(status): return (*(int *) &(status)) # macro
SEC_OID_PKIX_OCSP_BASIC_RESPONSE = 131
SEC_ERROR_BAD_SIGNATURE = -8182
def IN_CLASSC(a): return ((((in_addr_t)(a)) & 0xe0000000) == 0xc0000000) # macro
SEC_OID_NETSCAPE_NICKNAME = 175
# def CERT_LIST_HEAD(l): return ((CERTCertListNode *)PR_LIST_HEAD(&l->list)) # macro
SEC_OID_PKCS9_X509_CERT = 168
_SC_V7_ILP32_OFF32 = 237
SEC_OID_X509_EXT_KEY_USAGE = 92
# _G_wint_t = wint_t # alias
_SC_XOPEN_LEGACY = 129
_SC_XOPEN_LEGACY = _SC_XOPEN_LEGACY # alias
certValidityUndetermined = 0
SEC_ASN1_Length = 1
secCertTimeNotValidYet = 2
SEC_OID_PKCS9_EXTENDED_CERTIFICATE_ATTRIBUTES = 39
class PRCondVar(Structure):
    pass
PZCondVar = PRCondVar # alias
_PC_PRIO_IO = _PC_PRIO_IO # alias
# def PR_CLEAR_BIT(_map,_bit): return ((_map)[(_bit)>>PR_BITS_PER_LONG_LOG2] &= ~(1L << ((_bit) & (PR_BITS_PER_LONG-1)))) # macro
certificate = 11
# def LL_L2UI(ui,l): return ((ui) = (PRUint32)(l)) # macro
def PR_InMonitor(m): return (PR_GetMonitorEntryCount(m) > 0) # macro
IPPROTO_GRE = IPPROTO_GRE # alias
_CS_XBS5_ILP32_OFF32_LINTFLAGS = _CS_XBS5_ILP32_OFF32_LINTFLAGS # alias
rsaKey = 1
_SC_PII_OSI_CLTS = 64
_SC_PII_OSI_CLTS = _SC_PII_OSI_CLTS # alias
_SC_ARG_MAX = 0
_SC_ARG_MAX = _SC_ARG_MAX # alias
certRFC822Name = 2
PR_SockOpt_IpTypeOfService = 7
_CS_POSIX_V6_ILP32_OFF32_LIBS = 1118
_CS_POSIX_V6_ILP32_OFF32_LIBS = _CS_POSIX_V6_ILP32_OFF32_LIBS # alias
_SC_VERSION = _SC_VERSION # alias
ssl_sign_dsa = 2
sign_dsa = ssl_sign_dsa # alias
SEC_ERROR_BAD_EXPORT_ALGORITHM = -8117
PR_LOG_DEBUG = 4
# def PORT_ArenaZNew(poolp,type): return (type*) PORT_ArenaZAlloc(poolp, sizeof(type)) # macro
SSL_ERROR_NO_TRUSTED_SSL_CLIENT_CA = -12199
SEC_OID_SECG_EC_SECT193R1 = 249
SEC_OID_PKCS12_MODE_IDS = 101
SHUT_RD = SHUT_RD # alias
_CS_POSIX_V6_LPBIG_OFFBIG_LIBS = 1130
SEC_OID_ANSIX962_ECDSA_SIGNATURE_WITH_SHA1_DIGEST = SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE # alias
SEC_OID_DES_CBC = 10
SEC_ERROR_KRL_NOT_YET_VALID = -8079
SEC_OID_PKCS12_OIDS = 105
# def IS_SSL_ERROR(code): return (((code) >= SSL_ERROR_BASE) && ((code) < SSL_ERROR_LIMIT)) # macro
class PLArena(Structure):
    pass
PRArena = PLArena # alias
SEC_ERROR_CERT_ADDR_MISMATCH = -8100
illegal_parameter = 47
_SC_SEM_NSEMS_MAX = _SC_SEM_NSEMS_MAX # alias
SEC_OID_PKIX_OCSP_RESPONSE = 134
SEC_OID_ANSIX962_EC_C2PNB163V1 = 222
def PR_ROUNDUP(x,y): return ((((x)+((y)-1))/(y))*(y)) # macro
# def PORT_Atoi(buff): return (int)strtol(buff, NULL, 10) # macro
AF_LOCAL = PF_LOCAL # alias
SEC_OID_PKCS9_EXTENSION_REQUEST = 274
PR_ACCESS_READ_OK = 3
_SC_RE_DUP_MAX = 44
_SC_RE_DUP_MAX = _SC_RE_DUP_MAX # alias
SEC_OID_X509_INVALID_DATE = 96
SEC_OID_NS_CERT_EXT_COMMENT = 75
ssl_kea_size = 5
def PR_TEST_BIT(_map,_bit): return ((_map)[(_bit)>>PR_BITS_PER_LONG_LOG2] & (1L << ((_bit) & (PR_BITS_PER_LONG-1)))) # macro
TEST_BIT = PR_TEST_BIT # alias
SEC_ERROR_OCSP_UNAUTHORIZED_RESPONSE = -8062
IPPROTO_IGMP = 2
IPPROTO_IGMP = IPPROTO_IGMP # alias
PR_GLOBAL_BOUND_THREAD = 2
_SC_C_LANG_SUPPORT_R = 136
_SC_NL_NMAX = 122
_CS_POSIX_V6_LPBIG_OFFBIG_LIBS = _CS_POSIX_V6_LPBIG_OFFBIG_LIBS # alias
# PR_COUNT_ARENA = PL_COUNT_ARENA # alias
cert_po_errorLog = 5
SEC_OID_X509_SUBJECT_DIRECTORY_ATTR = 79
SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST = 276
PR_BYTES_PER_INT64 = 8 # Variable c_int '8'
BYTES_PER_INT64 = PR_BYTES_PER_INT64 # alias
certValidityChooseB = 1
ct_DSS_fixed_DH = 4
SEC_OID_X509_POLICY_MAPPINGS = 89
# def LL_SHL(r,a,b): return ((r) = (PRInt64)(a) << (b)) # macro
def __GLIBC_PREREQ(maj,min): return ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min)) # macro
SEC_OID_PKCS9_SDSI_CERT = 169
CKA_NSS_EMAIL = 3461563218L # Variable c_uint '-833404078u'
CKA_NETSCAPE_EMAIL = CKA_NSS_EMAIL # alias
SSL_ERROR_POST_WARNING = -12275
_SC_BC_DIM_MAX = 37
_SC_BC_DIM_MAX = _SC_BC_DIM_MAX # alias
nssILockSelfServ = 17
siAsciiNameString = 7
XP_SEC_FORTEZZA_NONE_SELECTED = -8140
SEC_OID_SECG_EC_SECT131R2 = 245
_SC_TRACE_USER_EVENT_MAX = 245
_SC_TRACE_USER_EVENT_MAX = _SC_TRACE_USER_EVENT_MAX # alias
def __bswap_constant_16(x): return ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)) # macro
PF_BLUETOOTH = 31 # Variable c_int '31'
AF_BLUETOOTH = PF_BLUETOOTH # alias
_SC_XOPEN_ENH_I18N = 93
_SC_XOPEN_ENH_I18N = _SC_XOPEN_ENH_I18N # alias
IPPORT_DAYTIME = 13
SEC_OID_EXT_KEY_USAGE_SERVER_AUTH = 146
SSL_ERROR_HANDSHAKE_FAILURE_ALERT = -12227
_PC_2_SYMLINKS = 20
SSL_ERROR_RX_MALFORMED_APPLICATION_DATA = -12248
SEC_OID_AES_192_CBC = 186
wait_client_cert = 1
PR_SKIP_HIDDEN = 4
def isupper_l(c,l): return __isupper_l ((c), (l)) # macro
SEEK_END = 2 # Variable c_int '2'
L_XTND = SEEK_END # alias
PR_TRANSMITFILE_CLOSE_SOCKET = 1
_PC_PIPE_BUF = _PC_PIPE_BUF # alias
_SC_STREAMS = 174
# def PR_CLIST_IS_EMPTY(_l): return ((_l)->next == (_l)) # macro
SEC_OID_PKIX_OCSP_SERVICE_LOCATOR = 137
SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE = 280
_CS_LFS_CFLAGS = _CS_LFS_CFLAGS # alias
SOCK_NONBLOCK = 2048
SOCK_NONBLOCK = SOCK_NONBLOCK # alias
def pr_bitscan_ctz32(val): return __builtin_ctz(val) # macro
SEC_OID_PKCS1_RSA_OAEP_ENCRYPTION = 304
# def CMSG_ALIGN(len): return (((len) + sizeof (size_t) - 1) & (size_t) ~(sizeof (size_t) - 1)) # macro
_SC_AIO_PRIO_DELTA_MAX = 25
_SC_AIO_PRIO_DELTA_MAX = _SC_AIO_PRIO_DELTA_MAX # alias
_SC_SIGQUEUE_MAX = 34
_SC_SIGQUEUE_MAX = _SC_SIGQUEUE_MAX # alias
IPPORT_EFSSERVER = 520
# PR_ArenaCountGrowth = PL_ArenaCountGrowth # alias
SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED = -12210
SEC_OID_SHA384 = 192
SEC_ERROR_BAD_KEY = -8178
def _IO_peekc(_fp): return _IO_peekc_unlocked (_fp) # macro
ssl_hmac_sha = 4
hmac_sha = ssl_hmac_sha # alias
# def PL_ARENA_DESTROY(pool,a,pnext): return PR_BEGIN_MACRO PL_COUNT_ARENA(pool,--); if ((pool)->current == (a)) (pool)->current = &(pool)->first; *(pnext) = (a)->next; PL_CLEAR_ARENA(a); free(a); (a) = 0; PR_END_MACRO # macro
# PR_ARENA_DESTROY = PL_ARENA_DESTROY # alias
# def PORT_ArenaZNewArray(poolp,type,num): return (type*) PORT_ArenaZAlloc (poolp, sizeof(type)*(num)) # macro
_SC_USER_GROUPS = _SC_USER_GROUPS # alias
CKT_NSS_TRUSTED_DELEGATOR = 3461563218L # Variable c_uint '-833404078u'
CKT_NETSCAPE_TRUSTED_DELEGATOR = CKT_NSS_TRUSTED_DELEGATOR # alias
SSL_ERROR_SESSION_NOT_FOUND = -12198
# def PR_DirName(dirEntry): return (dirEntry->name) # macro
_SC_NPROCESSORS_CONF = 83
# def __isctype_l(c,type,locale): return ((locale)->__ctype_b[(int) (c)] & (unsigned short int) type) # macro
SEC_OID_SECG_EC_SECP112R1 = 209
SEC_OID_RC5_CBC_PAD = 8
CKA_NSS_SMIME_TIMESTAMP = 3461563220L # Variable c_uint '-833404076u'
CKA_NETSCAPE_SMIME_TIMESTAMP = CKA_NSS_SMIME_TIMESTAMP # alias
SEC_ERROR_REVOKED_CERTIFICATE_CRL = -8047
_SC_ULONG_MAX = 117
# PR_ArenaRelease = PL_ArenaRelease # alias
SEC_OID_ANSIX962_EC_C2PNB163V2 = 223
# def PORT_New(type): return (type*)PORT_Alloc(sizeof(type)) # macro
cipher_aes_256 = 11
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC = 156
SSL_ERROR_EXPIRED_CERT_ALERT = -12269
_SC_REGEX_VERSION = 156
_SC_REGEX_VERSION = _SC_REGEX_VERSION # alias
SEC_OID_PKIX_OCSP_ARCHIVE_CUTOFF = 136
SEC_ERROR_OCSP_OLD_RESPONSE = -8060
PF_PACKET = 17 # Variable c_int '17'
AF_PACKET = PF_PACKET # alias
_CS_V5_WIDTH_RESTRICTED_ENVS = 4
_SC_XBS5_LPBIG_OFFBIG = 128
_SC_XBS5_LPBIG_OFFBIG = _SC_XBS5_LPBIG_OFFBIG # alias
CKK_NSS_PKCS8 = 3461563217L # Variable c_uint '-833404079u'
CKK_NETSCAPE_PKCS8 = CKK_NSS_PKCS8 # alias
_SC_MQ_OPEN_MAX = _SC_MQ_OPEN_MAX # alias
# def SEC_ASN1_CHOOSER_DECLARE(x): return extern const SEC_ASN1Template * NSS_Get_ ##x (void *arg, PRBool enc); # macro
_SC_DEVICE_SPECIFIC = 141
_SC_XBS5_ILP32_OFFBIG = 126
_SC_XBS5_ILP32_OFFBIG = _SC_XBS5_ILP32_OFFBIG # alias
_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = 1139
_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS # alias
_SC_INT_MAX = 104
_SC_INT_MAX = _SC_INT_MAX # alias
_SC_PII_INTERNET_DGRAM = 62
_CS_XBS5_ILP32_OFFBIG_LINTFLAGS = 1107
_CS_XBS5_ILP32_OFFBIG_LINTFLAGS = _CS_XBS5_ILP32_OFFBIG_LINTFLAGS # alias
_SC_MULTI_PROCESS = 150
_SC_MULTI_PROCESS = _SC_MULTI_PROCESS # alias
decode_error = 50
SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION = 17
SEC_ASN1_Identifier = 0
def isalpha_l(c,l): return __isalpha_l ((c), (l)) # macro
SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST = 125
SSL_ERROR_FORTEZZA_PQG = -12267
NSS_RWLOCK_RANK_NONE = 0 # Variable c_int '0'
SSL_LOCK_RANK_GLOBAL = NSS_RWLOCK_RANK_NONE # alias
_SC_MEMLOCK = 17
SEC_ERROR_BAD_DATABASE = -8174
SEC_OID_SECG_EC_SECT571R1 = 259
PR_SEEK_SET = 0
wait_client_key = 2
calg_rc4 = ssl_calg_rc4 # alias
# def ssl_HaveXmitBufLock(ss): return (PZ_InMonitor((ss)->xmitBufLock)) # macro
_PC_PATH_MAX = 4
_PC_PATH_MAX = _PC_PATH_MAX # alias
_SC_SS_REPL_MAX = _SC_SS_REPL_MAX # alias
UNSUPPORTED_CERT_EXTENSION = 1
PR_USER_THREAD = 0
SOCK_DGRAM = 2
SOCK_DGRAM = SOCK_DGRAM # alias
IPPROTO_IPIP = 4
IPPROTO_IPIP = IPPROTO_IPIP # alias
PR_LibSpec_Pathname = 0
SSL_ERROR_DECRYPT_ERROR_ALERT = -12192
_SC_AIO_MAX = 24
_SC_AIO_MAX = _SC_AIO_MAX # alias
certDNSName = 3
# def PR_ASSERT(expr): return ((void) 0) # macro
SEC_OID_SECG_EC_SECT283R1 = 255
# PR_InitArenaPool = PL_InitArenaPool # alias
SEC_OID_CMS_3DES_KEY_WRAP = 180
# def PL_ARENA_GROW(p,pool,size,incr): return PR_BEGIN_MACRO PLArena *_a = (pool)->current; PRUint32 _incr = PL_ARENA_ALIGN(pool, incr); PRUword _p = _a->avail; PRUword _q = _p + _incr; if (_p == (PRUword)(p) + PL_ARENA_ALIGN(pool, size) && _q <= _a->limit) { _a->avail = _q; PL_ArenaCountInplaceGrowth(pool, size, incr); } else { p = PL_ArenaGrow(pool, p, size, incr); } PL_ArenaCountGrowth(pool, size, incr); PR_END_MACRO # macro
# PR_ARENA_GROW = PL_ARENA_GROW # alias
SSL_ERROR_INTERNAL_ERROR_ALERT = -12188
_SC_THREAD_ATTR_STACKADDR = _SC_THREAD_ATTR_STACKADDR # alias
SOCK_RAW = 3
SEC_ERROR_NOT_FORTEZZA_ISSUER = -8088
SEC_OID_PKCS12_CERT_AND_CRL_BAG_ID = 111
SEC_ERROR_PKCS12_UNSUPPORTED_PBE_ALGORITHM = -8109
def NSPR_DATA_API(__type): return PR_IMPORT_DATA(__type) # macro
SSL_ERROR_INSUFFICIENT_SECURITY_ALERT = -12189
SEC_OID_ANSIX962_EC_C2PNB368W1 = 240
_SC_MONOTONIC_CLOCK = 149
_SC_MONOTONIC_CLOCK = _SC_MONOTONIC_CLOCK # alias
PR_SockOpt_IpTimeToLive = 6
def PZ_EnterMonitor(m): return PR_EnterMonitor((m)) # macro
SEC_OID_PKCS12_PBE_IDS = 106
SEC_OID_NS_TYPE_HTML = 52
PRUint32 = c_uint
PLHashNumber = PRUint32
PLHashFunction = CFUNCTYPE(PLHashNumber, c_void_p)
PRHashFunction = PLHashFunction # alias
PR_BITS_PER_INT64 = 64 # Variable c_int '64'
BITS_PER_INT64 = PR_BITS_PER_INT64 # alias
MSG_OOB = 1
MSG_OOB = MSG_OOB # alias
CKM_NSS_AES_KEY_WRAP = 3461563217L # Variable c_uint '-833404079u'
CKM_NETSCAPE_AES_KEY_WRAP = CKM_NSS_AES_KEY_WRAP # alias
_SC_MEMLOCK_RANGE = _SC_MEMLOCK_RANGE # alias
SEC_ERROR_OCSP_SERVER_ERROR = -8071
trustObjectSigning = 2
PR_BITS_PER_SHORT_LOG2 = 4 # Variable c_int '4'
BITS_PER_SHORT_LOG2 = PR_BITS_PER_SHORT_LOG2 # alias
SSL_ERROR_NO_RENEGOTIATION_ALERT = -12186
# def IN6_IS_ADDR_MC_SITELOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x5)) # macro
_SC_REGEXP = 155
_SC_REGEXP = _SC_REGEXP # alias
IPV6_LEAVE_GROUP = 21 # Variable c_int '21'
IPV6_DROP_MEMBERSHIP = IPV6_LEAVE_GROUP # alias
certUsageSSLClient = 0
SEC_ERROR_DIGEST_NOT_FOUND = -8059
kea_null = 0
_SC_FILE_LOCKING = 147
ct_ECDSA_fixed_ECDH = 66
IPPROTO_HOPOPTS = 0
IPPROTO_HOPOPTS = IPPROTO_HOPOPTS # alias
# def LL_L2F(f,l): return ((f) = (PRFloat64)(l)) # macro
_SC_THREADS = 67
ct_RSA_fixed_ECDH = 65
SEC_OID_PKCS12_SAFE_CONTENTS_ID = 160
__BYTE_ORDER = __LITTLE_ENDIAN # alias
# PR_HashTableEnumerateEntries = PL_HashTableEnumerateEntries # alias
SSL_ERROR_CERTIFICATE_UNOBTAINABLE_ALERT = -12183
SO_TIMESTAMP = 29 # Variable c_int '29'
SCM_TIMESTAMP = SO_TIMESTAMP # alias
no_certificate = 41
SEC_OID_PKCS5_PBMAC1 = 293
SEC_OID_PKCS9_UNSTRUCTURED_ADDRESS = 38
# def LL_CMP(a,op,b): return ((PRInt64)(a) op (PRInt64)(b)) # macro
_CS_XBS5_ILP32_OFFBIG_LIBS = 1106
_CS_XBS5_ILP32_OFFBIG_LIBS = _CS_XBS5_ILP32_OFFBIG_LIBS # alias
cert_pi_date = 8
SSL_ERROR_BAD_CERT_STATUS_RESPONSE_ALERT = -12181
SEC_OID_CERT_RENEWAL_LOCATOR = 177
SSLAppOpWrite = 1
SEC_OID_X509_INHIBIT_ANY_POLICY = 286
# SSL_IMPORT = extern # alias
# def PR_NEW(_struct): return ((_struct *) PR_MALLOC(sizeof(_struct))) # macro
# def __LDBL_REDIR(name,proto): return name proto # macro
SSL_ERROR_SYM_KEY_UNWRAP_FAILURE = -12211
_SC_THREAD_PRIO_INHERIT = 80
# DSSprivilege = DSSpriviledge # alias
wait_change_cipher = 4
def isspace_l(c,l): return __isspace_l ((c), (l)) # macro
# def __errordecl(name,msg): return extern void name (void) __attribute__((__error__ (msg))) # macro
_PC_NO_TRUNC = 7
_PC_NO_TRUNC = _PC_NO_TRUNC # alias
_SC_STREAMS = _SC_STREAMS # alias
MSG_WAITALL = 256
new_session_ticket = 4
IPPORT_MTP = 57
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4 = 154
SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE = -12219
_PC_LINK_MAX = 0
SEC_ERROR_CERT_NO_RESPONSE = -8163
PR_DESC_SOCKET_UDP = 3
_SC_NPROCESSORS_ONLN = 84
SEC_ERROR_NO_KEY = -8166
def pr_bitscan_clz32(val): return __builtin_clz(val) # macro
# def __intN_t(N,MODE): return typedef int int ##N ##_t __attribute__ ((__mode__ (MODE))) # macro
_ISspace = 8192
_SC_AIO_LISTIO_MAX = 23
_SC_AIO_LISTIO_MAX = _SC_AIO_LISTIO_MAX # alias
SSL_ERROR_BAD_CERT_HASH_VALUE_ALERT = -12180
# def PR_IMPORT_DATA(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
# def _IO_peekc_unlocked(_fp): return (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) && __underflow (_fp) == EOF ? EOF : *(unsigned char *) (_fp)->_IO_read_ptr) # macro
# def ssl_ReleaseSSL3HandshakeLock(ss): return { if (!ss->opt.noLocks) PZ_ExitMonitor((ss)->ssl3HandshakeLock); } # macro
# PR_ArenaCountRelease = PL_ArenaCountRelease # alias
SSL_ERROR_MAC_COMPUTATION_FAILURE = -12213
SEC_OID_ANSIX962_EC_PUBLIC_KEY = 200
certOwnerCA = 2
SEC_ERROR_DECRYPTION_DISALLOWED = -8143
SEC_ERROR_INCOMPATIBLE_PKCS11 = -8041
def __isascii_l(c,l): return ((l), __isascii (c)) # macro
SEC_ERROR_BAD_INFO_ACCESS_LOCATION = -8027
SEC_OID_UNKNOWN = 0
_SC_LEVEL4_CACHE_LINESIZE = 199
def NSPR_API(__type): return PR_IMPORT(__type) # macro
_SC_SINGLE_PROCESS = 151
SEC_OID_ANSIX962_EC_C2TNB431R1 = 241
def SSL_IS_SSL2_CIPHER(which): return (((which) & 0xfff0) == 0xff00) # macro
# def CERT_LIST_END(n,l): return (((void *)n) == ((void *)&l->list)) # macro
sender_server = 1397904978
# stderr = stderr # alias
SEC_OID_SECG_EC_SECP224K1 = 217
CKO_NSS_BUILTIN_ROOT_LIST = 3461563220L # Variable c_uint '-833404076u'
CKO_NETSCAPE_BUILTIN_ROOT_LIST = CKO_NSS_BUILTIN_ROOT_LIST # alias
PR_BITS_PER_SHORT = 16 # Variable c_int '16'
BITS_PER_SHORT = PR_BITS_PER_SHORT # alias
PR_TRANSMITFILE_KEEP_OPEN = 0
SSL_ERROR_MD5_DIGEST_FAILURE = -12215
_SC_2_C_DEV = 48
SSL_ERROR_RENEGOTIATION_NOT_ALLOWED = -12176
__codecvt_noconv = 3
SEC_OID_NS_CERT_EXT_CERT_RENEWAL_TIME = 77
PF_KEY = 15 # Variable c_int '15'
AF_KEY = PF_KEY # alias
unsupported_certificate = 43
PK11_OriginNULL = 0
def IN_BADCLASS(a): return ((((in_addr_t)(a)) & 0xf0000000) == 0xf0000000) # macro
_SC_XOPEN_SHM = 94
_SC_XOPEN_SHM = _SC_XOPEN_SHM # alias
# PR_HashTableDump = PL_HashTableDump # alias
ssl_mac_md5 = 1
_SC_GETPW_R_SIZE_MAX = _SC_GETPW_R_SIZE_MAX # alias
SEC_ERROR_PKCS12_UNABLE_TO_EXPORT_KEY = -8096
_SC_LINE_MAX = 43
alert_warning = 1
SEC_OID_PKCS7_ENVELOPED_DATA = 27
SSL_ERROR_DECRYPTION_FAILURE = -12217
PF_ROSE = 11 # Variable c_int '11'
AF_ROSE = PF_ROSE # alias
SEC_OID_PKCS12_RSA_SIGNATURE_WITH_SHA1_DIGEST = 123
kea_ecdhe_ecdsa = 16
SSL_ERROR_UNSUPPORTED_EXTENSION_ALERT = -12184
XP_SEC_FORTEZZA_NO_CARD = -8141
PK11_TypePubKey = 2
_SC_SPIN_LOCKS = 154
_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = 1135
_SC_FSYNC = _SC_FSYNC # alias
SEC_OID_AVA_STATE_OR_PROVINCE = 44
_CS_POSIX_V6_LP64_OFF64_LIBS = 1126
__gnuc_va_list = STRING
_G_va_list = __gnuc_va_list # alias
_CS_XBS5_ILP32_OFFBIG_CFLAGS = 1104
_CS_XBS5_ILP32_OFFBIG_CFLAGS = _CS_XBS5_ILP32_OFFBIG_CFLAGS # alias
PR_SHUTDOWN_SEND = 1
def isalnum_l(c,l): return __isalnum_l ((c), (l)) # macro
SSL_ERROR_RX_UNEXPECTED_UNCOMPRESSED_RECORD = -12174
# def __LDBL_REDIR1(name,proto,alias): return name proto # macro
SHUT_RDWR = 2
SHUT_RDWR = SHUT_RDWR # alias
SEC_OID_MD2 = 1
# def __FDMASK(d): return ((__fd_mask) 1 << ((d) % __NFDBITS)) # macro
SEC_OID_PKIX_CPS_POINTER_QUALIFIER = 128
certUsageEmailRecipient = 5
SEC_OID_ANSIX962_EC_PRIME192V2 = 203
_PC_NAME_MAX = 3
_PC_NAME_MAX = _PC_NAME_MAX # alias
_CS_POSIX_V6_ILP32_OFF32_LDFLAGS = 1117
_PC_MAX_CANON = 1
# def PR_LIST_HEAD(_l): return (_l)->next # macro
SEC_OID_PKCS9_COUNTER_SIGNATURE = 36
SSL_ERROR_WEAK_SERVER_EPHEMERAL_DH_KEY = -12173
_SC_ADVISORY_INFO = 132
_SC_ADVISORY_INFO = _SC_ADVISORY_INFO # alias
SEC_OID_PKCS7_DATA = 25
CLIENT_AUTH_CERTIFICATE = 1
XP_JAVA_CERT_NOT_EXISTS_ERROR = -8118
_SC_V7_ILP32_OFFBIG = 238
_SC_V7_ILP32_OFFBIG = _SC_V7_ILP32_OFFBIG # alias
SSL_ERROR_DECRYPTION_FAILED_ALERT = -12197
# def PR_EXPORT(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
_SC_TIMER_MAX = 35
_SC_TIMER_MAX = _SC_TIMER_MAX # alias
PF_IEEE802154 = 36 # Variable c_int '36'
AF_IEEE802154 = PF_IEEE802154 # alias
# def LL_MUL(r,a,b): return ((r) = (a) * (b)) # macro
SEC_ERROR_INADEQUATE_CERT_TYPE = -8101
nssILockOID = 12
SEC_OID_ANSIX962_EC_C2PNB163V3 = 224
# def PR_SET_BIT(_map,_bit): return ((_map)[(_bit)>>PR_BITS_PER_LONG_LOG2] |= (1L << ((_bit) & (PR_BITS_PER_LONG-1)))) # macro
SEC_OID_RC2_CBC = 5
_SC_UCHAR_MAX = 115
# PORT_Strncat = strncat # alias
_CS_XBS5_ILP32_OFF32_LDFLAGS = 1101
def __WIFEXITED(status): return (__WTERMSIG(status) == 0) # macro
ct_RSA_fixed_DH = 3
PF_IRDA = 23 # Variable c_int '23'
AF_IRDA = PF_IRDA # alias
SEC_ERROR_OCSP_MALFORMED_RESPONSE = -8063
hello_request = 0
PR_BYTES_PER_BYTE = 1 # Variable c_int '1'
BYTES_PER_BYTE = PR_BYTES_PER_BYTE # alias
SEC_OID_DES_EDE3_CBC = 7
SEC_OID_SEED_CBC = 302
kea_dh_rsa = 6
SSL_ERROR_UNKNOWN_CIPHER_SUITE = -12266
SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION = 20
SEC_OID_AVA_DN_QUALIFIER = 47
SEC_ERROR_PKCS7_BAD_SIGNATURE = -8145
CKT_NSS_TRUSTED = 3461563217L # Variable c_uint '-833404079u'
CKT_NETSCAPE_TRUSTED = CKT_NSS_TRUSTED # alias
PF_BRIDGE = 7 # Variable c_int '7'
AF_BRIDGE = PF_BRIDGE # alias
__DEV_T_TYPE = __UQUAD_TYPE # alias
IPPORT_SYSTAT = 11
SSL_ERROR_DECOMPRESSION_FAILURE_ALERT = -12228
_SC_LEVEL2_CACHE_SIZE = 191
nssILockKeyDB = 18
SSL_ERROR_ILLEGAL_PARAMETER_ALERT = -12226
SEC_OID_AES_192_ECB = 185
_SC_WORD_BIT = 107
_SC_WORD_BIT = _SC_WORD_BIT # alias
cert_pi_certList = 3
SSL_sni_host_name = 0
_PC_MAX_INPUT = 2
_PC_MAX_INPUT = _PC_MAX_INPUT # alias
_SC_SYSTEM_DATABASE = 162
_SC_SYSTEM_DATABASE = _SC_SYSTEM_DATABASE # alias
_SC_SYMLOOP_MAX = 173
CKA_NSS_PQG_H = 3461563238L # Variable c_uint '-833404058u'
CKA_NETSCAPE_PQG_H = CKA_NSS_PQG_H # alias
PR_UNJOINABLE_THREAD = 1
_SC_TRACE_NAME_MAX = 243
_SC_TRACE_NAME_MAX = _SC_TRACE_NAME_MAX # alias
CKA_NSS_PQG_COUNTER = 3461563236L # Variable c_uint '-833404060u'
CKA_NETSCAPE_PQG_COUNTER = CKA_NSS_PQG_COUNTER # alias
SEC_ERROR_NOT_INITIALIZED = -8038
IPPORT_CMDSERVER = 514
# def CK_DECLARE_FUNCTION(rtype,func): return extern rtype func # macro
# def ssl_ReleaseRecvBufLock(ss): return { if (!ss->opt.noLocks) PZ_ExitMonitor( (ss)->recvBufLock); } # macro
unrecognized_name = 112
_SC_LEVEL1_DCACHE_LINESIZE = 190
# def IN6_IS_ADDR_MULTICAST(a): return (((__const uint8_t *) (a))[0] == 0xff) # macro
# PORT_Strcasecmp = PL_strcasecmp # alias
_CS_XBS5_LPBIG_OFFBIG_CFLAGS = 1112
def va_arg(v,l): return __builtin_va_arg(v,l) # macro
# PORT_Strcmp = strcmp # alias
# def ssl_ReleaseSpecWriteLock(ss): return { if (!ss->opt.noLocks) NSSRWLock_UnlockWrite((ss)->specLock); } # macro
_PC_CHOWN_RESTRICTED = 6
SEC_OID_NS_CERT_EXT_CA_REVOCATION_URL = 66
SEC_ERROR_CRL_IMPORT_FAILED = -8021
def WTERMSIG(status): return __WTERMSIG (__WAIT_INT (status)) # macro
_SC_2_FORT_DEV = 49
PR_SockOpt_Reuseaddr = 2
__FLOAT_WORD_ORDER = __BYTE_ORDER # alias
# PR_CLEAR_UNUSED = PL_CLEAR_UNUSED # alias
_SC_SINGLE_PROCESS = _SC_SINGLE_PROCESS # alias
SEC_OID_NS_TYPE_URL = 51
certPackageNSCertSeq = 3
SUPPORTED_CERT_EXTENSION = 2
certUsageEmailSigner = 4
SSL_ERROR_RX_UNKNOWN_HANDSHAKE = -12232
_CS_POSIX_V7_WIDTH_RESTRICTED_ENVS = _CS_V7_WIDTH_RESTRICTED_ENVS # alias
_SC_MESSAGE_PASSING = 20
_SC_MESSAGE_PASSING = _SC_MESSAGE_PASSING # alias
access_denied = 49
# def LL_MOD(r,a,b): return ((r) = (a) % (b)) # macro
SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID = -8155
_SC_LEVEL1_ICACHE_LINESIZE = _SC_LEVEL1_ICACHE_LINESIZE # alias
CKT_NSS_MUST_VERIFY = 3461563220L # Variable c_uint '-833404076u'
CKT_NETSCAPE_MUST_VERIFY = CKT_NSS_MUST_VERIFY # alias
SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST = 126
IPPROTO_MAX = 256
SSL_ERROR_SSL_DISABLED = -12268
SEC_ERROR_KRL_EXPIRED = -8133
_PC_REC_XFER_ALIGN = 17
def PR_ROTATE_LEFT32(a,bits): return (((a) << (bits)) | ((a) >> (32 - (bits)))) # macro
# def PR_NEWZAP(_struct): return ((_struct*)PR_Calloc(1, sizeof(_struct))) # macro
nssILockLast = 19
SEC_ERROR_NO_NODELOCK = -8175
_SC_UIO_MAXIOV = _SC_UIO_MAXIOV # alias
_ISupper = 256
# KEAprivilege = KEApriviledge # alias
_SC_NPROCESSORS_CONF = _SC_NPROCESSORS_CONF # alias
PR_BITS_PER_FLOAT = 32 # Variable c_int '32'
BITS_PER_FLOAT = PR_BITS_PER_FLOAT # alias
_SC_SYMLOOP_MAX = _SC_SYMLOOP_MAX # alias
server_hello = 2
IPPROTO_MTP = 92
PR_FILE_FILE = 1
def ntohs(x): return __bswap_16 (x) # macro
_SC_2_UPE = _SC_2_UPE # alias
MSG_TRYHARD = 4
def PR_ATOMIC_ADD(ptr,val): return __sync_add_and_fetch(ptr, val) # macro
INADDR_LOOPBACK = 2130706433L # Variable c_uint '2130706433u'
PR_INADDR_LOOPBACK = INADDR_LOOPBACK # alias
PR_LOG_MIN = 4
_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = 1136
sign_rsa = ssl_sign_rsa # alias
_CS_POSIX_V6_LP64_OFF64_LIBS = _CS_POSIX_V6_LP64_OFF64_LIBS # alias
SEC_ERROR_BAD_NICKNAME = -8089
_SC_THREAD_PROCESS_SHARED = 82
_SC_THREAD_PROCESS_SHARED = _SC_THREAD_PROCESS_SHARED # alias
SEC_ERROR_PKCS12_CORRUPT_PFX_STRUCTURE = -8110
certURI = 7
SSL_ERROR_BAD_MAC_ALERT = -12272
cipher_idea = 9
SEC_OID_SECG_EC_SECT113R1 = 242
SEC_ERROR_REVOKED_CERTIFICATE_OCSP = -8046
SSLAppOpRDWR = 2
PR_PRIORITY_LOW = 0
SEC_OID_NS_CERT_EXT_USER_PICTURE = 73
SEC_ERROR_OCSP_MALFORMED_REQUEST = -8072
nssILockCert = 4
_SC_POLL = 58
_SC_POLL = _SC_POLL # alias
CKO_DOMAIN_PARAMETERS = 6 # Variable c_int '6'
CKO_KG_PARAMETERS = CKO_DOMAIN_PARAMETERS # alias
# def __ASMNAME2(prefix,cname): return __STRING (prefix) cname # macro
wait_cert_request = 9
def __FDELT(d): return ((d) / __NFDBITS) # macro
_SC_2_PBS_MESSAGE = 171
PF_UNSPEC = 0 # Variable c_int '0'
AF_UNSPEC = PF_UNSPEC # alias
PR_PROT_WRITECOPY = 2
def minor(dev): return gnu_dev_minor (dev) # macro
SSL_ERROR_US_ONLY_SERVER = -12287
_SC_FILE_SYSTEM = 148
_SC_FILE_SYSTEM = _SC_FILE_SYSTEM # alias
handshake_failure = 40
certUsageSSLCA = 3
SEC_ERROR_KRL_BAD_SIGNATURE = -8132
# __NLINK_T_TYPE = __UWORD_TYPE # alias
# PORT_Memcpy = memcpy # alias
IPV6_DSTOPTS = 59 # Variable c_int '59'
IPV6_RXDSTOPTS = IPV6_DSTOPTS # alias
_SC_MEMORY_PROTECTION = _SC_MEMORY_PROTECTION # alias
_SC_NL_SETMAX = _SC_NL_SETMAX # alias
_SC_JOB_CONTROL = _SC_JOB_CONTROL # alias
SEC_ASN1_T61_STRING = 20 # Variable c_int '20'
SEC_ASN1_TELETEX_STRING = SEC_ASN1_T61_STRING # alias
SSL_ERROR_RX_MALFORMED_CERTIFICATE = -12258
SEC_OID_NETSCAPE_RECOVERY_REQUEST = 176
PR_StandardOutput = 1
PR_IpAddrNull = 0
__BIG_ENDIAN = 4321 # Variable c_int '4321'
BIG_ENDIAN = __BIG_ENDIAN # alias
MSG_CTRUNC = 8
_PC_FILESIZEBITS = 13
# def PR_NEXT_LINK(_e): return ((_e)->next) # macro
calg_camellia = ssl_calg_camellia # alias
trustTypeNone = 3
SEC_OID_NETSCAPE_AOLSCREENNAME = 260
def isprint_l(c,l): return __isprint_l ((c), (l)) # macro
SEC_OID_VERISIGN_USER_NOTICES = 127
ssl_kea_rsa = 1
kt_rsa = ssl_kea_rsa # alias
cert_po_extendedKeyusage = 8
SSL_sni_type_total = 1
_PC_LINK_MAX = _PC_LINK_MAX # alias
_SC_SYSTEM_DATABASE_R = 163
_SC_SYSTEM_DATABASE_R = _SC_SYSTEM_DATABASE_R # alias
SEC_OID_FORTEZZA_SKIPJACK = 153
SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE = -12220
PR_DESC_LAYERED = 4
SSL_ERROR_BAD_MAC_READ = -12273
SSL_ERROR_RX_UNEXPECTED_HELLO_DONE = -12241
_SC_SPAWN = _SC_SPAWN # alias
IPPROTO_ENCAP = IPPROTO_ENCAP # alias
SEC_ERROR_FILING_KEY = -8167
kt_kea_size = ssl_kea_size # alias
IPPROTO_NONE = 59
PR_BITS_PER_LONG_LOG2 = 5 # Variable c_int '5'
BITS_PER_LONG_LOG2 = PR_BITS_PER_LONG_LOG2 # alias
SEC_OID_X500_RSA_ENCRYPTION = 97
# def CMSG_DATA(cmsg): return ((cmsg)->__cmsg_data) # macro
PR_SockOpt_AddMember = 8
def PR_ATOMIC_DECREMENT(val): return __sync_sub_and_fetch(val, 1) # macro
_CS_POSIX_V6_ILP32_OFF32_CFLAGS = _CS_POSIX_V6_ILP32_OFF32_CFLAGS # alias
# def PR_INIT_CLIST(_l): return PR_BEGIN_MACRO (_l)->next = (_l); (_l)->prev = (_l); PR_END_MACRO # macro
_PC_MAX_CANON = _PC_MAX_CANON # alias
_SC_XOPEN_XPG2 = 98
XP_SEC_FORTEZZA_PERSON_ERROR = -8135
IPPROTO_PIM = IPPROTO_PIM # alias
# def ssl_Release1stHandshakeLock(ss): return { if (!ss->opt.noLocks) PZ_ExitMonitor((ss)->firstHandshakeLock); } # macro
SSL_ERROR_SSL2_DISABLED = -12274
certDirectoryName = 5
_CS_POSIX_V6_LP64_OFF64_LDFLAGS = 1125
_CS_POSIX_V6_LP64_OFF64_LDFLAGS = _CS_POSIX_V6_LP64_OFF64_LDFLAGS # alias
SSL_ERROR_NO_COMPRESSION_OVERLAP = -12203
SEC_OID_AES_256_KEY_WRAP = 199
# def LL_L2I(i,l): return ((i) = (PRInt32)(l)) # macro
def PZ_ExitMonitor(m): return PR_ExitMonitor((m)) # macro
MSG_TRUNC = 32
# def __bswap_16(x): return (__extension__ ({ register unsigned short int __v, __x = (x); if (__builtin_constant_p (__x)) __v = __bswap_constant_16 (__x); else __asm__ ("rorw $8, %w0" : "=r" (__v) : "0" (__x) : "cc"); __v; })) # macro
_SC_LEVEL4_CACHE_ASSOC = 198
PR_SYSTEM_THREAD = 1
SSL_ERROR_RX_UNEXPECTED_APPLICATION_DATA = -12234
_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = 1131
SEC_OID_SECG_EC_SECT113R2 = 243
IPPROTO_AH = 51
SSL_ERROR_BAD_CERT_ALERT = -12271
PR_LOCAL_THREAD = 0
XP_SEC_FORTEZZA_NO_MORE_INFO = -8137
IPPORT_FTP = 21
SEC_OID_SECG_EC_SECP192K1 = 216
_SC_RTSIG_MAX = 31
SEC_OID_DES_ECB = 9
SSL_ERROR_BAD_CERT_DOMAIN = -12276
cipher_aes_128 = 10
# def PORT_ArenaNew(poolp,type): return (type*) PORT_ArenaAlloc(poolp, sizeof(type)) # macro
# def PORT_ArenaNewArray(poolp,type,num): return (type*) PORT_ArenaAlloc (poolp, sizeof(type)*(num)) # macro
content_alert = 21
def IN_CLASSB(a): return ((((in_addr_t)(a)) & 0xc0000000) == 0x80000000) # macro
# def IS_SEC_ERROR(code): return (((code) >= SEC_ERROR_BASE) && ((code) < SEC_ERROR_LIMIT)) # macro
_SC_PII_SOCKET = 55
_SC_PII_SOCKET = _SC_PII_SOCKET # alias
ssl_calg_des = 3
def __P(args): return args # macro
close_notify = 0
_SC_XOPEN_UNIX = 91
SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE = 277
PR_StandardError = 2
kea_dh_dss_export = 5
# def LL_OR2(r,a): return ((r) = (r) | (a)) # macro
nssILockRefLock = 3
_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS # alias
content_handshake = 22
# def CMSG_LEN(len): return (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len)) # macro
# def GROUP_FILTER_SIZE(numsrc): return (sizeof (struct group_filter) - sizeof (struct sockaddr_storage) + ((numsrc) * sizeof (struct sockaddr_storage))) # macro
kea_ecdh_ecdsa = 15
def va_end(v): return __builtin_va_end(v) # macro
__FSFILCNT64_T_TYPE = __UQUAD_TYPE # alias
XP_SEC_FORTEZZA_BAD_CARD = -8142
internal_error = 80
SEC_OID_PKIX_OCSP_NONCE = 132
_SC_NETWORKING = _SC_NETWORKING # alias
# __SWORD_TYPE = int # alias
_SC_INT_MIN = 105
_SC_INT_MIN = _SC_INT_MIN # alias
siDERNameBuffer = 5
_SC_ULONG_MAX = _SC_ULONG_MAX # alias
IPPROTO_FRAGMENT = 44
# _G_stat64 = stat64 # alias
cert_pi_revocationFlags = 9
def __REDIRECT_NTH_LDBL(name,proto,alias): return __REDIRECT_NTH (name, proto, alias) # macro
# def LL_NEG(r,a): return ((r) = -(a)) # macro
SEC_OID_DES_CFB = 12
_CS_PATH = 0
_PC_FILESIZEBITS = _PC_FILESIZEBITS # alias
SEC_ERROR_NO_SLOT_SELECTED = -8125
_SC_TRACE_EVENT_NAME_MAX = 242
_SC_TRACE_EVENT_NAME_MAX = _SC_TRACE_EVENT_NAME_MAX # alias
_CS_LFS64_LIBS = _CS_LFS64_LIBS # alias
# def PR_LIST_TAIL(_l): return (_l)->prev # macro
# def PORT_NewArray(type,num): return (type*) PORT_Alloc (sizeof(type)*(num)) # macro
SOCK_DCCP = SOCK_DCCP # alias
PR_LOG_WARN = 3
# PR_NewHashTable = PL_NewHashTable # alias
_ISxdigit = 4096
PR_BITS_PER_LONG = 32 # Variable c_int '32'
BITS_PER_LONG = PR_BITS_PER_LONG # alias
_SC_2_PBS_TRACK = 172
_SC_2_PBS_TRACK = _SC_2_PBS_TRACK # alias
secCertTimeUndetermined = 3
_CS_POSIX_V5_WIDTH_RESTRICTED_ENVS = _CS_V5_WIDTH_RESTRICTED_ENVS # alias
SOCK_RDM = SOCK_RDM # alias
IPPROTO_IPV6 = 41
IPPROTO_NONE = IPPROTO_NONE # alias
XP_JAVA_DELETE_PRIVILEGE_ERROR = -8119
SEC_OID_NS_CERT_EXT_CA_CERT_URL = 68
# PR_ArenaCountInplaceGrowth = PL_ArenaCountInplaceGrowth # alias
_SC_NZERO = 109
# def PR_EXPORT_DATA(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
ct_RSA_sign = 1
SEC_ERROR_NO_EVENT = -8040
_SC_LINE_MAX = _SC_LINE_MAX # alias
SEC_ERROR_LIBPKIX_INTERNAL = -8026
def __STRING(x): return #x # macro
SEC_OID_X509_HOLD_INSTRUCTION_CODE = 281
PR_FILE_DIRECTORY = 2
trustSSL = 0
SEC_ERROR_INADEQUATE_KEY_USAGE = -8102
SEC_OID_ANSIX962_EC_C2TNB191V1 = 226
# _G_VTABLE_LABEL_PREFIX_ID = __vt_ # alias
_SC_LEVEL3_CACHE_ASSOC = 195
SSL_ERROR_NO_CYPHER_OVERLAP = -12286
SEC_ERROR_OCSP_NO_DEFAULT_RESPONDER = -8064
# def LL_F2L(l,f): return ((l) = (PRInt64)(f)) # macro
_SC_NGROUPS_MAX = 3
_SC_NGROUPS_MAX = _SC_NGROUPS_MAX # alias
_SC_LEVEL2_CACHE_ASSOC = _SC_LEVEL2_CACHE_ASSOC # alias
__FD_SETSIZE = 1024 # Variable c_int '1024'
FD_SETSIZE = __FD_SETSIZE # alias
_SC_PII_OSI_M = 65
_SC_PII_OSI_M = _SC_PII_OSI_M # alias
_SC_GETGR_R_SIZE_MAX = _SC_GETGR_R_SIZE_MAX # alias
_CS_V5_WIDTH_RESTRICTED_ENVS = _CS_V5_WIDTH_RESTRICTED_ENVS # alias
# def IN6_IS_ADDR_MC_GLOBAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0xe)) # macro
ct_DSS_ephemeral_DH = 6
_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS # alias
_SC_FILE_ATTRIBUTES = 146
_SC_FILE_ATTRIBUTES = _SC_FILE_ATTRIBUTES # alias
bad_certificate_status_response = 113
SEC_ERROR_NOT_A_RECIPIENT = -8147
__OFF64_T_TYPE = __SQUAD_TYPE # alias
PR_JOINABLE_THREAD = 0
PR_ALIGN_OF_FLOAT = 4 # Variable c_int '4'
ALIGN_OF_FLOAT = PR_ALIGN_OF_FLOAT # alias
_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS # alias
# __RLIM_T_TYPE = __ULONGWORD_TYPE # alias
_SC_MEMLOCK = _SC_MEMLOCK # alias
cert_revocation_method_count = 2
SEC_OID_HMAC_SHA224 = 295
def WEXITSTATUS(status): return __WEXITSTATUS (__WAIT_INT (status)) # macro
nssILockOther = 16
SEC_ERROR_INVALID_AVA = -8185
IPPROTO_EGP = 8
PF_ASH = 18 # Variable c_int '18'
AF_ASH = PF_ASH # alias
SSL_ERROR_RX_UNEXPECTED_ALERT = -12236
SEC_OID_X509_PRIVATE_KEY_USAGE_PERIOD = 82
IPPORT_DISCARD = 9
SEC_OID_PKIX_REGINFO_UTF8_PAIRS = 144
SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT = -12229
SEC_ERROR_CERT_VALID = -8165
SEC_OID_AES_128_CBC = 184
wait_finished = 5
def islower_l(c,l): return __islower_l ((c), (l)) # macro
IPPROTO_TCP = 6
_PC_CHOWN_RESTRICTED = _PC_CHOWN_RESTRICTED # alias
CERT_N2A_INVERTIBLE = 20
SEC_ERROR_NO_EMAIL_CERT = -8149
_CS_LFS64_LDFLAGS = _CS_LFS64_LDFLAGS # alias
_SC_THREAD_SAFE_FUNCTIONS = 68
_SC_THREAD_SAFE_FUNCTIONS = _SC_THREAD_SAFE_FUNCTIONS # alias
def ntohl(x): return __bswap_32 (x) # macro
def SEC_ASN1_GET(x): return x # macro
_SC_2_PBS_MESSAGE = _SC_2_PBS_MESSAGE # alias
IPPORT_LOGINSERVER = 513
SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE = 190
SEC_ERROR_OLD_CRL = -8150
SSL_ERROR_RX_UNKNOWN_RECORD_TYPE = -12233
_SC_PHYS_PAGES = _SC_PHYS_PAGES # alias
IPPROTO_MTP = IPPROTO_MTP # alias
def __va_copy(d,s): return __builtin_va_copy(d,s) # macro
SEC_ERROR_CRL_INVALID = -8159
PK11_DIS_NONE = 0
def ssl_InMonitor(m): return PZ_InMonitor(m) # macro
_SC_FILE_LOCKING = _SC_FILE_LOCKING # alias
SSL_ERROR_ACCESS_DENIED_ALERT = -12194
_SC_THREAD_SPORADIC_SERVER = 161
_SC_THREAD_SPORADIC_SERVER = _SC_THREAD_SPORADIC_SERVER # alias
SEC_OID_PKCS12_ENVELOPING_IDS = 108
_SC_FIFO = _SC_FIFO # alias
_SC_THREADS = _SC_THREADS # alias
SEC_OID_ANSIX962_EC_PRIME239V3 = 207
SEC_OID_MISSI_KEA_DSS_OLD = 54
_SC_THREAD_ROBUST_PRIO_PROTECT = _SC_THREAD_ROBUST_PRIO_PROTECT # alias
SEC_ERROR_INVALID_KEY = -8152
SEC_OID_ANSIX962_EC_C2TNB191V2 = 227
# def LL_INIT(hi,lo): return ((hi ## LL << 32) + lo ## LL) # macro
def __FD_ISSET(d,set): return ((__FDS_BITS (set)[__FDELT (d)] & __FDMASK (d)) != 0) # macro
siBMPString = 15
MSG_TRYHARD = MSG_DONTROUTE # alias
# stdout = stdout # alias
SEC_INTERNAL_ONLY = -8153
SEC_ERROR_MODULE_STUCK = -8057
MSG_CMSG_CLOEXEC = 1073741824
_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = 1119
SEC_ERROR_PKCS12_IMPORTING_CERT_CHAIN = -8098
ssl_renegotiation_info_xtn = 65281
__RLIM64_T_TYPE = __UQUAD_TYPE # alias
MSG_TRUNC = MSG_TRUNC # alias
SEC_ERROR_CERT_USAGES_INVALID = -8154
def be16toh(x): return __bswap_16 (x) # macro
_SC_COLL_WEIGHTS_MAX = 40
_SC_COLL_WEIGHTS_MAX = _SC_COLL_WEIGHTS_MAX # alias
SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION = -8151
SEC_OID_PKCS5_PBKDF2 = 291
_SC_RTSIG_MAX = _SC_RTSIG_MAX # alias
PR_ALIGN_OF_DOUBLE = 4 # Variable c_int '4'
ALIGN_OF_DOUBLE = PR_ALIGN_OF_DOUBLE # alias
_CS_POSIX_V7_LPBIG_OFFBIG_LIBS = 1146
_CS_POSIX_V7_LPBIG_OFFBIG_LIBS = _CS_POSIX_V7_LPBIG_OFFBIG_LIBS # alias
_SC_MB_LEN_MAX = 108
_SC_MB_LEN_MAX = _SC_MB_LEN_MAX # alias
# def __REDIRECT_NTH(name,proto,alias): return name proto __THROW __asm__ (__ASMNAME (#alias)) # macro
unknown_ca = 48
ssl_calg_fortezza = 6
calg_fortezza = ssl_calg_fortezza # alias
PR_ALIGN_OF_WORD = 4 # Variable c_int '4'
ALIGN_OF_WORD = PR_ALIGN_OF_WORD # alias
cert_pi_policyOID = 4
_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = 1129
_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS # alias
IPPROTO_IP = 0
SEC_OID_PKCS12 = 100
# SSL_GETPID = getpid # alias
PK11_TypeCert = 3
siUTF8String = 14
SEC_ERROR_RETRY_PASSWORD = -8176
SEC_OID_HMAC_SHA512 = 298
_SC_BC_STRING_MAX = 39
_SC_BC_STRING_MAX = _SC_BC_STRING_MAX # alias
_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS # alias
cert_pi_useAIACertFetch = 12
PK11CertListCAUnique = 4
def __WSTOPSIG(status): return __WEXITSTATUS(status) # macro
# def LL_I2L(l,i): return ((l) = (PRInt64)(i)) # macro
def __isxdigit_l(c,l): return __isctype_l((c), _ISxdigit, (l)) # macro
# def __NTH(fct): return fct throw () # macro
IPPROTO_DSTOPTS = 60
# def CMSG_FIRSTHDR(mhdr): return ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr) ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) 0) # macro
_SC_2_PBS_LOCATE = 170
_SC_2_PBS_LOCATE = _SC_2_PBS_LOCATE # alias
PR_SockOpt_DropMember = 9
nssILockObject = 2
finished = 20
SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET = -12178
CKA_NSS_MODULE_SPEC = 3461563240L # Variable c_uint '-833404056u'
CKA_NETSCAPE_MODULE_SPEC = CKA_NSS_MODULE_SPEC # alias
IPPROTO_IPV6 = IPPROTO_IPV6 # alias
rsaPssKey = 7
def major(dev): return gnu_dev_major (dev) # macro
SEC_ERROR_EXPIRED_PASSWORD = -8020
_SC_THREAD_ATTR_STACKSIZE = _SC_THREAD_ATTR_STACKSIZE # alias
SIGEV_SIGNAL = 0
PR_MW_PENDING = 1
_SC_BARRIERS = _SC_BARRIERS # alias
insufficient_security = 71
SEC_ERROR_RETRY_OLD_PASSWORD = -8090
SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE = -8111
nssILockSlot = 10
_SC_NL_MSGMAX = _SC_NL_MSGMAX # alias
PR_FILE_OTHER = 3
SEC_OID_SECG_EC_SECT131R1 = 244
_PC_SYNC_IO = _PC_SYNC_IO # alias
def PZ_InMonitor(m): return PR_InMonitor((m)) # macro
siVisibleString = 13
PR_SUCCESS = 0
def IN_EXPERIMENTAL(a): return ((((in_addr_t)(a)) & 0xe0000000) == 0xe0000000) # macro
SEC_ERROR_OCSP_BAD_HTTP_RESPONSE = -8073
def __CONCAT(x,y): return x ## y # macro
SEC_ERROR_PKCS12_UNABLE_TO_READ = -8094
mac_md5 = ssl_mac_md5 # alias
_SC_2_VERSION = 46
_SC_2_VERSION = _SC_2_VERSION # alias
PF_NETLINK = 16 # Variable c_int '16'
AF_NETLINK = PF_NETLINK # alias
_SC_THREAD_CPUTIME = _SC_THREAD_CPUTIME # alias
_SC_THREAD_PRIO_INHERIT = _SC_THREAD_PRIO_INHERIT # alias
_SC_2_SW_DEV = 51
_SC_2_SW_DEV = _SC_2_SW_DEV # alias
MSG_CTRUNC = MSG_CTRUNC # alias
SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC = 23
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC = 158
SEC_OID_PKCS7_ENCRYPTED_DATA = 30
SEC_OID_X509_CRL_DIST_POINTS = 87
# PR_HashTableAdd = PL_HashTableAdd # alias
PR_SHUTDOWN_BOTH = 2
decompression_failure = 30
certUsageSSLServerWithStepUp = 2
PK11_TypeSymKey = 4
SEC_OID_AVA_PSEUDONYM = 272
BYTE_ORDER = __BYTE_ORDER # alias
SEC_ERROR_IO = -8192
def FD_SET(fd,fdsetp): return __FD_SET (fd, fdsetp) # macro
# __ID_T_TYPE = __U32_TYPE # alias
_SC_MAPPED_FILES = 16
_SC_MAPPED_FILES = _SC_MAPPED_FILES # alias
PR_LOG_MAX = 4
PR_ALIGN_OF_SHORT = 2 # Variable c_int '2'
ALIGN_OF_SHORT = PR_ALIGN_OF_SHORT # alias
# def SEC_GET_TRUST_FLAGS(trust,type): return (((type)==trustSSL)?((trust)->sslFlags): (((type)==trustEmail)?((trust)->emailFlags): (((type)==trustObjectSigning)?((trust)->objectSigningFlags):0))) # macro
size_t = c_uint
_G_size_t = size_t # alias
_CS_XBS5_ILP32_OFF32_LIBS = _CS_XBS5_ILP32_OFF32_LIBS # alias
siDEROID = 9
SEC_OID_SECG_EC_SECP160K1 = 213
# def PR_NetAddrFamily(addr): return ((addr)->raw.family) # macro
def __isgraph_l(c,l): return __isctype_l((c), _ISgraph, (l)) # macro
SEC_OID_AVA_COUNTRY_NAME = 42
def __isblank_l(c,l): return __isctype_l((c), _ISblank, (l)) # macro
PR_BYTES_PER_WORD_LOG2 = 2 # Variable c_int '2'
BYTES_PER_WORD_LOG2 = PR_BYTES_PER_WORD_LOG2 # alias
never_cached = 0
content_change_cipher_spec = 20
IPPORT_NAMESERVER = 42
SEC_OID_NETSCAPE_SMIME_KEA = 152
_SC_2_CHAR_TERM = _SC_2_CHAR_TERM # alias
PR_DESC_PIPE = 5
_SC_DEVICE_SPECIFIC = _SC_DEVICE_SPECIFIC # alias
IPPROTO_EGP = IPPROTO_EGP # alias
SEC_ERROR_ADDING_CERT = -8168
SEC_OID_PKCS7_DIGESTED_DATA = 29
explicit = xplicit # alias
PR_SKIP_DOT = 1
SEC_OID_MISSI_KEA = 58
_SC_2_PBS_CHECKPOINT = _SC_2_PBS_CHECKPOINT # alias
def PR_ATOMIC_INCREMENT(val): return __sync_add_and_fetch(val, 1) # macro
# def PR_INIT_STATIC_CLIST(_l): return {(_l), (_l)} # macro
_SC_V7_LPBIG_OFFBIG = 240
_SC_V7_LPBIG_OFFBIG = _SC_V7_LPBIG_OFFBIG # alias
_ISalnum = 8
_POSIX2_C_BIND = __POSIX2_THIS_VERSION # alias
SSL_ERROR_TOKEN_SLOT_NOT_FOUND = -12204
SOCK_CLOEXEC = SOCK_CLOEXEC # alias
_SC_LEVEL4_CACHE_SIZE = 197
# def IN6_IS_ADDR_LOOPBACK(a): return (((__const uint32_t *) (a))[0] == 0 && ((__const uint32_t *) (a))[1] == 0 && ((__const uint32_t *) (a))[2] == 0 && ((__const uint32_t *) (a))[3] == htonl (1)) # macro
SEC_OID_PKCS1_MD4_WITH_RSA_ENCRYPTION = 18
cipher_rc4_40 = 2
SEC_OID_SECG_EC_SECP160R2 = 215
SEC_ERROR_POLICY_VALIDATION_FAILED = -8032
PK11TokenNotRemovable = 0
ct_DSS_sign = 2
class PLHashTable(Structure):
    pass
PRHashTable = PLHashTable # alias
SEC_ERROR_TOKEN_NOT_LOGGED_IN = -8037
# def PR_PREV_LINK(_e): return ((_e)->prev) # macro
# def IN6_IS_ADDR_MC_LINKLOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x2)) # macro
SEC_OID_NS_CERT_EXT_CA_CRL_URL = 67
def __ispunct_l(c,l): return __isctype_l((c), _ISpunct, (l)) # macro
SIGEV_SIGNAL = SIGEV_SIGNAL # alias
kea_dh_dss = 4
# def IN6_ARE_ADDR_EQUAL(a,b): return ((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0]) && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1]) && (((__const uint32_t *) (a))[2] == ((__const uint32_t *) (b))[2]) && (((__const uint32_t *) (a))[3] == ((__const uint32_t *) (b))[3])) # macro
_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS # alias
nssILockArena = 0
kea_rsa_fips = 14
SEC_OID_PKCS12_SECRET_BAG_ID = 112
SSL_ERROR_UNSUPPORTED_VERSION = -12279
_SC_LONG_BIT = 106
_SC_LONG_BIT = _SC_LONG_BIT # alias
SEC_ERROR_SAFE_NOT_CREATED = -8122
SO_TIMESTAMPNS = 35 # Variable c_int '35'
SCM_TIMESTAMPNS = SO_TIMESTAMPNS # alias
ssl_auth_kea = 3
# PORT_Assert = PR_ASSERT # alias
def htobe64(x): return __bswap_64 (x) # macro
wait_server_hello = 6
_SC_UCHAR_MAX = _SC_UCHAR_MAX # alias
kg_null = 0
_SC_NPROCESSORS_ONLN = _SC_NPROCESSORS_ONLN # alias
_PC_2_SYMLINKS = _PC_2_SYMLINKS # alias
SEC_ERROR_UNKNOWN_SIGNER = -8076
PRTraceLockHandles = 7
SSL_ERROR_END_OF_LIST = -12172
IPPROTO_DSTOPTS = IPPROTO_DSTOPTS # alias
_SC_LEVEL1_DCACHE_LINESIZE = _SC_LEVEL1_DCACHE_LINESIZE # alias
_SC_2_PBS_ACCOUNTING = 169
_SC_2_PBS_ACCOUNTING = _SC_2_PBS_ACCOUNTING # alias
PR_BYTES_PER_FLOAT = 4 # Variable c_int '4'
BYTES_PER_FLOAT = PR_BYTES_PER_FLOAT # alias
SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY = -12240
nssILockCache = 7
XP_JAVA_REMOVE_PRINCIPAL_ERROR = -8120
SEC_OID_X509_REASON_CODE = 95
SSL_ERROR_DECODE_ERROR_ALERT = -12193
# def PR_EXTERN(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
siBuffer = 0
__S64_TYPE = __quad_t # alias
SEC_ERROR_CRL_NOT_YET_VALID = -8078
certRegisterID = 9
# def SSL_UNLOCK_READER(ss): return if (ss->recvLock) PZ_Unlock(ss->recvLock) # macro
def le16toh(x): return (x) # macro
SEC_ERROR_MESSAGE_SEND_ABORTED = -8103
PR_BYTES_PER_DWORD_LOG2 = 3 # Variable c_int '3'
BYTES_PER_DWORD_LOG2 = PR_BYTES_PER_DWORD_LOG2 # alias
SOCK_STREAM = 1
PR_MW_INTERRUPT = -3
_SC_PIPE = 145
_SC_PIPE = _SC_PIPE # alias
SEC_ERROR_CERT_NOT_IN_NAME_SPACE = -8080
def le64toh(x): return (x) # macro
SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE = 278
SEC_ERROR_CKL_CONFLICT = -8081
# SET_BIT = PR_SET_BIT # alias
def be32toh(x): return __bswap_32 (x) # macro
SEC_OID_CMS_EPHEMERAL_STATIC_DIFFIE_HELLMAN = 179
_SC_FD_MGMT = _SC_FD_MGMT # alias
SEC_OID_PKIX_REGCTRL_REGTOKEN = 138
_SC_NL_TEXTMAX = _SC_NL_TEXTMAX # alias
SECWouldBlock = -2
__uid_t = c_uint
_G_uid_t = __uid_t # alias
_SC_PII_OSI = 57
_SC_PII_OSI = _SC_PII_OSI # alias
_SC_LOGIN_NAME_MAX = _SC_LOGIN_NAME_MAX # alias
_SC_THREAD_DESTRUCTOR_ITERATIONS = 73
_SC_THREAD_DESTRUCTOR_ITERATIONS = _SC_THREAD_DESTRUCTOR_ITERATIONS # alias
ssl_compression_deflate = 1
SEC_ERROR_CRL_INVALID_VERSION = -8045
_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS # alias
# __wur = __attribute_warn_unused_result__ # alias
SO_TIMESTAMPING = 37 # Variable c_int '37'
SCM_TIMESTAMPING = SO_TIMESTAMPING # alias
__pid_t = c_int
_G_pid_t = __pid_t # alias
SEC_OID_PKIX_REGCTRL_PROTOCOL_ENC_KEY = 143
SSL_ERROR_CLOSE_NOTIFY_ALERT = -12230
PR_BYTES_PER_DOUBLE = 8 # Variable c_int '8'
BYTES_PER_DOUBLE = PR_BYTES_PER_DOUBLE # alias
SEC_OID_AES_128_ECB = 183
SECGreaterThan = 1
wait_server_cert = 7
PF_FILE = PF_LOCAL # alias
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC = 159
# _LIBUTIL_H_ = _LIBUTIL_H__Util # alias
IP_RETOPTS = 7 # Variable c_int '7'
IP_RECVRETOPTS = IP_RETOPTS # alias
def PR_LOG_DEFINE(_name): return NULL # macro
SEC_OID_PKCS7_SIGNED_ENVELOPED_DATA = 28
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC = 119
PK11TokenPresentEvent = 1
# def ssl_GetXmitBufLock(ss): return { if (!ss->opt.noLocks) PZ_EnterMonitor((ss)->xmitBufLock); } # macro
_SC_SPIN_LOCKS = _SC_SPIN_LOCKS # alias
PR_SockOpt_Last = 16
IPPORT_EXECSERVER = 512
SEC_ERROR_CRL_BAD_SIGNATURE = -8160
# def ssl_HaveSpecWriteLock(ss): return (NSSRWLock_HaveWriteLock((ss)->specLock)) # macro
_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = 1145
cipher_missing = 15
# def PR_NetAddrInetPort(addr): return ((addr)->raw.family == PR_AF_INET6 ? (addr)->ipv6.port : (addr)->inet.port) # macro
PR_SHUTDOWN_RCV = 0
__PDP_ENDIAN = 3412 # Variable c_int '3412'
PDP_ENDIAN = __PDP_ENDIAN # alias
BUFSIZ = _IO_BUFSIZ # alias
SEC_OID_ANSIX962_EC_PRIME239V2 = 206
# _G_OPEN64 = __open64 # alias
SEC_ERROR_UNKNOWN_AIA_LOCATION_TYPE = -8031
IPPORT_WHOSERVER = 513
cipher_seed = 14
PK11TokenChanged = 2
CKF_EC_F_P = 1048576 # Variable c_int '1048576'
CKF_EC_FP = CKF_EC_F_P # alias
PF_ROUTE = PF_NETLINK # alias
AF_ROUTE = PF_ROUTE # alias
_SC_XOPEN_XPG4 = _SC_XOPEN_XPG4 # alias
SEC_OID_NS_CERT_EXT_SSL_SERVER_NAME = 74
_SC_CHARCLASS_NAME_MAX = 45
_SC_CHARCLASS_NAME_MAX = _SC_CHARCLASS_NAME_MAX # alias
SEC_OID_NS_CERT_EXT_BASE_URL = 64
_CS_XBS5_LPBIG_OFFBIG_CFLAGS = _CS_XBS5_LPBIG_OFFBIG_CFLAGS # alias
SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST = -12242
_SC_EXPR_NEST_MAX = _SC_EXPR_NEST_MAX # alias
SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE = -12221
PR_SKIP_NONE = 0
PRTraceEnable = 1
def va_start(v,l): return __builtin_va_start(v,l) # macro
CKT_NSS_VALID_DELEGATOR = 3461563227L # Variable c_uint '-833404069u'
CKT_NETSCAPE_VALID_DELEGATOR = CKT_NSS_VALID_DELEGATOR # alias
# def SSL_UNLOCK_WRITER(ss): return if (ss->sendLock) PZ_Unlock(ss->sendLock) # macro
SEC_ERROR_BAD_PASSWORD = -8177
SEC_OID_AVA_SURNAME = 261
_SC_TYPED_MEMORY_OBJECTS = _SC_TYPED_MEMORY_OBJECTS # alias
PR_LOG_NONE = 0
# _IO_wint_t = _G_wint_t # alias
SEC_ERROR_INVALID_PASSWORD = -8091
IPPORT_TIMESERVER = 37
MSG_PEEK = MSG_PEEK # alias
def __isprint_l(c,l): return __isctype_l((c), _ISprint, (l)) # macro
SEC_OID_PKCS7_SIGNED_DATA = 26
_SC_2_LOCALEDEF = 52
_SC_2_LOCALEDEF = _SC_2_LOCALEDEF # alias
MSG_WAITALL = MSG_WAITALL # alias
_CS_PATH = _CS_PATH # alias
SEC_OID_SECG_EC_SECT409R1 = 257
def va_copy(d,s): return __builtin_va_copy(d,s) # macro
IPPROTO_TP = 29
IPPROTO_TP = IPPROTO_TP # alias
CLIENT_AUTH_ANONYMOUS = 0
cert_po_trustAnchor = 2
class PRMonitor(Structure):
    pass
PZMonitor = PRMonitor # alias
SEC_ERROR_PKCS12_KEY_DATABASE_NOT_INITIALIZED = -8093
PR_SKIP_BOTH = 3
export_restriction = 60
SEC_ERROR_INVALID_ALGORITHM = -8186
SEC_OID_PKCS12_KEY_BAG_ID = 110
SEC_OID_SECG_EC_SECP256K1 = 219
PR_LibSpec_MacNamedFragment = 1
__codecvt_ok = 0
SEC_ERROR_OCSP_UNKNOWN_RESPONSE_TYPE = -8074
PF_ISDN = 34 # Variable c_int '34'
AF_ISDN = PF_ISDN # alias
# def SECKEY_ATTRIBUTES_CACHED(key): return (0 != (key->staticflags & SECKEY_Attributes_Cached)) # macro
PK11_TypePrivKey = 1
SEC_ERROR_PKCS12_UNABLE_TO_WRITE = -8095
SEC_OID_SECG_EC_SECP128R1 = 211
SEC_OID_AVA_POSTAL_ADDRESS = 265
SEC_ERROR_BAD_TEMPLATE = -8056
kg_export = 2
ssl_session_ticket_xtn = 35
PR_LOG_NOTICE = 4
_SC_BC_BASE_MAX = _SC_BC_BASE_MAX # alias
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC = 157
secCertTimeExpired = 1
kea_rsa_export_1024 = 3
PK11_OriginUnwrap = 4
SEC_OID_ANSIX962_EC_C2PNB176V1 = 225
_SC_EQUIV_CLASS_MAX = _SC_EQUIV_CLASS_MAX # alias
# def SECMOD_MAKE_NSS_FLAGS(fips,slot): return "Flags=internal,critical"fips" slotparams=("#slot"={"SECMOD_SLOT_FLAGS"})" # macro
ct_ECDSA_sign = 64
user_canceled = 90
SEC_OID_PKIX_OCSP_CRL = 133
# def __FD_ZERO(fdsp): return do { int __d0, __d1; __asm__ __volatile__ ("cld; rep; " __FD_ZERO_STOS : "=c" (__d0), "=D" (__d1) : "a" (0), "0" (sizeof (fd_set) / sizeof (__fd_mask)), "1" (&__FDS_BITS (fdsp)[0]) : "memory"); } while (0) # macro
# __TIME_T_TYPE = __SLONGWORD_TYPE # alias
SSL_ERROR_RX_MALFORMED_CLIENT_HELLO = -12260
CKR_NSS_KEYDB_FAILED = 3461563218L # Variable c_uint '-833404078u'
CKR_NETSCAPE_KEYDB_FAILED = CKR_NSS_KEYDB_FAILED # alias
SEC_ERROR_INVALID_TIME = -8184
SSL_ERROR_REVOKED_CERT_ALERT = -12270
AF_FILE = PF_FILE # alias
cert_pi_policyFlags = 5
SEC_OID_CAMELLIA_128_CBC = 288
SEC_OID_ANSIX962_EC_C2TNB191V3 = 228
SEC_OID_DES_MAC = 13
CKT_NSS_VALID = 3461563226L # Variable c_uint '-833404070u'
CKT_NETSCAPE_VALID = CKT_NSS_VALID # alias
certPackagePKCS7 = 2
_SC_UINT_MAX = 116
_SC_UINT_MAX = _SC_UINT_MAX # alias
SEC_OID_ANSIX962_EC_C2ONB191V4 = 229
# def __FDS_BITS(set): return ((set)->fds_bits) # macro
SEC_OID_X509_AUTH_INFO_ACCESS = 93
_IO_va_list = __gnuc_va_list # alias
MSG_SYN = 1024
SEC_OID_OCSP_RESPONDER = 151
_CS_LFS64_CFLAGS = 1004
_CS_LFS64_CFLAGS = _CS_LFS64_CFLAGS # alias
SSL_ERROR_SIGN_HASHES_FAILURE = -12222
SEC_OID_SECG_EC_SECP160R1 = 214
CKA_NSS_KRL = 3461563224L # Variable c_uint '-833404072u'
CKA_NETSCAPE_KRL = CKA_NSS_KRL # alias
SIGEV_THREAD_ID = 4
SIGEV_THREAD_ID = SIGEV_THREAD_ID # alias
SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH = -12243
def makedev(maj,min): return gnu_dev_makedev (maj, min) # macro
PF_ATMPVC = 8 # Variable c_int '8'
AF_ATMPVC = PF_ATMPVC # alias
_SC_2_FORT_RUN = 50
_SC_2_FORT_RUN = _SC_2_FORT_RUN # alias
def PR_ATOMIC_SET(val,newval): return __sync_lock_test_and_set(val, newval) # macro
PRTraceDisable = 2
SSL_ERROR_DECOMPRESSION_FAILURE = -12177
# def PR_INSERT_AFTER(_e,_l): return PR_BEGIN_MACRO (_e)->next = (_l)->next; (_e)->prev = (_l); (_l)->next->prev = (_e); (_l)->next = (_e); PR_END_MACRO # macro
IPPROTO_RAW = 255
IPPROTO_RAW = IPPROTO_RAW # alias
SEC_OID_PKCS9_CONTENT_TYPE = 33
_ISpunct = 4
SEC_OID_PKCS1_PSPECIFIED = 306
SEC_OID_RFC1274_MAIL = 99
IPPORT_USERRESERVED = 5000
SSL_ERROR_TOKEN_INSERTION_REMOVAL = -12205
SEC_OID_AES_128_KEY_WRAP = 197
cipher_rc2 = 4
PR_SI_HOSTNAME_UNTRUNCATED = 4
_CS_POSIX_V6_ILP32_OFF32_LDFLAGS = _CS_POSIX_V6_ILP32_OFF32_LDFLAGS # alias
_CS_XBS5_LP64_OFF64_CFLAGS = _CS_XBS5_LP64_OFF64_CFLAGS # alias
_SC_LEVEL4_CACHE_SIZE = _SC_LEVEL4_CACHE_SIZE # alias
SEC_ERROR_CRL_ALREADY_EXISTS = -8039
SEC_ERROR_PKCS11_GENERAL_ERROR = -8025
PR_PRIORITY_LAST = 3
_SC_LEVEL3_CACHE_LINESIZE = 196
# def LL_SUB(r,a,b): return ((r) = (a) - (b)) # macro
SEC_OID_SECG_EC_SECT163K1 = 246
PRTraceBufSize = 0
CKO_NSS_TRUST = 3461563219L # Variable c_uint '-833404077u'
CKO_NETSCAPE_TRUST = CKO_NSS_TRUST # alias
cipher_rc4_56 = 3
cipher_rc4 = 1
# def ssl_ReleaseSpecReadLock(ss): return { if (!ss->opt.noLocks) NSSRWLock_UnlockRead((ss)->specLock); } # macro
_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS # alias
PRHashNumber = PLHashNumber # alias
# def __WIFSIGNALED(status): return (((signed char) (((status) & 0x7f) + 1) >> 1) > 0) # macro
SEC_OID_ANSIX962_EC_C2PNB272W1 = 237
SSLAppOpHeader = 4
CERT_N2A_READABLE = 0
def PR_REALLOC(_ptr,_size): return (PR_Realloc((_ptr), (_size))) # macro
CKO_NSS_NEWSLOT = 3461563221L # Variable c_uint '-833404075u'
CKO_NETSCAPE_NEWSLOT = CKO_NSS_NEWSLOT # alias
def isgraph_l(c,l): return __isgraph_l ((c), (l)) # macro
SEEK_CUR = 1 # Variable c_int '1'
L_INCR = SEEK_CUR # alias
PR_GLOBAL_THREAD = 1
IPPROTO_UDP = IPPROTO_UDP # alias
PR_LOG_ALWAYS = 1
# def SECKEY_ATTRIBUTE_VALUE(key,attribute): return (0 != (key->staticflags & SECKEY_ ##attribute)) # macro
_SC_DEVICE_SPECIFIC_R = _SC_DEVICE_SPECIFIC_R # alias
# def __REDIRECT(name,proto,alias): return name proto __asm__ (__ASMNAME (#alias)) # macro
record_overflow = 22
certUsageSSLServer = 1
ssl_kea_fortezza = 3
# __OFF_T_TYPE = __SLONGWORD_TYPE # alias
kea_dh_anon_export = 13
_SC_USHRT_MAX = 118
_SC_USHRT_MAX = _SC_USHRT_MAX # alias
SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE = -12280
certificate_verify = 15
_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS # alias
INADDR_ANY = 0L # Variable c_uint '0u'
PR_INADDR_ANY = INADDR_ANY # alias
SEC_ERROR_UNSUPPORTED_KEYALG = -8144
SEC_OID_AVA_POST_OFFICE_BOX = 267
def PZ_NotifyAll(m): return PR_Notify((m)) # macro
# def __bswap_constant_64(x): return ((((x) & 0xff00000000000000ull) >> 56) | (((x) & 0x00ff000000000000ull) >> 40) | (((x) & 0x0000ff0000000000ull) >> 24) | (((x) & 0x000000ff00000000ull) >> 8) | (((x) & 0x00000000ff000000ull) << 8) | (((x) & 0x0000000000ff0000ull) << 24) | (((x) & 0x000000000000ff00ull) << 40) | (((x) & 0x00000000000000ffull) << 56)) # macro
ssl_sign_ecdsa = 3
_CS_XBS5_ILP32_OFF32_LDFLAGS = _CS_XBS5_ILP32_OFF32_LDFLAGS # alias
MSG_CMSG_CLOEXEC = MSG_CMSG_CLOEXEC # alias
# __SSIZE_T_TYPE = __SWORD_TYPE # alias
IPPROTO_DCCP = 33
PR_SEEK_CUR = 1
wait_server_key = 8
SEC_OID_PKCS9_SMIME_CAPABILITIES = 40
PK11CertListRootUnique = 2
_IO_uid_t = _G_uid_t # alias
# def __nonnull(params): return __attribute__ ((__nonnull__ params)) # macro
SEC_ERROR_NO_TOKEN = -8127
_CS_GNU_LIBPTHREAD_VERSION = 3
_CS_GNU_LIBPTHREAD_VERSION = _CS_GNU_LIBPTHREAD_VERSION # alias
SIGEV_THREAD = 2
SIGEV_THREAD = SIGEV_THREAD # alias
IPPROTO_DCCP = IPPROTO_DCCP # alias
nullKey = 0
sign_ecdsa = ssl_sign_ecdsa # alias
SEC_ERROR_BAGGAGE_NOT_CREATED = -8121
cert_po_nbioContext = 1
def PORT_Strlen(s): return strlen(s) # macro
SSL_ERROR_EXPORT_RESTRICTION_ALERT = -12191
# def PR_EXTERN_DATA(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
PRTraceSuspendRecording = 5
sslHandshakingUndetermined = 0
PR_PRIORITY_NORMAL = 1
SEC_ERROR_LIBRARY_FAILURE = -8191
# PORT_Memset = memset # alias
CKA_NSS_SMIME_INFO = 3461563219L # Variable c_uint '-833404077u'
CKA_NETSCAPE_SMIME_INFO = CKA_NSS_SMIME_INFO # alias
SEC_ERROR_JS_DEL_MOD_FAILURE = -8083
SEC_OID_PKCS12_CERT_BAG_IDS = 104
# def IN6_IS_ADDR_SITELOCAL(a): return ((((__const uint32_t *) (a))[0] & htonl (0xffc00000)) == htonl (0xfec00000)) # macro
SEC_OID_ANSIX962_EC_PRIME192V3 = 204
# PORT_Strchr = strchr # alias
SEC_ERROR_PKCS12_DUPLICATE_DATA = -8104
_SC_PII_OSI_COTS = _SC_PII_OSI_COTS # alias
SEC_OID_ANSIX962_EC_C2ONB191V5 = 230
PR_MW_TIMEOUT = -2
def PR_UINT32(x): return x ## U # macro
CKO_NSS_CRL = 3461563217L # Variable c_uint '-833404079u'
CKO_NETSCAPE_CRL = CKO_NSS_CRL # alias
SEC_ERROR_UNSUPPORTED_EC_POINT_FORM = -8050
# PORT_Strncasecmp = PL_strncasecmp # alias
SEC_ERROR_OCSP_RESPONDER_CERT_INVALID = -8036
# stdin = stdin # alias
SEC_OID_PKCS5_PBES2 = 292
SEC_ERROR_OCSP_UNKNOWN_CERT = -8066
PR_BITS_PER_WORD_LOG2 = 5 # Variable c_int '5'
BITS_PER_WORD_LOG2 = PR_BITS_PER_WORD_LOG2 # alias
SSL_ERROR_RX_MALFORMED_HANDSHAKE = -12249
SEC_OID_NS_TYPE_GIF = 49
ssl_calg_idea = 5
def __PMT(args): return args # macro
certUsageVerifyCA = 8
secCertTimeValid = 0
# PR_HashString = PL_HashString # alias
bad_certificate_hash_value = 114
SEC_OID_NS_CERT_EXT_REVOCATION_URL = 65
SEC_OID_PKCS12_V1_CRL_BAG_ID = 165
nssILockDBM = 6
SEC_OID_X509_POLICY_CONSTRAINTS = 90
PRTraceUnLockHandles = 8
cert_pi_certStores = 10
# PR_HashTableRemove = PL_HashTableRemove # alias
_SC_LEVEL4_CACHE_ASSOC = _SC_LEVEL4_CACHE_ASSOC # alias
SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER = -12251
SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM = -8112
SEC_OID_PKIX_REGCTRL_OLD_CERT_ID = 142
SOCK_STREAM = SOCK_STREAM # alias
SSL_ERROR_RX_UNKNOWN_ALERT = -12231
SEC_ERROR_INVALID_ARGS = -8187
SSL_ERROR_RX_MALFORMED_FINISHED = -12252
SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE = 182
PK11_DIS_TOKEN_VERIFY_FAILED = 3
SEC_OID_SECG_EC_SECT193R2 = 250
def getc(_fp): return _IO_getc (_fp) # macro
PR_BITS_PER_DOUBLE_LOG2 = 6 # Variable c_int '6'
BITS_PER_DOUBLE_LOG2 = PR_BITS_PER_DOUBLE_LOG2 # alias
def PR_LOG_TEST(module,level): return 0 # macro
HASH_AlgTOTAL = 7
IPPROTO_COMP = IPPROTO_COMP # alias
PRTraceResumeRecording = 6
IPPORT_SUPDUP = 95
SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE = -8162
SEC_OID_AES_256_CBC = 188
_SC_PAGE_SIZE = _SC_PAGESIZE # alias
SSL_ERROR_RX_UNEXPECTED_HANDSHAKE = -12235
SEC_ERROR_CRL_EXPIRED = -8161
SEC_OID_AES_192_KEY_WRAP = 198
def PR_MALLOC(_bytes): return (PR_Malloc((_bytes))) # macro
# def ssl_HaveSSL3HandshakeLock(ss): return (PZ_InMonitor((ss)->ssl3HandshakeLock)) # macro
def __attribute_format_strfmon__(a,b): return __attribute__ ((__format__ (__strfmon__, a, b))) # macro
SEC_OID_SECG_EC_SECT233K1 = 251
SSL_ERROR_PROTOCOL_VERSION_ALERT = -12190
SEC_OID_SECG_EC_SECT233R1 = 252
SEC_ERROR_OCSP_NOT_ENABLED = -8065
CKA_NSS_PKCS8_SALT = 3461563221L # Variable c_uint '-833404075u'
CKA_NETSCAPE_PKCS8_SALT = CKA_NSS_PKCS8_SALT # alias
ssl_compression_null = 0
def LL_IS_ZERO(a): return ((a) == 0) # macro
certOtherName = 1
SEC_OID_ANSIX962_EC_PRIME239V1 = 205
HASH_AlgSHA256 = 4
PK11TokenPresent = 1
SEC_OID_DES_EDE = 14
CKA_SUBPRIME_BITS = 308 # Variable c_int '308'
CKA_SUB_PRIME_BITS = CKA_SUBPRIME_BITS # alias
HASH_AlgSHA1 = 3
cipher_des40 = 8
_SC_XOPEN_STREAMS = 246
__codecvt_error = 2
PR_StandardInput = 0
_SC_THREAD_THREADS_MAX = 76
SEC_ERROR_UNTRUSTED_ISSUER = -8172
# def IN6_IS_ADDR_MC_NODELOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x1)) # macro
SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH = -12257
HASH_AlgMD2 = 1
PK11_OriginFortezzaHack = 3
sslHandshakingAsClient = 1
# PR_FreeArenaPool = PL_FreeArenaPool # alias
_SC_DEVICE_IO = 140
_SC_DEVICE_IO = _SC_DEVICE_IO # alias
SEC_OID_PKIX_REGCTRL_AUTHENTICATOR = 139
# def PR_STATIC_CALLBACK(__x): return static __x # macro
def LL_NE(a,b): return ((a) != (b)) # macro
SEC_OID_PKIX_CA_ISSUERS = 273
PR_SI_RELEASE = 2
_SC_LEVEL3_CACHE_SIZE = _SC_LEVEL3_CACHE_SIZE # alias
certificate_unknown = 46
siUTCTime = 11
siCipherDataBuffer = 2
ssl_auth_rsa = 1
def WSTOPSIG(status): return __WSTOPSIG (__WAIT_INT (status)) # macro
SSL_ERROR_RX_MALFORMED_SERVER_HELLO = -12259
SEC_OID_AVA_GIVEN_NAME = 268
XP_SEC_FORTEZZA_BAD_PIN = -8136
siGeneralizedTime = 12
def __islower_l(c,l): return __isctype_l((c), _ISlower, (l)) # macro
SECEqual = 0
PK11_DIS_TOKEN_NOT_PRESENT = 4
PF_APPLETALK = 5 # Variable c_int '5'
AF_APPLETALK = PF_APPLETALK # alias
PR_BITS_PER_DOUBLE = 64 # Variable c_int '64'
BITS_PER_DOUBLE = PR_BITS_PER_DOUBLE # alias
SEC_OID_X509_CRL_NUMBER = 94
def SEC_ASN1_SUB(x): return x # macro
def __toascii(c): return ((c) & 0x7f) # macro
IPPORT_SMTP = 25
cert_po_end = 0
def WIFSIGNALED(status): return __WIFSIGNALED (__WAIT_INT (status)) # macro
_SC_XBS5_ILP32_OFF32 = _SC_XBS5_ILP32_OFF32 # alias
_ISalpha = 1024
PR_BITS_PER_INT_LOG2 = 5 # Variable c_int '5'
BITS_PER_INT_LOG2 = PR_BITS_PER_INT_LOG2 # alias
_SC_HOST_NAME_MAX = _SC_HOST_NAME_MAX # alias
# __BLKSIZE_T_TYPE = __SLONGWORD_TYPE # alias
def __attribute_format_arg__(x): return __attribute__ ((__format_arg__ (x))) # macro
_SC_2_C_DEV = _SC_2_C_DEV # alias
SEC_OID_SECG_EC_SECT409K1 = 256
keaKey = 5
CKA_NSS_PASSWORD_CHECK = 3461563222L # Variable c_uint '-833404074u'
CKA_NETSCAPE_PASSWORD_CHECK = CKA_NSS_PASSWORD_CHECK # alias
SEC_ERROR_KEYGEN_FAIL = -8092
SEC_ERROR_PKCS12_INVALID_MAC = -8113
_SC_NL_NMAX = _SC_NL_NMAX # alias
sender_client = 1129074260
SEC_ERROR_CRL_V1_CRITICAL_EXTENSION = -8044
def __iscntrl_l(c,l): return __isctype_l((c), _IScntrl, (l)) # macro
SEC_OID_SDN702_DSA_SIGNATURE = 189
CERT_N2A_STRICT = 10
SEC_ERROR_BAD_HTTP_RESPONSE = -8030
# def LL_OR(r,a,b): return ((r) = (a) | (b)) # macro
def _PARAMS(protos): return __P(protos) # macro
INVALID_CERT_EXTENSION = 0
SEC_ERROR_CERT_BAD_ACCESS_LOCATION = -8075
SSLAppOpPost = 3
# def PR_REMOVE_AND_INIT_LINK(_e): return PR_BEGIN_MACRO (_e)->prev->next = (_e)->next; (_e)->next->prev = (_e)->prev; (_e)->next = (_e); (_e)->prev = (_e); PR_END_MACRO # macro
_SC_THREAD_THREADS_MAX = _SC_THREAD_THREADS_MAX # alias
_SC_C_LANG_SUPPORT = 135
certUsageStatusResponder = 10
SOCK_PACKET = 10
SOCK_PACKET = SOCK_PACKET # alias
PF_PHONET = 35 # Variable c_int '35'
AF_PHONET = PF_PHONET # alias
_SC_2_PBS = 168
class PRLock(Structure):
    pass
PZLock = PRLock # alias
__FSBLKCNT64_T_TYPE = __UQUAD_TYPE # alias
SEC_OID_CAMELLIA_256_CBC = 290
# __PID_T_TYPE = __S32_TYPE # alias
SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC = 22
PF_X25 = 9 # Variable c_int '9'
AF_X25 = PF_X25 # alias
SEC_OID_X509_CERTIFICATE_POLICIES = 88
_SC_LEVEL3_CACHE_LINESIZE = _SC_LEVEL3_CACHE_LINESIZE # alias
_SC_2_PBS = _SC_2_PBS # alias
SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION = 19
# SCM_SRCRT = IPV6_RXSRCRT # alias
SSL_ERROR_RX_MALFORMED_HELLO_REQUEST = -12261
SEC_ERROR_BAD_DER = -8183
SEC_OID_BOGUS_KEY_USAGE = 173
# def PR_DELETE(_ptr): return { PR_Free(_ptr); (_ptr) = NULL; } # macro
_SC_DELAYTIMER_MAX = 26
# def ssl_ReleaseXmitBufLock(ss): return { if (!ss->opt.noLocks) PZ_ExitMonitor( (ss)->xmitBufLock); } # macro
_SC_XOPEN_STREAMS = _SC_XOPEN_STREAMS # alias
# NULL = __null # alias
SEC_OID_AVA_SERIAL_NUMBER = 262
def htonl(x): return __bswap_32 (x) # macro
# def LL_DIV(r,a,b): return ((r) = (a) / (b)) # macro
def __WTERMSIG(status): return ((status) & 0x7f) # macro
def CK_DECLARE_FUNCTION_POINTER(rtype,func): return rtype (PR_CALLBACK * func) # macro
_IO_size_t = _G_size_t # alias
cert_pi_end = 0
SEC_OID_EXT_KEY_USAGE_TIME_STAMP = 150
SSL_ERROR_GENERATE_RANDOM_FAILURE = -12223
SSL_ERROR_RX_UNEXPECTED_CERTIFICATE = -12244
SEC_ERROR_DUPLICATE_CERT = -8170
# PR_PUBLIC_API = PR_IMPLEMENT # alias
# def _IO_feof_unlocked(__fp): return (((__fp)->_flags & _IO_EOF_SEEN) != 0) # macro
PR_BITS_PER_INT64_LOG2 = 6 # Variable c_int '6'
BITS_PER_INT64_LOG2 = PR_BITS_PER_INT64_LOG2 # alias
_SC_2_C_BIND = _SC_2_C_BIND # alias
# def PR_BIT(n): return ((PRUint32)1 << (n)) # macro
# def PR_INSERT_BEFORE(_e,_l): return PR_BEGIN_MACRO (_e)->next = (_l); (_e)->prev = (_l)->prev; (_l)->prev->next = (_e); (_l)->prev = (_e); PR_END_MACRO # macro
PR_SockOpt_Broadcast = 15
IPPROTO_IP = IPPROTO_IP # alias
# PR_INIT_ARENA_POOL = PL_INIT_ARENA_POOL # alias
# def ssl_Have1stHandshakeLock(ss): return (PZ_InMonitor((ss)->firstHandshakeLock)) # macro
# def IN6_IS_ADDR_V4COMPAT(a): return ((((__const uint32_t *) (a))[0] == 0) && (((__const uint32_t *) (a))[1] == 0) && (((__const uint32_t *) (a))[2] == 0) && (ntohl (((__const uint32_t *) (a))[3]) > 1)) # macro
PR_SockOpt_RecvBufferSize = 4
IPPORT_RESERVED = 1024
SSL_ERROR_NO_SERVER_KEY_FOR_ALG = -12206
SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION = 196
def PR_ROTATE_RIGHT32(a,bits): return (((a) >> (bits)) | ((a) << (32 - (bits)))) # macro
SEC_OID_PKCS12_SIGNATURE_IDS = 107
no_renegotiation = 100
def PZ_NewCondVar(l): return PR_NewCondVar((l)) # macro
def LL_EQ(a,b): return ((a) == (b)) # macro
certificate_expired = 45
def __WCOREDUMP(status): return ((status) & __WCOREFLAG) # macro
_SC_2_FORT_DEV = _SC_2_FORT_DEV # alias
SEC_OID_PKCS9_UNSTRUCTURED_NAME = 32
class PLHashEntry(Structure):
    pass
PLHashEnumerator = CFUNCTYPE(PRIntn, POINTER(PLHashEntry), PRIntn, c_void_p)
PRHashEnumerator = PLHashEnumerator # alias
MSG_ERRQUEUE = MSG_ERRQUEUE # alias
crlEntryReasonAaCompromise = 10
# PR_ArenaAllocate = PL_ArenaAllocate # alias
_SC_SELECT = _SC_SELECT # alias
certPackageCert = 1
kg_strong = 1
# def __isctype(c,type): return ((*__ctype_b_loc ())[(int) (c)] & (unsigned short int) type) # macro
IPPROTO_FRAGMENT = IPPROTO_FRAGMENT # alias
calg_idea = ssl_calg_idea # alias
# def PR_FREEIF(_ptr): return if (_ptr) PR_DELETE(_ptr) # macro
# PORT_Strtok = strtok # alias
kt_fortezza = ssl_kea_fortezza # alias
_CS_POSIX_V7_ILP32_OFF32_LIBS = 1134
_CS_POSIX_V7_ILP32_OFF32_LIBS = _CS_POSIX_V7_ILP32_OFF32_LIBS # alias
invalid_cache = 3
_SC_C_LANG_SUPPORT_R = _SC_C_LANG_SUPPORT_R # alias
kea_dh_anon = 12
SSL_ERROR_BAD_SERVER = -12281
PR_BITS_PER_FLOAT_LOG2 = 5 # Variable c_int '5'
BITS_PER_FLOAT_LOG2 = PR_BITS_PER_FLOAT_LOG2 # alias
_SC_LEVEL3_CACHE_ASSOC = _SC_LEVEL3_CACHE_ASSOC # alias
siAsciiString = 8
# _IO_file_flags = _flags # alias
PR_DESC_FILE = 1
siDERCertBuffer = 3
PR_ALIGN_OF_POINTER = 4 # Variable c_int '4'
ALIGN_OF_POINTER = PR_ALIGN_OF_POINTER # alias
# __FSFILCNT_T_TYPE = __ULONGWORD_TYPE # alias
client_hello = 1
SEC_ASN1_EndOfContents = 3
certPackageNone = 0
_SC_NZERO = _SC_NZERO # alias
_IO_pos_t = _G_fpos_t # alias
PF_AX25 = 3 # Variable c_int '3'
AF_AX25 = PF_AX25 # alias
SEC_ERROR_NO_MODULE = -8128
PR_SKIP_DOT_DOT = 2
generalName = 1
def putc(_ch,_fp): return _IO_putc (_ch, _fp) # macro
nssILockAttribute = 13
SEC_OID_TOTAL = 309
def __isspace_l(c,l): return __isctype_l((c), _ISspace, (l)) # macro
# def PORT_ZNew(type): return (type*)PORT_ZAlloc(sizeof(type)) # macro
# def PR_FLOOR_LOG2(_log2,_n): return PR_BEGIN_MACRO PRUint32 j_ = (PRUint32)(_n); (_log2) = 31 - pr_bitscan_clz32((j_) | 1); PR_END_MACRO # macro
_SC_TRACE_LOG = _SC_TRACE_LOG # alias
def PZ_Wait(m,t): return PR_Wait(((m)),((t))) # macro
_SC_LEVEL4_CACHE_LINESIZE = _SC_LEVEL4_CACHE_LINESIZE # alias
SEC_ERROR_PKCS11_FUNCTION_FAILED = -8024
SEC_OID_PKCS9_CHALLENGE_PASSWORD = 37
SEC_OID_HMAC_SHA256 = 296
SHA512_LENGTH = 64 # Variable c_int '64'
HASH_LENGTH_MAX = SHA512_LENGTH # alias
SEC_ERROR_JS_ADD_MOD_FAILURE = -8084
# PORT_Strcat = strcat # alias
SEC_ERROR_USER_CANCELLED = -8105
SEC_OID_ANSIX962_EC_C2TNB239V1 = 232
# def _IO_putc_unlocked(_ch,_fp): return (_IO_BE ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end, 0) ? __overflow (_fp, (unsigned char) (_ch)) : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch))) # macro
decryption_failed_RESERVED = 21
# def LL_ISHL(r,a,b): return ((r) = (PRInt64)(a) << (b)) # macro
PRHashEntry = PLHashEntry # alias
mac_null = ssl_mac_null # alias
def __ASMNAME(cname): return __ASMNAME2 (__USER_LABEL_PREFIX__, cname) # macro
SEC_ERROR_INVALID_POLICY_MAPPING = -8033
IPPROTO_TCP = IPPROTO_TCP # alias
SEC_ERROR_OCSP_UNKNOWN_RESPONSE_STATUS = -8067
# PORT_Strncpy = strncpy # alias
SEC_OID_PKCS7 = 24
SEC_OID_PKCS12_X509_CERT_CRL_BAG = 113
def FD_CLR(fd,fdsetp): return __FD_CLR (fd, fdsetp) # macro
def _G_FSTAT64(fd,buf): return __fxstat64 (_STAT_VER, fd, buf) # macro
_CS_POSIX_V7_ILP32_OFF32_LDFLAGS = 1133
_CS_POSIX_V7_ILP32_OFF32_LDFLAGS = _CS_POSIX_V7_ILP32_OFF32_LDFLAGS # alias
_SC_C_LANG_SUPPORT = _SC_C_LANG_SUPPORT # alias
SEC_OID_PKCS12_SDSI_CERT_BAG = 114
SEC_ERROR_DUPLICATE_CERT_NAME = -8169
# _G_wchar_t = wchar_t # alias
SEC_OID_PKCS12_V1_CERT_BAG_ID = 164
SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_40_BIT_RC4 = 121
_CS_POSIX_V7_LP64_OFF64_LINTFLAGS = _CS_POSIX_V7_LP64_OFF64_LINTFLAGS # alias
SEC_OID_AVA_DC = 48
_SC_LEVEL2_CACHE_SIZE = _SC_LEVEL2_CACHE_SIZE # alias
ssl_auth_dsa = 2
calg_des = ssl_calg_des # alias
# CLEAR_BIT = PR_CLEAR_BIT # alias
_SC_XOPEN_UNIX = _SC_XOPEN_UNIX # alias
SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH = -12253
# def IN6_IS_ADDR_LINKLOCAL(a): return ((((__const uint32_t *) (a))[0] & htonl (0xffc00000)) == htonl (0xfe800000)) # macro
SEC_OID_CMS_RC2_KEY_WRAP = 181
PR_SEEK_END = 2
wait_hello_done = 10
cert_pi_trustAnchors = 11
PR_IpAddrV4Mapped = 3
_IO_pid_t = _G_pid_t # alias
type_stream = 0
IPPROTO_AH = IPPROTO_AH # alias
_POSIX2_VERSION = __POSIX2_THIS_VERSION # alias
PR_SockOpt_McastInterface = 10
PRTraceSuspend = 3
def __LONG_LONG_PAIR(HI,LO): return LO, HI # macro
SOCK_RAW = SOCK_RAW # alias
SEC_ERROR_UNKNOWN_ISSUER = -8179
PK11_DIS_USER_SELECTED = 1
PR_SockOpt_Nonblocking = 0
_SC_DELAYTIMER_MAX = _SC_DELAYTIMER_MAX # alias
siEncodedNameBuffer = 6
cert_revocation_method_ocsp = 1
def __bos0(ptr): return __builtin_object_size (ptr, 0) # macro
certOwnerUser = 0
kea_dh_rsa_export = 7
SEC_OID_NS_TYPE_CERT_SEQUENCE = 53
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4 = 115
SSL_ERROR_EXPORT_ONLY_SERVER = -12288
SEC_OID_ANSIX962_EC_C2TNB239V2 = 233
def ispunct_l(c,l): return __ispunct_l ((c), (l)) # macro
PR_ALIGN_OF_LONG = 4 # Variable c_int '4'
ALIGN_OF_LONG = PR_ALIGN_OF_LONG # alias
def __isascii(c): return (((c) & ~0x7f) == 0) # macro
SEC_ERROR_CRL_NOT_FOUND = -8055
def isblank_l(c,l): return __isblank_l ((c), (l)) # macro
_SC_V6_LPBIG_OFFBIG = 179
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4 = 116
crlEntryReasoncertificatedHold = 6
MSG_SYN = MSG_SYN # alias
kea_rsa = 1
_SC_CPUTIME = 138
_SC_XOPEN_XPG3 = _SC_XOPEN_XPG3 # alias
_SC_V6_LPBIG_OFFBIG = _SC_V6_LPBIG_OFFBIG # alias
SEC_OID_AVA_HOUSE_IDENTIFIER = 271
_SC_XOPEN_XPG2 = _SC_XOPEN_XPG2 # alias
in_server_cache = 2
_SC_PII_INTERNET_DGRAM = _SC_PII_INTERNET_DGRAM # alias
_SC_CPUTIME = _SC_CPUTIME # alias
def __REDIRECT_LDBL(name,proto,alias): return __REDIRECT (name, proto, alias) # macro
PR_SI_HOSTNAME = 0
def htole32(x): return (x) # macro
SEC_OID_X509_SUBJECT_KEY_ID = 80
def PZ_NotifyCondVar(v): return PR_NotifyCondVar((v)) # macro
PR_ALIGN_OF_INT64 = 4 # Variable c_int '4'
ALIGN_OF_INT64 = PR_ALIGN_OF_INT64 # alias
# def IN6_IS_ADDR_V4MAPPED(a): return ((((__const uint32_t *) (a))[0] == 0) && (((__const uint32_t *) (a))[1] == 0) && (((__const uint32_t *) (a))[2] == htonl (0xffff))) # macro
SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_128_BIT_RC4 = 120
PK11CertListAll = 6
_SC_LEVEL2_CACHE_LINESIZE = _SC_LEVEL2_CACHE_LINESIZE # alias
SEC_ASN1_Contents = 2
SEC_OID_PKCS1_MGF1 = 305
__INO64_T_TYPE = __UQUAD_TYPE # alias
SEC_OID_AVA_COMMON_NAME = 41
SEC_OID_MISSI_ALT_KEA = 59
def htole64(x): return (x) # macro
_SC_V7_ILP32_OFF32 = _SC_V7_ILP32_OFF32 # alias
IPPORT_TELNET = 23
_CS_GNU_LIBC_VERSION = 2
_CS_GNU_LIBC_VERSION = _CS_GNU_LIBC_VERSION # alias
SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE = -8058
PR_SI_ARCHITECTURE = 3
_POSIX2_SW_DEV = __POSIX2_THIS_VERSION # alias
PR_ALIGN_OF_INT = 4 # Variable c_int '4'
ALIGN_OF_INT = PR_ALIGN_OF_INT # alias
_CS_LFS_LINTFLAGS = _CS_LFS_LINTFLAGS # alias
certificateUsageAnyCA = 2048 # Variable c_int '2048'
certificateUsageHighest = certificateUsageAnyCA # alias
SSL_ERROR_UNKNOWN_CA_ALERT = -12195
SEC_ERROR_END_OF_LIST = -8018
IPPROTO_ESP = IPPROTO_ESP # alias
PR_SockOpt_Linger = 1
_PC_REC_XFER_ALIGN = _PC_REC_XFER_ALIGN # alias
SEC_ERROR_PKCS12_DECODING_PFX = -8114
SEC_OID_AVA_ORGANIZATION_NAME = 45
SEC_OID_PKCS12_V1_SAFE_CONTENTS_BAG_ID = 167
SEC_OID_SECG_EC_SECT163R1 = 247
def __isalnum_l(c,l): return __isctype_l((c), _ISalnum, (l)) # macro
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC = 118
SEC_ERROR_EXTRA_INPUT = -8052
SEC_OID_AVA_LOCALITY = 43
SEC_OID_NS_TYPE_JPEG = 50
cipher_3des = 7
SEC_ERROR_PKCS12_UNABLE_TO_LOCATE_OBJECT_BY_NAME = -8097
in_client_cache = 1
def isascii_l(c,l): return __isascii_l ((c), (l)) # macro
PR_PROT_READONLY = 0
def isdigit_l(c,l): return __isdigit_l ((c), (l)) # macro
_SC_THREAD_ROBUST_PRIO_INHERIT = _SC_THREAD_ROBUST_PRIO_INHERIT # alias
siEncodedCertBuffer = 4
SEC_OID_SECG_EC_SECT571K1 = 258
rsaOaepKey = 8
def iscntrl_l(c,l): return __iscntrl_l ((c), (l)) # macro
PR_BYTES_PER_SHORT = 2 # Variable c_int '2'
BYTES_PER_SHORT = PR_BYTES_PER_SHORT # alias
SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME = 46
# PR_HashTableRawRemove = PL_HashTableRawRemove # alias
SEC_OID_X509_FRESHEST_CRL = 285
alert_fatal = 2
class SECHashObjectStr(Structure):
    pass
SECHashObject = SECHashObjectStr
class HASHContextStr(Structure):
    pass
HASHContext = HASHContextStr

# values for enumeration 'HASH_HashType'
HASH_HashType = c_int # enum
PRBool = PRIntn
SECHashObjectStr._fields_ = [
    ('length', c_uint),
    ('create', CFUNCTYPE(c_void_p)),
    ('clone', CFUNCTYPE(c_void_p, c_void_p)),
    ('destroy', CFUNCTYPE(None, c_void_p, PRBool)),
    ('begin', CFUNCTYPE(None, c_void_p)),
    ('update', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_uint)),
    ('end', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), POINTER(c_uint), c_uint)),
    ('blocklength', c_uint),
    ('type', HASH_HashType),
]
HASHContextStr._fields_ = [
    ('hashobj', POINTER(SECHashObjectStr)),
    ('hash_context', c_void_p),
]

# values for enumeration 'SECErrorCodes'
SECErrorCodes = c_int # enum
PRUint8 = c_ubyte
uint8 = PRUint8
SSL3Opaque = uint8
PRUint16 = c_ushort
uint16 = PRUint16
SSL3ProtocolVersion = uint16
ssl3CipherSuite = uint16

# values for enumeration 'SSL3ContentType'
SSL3ContentType = c_int # enum
class SSL3Plaintext(Structure):
    pass
class SECItemStr(Structure):
    pass

# values for enumeration 'SECItemType'
SECItemType = c_int # enum
SECItemStr._fields_ = [
    ('type', SECItemType),
    ('data', POINTER(c_ubyte)),
    ('len', c_uint),
]
SECItem = SECItemStr
SSL3Plaintext._fields_ = [
    ('type', SSL3ContentType),
    ('version', SSL3ProtocolVersion),
    ('length', uint16),
    ('fragment', SECItem),
]
class SSL3Compressed(Structure):
    pass
SSL3Compressed._fields_ = [
    ('type', SSL3ContentType),
    ('version', SSL3ProtocolVersion),
    ('length', uint16),
    ('fragment', SECItem),
]
class SSL3GenericStreamCipher(Structure):
    pass
SSL3GenericStreamCipher._fields_ = [
    ('content', SECItem),
    ('MAC', SSL3Opaque * 64),
]
class SSL3GenericBlockCipher(Structure):
    pass
SSL3GenericBlockCipher._fields_ = [
    ('content', SECItem),
    ('MAC', SSL3Opaque * 64),
    ('padding', uint8 * 64),
    ('padding_length', uint8),
]

# values for enumeration 'SSL3ChangeCipherSpecChoice'
SSL3ChangeCipherSpecChoice = c_int # enum
class SSL3ChangeCipherSpec(Structure):
    pass
SSL3ChangeCipherSpec._fields_ = [
    ('choice', SSL3ChangeCipherSpecChoice),
]

# values for enumeration 'SSL3AlertLevel'
SSL3AlertLevel = c_int # enum

# values for enumeration 'SSL3AlertDescription'
SSL3AlertDescription = c_int # enum
class SSL3Alert(Structure):
    pass
SSL3Alert._fields_ = [
    ('level', SSL3AlertLevel),
    ('description', SSL3AlertDescription),
]

# values for enumeration 'SSL3HandshakeType'
SSL3HandshakeType = c_int # enum
class SSL3HelloRequest(Structure):
    pass
SSL3HelloRequest._fields_ = [
    ('empty', uint8),
]
class SSL3Random(Structure):
    pass
SSL3Random._fields_ = [
    ('rand', SSL3Opaque * 32),
]
class SSL3SessionID(Structure):
    pass
SSL3SessionID._fields_ = [
    ('id', SSL3Opaque * 32),
    ('length', uint8),
]
class SSL3ClientHello(Structure):
    pass

# values for enumeration 'SSLCompressionMethod'
SSLCompressionMethod = c_int # enum
SSL3ClientHello._fields_ = [
    ('client_version', SSL3ProtocolVersion),
    ('random', SSL3Random),
    ('session_id', SSL3SessionID),
    ('cipher_suites', SECItem),
    ('cm_count', uint8),
    ('compression_methods', SSLCompressionMethod * 10),
]
class SSL3ServerHello(Structure):
    pass
SSL3ServerHello._fields_ = [
    ('server_version', SSL3ProtocolVersion),
    ('random', SSL3Random),
    ('session_id', SSL3SessionID),
    ('cipher_suite', ssl3CipherSuite),
    ('compression_method', SSLCompressionMethod),
]
class SSL3Certificate(Structure):
    pass
SSL3Certificate._fields_ = [
    ('list', SECItem),
]

# values for enumeration 'SSL3KeyExchangeAlgorithm'
SSL3KeyExchangeAlgorithm = c_int # enum
class SSL3ServerRSAParams(Structure):
    pass
SSL3ServerRSAParams._fields_ = [
    ('modulus', SECItem),
    ('exponent', SECItem),
]
class SSL3ServerDHParams(Structure):
    pass
SSL3ServerDHParams._fields_ = [
    ('p', SECItem),
    ('g', SECItem),
    ('Ys', SECItem),
]
class N16SSL3ServerParams5DOT_120E(Union):
    pass
N16SSL3ServerParams5DOT_120E._fields_ = [
    ('dh', SSL3ServerDHParams),
    ('rsa', SSL3ServerRSAParams),
]
class SSL3ServerParams(Structure):
    pass
SSL3ServerParams._fields_ = [
    ('u', N16SSL3ServerParams5DOT_120E),
]
class SSL3Hashes(Structure):
    pass
SSL3Hashes._fields_ = [
    ('md5', uint8 * 16),
    ('sha', uint8 * 20),
]
class N21SSL3ServerKeyExchange5DOT_123E(Union):
    pass
N21SSL3ServerKeyExchange5DOT_123E._fields_ = [
    ('anonymous', SSL3Opaque),
    ('certified', SSL3Hashes),
]
class SSL3ServerKeyExchange(Structure):
    pass
SSL3ServerKeyExchange._fields_ = [
    ('u', N21SSL3ServerKeyExchange5DOT_123E),
]

# values for enumeration 'SSL3ClientCertificateType'
SSL3ClientCertificateType = c_int # enum
SSL3DistinquishedName = POINTER(SECItem)
class SSL3RSAPreMasterSecret(Structure):
    pass
SSL3RSAPreMasterSecret._fields_ = [
    ('client_version', SSL3Opaque * 2),
    ('random', SSL3Opaque * 46),
]
SSL3EncryptedPreMasterSecret = SECItem
SSL3MasterSecret = SSL3Opaque * 48

# values for enumeration 'SSL3PublicValueEncoding'
SSL3PublicValueEncoding = c_int # enum
class N29SSL3ClientDiffieHellmanPublic5DOT_128E(Union):
    pass
N29SSL3ClientDiffieHellmanPublic5DOT_128E._fields_ = [
    ('implicit', SSL3Opaque),
    ('xplicit', SECItem),
]
class SSL3ClientDiffieHellmanPublic(Structure):
    pass
SSL3ClientDiffieHellmanPublic._fields_ = [
    ('dh_public', N29SSL3ClientDiffieHellmanPublic5DOT_128E),
]
class N21SSL3ClientKeyExchange5DOT_130E(Union):
    pass
N21SSL3ClientKeyExchange5DOT_130E._fields_ = [
    ('rsa', SSL3EncryptedPreMasterSecret),
    ('diffie_helman', SSL3ClientDiffieHellmanPublic),
]
class SSL3ClientKeyExchange(Structure):
    pass
SSL3ClientKeyExchange._fields_ = [
    ('exchange_keys', N21SSL3ClientKeyExchange5DOT_130E),
]
SSL3PreSignedCertificateVerify = SSL3Hashes
SSL3CertificateVerify = SECItem

# values for enumeration 'SSL3Sender'
SSL3Sender = c_int # enum
SSL3Finished = SSL3Hashes
class TLSFinished(Structure):
    pass
TLSFinished._fields_ = [
    ('verify_data', SSL3Opaque * 12),
]
class NewSessionTicket(Structure):
    pass
uint32 = PRUint32
NewSessionTicket._fields_ = [
    ('received_timestamp', uint32),
    ('ticket_lifetime_hint', uint32),
    ('ticket', SECItem),
]

# values for enumeration 'ClientAuthenticationType'
ClientAuthenticationType = c_int # enum
class N14ClientIdentity5DOT_136E(Union):
    pass
N14ClientIdentity5DOT_136E._fields_ = [
    ('certificate_list', POINTER(SSL3Opaque)),
]
class ClientIdentity(Structure):
    pass
ClientIdentity._fields_ = [
    ('client_auth_type', ClientAuthenticationType),
    ('identity', N14ClientIdentity5DOT_136E),
]
class EncryptedSessionTicket(Structure):
    pass
EncryptedSessionTicket._fields_ = [
    ('key_name', POINTER(c_ubyte)),
    ('iv', POINTER(c_ubyte)),
    ('encrypted_state', SECItem),
    ('mac', POINTER(c_ubyte)),
]

# values for enumeration 'SSLErrorCodes'
SSLErrorCodes = c_int # enum

# values for enumeration 'SSLKEAType'
SSLKEAType = c_int # enum
SSL3KEAType = SSLKEAType

# values for enumeration 'SSLMACAlgorithm'
SSLMACAlgorithm = c_int # enum
SSL3MACAlgorithm = SSLMACAlgorithm

# values for enumeration 'SSLSignType'
SSLSignType = c_int # enum
SSL3SignType = SSLSignType

# values for enumeration 'SSLAppOperation'
SSLAppOperation = c_int # enum
class sslBufferStr(Structure):
    pass
sslBuffer = sslBufferStr
class sslConnectInfoStr(Structure):
    pass
sslConnectInfo = sslConnectInfoStr
class sslGatherStr(Structure):
    pass
sslGather = sslGatherStr
class sslSecurityInfoStr(Structure):
    pass
sslSecurityInfo = sslSecurityInfoStr
class sslSessionIDStr(Structure):
    pass
sslSessionID = sslSessionIDStr
class sslSocketStr(Structure):
    pass
sslSocket = sslSocketStr
class sslSocketOpsStr(Structure):
    pass
sslSocketOps = sslSocketOpsStr
class ssl3StateStr(Structure):
    pass
ssl3State = ssl3StateStr
class ssl3CertNodeStr(Structure):
    pass
ssl3CertNode = ssl3CertNodeStr
class ssl3BulkCipherDefStr(Structure):
    pass
ssl3BulkCipherDef = ssl3BulkCipherDefStr
class ssl3MACDefStr(Structure):
    pass
ssl3MACDef = ssl3MACDefStr
class ssl3KeyPairStr(Structure):
    pass
ssl3KeyPair = ssl3KeyPairStr
class CERTCertificateStr(Structure):
    pass
CERTCertificate = CERTCertificateStr
ssl3CertNodeStr._fields_ = [
    ('next', POINTER(ssl3CertNodeStr)),
    ('cert', POINTER(CERTCertificate)),
]

# values for enumeration '_SECStatus'
_SECStatus = c_int # enum
SECStatus = _SECStatus
sslHandshakeFunc = CFUNCTYPE(SECStatus, POINTER(sslSocket))
PRInt32 = c_int
sslSendFunc = CFUNCTYPE(PRInt32, POINTER(sslSocket), POINTER(c_ubyte), PRInt32, PRInt32)
sslSessionIDCacheFunc = CFUNCTYPE(None, POINTER(sslSessionID))
sslSessionIDUncacheFunc = CFUNCTYPE(None, POINTER(sslSessionID))
class PRIPv6Addr(Structure):
    pass
class NSSTrustDomainStr(Structure):
    pass
CERTCertDBHandle = NSSTrustDomainStr
sslSessionIDLookupFunc = CFUNCTYPE(POINTER(sslSessionID), POINTER(PRIPv6Addr), POINTER(c_ubyte), c_uint, POINTER(CERTCertDBHandle))
ssl3HelloExtensionSenderFunc = CFUNCTYPE(PRInt32, POINTER(sslSocket), PRBool, PRUint32)
ssl3HelloExtensionHandlerFunc = CFUNCTYPE(SECStatus, POINTER(sslSocket), PRUint16, POINTER(SECItem))
class ssl3HelloExtensionSender(Structure):
    pass
ssl3HelloExtensionSender._fields_ = [
    ('ex_type', PRInt32),
    ('ex_sender', ssl3HelloExtensionSenderFunc),
]
class ssl3HelloExtensionHandler(Structure):
    pass
ssl3HelloExtensionHandler._fields_ = [
    ('ex_type', PRInt32),
    ('ex_handler', ssl3HelloExtensionHandlerFunc),
]
class PRNetAddr(Union):
    pass
class PRFileDesc(Structure):
    pass
sslSocketOpsStr._fields_ = [
    ('connect', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(PRNetAddr))),
    ('accept', CFUNCTYPE(POINTER(PRFileDesc), POINTER(sslSocket), POINTER(PRNetAddr))),
    ('bind', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(PRNetAddr))),
    ('listen', CFUNCTYPE(c_int, POINTER(sslSocket), c_int)),
    ('shutdown', CFUNCTYPE(c_int, POINTER(sslSocket), c_int)),
    ('close', CFUNCTYPE(c_int, POINTER(sslSocket))),
    ('recv', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(c_ubyte), c_int, c_int)),
    ('send', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(c_ubyte), c_int, c_int)),
    ('read', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(c_ubyte), c_int)),
    ('write', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(c_ubyte), c_int)),
    ('getpeername', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(PRNetAddr))),
    ('getsockname', CFUNCTYPE(c_int, POINTER(sslSocket), POINTER(PRNetAddr))),
]
sslBufferStr._fields_ = [
    ('buf', POINTER(c_ubyte)),
    ('len', c_uint),
    ('space', c_uint),
]
class ssl3CipherSuiteCfg(Structure):
    pass
ssl3CipherSuiteCfg._fields_ = [
    ('cipher_suite', c_uint, 16),
    ('policy', c_uint, 8),
    ('enabled', c_uint, 1),
    ('isPresent', c_uint, 1),
]
class sslOptionsStr(Structure):
    pass
sslOptionsStr._fields_ = [
    ('useSecurity', c_uint, 1),
    ('useSocks', c_uint, 1),
    ('requestCertificate', c_uint, 1),
    ('requireCertificate', c_uint, 2),
    ('handshakeAsClient', c_uint, 1),
    ('handshakeAsServer', c_uint, 1),
    ('enableSSL2', c_uint, 1),
    ('enableSSL3', c_uint, 1),
    ('enableTLS', c_uint, 1),
    ('noCache', c_uint, 1),
    ('fdx', c_uint, 1),
    ('v2CompatibleHello', c_uint, 1),
    ('detectRollBack', c_uint, 1),
    ('noStepDown', c_uint, 1),
    ('bypassPKCS11', c_uint, 1),
    ('noLocks', c_uint, 1),
    ('enableSessionTickets', c_uint, 1),
    ('enableDeflate', c_uint, 1),
    ('enableRenegotiation', c_uint, 2),
    ('requireSafeNegotiation', c_uint, 1),
    ('enableFalseStart', c_uint, 1),
]
sslOptions = sslOptionsStr

# values for enumeration 'sslHandshakingType'
sslHandshakingType = c_int # enum
class sslServerCertsStr(Structure):
    pass
class CERTCertificateListStr(Structure):
    pass
CERTCertificateList = CERTCertificateListStr
sslServerCertsStr._fields_ = [
    ('serverCert', POINTER(CERTCertificate)),
    ('serverCertChain', POINTER(CERTCertificateList)),
    ('serverKeyPair', POINTER(ssl3KeyPair)),
    ('serverKeyBits', c_uint),
]
sslServerCerts = sslServerCertsStr
sslGatherStr._fields_ = [
    ('state', c_int),
    ('buf', sslBuffer),
    ('offset', c_uint),
    ('remainder', c_uint),
    ('count', c_uint),
    ('recordLen', c_uint),
    ('recordPadding', c_uint),
    ('recordOffset', c_uint),
    ('encrypted', c_int),
    ('readOffset', c_uint),
    ('writeOffset', c_uint),
    ('inbuf', sslBuffer),
    ('hdr', c_ubyte * 5),
]
SSLCipher = CFUNCTYPE(SECStatus, c_void_p, POINTER(c_ubyte), POINTER(c_int), c_int, POINTER(c_ubyte), c_int)
SSLCompressor = CFUNCTYPE(SECStatus, c_void_p, POINTER(c_ubyte), POINTER(c_int), c_int, POINTER(c_ubyte), c_int)
SSLDestroy = CFUNCTYPE(SECStatus, c_void_p, PRBool)

# values for enumeration 'SSL3BulkCipher'
SSL3BulkCipher = c_int # enum

# values for enumeration 'CipherType'
CipherType = c_int # enum
class SSL3SequenceNumber(Structure):
    pass
SSL3SequenceNumber._fields_ = [
    ('high', PRUint32),
    ('low', PRUint32),
]
class ssl3SidKeys(Structure):
    pass
ssl3SidKeys._fields_ = [
    ('client_write_iv', SSL3Opaque * 24),
    ('server_write_iv', SSL3Opaque * 24),
    ('wrapped_master_secret', SSL3Opaque * 48),
    ('wrapped_master_secret_len', PRUint16),
    ('msIsWrapped', PRUint8),
    ('resumable', PRUint8),
]
class ssl3KeyMaterial(Structure):
    pass
class PK11SymKeyStr(Structure):
    pass
PK11SymKey = PK11SymKeyStr
class PK11ContextStr(Structure):
    pass
PK11Context = PK11ContextStr
PRUint64 = c_ulonglong
ssl3KeyMaterial._pack_ = 4
ssl3KeyMaterial._fields_ = [
    ('write_key', POINTER(PK11SymKey)),
    ('write_mac_key', POINTER(PK11SymKey)),
    ('write_mac_context', POINTER(PK11Context)),
    ('write_key_item', SECItem),
    ('write_iv_item', SECItem),
    ('write_mac_key_item', SECItem),
    ('write_iv', SSL3Opaque * 64),
    ('cipher_context', PRUint64 * 260),
]
class ssl3CipherSpec(Structure):
    pass
ssl3CipherSpec._fields_ = [
    ('cipher_def', POINTER(ssl3BulkCipherDef)),
    ('mac_def', POINTER(ssl3MACDef)),
    ('compression_method', SSLCompressionMethod),
    ('mac_size', c_int),
    ('encode', SSLCipher),
    ('decode', SSLCipher),
    ('destroy', SSLDestroy),
    ('encodeContext', c_void_p),
    ('decodeContext', c_void_p),
    ('compressor', SSLCompressor),
    ('decompressor', SSLCompressor),
    ('destroyCompressContext', SSLDestroy),
    ('compressContext', c_void_p),
    ('destroyDecompressContext', SSLDestroy),
    ('decompressContext', c_void_p),
    ('bypassCiphers', PRBool),
    ('master_secret', POINTER(PK11SymKey)),
    ('write_seq_num', SSL3SequenceNumber),
    ('read_seq_num', SSL3SequenceNumber),
    ('version', SSL3ProtocolVersion),
    ('client', ssl3KeyMaterial),
    ('server', ssl3KeyMaterial),
    ('msItem', SECItem),
    ('key_block', c_ubyte * 144),
    ('raw_master_secret', c_ubyte * 56),
    ('srvVirtName', SECItem),
]

# values for enumeration 'Cached'
Cached = c_int # enum
class N10PRIPv6Addr4DOT_50E(Union):
    pass
N10PRIPv6Addr4DOT_50E._pack_ = 4
N10PRIPv6Addr4DOT_50E._fields_ = [
    ('_S6_u8', PRUint8 * 16),
    ('_S6_u16', PRUint16 * 8),
    ('_S6_u32', PRUint32 * 4),
    ('_S6_u64', PRUint64 * 2),
]
PRIPv6Addr._fields_ = [
    ('_S6_un', N10PRIPv6Addr4DOT_50E),
]
class N15sslSessionIDStr5DOT_155E(Union):
    pass
class N15sslSessionIDStr5DOT_1555DOT_156E(Structure):
    pass
N15sslSessionIDStr5DOT_1555DOT_156E._fields_ = [
    ('sessionID', c_ubyte * 16),
    ('masterKey', SECItem),
    ('cipherType', c_int),
    ('cipherArg', SECItem),
    ('keyBits', c_int),
    ('secretKeyBits', c_int),
]
class N15sslSessionIDStr5DOT_1555DOT_157E(Structure):
    pass
CK_ULONG = c_ulong
CK_MECHANISM_TYPE = CK_ULONG
SECMODModuleID = c_ulong
CK_SLOT_ID = CK_ULONG
N15sslSessionIDStr5DOT_1555DOT_157E._fields_ = [
    ('sessionIDLength', uint8),
    ('sessionID', SSL3Opaque * 32),
    ('cipherSuite', ssl3CipherSuite),
    ('compression', SSLCompressionMethod),
    ('policy', c_int),
    ('keys', ssl3SidKeys),
    ('masterWrapMech', CK_MECHANISM_TYPE),
    ('exchKeyType', SSL3KEAType),
    ('clientWriteKey', POINTER(PK11SymKey)),
    ('serverWriteKey', POINTER(PK11SymKey)),
    ('masterModuleID', SECMODModuleID),
    ('masterSlotID', CK_SLOT_ID),
    ('masterWrapIndex', PRUint16),
    ('masterWrapSeries', PRUint16),
    ('clAuthModuleID', SECMODModuleID),
    ('clAuthSlotID', CK_SLOT_ID),
    ('clAuthSeries', PRUint16),
    ('masterValid', c_char),
    ('clAuthValid', c_char),
    ('sessionTicket', NewSessionTicket),
    ('srvName', SECItem),
]
N15sslSessionIDStr5DOT_155E._fields_ = [
    ('ssl2', N15sslSessionIDStr5DOT_1555DOT_156E),
    ('ssl3', N15sslSessionIDStr5DOT_1555DOT_157E),
]
sslSessionIDStr._fields_ = [
    ('next', POINTER(sslSessionID)),
    ('peerCert', POINTER(CERTCertificate)),
    ('peerID', STRING),
    ('urlSvrName', STRING),
    ('localCert', POINTER(CERTCertificate)),
    ('addr', PRIPv6Addr),
    ('port', PRUint16),
    ('version', SSL3ProtocolVersion),
    ('creationTime', PRUint32),
    ('lastAccessTime', PRUint32),
    ('expirationTime', PRUint32),
    ('cached', Cached),
    ('references', c_int),
    ('authAlgorithm', SSLSignType),
    ('authKeyBits', PRUint32),
    ('keaType', SSLKEAType),
    ('keaKeyBits', PRUint32),
    ('u', N15sslSessionIDStr5DOT_155E),
]
class ssl3CipherSuiteDefStr(Structure):
    pass
ssl3CipherSuiteDefStr._fields_ = [
    ('cipher_suite', ssl3CipherSuite),
    ('bulk_cipher_alg', SSL3BulkCipher),
    ('mac_alg', SSL3MACAlgorithm),
    ('key_exchange_alg', SSL3KeyExchangeAlgorithm),
]
ssl3CipherSuiteDef = ssl3CipherSuiteDefStr
class ssl3KEADef(Structure):
    pass
ssl3KEADef._fields_ = [
    ('kea', SSL3KeyExchangeAlgorithm),
    ('exchKeyType', SSL3KEAType),
    ('signKeyType', SSL3SignType),
    ('is_limited', PRBool),
    ('key_size_limit', c_int),
    ('tls_keygen', PRBool),
]

# values for enumeration 'SSL3KeyGenMode'
SSL3KeyGenMode = c_int # enum

# values for enumeration 'SSLCipherAlgorithm'
SSLCipherAlgorithm = c_int # enum
ssl3BulkCipherDefStr._fields_ = [
    ('cipher', SSL3BulkCipher),
    ('calg', SSLCipherAlgorithm),
    ('key_size', c_int),
    ('secret_key_size', c_int),
    ('type', CipherType),
    ('iv_size', c_int),
    ('block_size', c_int),
    ('keygen_mode', SSL3KeyGenMode),
]
ssl3MACDefStr._fields_ = [
    ('mac', SSL3MACAlgorithm),
    ('mmech', CK_MECHANISM_TYPE),
    ('pad_size', c_int),
    ('mac_size', c_int),
]

# values for enumeration 'SSL3WaitState'
SSL3WaitState = c_int # enum
class TLSExtensionDataStr(Structure):
    pass
TLSExtensionData = TLSExtensionDataStr
class SessionTicketDataStr(Structure):
    pass
SessionTicketDataStr._fields_ = [
]
SessionTicketData = SessionTicketDataStr
TLSExtensionDataStr._fields_ = [
    ('serverSenders', ssl3HelloExtensionSender * 5),
    ('numAdvertised', PRUint16),
    ('numNegotiated', PRUint16),
    ('advertised', PRUint16 * 5),
    ('negotiated', PRUint16 * 5),
    ('ticketTimestampVerified', PRBool),
    ('emptySessionTicket', PRBool),
    ('sniNameArr', POINTER(SECItem)),
    ('sniNameArrSize', PRUint32),
]
class SSL3HandshakeStateStr(Structure):
    pass
class N21SSL3HandshakeStateStr5DOT_161E(Union):
    pass
N21SSL3HandshakeStateStr5DOT_161E._fields_ = [
    ('tFinished', TLSFinished * 2),
    ('sFinished', SSL3Hashes * 2),
    ('data', SSL3Opaque * 72),
]
SSL3HandshakeStateStr._pack_ = 4
SSL3HandshakeStateStr._fields_ = [
    ('server_random', SSL3Random),
    ('client_random', SSL3Random),
    ('ws', SSL3WaitState),
    ('md5_cx', PRUint64 * 50),
    ('sha_cx', PRUint64 * 50),
    ('md5', POINTER(PK11Context)),
    ('sha', POINTER(PK11Context)),
    ('kea_def', POINTER(ssl3KEADef)),
    ('cipher_suite', ssl3CipherSuite),
    ('suite_def', POINTER(ssl3CipherSuiteDef)),
    ('compression', SSLCompressionMethod),
    ('msg_body', sslBuffer),
    ('header_bytes', c_uint),
    ('msg_type', SSL3HandshakeType),
    ('msg_len', c_ulong),
    ('ca_list', SECItem),
    ('isResuming', PRBool),
    ('rehandshake', PRBool),
    ('usedStepDownKey', PRBool),
    ('sendingSCSV', PRBool),
    ('msgState', sslBuffer),
    ('messages', sslBuffer),
    ('finishedBytes', PRUint16),
    ('finishedMsgs', N21SSL3HandshakeStateStr5DOT_161E),
]
SSL3HandshakeState = SSL3HandshakeStateStr
class SECKEYPrivateKeyStr(Structure):
    pass
SECKEYPrivateKey = SECKEYPrivateKeyStr
class CERTDistNamesStr(Structure):
    pass
CERTDistNames = CERTDistNamesStr
ssl3StateStr._fields_ = [
    ('crSpec', POINTER(ssl3CipherSpec)),
    ('prSpec', POINTER(ssl3CipherSpec)),
    ('cwSpec', POINTER(ssl3CipherSpec)),
    ('pwSpec', POINTER(ssl3CipherSpec)),
    ('clientCertificate', POINTER(CERTCertificate)),
    ('clientPrivateKey', POINTER(SECKEYPrivateKey)),
    ('clientCertChain', POINTER(CERTCertificateList)),
    ('sendEmptyCert', PRBool),
    ('policy', c_int),
    ('peerCertArena', POINTER(PLArenaPool)),
    ('peerCertChain', c_void_p),
    ('ca_list', POINTER(CERTDistNames)),
    ('initialized', PRBool),
    ('hs', SSL3HandshakeState),
    ('specs', ssl3CipherSpec * 2),
]
class SSL3Ciphertext(Structure):
    pass
SSL3Ciphertext._fields_ = [
    ('type', SSL3ContentType),
    ('version', SSL3ProtocolVersion),
    ('buf', POINTER(sslBuffer)),
]
class SECKEYPublicKeyStr(Structure):
    pass
SECKEYPublicKey = SECKEYPublicKeyStr
ssl3KeyPairStr._fields_ = [
    ('privKey', POINTER(SECKEYPrivateKey)),
    ('pubKey', POINTER(SECKEYPublicKey)),
    ('refCount', PRInt32),
]
class SSLWrappedSymWrappingKeyStr(Structure):
    pass
SSLWrappedSymWrappingKeyStr._fields_ = [
    ('wrappedSymmetricWrappingkey', SSL3Opaque * 512),
    ('wrapIV', SSL3Opaque * 24),
    ('symWrapMechanism', CK_MECHANISM_TYPE),
    ('asymWrapMechanism', CK_MECHANISM_TYPE),
    ('exchKeyType', SSL3KEAType),
    ('symWrapMechIndex', PRInt32),
    ('wrappedSymKeyLen', PRUint16),
    ('wrapIVLen', PRUint16),
]
SSLWrappedSymWrappingKey = SSLWrappedSymWrappingKeyStr
class SessionTicketStr(Structure):
    pass
SessionTicketStr._fields_ = [
    ('ticket_version', uint16),
    ('ssl_version', SSL3ProtocolVersion),
    ('cipher_suite', ssl3CipherSuite),
    ('compression_method', SSLCompressionMethod),
    ('authAlgorithm', SSLSignType),
    ('authKeyBits', uint32),
    ('keaType', SSLKEAType),
    ('keaKeyBits', uint32),
    ('ms_is_wrapped', uint8),
    ('exchKeyType', SSLKEAType),
    ('msWrapMech', CK_MECHANISM_TYPE),
    ('ms_length', uint16),
    ('master_secret', SSL3Opaque * 48),
    ('client_identity', ClientIdentity),
    ('peer_cert', SECItem),
    ('timestamp', uint32),
    ('srvName', SECItem),
]
SessionTicket = SessionTicketStr
sslConnectInfoStr._fields_ = [
    ('sendBuf', sslBuffer),
    ('peer', PRIPv6Addr),
    ('port', c_ushort),
    ('sid', POINTER(sslSessionID)),
    ('elements', c_char),
    ('requiredElements', c_char),
    ('sentElements', c_char),
    ('sentFinished', c_char),
    ('serverChallengeLen', c_int),
    ('authType', c_ubyte),
    ('clientChallenge', c_ubyte * 32),
    ('connectionID', c_ubyte * 16),
    ('serverChallenge', c_ubyte * 32),
    ('readKey', c_ubyte * 64),
    ('writeKey', c_ubyte * 64),
    ('keySize', c_uint),
]
sslSecurityInfoStr._fields_ = [
    ('send', sslSendFunc),
    ('isServer', c_int),
    ('writeBuf', sslBuffer),
    ('cipherType', c_int),
    ('keyBits', c_int),
    ('secretKeyBits', c_int),
    ('localCert', POINTER(CERTCertificate)),
    ('peerCert', POINTER(CERTCertificate)),
    ('peerKey', POINTER(SECKEYPublicKey)),
    ('authAlgorithm', SSLSignType),
    ('authKeyBits', PRUint32),
    ('keaType', SSLKEAType),
    ('keaKeyBits', PRUint32),
    ('cache', sslSessionIDCacheFunc),
    ('uncache', sslSessionIDUncacheFunc),
    ('sendSequence', PRUint32),
    ('rcvSequence', PRUint32),
    ('hash', POINTER(SECHashObject)),
    ('hashcx', c_void_p),
    ('sendSecret', SECItem),
    ('rcvSecret', SECItem),
    ('readcx', c_void_p),
    ('writecx', c_void_p),
    ('enc', SSLCipher),
    ('dec', SSLCipher),
    ('destroy', CFUNCTYPE(None, c_void_p, PRBool)),
    ('blockShift', c_int),
    ('blockSize', c_int),
    ('ci', sslConnectInfo),
]
SSLAuthCertificate = CFUNCTYPE(SECStatus, c_void_p, POINTER(PRFileDesc), PRBool, PRBool)
SSLGetClientAuthData = CFUNCTYPE(SECStatus, c_void_p, POINTER(PRFileDesc), POINTER(CERTDistNames), POINTER(POINTER(CERTCertificate)), POINTER(POINTER(SECKEYPrivateKey)))
SSLSNISocketConfig = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), POINTER(SECItem), PRUint32, c_void_p)
SSLBadCertHandler = CFUNCTYPE(SECStatus, c_void_p, POINTER(PRFileDesc))
SSLHandshakeCallback = CFUNCTYPE(None, POINTER(PRFileDesc), c_void_p)
PRIntervalTime = PRUint32
class nssRWLockStr(Structure):
    pass
NSSRWLock = nssRWLockStr
class PRThread(Structure):
    pass
sslSocketStr._fields_ = [
    ('fd', POINTER(PRFileDesc)),
    ('ops', POINTER(sslSocketOps)),
    ('opt', sslOptions),
    ('clientAuthRequested', c_ulong),
    ('delayDisabled', c_ulong),
    ('firstHsDone', c_ulong),
    ('handshakeBegun', c_ulong),
    ('lastWriteBlocked', c_ulong),
    ('recvdCloseNotify', c_ulong),
    ('TCPconnected', c_ulong),
    ('appDataBuffered', c_ulong),
    ('peerRequestedProtection', c_ulong),
    ('version', SSL3ProtocolVersion),
    ('clientHelloVersion', SSL3ProtocolVersion),
    ('sec', sslSecurityInfo),
    ('url', STRING),
    ('handshake', sslHandshakeFunc),
    ('nextHandshake', sslHandshakeFunc),
    ('securityHandshake', sslHandshakeFunc),
    ('peerID', STRING),
    ('cipherSpecs', POINTER(c_ubyte)),
    ('sizeCipherSpecs', c_uint),
    ('preferredCipher', POINTER(c_ubyte)),
    ('stepDownKeyPair', POINTER(ssl3KeyPair)),
    ('authCertificate', SSLAuthCertificate),
    ('authCertificateArg', c_void_p),
    ('getClientAuthData', SSLGetClientAuthData),
    ('getClientAuthDataArg', c_void_p),
    ('sniSocketConfig', SSLSNISocketConfig),
    ('sniSocketConfigArg', c_void_p),
    ('handleBadCert', SSLBadCertHandler),
    ('badCertArg', c_void_p),
    ('handshakeCallback', SSLHandshakeCallback),
    ('handshakeCallbackData', c_void_p),
    ('pkcs11PinArg', c_void_p),
    ('rTimeout', PRIntervalTime),
    ('wTimeout', PRIntervalTime),
    ('cTimeout', PRIntervalTime),
    ('recvLock', POINTER(PRLock)),
    ('sendLock', POINTER(PRLock)),
    ('recvBufLock', POINTER(PRMonitor)),
    ('xmitBufLock', POINTER(PRMonitor)),
    ('firstHandshakeLock', POINTER(PRMonitor)),
    ('ssl3HandshakeLock', POINTER(PRMonitor)),
    ('specLock', POINTER(NSSRWLock)),
    ('dbHandle', POINTER(CERTCertDBHandle)),
    ('writerThread', POINTER(PRThread)),
    ('shutdownHow', PRUint16),
    ('allowedByPolicy', PRUint16),
    ('maybeAllowedByPolicy', PRUint16),
    ('chosenPreference', PRUint16),
    ('handshaking', sslHandshakingType),
    ('gs', sslGather),
    ('saveBuf', sslBuffer),
    ('pendingBuf', sslBuffer),
    ('serverCerts', sslServerCerts * 5),
    ('cipherSuites', ssl3CipherSuiteCfg * 30),
    ('ephemeralECDHKeyPair', POINTER(ssl3KeyPair)),
    ('ssl3', ssl3State),
    ('statelessResume', PRBool),
    ('xtnData', TLSExtensionData),
]
SECMOD_SHA256_FLAG = 16384 # Variable c_long '16384l'
AI_CANONIDN = 128 # Variable c_int '128'
SO_RCVBUF = 8 # Variable c_int '8'
PR_READ_ONLY_FILESYSTEM_ERROR = -5948 # Variable c_long '-0x00000173cl'
PR_FILESYSTEM_MOUNTED_ERROR = -5946 # Variable c_long '-0x00000173al'
CKM_CONCATENATE_DATA_AND_BASE = 867 # Variable c_int '867'
SECMOD_SSL_FLAG = 2048 # Variable c_long '2048l'
CKR_TOKEN_NOT_PRESENT = 224 # Variable c_int '224'
SEC_ASN1_CONSTRUCTED = 32 # Variable c_int '32'
CKM_SEED_MAC_GENERAL = 1620 # Variable c_int '1620'
CKM_DSA_PARAMETER_GEN = 8192 # Variable c_int '8192'
EAI_AGAIN = -3 # Variable c_int '-0x000000003'
CKM_JUNIPER_CBC128 = 4194 # Variable c_int '4194'
CKM_PBE_SHA1_CAST128_CBC = 933 # Variable c_int '933'
CKM_PBE_MD5_CAST3_CBC = 931 # Variable c_int '931'
SO_OOBINLINE = 10 # Variable c_int '10'
SSL_ERROR_LIMIT = -11288 # Variable c_int '-0x000002c18'
CKR_KEY_NOT_WRAPPABLE = 105 # Variable c_int '105'
SSL_RENEGOTIATE_NEVER = 0 # Variable c_int '0'
_POSIX_THREAD_PRIO_PROTECT = 200809 # Variable c_long '200809l'
ssl_SEND_FLAG_FORCE_INTO_BUFFER = 1073741824 # Variable c_int '1073741824'
PR_IS_CONNECTED_ERROR = -5984 # Variable c_long '-0x000001760l'
CKT_NSS = 3461563216L # Variable c_uint '-833404080u'
CKF_EC_UNCOMPRESS = 16777216 # Variable c_int '16777216'
LL_MAXUINT = 18446744073709551615L # Variable c_ulonglong '0xffffffffffffffffull'
CKM_BATON_WRAP = 4150 # Variable c_int '4150'
CKK_X9_42_DH = 4 # Variable c_int '4'
NI_IDN = 32 # Variable c_int '32'
CKK_DH = 2 # Variable c_int '2'
CKM_SHA_1_HMAC = 545 # Variable c_int '545'
CKA_PIXEL_Y = 1025 # Variable c_int '1025'
CRL_DECODE_DEFAULT_OPTIONS = 0 # Variable c_int '0'
SEC_CERT_CLASS_USER = 3 # Variable c_int '3'
CKR_DATA_INVALID = 32 # Variable c_int '32'
SECMOD_RC2_FLAG = 4 # Variable c_long '4l'
CKM_RC2_MAC_GENERAL = 260 # Variable c_int '260'
SSL_V2_COMPATIBLE_HELLO = 12 # Variable c_int '12'
_IO_SHOWBASE = 128 # Variable c_int '128'
CKA_RESOLUTION = 1026 # Variable c_int '1026'
EXPORT_KEY_LENGTH = 5 # Variable c_int '5'
DER_BOOLEAN = 1 # Variable c_int '1'
CKF_SERIAL_SESSION = 4 # Variable c_int '4'
_POSIX_RAW_SOCKETS = 200809 # Variable c_long '200809l'
CKM_SEED_CBC_ENCRYPT_DATA = 1623 # Variable c_int '1623'
SEC_ASN1_PRINTABLE_STRING = 19 # Variable c_int '19'
CKM_SHA256 = 592 # Variable c_int '592'
IPV6_RTHDR = 57 # Variable c_int '57'
CKA_TRUST_EMAIL_PROTECTION = 3461571419L # Variable c_uint '-833395877u'
CERT_MAX_DN_BYTES = 4096 # Variable c_int '4096'
IPV6_PMTUDISC_DO = 2 # Variable c_int '2'
SSL_REQUIRE_FIRST_HANDSHAKE = 2 # Variable c_int '2'
CKM_KEA_KEY_DERIVE = 4113 # Variable c_int '4113'
PR_HOST_UNREACHABLE_ERROR = -5927 # Variable c_long '-0x000001727l'
CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC = 2147483652L # Variable c_ulong '-2147483644ul'
_IO_DEC = 16 # Variable c_int '16'
SSL_MAX_CACHED_CERT_LEN = 4060 # Variable c_int '4060'
SSL_MAX_MASTER_KEY_BYTES = 64 # Variable c_int '64'
PK11_ATTR_SESSION = 2 # Variable c_long '2l'
CKA_MIME_TYPES = 1154 # Variable c_int '1154'
SECKEY_Attributes_Cached = 1 # Variable c_int '1'
CKK_SEED = 38 # Variable c_int '38'
_POSIX_VERSION = 200809 # Variable c_long '200809l'
CKO_HW_FEATURE = 5 # Variable c_int '5'
NI_IDN_ALLOW_UNASSIGNED = 64 # Variable c_int '64'
IP_PKTINFO = 8 # Variable c_int '8'
CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC = 2147483653L # Variable c_ulong '-2147483643ul'
CKM_RIPEMD128_HMAC = 561 # Variable c_int '561'
CKA_VERIFY = 266 # Variable c_int '266'
PR_INT16_MAX = 32767 # Variable c_int '32767'
R_OK = 4 # Variable c_int '4'
_IO_BOOLALPHA = 65536 # Variable c_int '65536'
PR_TPD_RANGE_ERROR = -5972 # Variable c_long '-0x000001754l'
PR_CONNECT_RESET_ERROR = -5961 # Variable c_long '-0x000001749l'
SYS_INFO_BUFFER_LENGTH = 256 # Variable c_int '256'
PR_TRUE = 1 # Variable c_int '1'
CKF_VERIFY = 8192 # Variable c_int '8192'
SEC_ASN1_DEBUG_BREAK = 4194304 # Variable c_int '4194304'
CKS_RO_USER_FUNCTIONS = 1 # Variable c_int '1'
PK11_ATTR_EXTRACTABLE = 256 # Variable c_long '256l'
EXT_KEY_USAGE_STATUS_RESPONDER = 16384 # Variable c_int '16384'
CKM_BATON_KEY_GEN = 4144 # Variable c_int '4144'
CKR_KEY_PARAMS_INVALID = 107 # Variable c_int '107'
CKM_DSA_SHA1 = 18 # Variable c_int '18'
_XOPEN_SOURCE = 700 # Variable c_int '700'
_UNISTD_H = 1 # Variable c_int '1'
CKG_MGF1_SHA512 = 4 # Variable c_int '4'
CKF_GENERATE = 32768 # Variable c_int '32768'
IN_CLASSA_MAX = 128 # Variable c_int '128'
PR_MSEC_PER_SEC = 1000L # Variable c_ulong '1000ul'
SO_SECURITY_ENCRYPTION_NETWORK = 24 # Variable c_int '24'
__GLIBC__ = 2 # Variable c_int '2'
_XLOCALE_H = 1 # Variable c_int '1'
CKM_AES_CBC = 4226 # Variable c_int '4226'
CKH_MONOTONIC_COUNTER = 1 # Variable c_int '1'
CKM_SKIPJACK_OFB64 = 4099 # Variable c_int '4099'
PR_IWGRP = 16 # Variable c_int '16'
_IONBF = 2 # Variable c_int '2'
CKR_BUFFER_TOO_SMALL = 336 # Variable c_int '336'
_BITS_UIO_H = 1 # Variable c_int '1'
__USE_POSIX2 = 1 # Variable c_int '1'
CKA_ALWAYS_SENSITIVE = 357 # Variable c_int '357'
IPV6_RECVRTHDR = 56 # Variable c_int '56'
_PATH_SERVICES = '/etc/services' # Variable STRING '(const char*)"/etc/services"'
SSL_BYPASS_PKCS11 = 16 # Variable c_int '16'
NS_CERT_TYPE_SSL_SERVER = 64 # Variable c_int '64'
CKM_MD2_HMAC_GENERAL = 514 # Variable c_int '514'
PR_MAX_ERROR = -5924 # Variable c_long '-0x000001724l'
MD2_LENGTH = 16 # Variable c_int '16'
CKR_MECHANISM_PARAM_INVALID = 113 # Variable c_int '113'
CKM_SEED_MAC = 1619 # Variable c_int '1619'
IP_MAX_MEMBERSHIPS = 20 # Variable c_int '20'
CKM_SEED_ECB_ENCRYPT_DATA = 1622 # Variable c_int '1622'
CKF_RNG = 1 # Variable c_int '1'
SEC_ASN1_NULL = 5 # Variable c_int '5'
CKA_HAS_RESET = 770 # Variable c_int '770'
EAI_FAIL = -4 # Variable c_int '-0x000000004'
IP_RECVOPTS = 6 # Variable c_int '6'
PR_UINT16_MAX = 65535L # Variable c_uint '65535u'
IP_PMTUDISC_WANT = 1 # Variable c_int '1'
TLS_EX_SESS_TICKET_LIFETIME_HINT = 172800 # Variable c_int '172800'
PR_END_OF_FILE_ERROR = -5938 # Variable c_long '-0x000001732l'
EAI_FAMILY = -6 # Variable c_int '-0x000000006'
_POSIX_SOURCE = 1 # Variable c_int '1'
__ILP32_OFFBIG_CFLAGS = '-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64' # Variable STRING '(const char*)"-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64"'
IPV6_RTHDR_STRICT = 1 # Variable c_int '1'
DER_ANY = 1024 # Variable c_int '1024'
HT_ENUMERATE_REMOVE = 2 # Variable c_int '2'
SEC_ASN1_OBJECT_DESCRIPTOR = 7 # Variable c_int '7'
IP_MULTICAST_LOOP = 34 # Variable c_int '34'
_POSIX_FSYNC = 200809 # Variable c_long '200809l'
PR_INVALID_IO_LAYER = -1 # Variable c_int '-0x000000001'
CKA_ISSUER = 129 # Variable c_int '129'
CKD_NULL = 1 # Variable c_int '1'
CKM_RSA_X_509 = 3 # Variable c_int '3'
SO_DEBUG = 1 # Variable c_int '1'
SSL_SECURITY = 1 # Variable c_int '1'
PR_NO_MORE_FILES_ERROR = -5939 # Variable c_long '-0x000001733l'
CKA_SIGN_RECOVER = 265 # Variable c_int '265'
CKM_RC5_MAC = 819 # Variable c_int '819'
SIOCGSTAMPNS = 35079 # Variable c_int '35079'
CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN = 2147483658L # Variable c_ulong '-2147483638ul'
PR_NOT_DIRECTORY_ERROR = -5949 # Variable c_long '-0x00000173dl'
CKR_KEY_TYPE_INCONSISTENT = 99 # Variable c_int '99'
IPV6_2292PKTOPTIONS = 6 # Variable c_int '6'
CKM_PBE_MD5_CAST_CBC = 930 # Variable c_int '930'
CKM_SHA224 = 597 # Variable c_int '597'
_PATH_HOSTS = '/etc/hosts' # Variable STRING '(const char*)"/etc/hosts"'
CKM_SEED_CBC_PAD = 1621 # Variable c_int '1621'
CKK_EC = 3 # Variable c_int '3'
CKA_PIXEL_X = 1024 # Variable c_int '1024'
CKA_TRUST_DIGITAL_SIGNATURE = 3461571409L # Variable c_uint '-833395887u'
__STDC_ISO_10646__ = 200009 # Variable c_long '200009l'
CKM_GENERIC_SECRET_KEY_GEN = 848 # Variable c_int '848'
_IO_TIED_PUT_GET = 1024 # Variable c_int '1024'
SSL_MIN_MASTER_KEY_BYTES = 5 # Variable c_int '5'
CKC_NSS = 3461563216L # Variable c_uint '-833404080u'
CKM_RIPEMD128 = 560 # Variable c_int '560'
CKM_MD2_KEY_DERIVATION = 913 # Variable c_int '913'
_IOS_INPUT = 1 # Variable c_int '1'
_BITS_TYPES_H = 1 # Variable c_int '1'
IP_DEFAULT_MULTICAST_LOOP = 1 # Variable c_int '1'
__have_sigevent_t = 1 # Variable c_int '1'
CKK_DES = 19 # Variable c_int '19'
CKF_ENCRYPT = 256 # Variable c_int '256'
PR_DIRECTORY_NOT_EMPTY_ERROR = -5947 # Variable c_long '-0x00000173bl'
PK11_DISABLE_FLAG = 1073741824 # Variable c_long '1073741824l'
CKM_PBE_MD5_DES_CBC = 929 # Variable c_int '929'
INADDR_ALLHOSTS_GROUP = 3758096385L # Variable c_uint '-536870911u'
_IOS_ATEND = 4 # Variable c_int '4'
SECMOD_RC4_FLAG = 8 # Variable c_long '8l'
PK11_ATTR_SENSITIVE = 64 # Variable c_long '64l'
SECMOD_DH_FLAG = 32 # Variable c_long '32l'
_XOPEN_LEGACY = 1 # Variable c_int '1'
DER_APPLICATION = 64 # Variable c_int '64'
CKA_PRIVATE_EXPONENT = 291 # Variable c_int '291'
MAX_PADDING_LENGTH = 64 # Variable c_int '64'
PR_OPERATION_NOT_SUPPORTED_ERROR = -5965 # Variable c_long '-0x00000174dl'
_POSIX_SAVED_IDS = 1 # Variable c_int '1'
CKC_X_509_ATTR_CERT = 1 # Variable c_int '1'
CKA_ATTR_TYPES = 133 # Variable c_int '133'
DER_OPTIONAL = 256 # Variable c_int '256'
__GNU_LIBRARY__ = 6 # Variable c_int '6'
_BITS_TYPESIZES_H = 1 # Variable c_int '1'
SSL_REQUIRE_NO_ERROR = 3 # Variable c_int '3'
SEC_ASN1_METHOD_MASK = 32 # Variable c_int '32'
SEC_ASN1_DEFAULT_ARENA_SIZE = 2048 # Variable c_int '2048'
PR_INVALID_DEVICE_STATE_ERROR = -5941 # Variable c_long '-0x000001735l'
PR_DEADLOCK_ERROR = -5959 # Variable c_long '-0x000001747l'
CKR_DEVICE_REMOVED = 50 # Variable c_int '50'
PR_FILE_IS_BUSY_ERROR = -5936 # Variable c_long '-0x000001730l'
CKA_SERIAL_NUMBER = 130 # Variable c_int '130'
NS_CERT_TYPE_APP = 240 # Variable c_int '240'
IPV6_MULTICAST_IF = 17 # Variable c_int '17'
CKR_KEY_CHANGED = 101 # Variable c_int '101'
SECMOD_MODULE_DB_FUNCTION_FIND = 0 # Variable c_int '0'
certificateUsageSSLCA = 8 # Variable c_int '8'
_POSIX_TRACE = -1 # Variable c_int '-0x000000001'
IP_DROP_SOURCE_MEMBERSHIP = 40 # Variable c_int '40'
PR_NOT_SAME_DEVICE_ERROR = -5945 # Variable c_long '-0x000001739l'
SSL_RESTRICTED = 2 # Variable c_int '2'
PR_FILEMAP_STRING_BUFSIZE = 128 # Variable c_int '128'
CKA_TRUST_TIME_STAMPING = 3461571423L # Variable c_uint '-833395873u'
KU_CRL_SIGN = 2 # Variable c_int '2'
CKM_INVALID_MECHANISM = 4294967295L # Variable c_ulong '-1ul'
SEC_ASN1_BMP_STRING = 30 # Variable c_int '30'
CKA_CHAR_SETS = 1152 # Variable c_int '1152'
IP_FREEBIND = 15 # Variable c_int '15'
IPV6_PKTINFO = 50 # Variable c_int '50'
SEC_CERTIFICATE_VERSION_2 = 1 # Variable c_int '1'
SEC_CERTIFICATE_VERSION_3 = 2 # Variable c_int '2'
SEC_CERTIFICATE_VERSION_1 = 0 # Variable c_int '0'
_POSIX_CLOCK_SELECTION = 200809 # Variable c_long '200809l'
PR_WRONLY = 2 # Variable c_int '2'
_POSIX_THREAD_PRIO_INHERIT = 200809 # Variable c_long '200809l'
CKM_SHA512_HMAC = 625 # Variable c_int '625'
PR_ADDRESS_IN_USE_ERROR = -5982 # Variable c_long '-0x00000175el'
TLS_EX_SESS_TICKET_VERSION = 256 # Variable c_int '256'
DER_OBJECT_ID = 6 # Variable c_int '6'
_POSIX_THREAD_SAFE_FUNCTIONS = 200809 # Variable c_long '200809l'
NI_NUMERICHOST = 1 # Variable c_int '1'
PR_FILE_SEEK_ERROR = -5937 # Variable c_long '-0x000001731l'
PL_HASH_BITS = 32 # Variable c_int '32'
MAX_CIPHER_CONTEXT_LLONGS = 260 # Variable c_int '260'
DER_SET = 17 # Variable c_int '17'
SSL_SNI_CURRENT_CONFIG_IS_USED = -1 # Variable c_int '-0x000000001'
SSL_HANDSHAKE_AS_SERVER = 6 # Variable c_int '6'
SOL_DECNET = 261 # Variable c_int '261'
SSL_SECURITY_STATUS_FORTEZZA = 3 # Variable c_int '3'
_IO_HEX = 64 # Variable c_int '64'
PR_AI_ALL = 8 # Variable c_int '8'
CKA_MODIFIABLE = 368 # Variable c_int '368'
WNOHANG = 1 # Variable c_int '1'
_IO_SKIPWS = 1 # Variable c_int '1'
SEC_ASN1_BIT_STRING = 3 # Variable c_int '3'
FILENAME_MAX = 4096 # Variable c_int '4096'
CKM_CAST128_ECB = 801 # Variable c_int '801'
EXIT_SUCCESS = 0 # Variable c_int '0'
SSL3_RECORD_HEADER_LENGTH = 5 # Variable c_int '5'
CKM_TLS_KEY_AND_MAC_DERIVE = 886 # Variable c_int '886'
DER_METHOD_MASK = 32 # Variable c_int '32'
CKR_ARGUMENTS_BAD = 7 # Variable c_int '7'
CKM_SSL3_MASTER_KEY_DERIVE = 881 # Variable c_int '881'
HT_ENUMERATE_UNHASH = 4 # Variable c_int '4'
certificateUsageVerifyCA = 256 # Variable c_int '256'
CKR_DEVICE_MEMORY = 49 # Variable c_int '49'
CKM_RSA_PKCS = 1 # Variable c_int '1'
PR_UNLOAD_LIBRARY_ERROR = -5976 # Variable c_long '-0x000001758l'
CKA_COEFFICIENT = 296 # Variable c_int '296'
CKM_TLS_PRF = 888 # Variable c_int '888'
PR_IO_TIMEOUT_ERROR = -5990 # Variable c_long '-0x000001766l'
_IO_SCIENTIFIC = 2048 # Variable c_int '2048'
SO_SECURITY_AUTHENTICATION = 22 # Variable c_int '22'
CRL_IMPORT_DEFAULT_OPTIONS = 0 # Variable c_int '0'
CKM_BATON_CBC128 = 4147 # Variable c_int '4147'
SEC_ASN1_SKIP = 32768 # Variable c_int '32768'
SSL_REQUIRE_ALWAYS = 1 # Variable c_int '1'
_POSIX_BARRIERS = 200809 # Variable c_long '200809l'
__SIZEOF_PTHREAD_ATTR_T = 36 # Variable c_int '36'
SO_PROTOCOL = 38 # Variable c_int '38'
certificateUsageEmailSigner = 16 # Variable c_int '16'
CKM_RC2_KEY_GEN = 256 # Variable c_int '256'
PR_VMINOR = 8 # Variable c_int '8'
CKN_SURRENDER = 0 # Variable c_int '0'
SEC_ERROR_BASE = -8192 # Variable c_int '-0x000002000'
CKK_RC2 = 17 # Variable c_int '17'
MCAST_UNBLOCK_SOURCE = 44 # Variable c_int '44'
CKK_RC4 = 18 # Variable c_int '18'
CKK_RC5 = 25 # Variable c_int '25'
PR_SHM_CREATE = 1 # Variable c_int '1'
CKH_USER_INTERFACE = 3 # Variable c_int '3'
__USE_XOPEN2KXSI = 1 # Variable c_int '1'
AI_NUMERICHOST = 4 # Variable c_int '4'
PR_NOT_CONNECTED_ERROR = -5978 # Variable c_long '-0x00000175al'
CKM_FORTEZZA_TIMESTAMP = 4128 # Variable c_int '4128'
ssl_SHUTDOWN_SEND = 2 # Variable c_int '2'
__USE_XOPEN2K8 = 1 # Variable c_int '1'
EXPORT_RSA_KEY_LENGTH = 64 # Variable c_int '64'
RAND_MAX = 2147483647 # Variable c_int '2147483647'
CKA_DERIVE = 268 # Variable c_int '268'
SECMOD_TLS_FLAG = 4096 # Variable c_long '4096l'
PR_FIND_SYMBOL_ERROR = -5975 # Variable c_long '-0x000001757l'
SSL_RENEGOTIATE_REQUIRES_XTN = 2 # Variable c_int '2'
__STDC_IEC_559__ = 1 # Variable c_int '1'
CKA_ECDSA_PARAMS = 384 # Variable c_int '384'
SECMOD_RANDOM_FLAG = 2147483648L # Variable c_ulong '-2147483648ul'
CKM_X9_42_DH_PARAMETER_GEN = 8194 # Variable c_int '8194'
PR_POLL_WRITE = 2 # Variable c_int '2'
SO_PEERSEC = 31 # Variable c_int '31'
MCAST_BLOCK_SOURCE = 43 # Variable c_int '43'
PR_NOT_IMPLEMENTED_ERROR = -5992 # Variable c_long '-0x000001768l'
CKM_CAMELLIA_KEY_GEN = 1360 # Variable c_int '1360'
_ISOC99_SOURCE = 1 # Variable c_int '1'
CKK_ECDSA = 3 # Variable c_int '3'
CKM_CMS_SIG = 1280 # Variable c_int '1280'
KU_DATA_ENCIPHERMENT = 16 # Variable c_int '16'
DER_UNIVERSAL = 0 # Variable c_int '0'
PR_WOULD_BLOCK_ERROR = -5998 # Variable c_long '-0x00000176el'
SSL_REQUIRE_NEVER = 0 # Variable c_int '0'
CKM_AES_CBC_PAD = 4229 # Variable c_int '4229'
_IO_MAGIC = 4222418944L # Variable c_uint '-72548352u'
IP_PKTOPTIONS = 9 # Variable c_int '9'
EAI_ADDRFAMILY = -9 # Variable c_int '-0x000000009'
certificateUsageObjectSigner = 64 # Variable c_int '64'
__timer_t_defined = 1 # Variable c_int '1'
_IO_FIXED = 4096 # Variable c_int '4096'
CKA_DECRYPT = 261 # Variable c_int '261'
CKM_SHA512_RSA_PKCS = 66 # Variable c_int '66'
CKM_KEA_KEY_PAIR_GEN = 4112 # Variable c_int '4112'
NS_CERT_TYPE_EMAIL = 32 # Variable c_int '32'
CKA_MODULUS_BITS = 289 # Variable c_int '289'
PR_FILE_EXISTS_ERROR = -5943 # Variable c_long '-0x000001737l'
SO_RXQ_OVFL = 40 # Variable c_int '40'
CKS_RO_PUBLIC_SESSION = 0 # Variable c_int '0'
CKM_SHA384_HMAC = 609 # Variable c_int '609'
PR_RWLOCK_RANK_NONE = 0 # Variable c_int '0'
_BITS_SOCKADDR_H = 1 # Variable c_int '1'
SEC_ASN1_GENERAL_STRING = 27 # Variable c_int '27'
_POSIX2_CHAR_TERM = 200809 # Variable c_long '200809l'
_IO_IN_BACKUP = 256 # Variable c_int '256'
CKA_AUTH_PIN_FLAGS = 513 # Variable c_int '513'
CERT_REV_M_ALLOW_NETWORK_FETCHING = 0 # Variable c_long '0l'
_SIGSET_H_types = 1 # Variable c_int '1'
CKM_PBA_SHA1_WITH_SHA1_HMAC = 960 # Variable c_int '960'
CERT_REV_M_FAIL_ON_MISSING_FRESH_INFO = 16 # Variable c_long '16l'
_G_HAVE_BOOL = 1 # Variable c_int '1'
PR_NOT_TCP_SOCKET_ERROR = -5968 # Variable c_long '-0x000001750l'
_POSIX_CPUTIME = 0 # Variable c_int '0'
CKA_CERT_SHA1_HASH = 3461571508L # Variable c_uint '-833395788u'
EAI_INTR = -104 # Variable c_int '-0x000000068'
CKF_OS_LOCKING_OK = 2 # Variable c_int '2'
CKM_CAST3_ECB = 785 # Variable c_int '785'
CKM_SEED_KEY_GEN = 1616 # Variable c_int '1616'
CKM_CAST128_CBC = 802 # Variable c_int '802'
_POSIX_SPAWN = 200809 # Variable c_long '200809l'
PK11_ATTR_PUBLIC = 8 # Variable c_long '8l'
PR_NSEC_PER_SEC = 1000000000L # Variable c_ulong '1000000000ul'
CKF_USER_PIN_COUNT_LOW = 65536 # Variable c_int '65536'
PK11_PW_RETRY = 'RETRY' # Variable STRING '(const char*)"RETRY"'
CK_TRUE = 1 # Variable c_int '1'
_ENDIAN_H = 1 # Variable c_int '1'
CKO_PRIVATE_KEY = 3 # Variable c_int '3'
CKM_SHA1_RSA_PKCS_PSS = 14 # Variable c_int '14'
_POSIX_TIMEOUTS = 200809 # Variable c_long '200809l'
SEC_ASN1_HIGH_TAG_NUMBER = 31 # Variable c_int '31'
PR_LD_NOW = 2 # Variable c_int '2'
SEC_ASN1_TAG_MASK = 255 # Variable c_int '255'
SEC_ASN1_XTRN = 0 # Variable c_int '0'
PR_REMOTE_FILE_ERROR = -5963 # Variable c_long '-0x00000174bl'
PR_MSG_PEEK = 2 # Variable c_int '2'
STDOUT_FILENO = 1 # Variable c_int '1'
SOL_X25 = 262 # Variable c_int '262'
MCAST_JOIN_GROUP = 42 # Variable c_int '42'
TLS_STE_NO_SERVER_NAME = -1 # Variable c_int '-0x000000001'
__SIZEOF_PTHREAD_RWLOCKATTR_T = 8 # Variable c_int '8'
CKK_KEA = 5 # Variable c_int '5'
_LARGEFILE64_SOURCE = 1 # Variable c_int '1'
CKM_MD5 = 528 # Variable c_int '528'
CKM_MD2 = 512 # Variable c_int '512'
EAI_CANCELED = -101 # Variable c_int '-0x000000065'
MAX_MAC_CONTEXT_LLONGS = 50 # Variable c_int '50'
CKK_BATON = 28 # Variable c_int '28'
SO_DOMAIN = 39 # Variable c_int '39'
DER_CLASS_MASK = 192 # Variable c_int '192'
CKM_RIPEMD128_HMAC_GENERAL = 562 # Variable c_int '562'
_LFS64_ASYNCHRONOUS_IO = 1 # Variable c_int '1'
SO_PASSSEC = 34 # Variable c_int '34'
CKM_MD2_RSA_PKCS = 4 # Variable c_int '4'
SEC_ASN1_UNIVERSAL_STRING = 28 # Variable c_int '28'
SIOCSPGRP = 35074 # Variable c_int '35074'
CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN = 2147483659L # Variable c_ulong '-2147483637ul'
SSL_MIN_CYPHER_ARG_BYTES = 0 # Variable c_int '0'
SO_PASSCRED = 16 # Variable c_int '16'
CKM_RSA_PKCS_OAEP = 9 # Variable c_int '9'
CERT_REV_MI_REQUIRE_SOME_FRESH_INFO_AVAILABLE = 2 # Variable c_long '2l'
KU_KEY_ENCIPHERMENT = 32 # Variable c_int '32'
PR_DIRECTORY_CORRUPTED_ERROR = -5944 # Variable c_long '-0x000001738l'
SSL_ENABLE_TLS = 13 # Variable c_int '13'
CKA_UNWRAP_TEMPLATE = 1073742354 # Variable c_int '1073742354'
_G_HAVE_SYS_CDEFS = 1 # Variable c_int '1'
CKA_ENCRYPT = 260 # Variable c_int '260'
CKM_SHA256_HMAC = 593 # Variable c_int '593'
CKM_ECDSA = 4161 # Variable c_int '4161'
CKR_UNWRAPPING_KEY_SIZE_RANGE = 241 # Variable c_int '241'
SOL_AAL = 265 # Variable c_int '265'
PR_LD_ALT_SEARCH_PATH = 16 # Variable c_int '16'
SECMOD_MD5_FLAG = 512 # Variable c_long '512l'
__mbstate_t_defined = 1 # Variable c_int '1'
IPV6_ADDRFORM = 1 # Variable c_int '1'
KU_ENCIPHER_ONLY = 1 # Variable c_int '1'
__time_t_defined = 1 # Variable c_int '1'
CKM_PBE_SHA1_RC2_40_CBC = 939 # Variable c_int '939'
CKR_MUTEX_BAD = 416 # Variable c_int '416'
SEC_ASN1_OBJECT_ID = 6 # Variable c_int '6'
SEC_ASN1_REAL = 9 # Variable c_int '9'
CKM_RSA_9796 = 2 # Variable c_int '2'
SEC_ERROR_LIMIT = -7192 # Variable c_int '-0x000001c18'
IPV6_HOPLIMIT = 52 # Variable c_int '52'
CKM_DES3_MAC = 308 # Variable c_int '308'
CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = 980 # Variable c_int '980'
_IO_UNIFIED_JUMPTABLES = 1 # Variable c_int '1'
SO_BROADCAST = 6 # Variable c_int '6'
LL_MININT = -9223372036854775808L # Variable c_longlong '-0x8000000000000000ll'
CKM_MD5_HMAC_GENERAL = 530 # Variable c_int '530'
PR_AI_NOCANONNAME = 32768 # Variable c_int '32768'
CKM_RC2_CBC_PAD = 261 # Variable c_int '261'
CKM_DH_PKCS_PARAMETER_GEN = 8193 # Variable c_int '8193'
_G_HAVE_MMAP = 1 # Variable c_int '1'
CKM_WTLS_MASTER_KEY_DERIVE = 977 # Variable c_int '977'
_XOPEN_REALTIME = 1 # Variable c_int '1'
SSL_SNI_SEND_ALERT = -2 # Variable c_int '-0x000000002'
SO_NO_CHECK = 11 # Variable c_int '11'
SECMOD_MODULE_DB_FUNCTION_DEL = 2 # Variable c_int '2'
CKK_CAST5 = 24 # Variable c_int '24'
SECMOD_WAIT_PKCS11_EVENT = 4 # Variable c_int '4'
CIS_HAVE_MASTER_KEY = 1 # Variable c_int '1'
CKR_KEY_SIZE_RANGE = 98 # Variable c_int '98'
IPV6_RTHDR_LOOSE = 0 # Variable c_int '0'
_LARGEFILE_SOURCE = 1 # Variable c_int '1'
IP_MTU = 14 # Variable c_int '14'
GS_DATA = 3 # Variable c_int '3'
PR_NO_ACCESS_RIGHTS_ERROR = -5966 # Variable c_long '-0x00000174el'
SEC_ASN1_TAGNUM_MASK = 31 # Variable c_int '31'
_POSIX_ASYNC_IO = 1 # Variable c_int '1'
PK11_ATTR_INSENSITIVE = 128 # Variable c_long '128l'
CKA_START_DATE = 272 # Variable c_int '272'
CKR_KEY_UNEXTRACTABLE = 106 # Variable c_int '106'
CKA_EC_PARAMS = 384 # Variable c_int '384'
PR_LANGUAGE_EN = 1 # Variable c_int '1'
CKF_GENERATE_KEY_PAIR = 65536 # Variable c_int '65536'
PR_LOAD_LIBRARY_ERROR = -5977 # Variable c_long '-0x000001759l'
_IOS_TRUNC = 16 # Variable c_int '16'
NI_NOFQDN = 4 # Variable c_int '4'
PR_APPEND = 16 # Variable c_int '16'
CKM_BATON_ECB96 = 4146 # Variable c_int '4146'
FIOGETOWN = 35075 # Variable c_int '35075'
SECMOD_SHA1_FLAG = 256 # Variable c_long '256l'
CKA_NETSCAPE_TRUST = 2147483649L # Variable c_ulong '-2147483647ul'
SESS_TICKET_KEY_NAME_PREFIX = 'NSS!' # Variable STRING '(const char*)"NSS!"'
CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 138 # Variable c_int '138'
CKR_HOST_MEMORY = 2 # Variable c_int '2'
__WALL = 1073741824 # Variable c_int '1073741824'
_IO_UNITBUF = 8192 # Variable c_int '8192'
CKF_EC_NAMEDCURVE = 8388608 # Variable c_int '8388608'
CKO_DATA = 0 # Variable c_int '0'
SEC_ASN1_INTEGER = 2 # Variable c_int '2'
SOL_PACKET = 263 # Variable c_int '263'
PR_NETWORK_UNREACHABLE_ERROR = -5980 # Variable c_long '-0x00000175cl'
CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4 = 2147483655L # Variable c_ulong '-2147483641ul'
CKK_RSA = 0 # Variable c_int '0'
CRL_DECODE_ADOPT_HEAP_DER = 8 # Variable c_int '8'
NSS_USE_ALG_IN_CMS_SIGNATURE = 2 # Variable c_int '2'
SO_KEEPALIVE = 9 # Variable c_int '9'
CK_INVALID_HANDLE = 0 # Variable c_int '0'
CKM_DES_MAC = 291 # Variable c_int '291'
CIS_HAVE_VERIFY = 8 # Variable c_int '8'
IP_PMTUDISC_DO = 2 # Variable c_int '2'
CKM_SKIPJACK_CFB16 = 4102 # Variable c_int '4102'
CERT_POLICY_FLAG_NO_MAPPING = 1 # Variable c_int '1'
CERT_REV_M_DO_NOT_TEST_USING_THIS_METHOD = 0 # Variable c_long '0l'
CKM_SKIPJACK_CFB8 = 4103 # Variable c_int '4103'
CKR_CRYPTOKI_ALREADY_INITIALIZED = 401 # Variable c_int '401'
CKM_IDEA_MAC = 835 # Variable c_int '835'
PR_LOOP_ERROR = -5952 # Variable c_long '-0x000001740l'
_G_HAVE_IO_GETLINE_INFO = 1 # Variable c_int '1'
SECMOD_DES_FLAG = 16 # Variable c_long '16l'
DER_DEFAULT_CHUNKSIZE = 2048 # Variable c_int '2048'
NI_IDN_USE_STD3_ASCII_RULES = 128 # Variable c_int '128'
IN_CLASSB_HOST = 65535L # Variable c_uint '65535u'
CKM_ECDSA_KEY_PAIR_GEN = 4160 # Variable c_int '4160'
DER_INTEGER = 2 # Variable c_int '2'
CKO_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
CKA_CHAR_ROWS = 1027 # Variable c_int '1027'
__WORDSIZE = 32 # Variable c_int '32'
SOL_IRDA = 266 # Variable c_int '266'
_POSIX_MEMLOCK_RANGE = 200809 # Variable c_long '200809l'
IN_CLASSB_MAX = 65536 # Variable c_int '65536'
SSL3_RANDOM_LENGTH = 32 # Variable c_int '32'
PR_SOCKET_SHUTDOWN_ERROR = -5929 # Variable c_long '-0x000001729l'
CKR_FUNCTION_NOT_SUPPORTED = 84 # Variable c_int '84'
__USE_POSIX = 1 # Variable c_int '1'
CKF_VERIFY_RECOVER = 16384 # Variable c_int '16384'
MCAST_LEAVE_SOURCE_GROUP = 47 # Variable c_int '47'
SSL_ENABLE_FALSE_START = 22 # Variable c_int '22'
CKM_KEY_WRAP_SET_OAEP = 1025 # Variable c_int '1025'
CKM_TLS_PRF_GENERAL = 2147484531L # Variable c_ulong '-2147482765ul'
PR_GROUP_EMPTY_ERROR = -5932 # Variable c_long '-0x00000172cl'
NI_NUMERICSERV = 2 # Variable c_int '2'
CERT_UNLIMITED_PATH_CONSTRAINT = -2 # Variable c_int '-0x000000002'
IPV6_RECVHOPOPTS = 53 # Variable c_int '53'
CKD_SHA1_KDF_CONCATENATE = 4 # Variable c_int '4'
_BITS_WCHAR_H = 1 # Variable c_int '1'
__clockid_t_defined = 1 # Variable c_int '1'
CKM_RSA_X9_31 = 11 # Variable c_int '11'
CKR_NO_EVENT = 8 # Variable c_int '8'
PR_POLL_EXCEPT = 4 # Variable c_int '4'
PR_PROC_DESC_TABLE_FULL_ERROR = -5971 # Variable c_long '-0x000001753l'
IPV6_2292HOPLIMIT = 8 # Variable c_int '8'
CKA_REQUIRED_CMS_ATTRIBUTES = 1281 # Variable c_int '1281'
CKF_USER_PIN_LOCKED = 262144 # Variable c_int '262144'
PR_IROTH = 4 # Variable c_int '4'
SO_RCVLOWAT = 18 # Variable c_int '18'
PR_FILE_TOO_BIG_ERROR = -5957 # Variable c_long '-0x000001745l'
IN_CLASSB_NSHIFT = 16 # Variable c_int '16'
_SYS_TYPES_H = 1 # Variable c_int '1'
CKM_X9_42_DH_HYBRID_DERIVE = 50 # Variable c_int '50'
_IO_ERR_SEEN = 32 # Variable c_int '32'
SEC_ASN1_CHOICE = 1048576 # Variable c_int '1048576'
CKM_TWOFISH_CBC = 4243 # Variable c_int '4243'
__USE_GNU = 1 # Variable c_int '1'
WUNTRACED = 2 # Variable c_int '2'
CKA_TRUST_CODE_SIGNING = 3461571418L # Variable c_uint '-833395878u'
CKA_WRAP_TEMPLATE = 1073742353 # Variable c_int '1073742353'
CKR_SESSION_READ_ONLY_EXISTS = 183 # Variable c_int '183'
CKA_BITS_PER_PIXEL = 1030 # Variable c_int '1030'
SOL_IPV6 = 41 # Variable c_int '41'
CKM_CAST_CBC_PAD = 773 # Variable c_int '773'
CKA_VALUE = 17 # Variable c_int '17'
CKF_TOKEN_PRESENT = 1 # Variable c_int '1'
CKM_SEED_ECB = 1617 # Variable c_int '1617'
PR_BUFFER_OVERFLOW_ERROR = -5962 # Variable c_long '-0x00000174al'
CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC = 2147483656L # Variable c_ulong '-2147483640ul'
__ldiv_t_defined = 1 # Variable c_int '1'
CKR_TEMPLATE_INCOMPLETE = 208 # Variable c_int '208'
certificateUsageProtectedObjectSigner = 512 # Variable c_int '512'
CKR_CANCEL = 1 # Variable c_int '1'
__W_CONTINUED = 65535 # Variable c_int '65535'
NI_DGRAM = 16 # Variable c_int '16'
IP_BLOCK_SOURCE = 38 # Variable c_int '38'
CKG_MGF1_SHA224 = 5 # Variable c_int '5'
ssl_SHUTDOWN_BOTH = 3 # Variable c_int '3'
SOL_ATM = 264 # Variable c_int '264'
CKM_CAST_MAC_GENERAL = 772 # Variable c_int '772'
_IO_INTERNAL = 8 # Variable c_int '8'
SEC_ASN1_ANY = 1024 # Variable c_int '1024'
SECMOD_INT_NAME = 'NSS Internal PKCS #11 Module' # Variable STRING '(const char*)"NSS Internal PKCS #11 Module"'
CKA_APPLICATION = 16 # Variable c_int '16'
CKM_SHA256_HMAC_GENERAL = 594 # Variable c_int '594'
PR_TOP_IO_LAYER = -2 # Variable c_int '-0x000000002'
IPV6_MTU_DISCOVER = 23 # Variable c_int '23'
CKR_PIN_EXPIRED = 163 # Variable c_int '163'
CKM_AES_MAC_GENERAL = 4228 # Variable c_int '4228'
CKM_DES3_CBC_PAD = 310 # Variable c_int '310'
IP_ROUTER_ALERT = 5 # Variable c_int '5'
BPB = 8 # Variable c_int '8'
PR_NOT_SOCKET_ERROR = -5969 # Variable c_long '-0x000001751l'
CKF_LOGIN_REQUIRED = 4 # Variable c_int '4'
_POSIX_V7_ILP32_OFF32 = 1 # Variable c_int '1'
PR_INVALID_METHOD_ERROR = -5996 # Variable c_long '-0x00000176cl'
CKA_CERTIFICATE_CATEGORY = 135 # Variable c_int '135'
CKR_DEVICE_ERROR = 48 # Variable c_int '48'
PR_AI_DEFAULT = 48 # Variable c_int '48'
CKM_JUNIPER_COUNTER = 4195 # Variable c_int '4195'
WNOWAIT = 16777216 # Variable c_int '16777216'
CKR_TOKEN_NOT_RECOGNIZED = 225 # Variable c_int '225'
SECMOD_SEED_FLAG = 131072 # Variable c_long '131072l'
CKF_SIGN_RECOVER = 4096 # Variable c_int '4096'
PR_IO_ERROR = -5991 # Variable c_long '-0x000001767l'
CKR_SESSION_PARALLEL_NOT_SUPPORTED = 180 # Variable c_int '180'
CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4 = 2147483654L # Variable c_ulong '-2147483642ul'
IPV6_TCLASS = 67 # Variable c_int '67'
CKA_CHECK_VALUE = 144 # Variable c_int '144'
CKM_DES3_CBC = 307 # Variable c_int '307'
_RPC_NETDB_H = 1 # Variable c_int '1'
PK11_PW_TRY = 'TRY' # Variable STRING '(const char*)"TRY"'
CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = 981 # Variable c_int '981'
_POSIX_READER_WRITER_LOCKS = 200809 # Variable c_long '200809l'
IPV6_2292DSTOPTS = 4 # Variable c_int '4'
NS_CERT_TYPE_OBJECT_SIGNING = 16 # Variable c_int '16'
SEC_CRL_VERSION_2 = 1 # Variable c_int '1'
SEC_CRL_VERSION_1 = 0 # Variable c_int '0'
SIOCGPGRP = 35076 # Variable c_int '35076'
SSL_SECURITY_STATUS_OFF = 0 # Variable c_int '0'
__FD_ZERO_STOS = 'stosl' # Variable STRING '(const char*)"stosl"'
SSL_MAX_CHALLENGE_BYTES = 32 # Variable c_int '32'
CKM_TLS_MASTER_KEY_DERIVE_DH = 887 # Variable c_int '887'
CKR_DOMAIN_PARAMS_INVALID = 304 # Variable c_int '304'
CKA_MECHANISM_TYPE = 1280 # Variable c_int '1280'
SECMOD_DSA_FLAG = 2 # Variable c_long '2l'
IP_RECVTTL = 12 # Variable c_int '12'
CKR_ATTRIBUTE_TYPE_INVALID = 18 # Variable c_int '18'
PR_NETDB_BUF_SIZE = 1024 # Variable c_int '1024'
_XOPEN_SHM = 1 # Variable c_int '1'
PR_INTERVAL_MIN = 1000L # Variable c_ulong '1000ul'
SO_ERROR = 4 # Variable c_int '4'
MCAST_LEAVE_GROUP = 45 # Variable c_int '45'
_IO_LINE_BUF = 512 # Variable c_int '512'
IPV6_RECVHOPLIMIT = 51 # Variable c_int '51'
certificateUsageSSLClient = 1 # Variable c_int '1'
_POSIX_THREAD_CPUTIME = 0 # Variable c_int '0'
_G_config_h = 1 # Variable c_int '1'
CKK_BLOWFISH = 32 # Variable c_int '32'
_IO_FLAGS2_MMAP = 1 # Variable c_int '1'
_POSIX_THREAD_SPORADIC_SERVER = -1 # Variable c_int '-0x000000001'
_POSIX_SPORADIC_SERVER = -1 # Variable c_int '-0x000000001'
__GLIBC_HAVE_LONG_LONG = 1 # Variable c_int '1'
_POSIX_MEMORY_PROTECTION = 200809 # Variable c_long '200809l'
CKA_EXPONENT_1 = 294 # Variable c_int '294'
CKA_EXPONENT_2 = 295 # Variable c_int '295'
CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = 978 # Variable c_int '978'
CKF_WRAP = 131072 # Variable c_int '131072'
CKM_SHA256_RSA_PKCS = 64 # Variable c_int '64'
PR_INT8_MAX = 127 # Variable c_int '127'
SSL_NOT_ALLOWED = 0 # Variable c_int '0'
SO_REUSEADDR = 2 # Variable c_int '2'
CKA_DIGEST = 2164260864L # Variable c_ulong '-2130706432ul'
SO_BINDTODEVICE = 25 # Variable c_int '25'
_STDLIB_H = 1 # Variable c_int '1'
GAI_NOWAIT = 1 # Variable c_int '1'
IN_CLASSC_HOST = 255L # Variable c_uint '255u'
PR_RDWR = 4 # Variable c_int '4'
GS_INIT = 0 # Variable c_int '0'
CKM_AES_CBC_ENCRYPT_DATA = 4357 # Variable c_int '4357'
CKM_DES_OFB8 = 337 # Variable c_int '337'
F_LOCK = 1 # Variable c_int '1'
__USE_XOPEN2K = 1 # Variable c_int '1'
SO_SECURITY_ENCRYPTION_TRANSPORT = 23 # Variable c_int '23'
CKM_CAST128_MAC_GENERAL = 804 # Variable c_int '804'
IPV6_RTHDRDSTOPTS = 55 # Variable c_int '55'
IP_DROP_MEMBERSHIP = 36 # Variable c_int '36'
CKR_WRAPPING_KEY_SIZE_RANGE = 276 # Variable c_int '276'
EAI_MEMORY = -10 # Variable c_int '-0x00000000a'
CKF_DIGEST = 1024 # Variable c_int '1024'
PR_SOCKET_ADDRESS_IS_BOUND_ERROR = -5967 # Variable c_long '-0x00000174fl'
_IO_LINKED = 128 # Variable c_int '128'
SFTK_MIN_USER_SLOT_ID = 4 # Variable c_int '4'
NS_CERT_TYPE_OBJECT_SIGNING_CA = 1 # Variable c_int '1'
STDERR_FILENO = 2 # Variable c_int '2'
PR_AF_INET6 = 10 # Variable c_int '10'
_POSIX_REENTRANT_FUNCTIONS = 1 # Variable c_int '1'
CKM_IDEA_CBC = 834 # Variable c_int '834'
CKR_STATE_UNSAVEABLE = 384 # Variable c_int '384'
CKM_RC5_MAC_GENERAL = 820 # Variable c_int '820'
IPV6_MULTICAST_HOPS = 18 # Variable c_int '18'
SSL_RENEGOTIATE_UNRESTRICTED = 1 # Variable c_int '1'
CKM_AES_ECB = 4225 # Variable c_int '4225'
SSL_NO_STEP_DOWN = 15 # Variable c_int '15'
SSL_MAX_MAC_BYTES = 16 # Variable c_int '16'
CKF_EC_ECPARAMETERS = 4194304 # Variable c_int '4194304'
CKK_CAST128 = 24 # Variable c_int '24'
_STDINT_H = 1 # Variable c_int '1'
CKM_RC5_CBC = 818 # Variable c_int '818'
PR_ADDRESS_NOT_SUPPORTED_ERROR = -5985 # Variable c_long '-0x000001761l'
CKF_PROTECTED_AUTHENTICATION_PATH = 256 # Variable c_int '256'
CKM_FASTHASH = 4208 # Variable c_int '4208'
CKF_SECONDARY_AUTHENTICATION = 2048 # Variable c_int '2048'
CKF_REMOVABLE_DEVICE = 2 # Variable c_int '2'
CKR_NSS = 3461563216L # Variable c_uint '-833404080u'
CKM_SEED_CBC = 1618 # Variable c_int '1618'
CKM_CAST5_CBC = 802 # Variable c_int '802'
PR_LD_GLOBAL = 4 # Variable c_int '4'
PR_NAME = 'NSPR' # Variable STRING '(const char*)"NSPR"'
SECMOD_MD2_FLAG = 1024 # Variable c_long '1024l'
_STRING_H = 1 # Variable c_int '1'
CKM_DES_KEY_GEN = 288 # Variable c_int '288'
SEC_ASN1_DYNAMIC = 16384 # Variable c_int '16384'
CKA_KEY_TYPE = 256 # Variable c_int '256'
SO_RCVBUFFORCE = 33 # Variable c_int '33'
NUM_MIXERS = 9 # Variable c_int '9'
PR_SEM_CREATE = 1 # Variable c_int '1'
STDIN_FILENO = 0 # Variable c_int '0'
CKA_TRUST_IPSEC_USER = 3461571422L # Variable c_uint '-833395874u'
CKS_RW_PUBLIC_SESSION = 2 # Variable c_int '2'
PR_ACCEPT_READ_BUF_OVERHEAD = 248L # Variable c_uint '248u'
CKA_NETSCAPE_DB = 3584088832L # Variable c_ulong '-710878464ul'
IP_UNBLOCK_SOURCE = 37 # Variable c_int '37'
EAI_OVERFLOW = -12 # Variable c_int '-0x00000000c'
CKM_TWOFISH_KEY_GEN = 4242 # Variable c_int '4242'
_POSIX_TYPED_MEMORY_OBJECTS = -1 # Variable c_int '-0x000000001'
CKF_TOKEN_INITIALIZED = 1024 # Variable c_int '1024'
DER_PRINTABLE_STRING = 19 # Variable c_int '19'
_OLD_STDIO_MAGIC = 4206624768L # Variable c_uint '-88342528u'
CKM_KEY_WRAP_LYNKS = 1024 # Variable c_int '1024'
SEC_ASN1_SKIP_REST = 524288 # Variable c_int '524288'
CKF_SIGN = 2048 # Variable c_int '2048'
SEC_ASN1_UTC_TIME = 23 # Variable c_int '23'
EAI_NODATA = -5 # Variable c_int '-0x000000005'
SECMOD_FRIENDLY_FLAG = 268435456 # Variable c_long '268435456l'
CKF_WRITE_PROTECTED = 2 # Variable c_int '2'
CKK_GENERIC_SECRET = 16 # Variable c_int '16'
SSL_ERROR_BASE = -12288 # Variable c_int '-0x000003000'
CKS_RW_USER_FUNCTIONS = 3 # Variable c_int '3'
SSL_ALLOWED = 1 # Variable c_int '1'
_POSIX_SYNCHRONIZED_IO = 200809 # Variable c_long '200809l'
PR_UINT32_MAX = 4294967295L # Variable c_uint '-1u'
CKM_DES3_CBC_ENCRYPT_DATA = 4355 # Variable c_int '4355'
PR_DIRECTORY_LOOKUP_ERROR = -5973 # Variable c_long '-0x000001755l'
_STRUCT_TIMEVAL = 1 # Variable c_int '1'
CKR_USER_TYPE_INVALID = 259 # Variable c_int '259'
CKM_SHA_1_HMAC_GENERAL = 546 # Variable c_int '546'
SSL_REQUEST_CERTIFICATE = 3 # Variable c_int '3'
CKR_SIGNATURE_LEN_RANGE = 193 # Variable c_int '193'
NSSCK_VENDOR_NSS = 1314079568 # Variable c_int '1314079568'
CKF_USER_PIN_FINAL_TRY = 131072 # Variable c_int '131072'
IP_IPSEC_POLICY = 16 # Variable c_int '16'
CKH_CLOCK = 2 # Variable c_int '2'
DER_PRIVATE = 192 # Variable c_int '192'
_BITS_PTHREADTYPES_H = 1 # Variable c_int '1'
_IO_FLAGS2_NOTCANCEL = 2 # Variable c_int '2'
PR_OPERATION_ABORTED_ERROR = -5935 # Variable c_long '-0x00000172fl'
_PATH_PROTOCOLS = '/etc/protocols' # Variable STRING '(const char*)"/etc/protocols"'
IPV6_RTHDR_TYPE_0 = 0 # Variable c_int '0'
SECMOD_INTERNAL = 1 # Variable c_int '1'
KU_KEY_AGREEMENT_OR_ENCIPHERMENT = 16384 # Variable c_int '16384'
CKA_PRIVATE = 2 # Variable c_int '2'
SECMOD_SLOT_FLAGS = 'slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]' # Variable STRING '(const char*)"slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]"'
SEC_ASN1_APPLICATION = 64 # Variable c_int '64'
_LFS64_STDIO = 1 # Variable c_int '1'
SHA384_LENGTH = 48 # Variable c_int '48'
CERT_REV_M_REQUIRE_INFO_ON_MISSING_SOURCE = 8 # Variable c_long '8l'
CKK_DES2 = 20 # Variable c_int '20'
CKK_DES3 = 21 # Variable c_int '21'
PR_VPATCH = 6 # Variable c_int '6'
DER_OUTER = 262144 # Variable c_int '262144'
CKM_PBE_MD5_CAST128_CBC = 932 # Variable c_int '932'
CKM_CDMF_ECB = 321 # Variable c_int '321'
CKK_CAST = 22 # Variable c_int '22'
PK11_ATTR_MODIFIABLE = 16 # Variable c_long '16l'
MAX_COMPRESSION_METHODS = 10 # Variable c_int '10'
MCAST_MSFILTER = 48 # Variable c_int '48'
CERT_MAX_CERT_CHAIN = 20 # Variable c_int '20'
_SVID_SOURCE = 1 # Variable c_int '1'
CKM_SSL3_KEY_AND_MAC_DERIVE = 882 # Variable c_int '882'
IP_DEFAULT_MULTICAST_TTL = 1 # Variable c_int '1'
IPV6_V6ONLY = 26 # Variable c_int '26'
_PATH_NETWORKS = '/etc/networks' # Variable STRING '(const char*)"/etc/networks"'
CKM_SHA1_RSA_PKCS = 6 # Variable c_int '6'
CKM_SHA384 = 608 # Variable c_int '608'
CKR_SLOT_ID_INVALID = 3 # Variable c_int '3'
SECMOD_RSA_FLAG = 1 # Variable c_long '1l'
SEC_ASN1_OCTET_STRING = 4 # Variable c_int '4'
PK11_ATTR_TOKEN = 1 # Variable c_long '1l'
IP_MTU_DISCOVER = 10 # Variable c_int '10'
CKM_CAMELLIA_ECB = 1361 # Variable c_int '1361'
NI_MAXHOST = 1025 # Variable c_int '1025'
SOL_RAW = 255 # Variable c_int '255'
CKM_CDMF_MAC_GENERAL = 324 # Variable c_int '324'
HT_FREE_VALUE = 0 # Variable c_int '0'
CKA_TRUST_KEY_CERT_SIGN = 3461571414L # Variable c_uint '-833395882u'
IPV6_2292HOPOPTS = 3 # Variable c_int '3'
__SIZEOF_PTHREAD_MUTEX_T = 24 # Variable c_int '24'
_IO_STDIO = 16384 # Variable c_int '16384'
PR_MAX_DIRECTORY_ENTRIES_ERROR = -5942 # Variable c_long '-0x000001736l'
CKM_SKIPJACK_CBC64 = 4098 # Variable c_int '4098'
CKA_LOCAL = 355 # Variable c_int '355'
INADDR_MAX_LOCAL_GROUP = 3758096639L # Variable c_uint '-536870657u'
SOL_IP = 0 # Variable c_int '0'
IP_XFRM_POLICY = 17 # Variable c_int '17'
CKM_RC5_KEY_GEN = 816 # Variable c_int '816'
certificateUsageSSLServerWithStepUp = 4 # Variable c_int '4'
X_OK = 1 # Variable c_int '1'
PR_IO_LAYER_HEAD = -3 # Variable c_int '-0x000000003'
CKM_DES3_ECB = 306 # Variable c_int '306'
NS_CERT_TYPE_SSL_CLIENT = 128 # Variable c_int '128'
RF_KEY_COMPROMISE = 64 # Variable c_int '64'
PR_IXOTH = 1 # Variable c_int '1'
EAI_NONAME = -2 # Variable c_int '-0x000000002'
CKR_ENCRYPTED_DATA_INVALID = 64 # Variable c_int '64'
INET6_ADDRSTRLEN = 46 # Variable c_int '46'
F_TEST = 3 # Variable c_int '3'
CKF_SO_PIN_FINAL_TRY = 2097152 # Variable c_int '2097152'
SECMOD_MODULE_DB_FUNCTION_ADD = 1 # Variable c_int '1'
__WCHAR_MIN = -2147483648 # Variable c_int '-0x080000000'
SSL_SECURITY_STATUS_ON_HIGH = 1 # Variable c_int '1'
CKM_DES3_ECB_ENCRYPT_DATA = 4354 # Variable c_int '4354'
EAI_SOCKTYPE = -7 # Variable c_int '-0x000000007'
SSL_CHALLENGE_BYTES = 16 # Variable c_int '16'
CKM_CAST128_CBC_PAD = 805 # Variable c_int '805'
_BITS_BYTESWAP_H = 1 # Variable c_int '1'
CKM_SSL3_PRE_MASTER_KEY_GEN = 880 # Variable c_int '880'
SEC_ASN1_OPTIONAL = 256 # Variable c_int '256'
AI_IDN_ALLOW_UNASSIGNED = 256 # Variable c_int '256'
_SIGSET_NWORDS = 32L # Variable c_uint '32u'
GAI_WAIT = 0 # Variable c_int '0'
CKM_DSA_KEY_PAIR_GEN = 16 # Variable c_int '16'
IPV6_PMTUDISC_DONT = 0 # Variable c_int '0'
IPV6_RECVTCLASS = 66 # Variable c_int '66'
CKA_TRUST_IPSEC_TUNNEL = 3461571421L # Variable c_uint '-833395875u'
CKD_SHA1_KDF_ASN1 = 3 # Variable c_int '3'
PR_IRWXG = 56 # Variable c_int '56'
_G_HAVE_ATEXIT = 1 # Variable c_int '1'
CERT_ENABLE_HTTP_FETCH = 2 # Variable c_int '2'
PR_IRWXO = 7 # Variable c_int '7'
_POSIX_THREAD_ATTR_STACKADDR = 200809 # Variable c_long '200809l'
CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 277 # Variable c_int '277'
PR_IRWXU = 448 # Variable c_int '448'
_NETINET_IN_H = 1 # Variable c_int '1'
CKM_CAST5_MAC_GENERAL = 804 # Variable c_int '804'
_IO_USER_LOCK = 32768 # Variable c_int '32768'
CKA_TRUST_SERVER_AUTH = 3461571416L # Variable c_uint '-833395880u'
SECMOD_INT_FLAGS = 'Flags=internal,critical slotparams=(1={slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]})' # Variable STRING '(const char*)"Flags=internal,critical slotparams=(1={slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]})"'
EOF = -1 # Variable c_int '-0x000000001'
__WCOREFLAG = 128 # Variable c_int '128'
_G_HAVE_MREMAP = 1 # Variable c_int '1'
SEC_ASN1_SET_OF = 8209 # Variable c_int '8209'
CKA_OWNER = 132 # Variable c_int '132'
CKM_BLOWFISH_CBC = 4241 # Variable c_int '4241'
PR_UINT8_MAX = 255L # Variable c_uint '255u'
CKA_EXTRACTABLE = 354 # Variable c_int '354'
DER_EXPLICIT = 512 # Variable c_int '512'
PR_SHM_EXCL = 2 # Variable c_int '2'
CKO_PUBLIC_KEY = 2 # Variable c_int '2'
SEC_ASN1_ENUMERATED = 10 # Variable c_int '10'
IP_RECVERR = 11 # Variable c_int '11'
_XOPEN_ENH_I18N = 1 # Variable c_int '1'
MAX_IV_LENGTH = 64 # Variable c_int '64'
CK_UNAVAILABLE_INFORMATION = 4294967295L # Variable c_ulong '-1ul'
PR_CONNECT_REFUSED_ERROR = -5981 # Variable c_long '-0x00000175dl'
__SIZEOF_PTHREAD_MUTEXATTR_T = 4 # Variable c_int '4'
CKA_EC_POINT = 385 # Variable c_int '385'
SEC_ASN1_VISIBLE_STRING = 26 # Variable c_int '26'
EAI_NOTCANCELED = -102 # Variable c_int '-0x000000066'
CKR_KEY_INDIGESTIBLE = 103 # Variable c_int '103'
CKM_CDMF_CBC = 322 # Variable c_int '322'
SEC_CERTIFICATE_REQUEST_VERSION = 0 # Variable c_int '0'
PR_IRGRP = 32 # Variable c_int '32'
CKA_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
SSL_ENABLE_SESSION_TICKETS = 18 # Variable c_int '18'
PR_CONNECT_TIMEOUT_ERROR = -5979 # Variable c_long '-0x00000175bl'
SSL_NO_LOCKS = 17 # Variable c_int '17'
SSL_ENABLE_FDX = 11 # Variable c_int '11'
CRL_DECODE_DONT_COPY_DER = 1 # Variable c_int '1'
PR_CONNECT_ABORTED_ERROR = -5928 # Variable c_long '-0x000001728l'
CERT_REV_M_ALLOW_IMPLICIT_DEFAULT_SOURCE = 0 # Variable c_long '0l'
CKM_SKIPJACK_ECB64 = 4097 # Variable c_int '4097'
PR_LANGUAGE_I_DEFAULT = 0 # Variable c_int '0'
CKM_CAMELLIA_CBC = 1362 # Variable c_int '1362'
CK_NULL_PTR = 0 # Variable c_int '0'
CERT_ENABLE_LDAP_FETCH = 1 # Variable c_int '1'
CKM_EXTRACT_KEY_FROM_KEY = 869 # Variable c_int '869'
CKR_TOKEN_WRITE_PROTECTED = 226 # Variable c_int '226'
CKR_NEED_TO_CREATE_THREADS = 9 # Variable c_int '9'
MAX_CERT_TYPES = 10 # Variable c_int '10'
CKA_CLASS = 0 # Variable c_int '0'
CKA_PRIME_BITS = 307 # Variable c_int '307'
CKF_DUAL_CRYPTO_OPERATIONS = 512 # Variable c_int '512'
CKR_SESSION_READ_WRITE_SO_EXISTS = 184 # Variable c_int '184'
SECMOD_RC5_FLAG = 128 # Variable c_long '128l'
CKM_DES_ECB = 289 # Variable c_int '289'
SEC_ASN1_EMBEDDED_PDV = 11 # Variable c_int '11'
CKM_MD5_HMAC = 529 # Variable c_int '529'
SECMOD_WAIT_SIMULATED_EVENT = 2 # Variable c_int '2'
INET_ADDRSTRLEN = 16 # Variable c_int '16'
PR_PIPE_ERROR = -5955 # Variable c_long '-0x000001743l'
_POSIX_SHELL = 1 # Variable c_int '1'
PR_INSUFFICIENT_RESOURCES_ERROR = -5974 # Variable c_long '-0x000001756l'
CKA_SUPPORTED_CMS_ATTRIBUTES = 1283 # Variable c_int '1283'
SECMOD_FIPS = 2 # Variable c_int '2'
__USE_FORTIFY_LEVEL = 2 # Variable c_int '2'
CKA_SUBPRIME = 305 # Variable c_int '305'
SEC_ASN1_PRIVATE = 192 # Variable c_int '192'
EAI_SYSTEM = -11 # Variable c_int '-0x00000000b'
SIOCGSTAMP = 35078 # Variable c_int '35078'
CKM_SHA256_RSA_PKCS_PSS = 67 # Variable c_int '67'
RF_AFFILIATION_CHANGED = 16 # Variable c_int '16'
KU_NON_REPUDIATION = 64 # Variable c_int '64'
CKF_HW = 1 # Variable c_int '1'
CKM_CONCATENATE_BASE_AND_DATA = 866 # Variable c_int '866'
CKR_KEY_HANDLE_INVALID = 96 # Variable c_int '96'
SO_PEERCRED = 17 # Variable c_int '17'
_POSIX_MAPPED_FILES = 200809 # Variable c_long '200809l'
CKM_ECDSA_SHA1 = 4162 # Variable c_int '4162'
F_TLOCK = 2 # Variable c_int '2'
CKA_TRUST_KEY_ENCIPHERMENT = 3461571411L # Variable c_uint '-833395885u'
CKA_HW_FEATURE_TYPE = 768 # Variable c_int '768'
CKK_CAST3 = 23 # Variable c_int '23'
CKM_RC2_ECB = 257 # Variable c_int '257'
CKM_SKIPJACK_RELAYX = 4106 # Variable c_int '4106'
SEC_CERT_CLASS_EMAIL = 4 # Variable c_int '4'
SEC_ASN1D_MAX_DEPTH = 32 # Variable c_int '32'
PR_AF_UNSPEC = 0 # Variable c_int '0'
CKR_KEY_NOT_NEEDED = 100 # Variable c_int '100'
CKM_SHA_1 = 544 # Variable c_int '544'
PR_IXUSR = 64 # Variable c_int '64'
SEC_ASN1_SET = 17 # Variable c_int '17'
PR_INVALID_STATE_ERROR = -5931 # Variable c_long '-0x00000172bl'
CKR_ENCRYPTED_DATA_LEN_RANGE = 65 # Variable c_int '65'
_POSIX_SEMAPHORES = 200809 # Variable c_long '200809l'
CKA_URL = 137 # Variable c_int '137'
SSL_REQUIRE_SAFE_NEGOTIATION = 21 # Variable c_int '21'
CKM_CAST128_KEY_GEN = 800 # Variable c_int '800'
IN_CLASSC_NSHIFT = 8 # Variable c_int '8'
CKM_AES_ECB_ENCRYPT_DATA = 4356 # Variable c_int '4356'
SSL_ENV_VAR_NAME = 'SSL_INHERITANCE' # Variable STRING '(const char*)"SSL_INHERITANCE"'
CKA_PRIME_1 = 292 # Variable c_int '292'
CKR_UNWRAPPING_KEY_HANDLE_INVALID = 240 # Variable c_int '240'
CKA_PRIME_2 = 293 # Variable c_int '293'
CKA_ALLOWED_MECHANISMS = 1073743360 # Variable c_int '1073743360'
IN_CLASSA_HOST = 16777215L # Variable c_uint '16777215u'
CKM_CAST_ECB = 769 # Variable c_int '769'
IPV6_RECVERR = 25 # Variable c_int '25'
__STDLIB_MB_LEN_MAX = 16 # Variable c_int '16'
CKF_CLOCK_ON_TOKEN = 64 # Variable c_int '64'
CKM_DES_ECB_ENCRYPT_DATA = 4352 # Variable c_int '4352'
MAX_MAC_LENGTH = 64 # Variable c_int '64'
__WCLONE = 2147483648L # Variable c_uint '-2147483648u'
CIS_HAVE_CERTIFICATE = 2 # Variable c_int '2'
CKM_IDEA_MAC_GENERAL = 836 # Variable c_int '836'
CKM_BATON_SHUFFLE = 4149 # Variable c_int '4149'
CKK_SKIPJACK = 27 # Variable c_int '27'
PR_POLL_READ = 1 # Variable c_int '1'
CKF_EC_COMPRESS = 33554432 # Variable c_int '33554432'
_POSIX_SHARED_MEMORY_OBJECTS = 200809 # Variable c_long '200809l'
SEC_ASN1_INLINE = 2048 # Variable c_int '2048'
CKM_X9_42_MQV_DERIVE = 51 # Variable c_int '51'
F_OK = 0 # Variable c_int '0'
_G_HAVE_LONG_DOUBLE_IO = 1 # Variable c_int '1'
IPV6_2292PKTINFO = 2 # Variable c_int '2'
_IO_RIGHT = 4 # Variable c_int '4'
_IOS_APPEND = 8 # Variable c_int '8'
PR_CREATE_FILE = 8 # Variable c_int '8'
SO_LINGER = 13 # Variable c_int '13'
CKA_AC_ISSUER = 131 # Variable c_int '131'
KU_DIGITAL_SIGNATURE = 128 # Variable c_int '128'
SEC_ASN1_CONTEXT_SPECIFIC = 128 # Variable c_int '128'
RF_UNUSED = 128 # Variable c_int '128'
_XOPEN_VERSION = 700 # Variable c_int '700'
CKR_KEY_NEEDED = 102 # Variable c_int '102'
PR_LD_LAZY = 1 # Variable c_int '1'
SO_PEERNAME = 28 # Variable c_int '28'
NI_NAMEREQD = 8 # Variable c_int '8'
IPV6_AUTHHDR = 10 # Variable c_int '10'
PR_SYNC = 64 # Variable c_int '64'
CKM_CAST5_KEY_GEN = 800 # Variable c_int '800'
__USE_ANSI = 1 # Variable c_int '1'
_G_NAMES_HAVE_UNDERSCORE = 0 # Variable c_int '0'
_IO_NO_READS = 4 # Variable c_int '4'
SSL_SECURITY_STATUS_NOOPT = -1 # Variable c_int '-0x000000001'
CERT_REV_MI_TEST_EACH_METHOD_SEPARATELY = 0 # Variable c_long '0l'
PR_FILE_IS_LOCKED_ERROR = -5958 # Variable c_long '-0x000001746l'
AI_IDN = 64 # Variable c_int '64'
__GLIBC_MINOR__ = 12 # Variable c_int '12'
SO_ACCEPTCONN = 30 # Variable c_int '30'
SHA1_LENGTH = 20 # Variable c_int '20'
CKM_CAST3_KEY_GEN = 784 # Variable c_int '784'
CKM_BLOWFISH_KEY_GEN = 4240 # Variable c_int '4240'
PR_AI_V4MAPPED = 16 # Variable c_int '16'
IP_OPTIONS = 4 # Variable c_int '4'
SEC_ASN1_NO_STREAM = 2097152 # Variable c_int '2097152'
_POSIX_REGEXP = 1 # Variable c_int '1'
CKR_USER_PIN_NOT_INITIALIZED = 258 # Variable c_int '258'
CKM_MD5_KEY_DERIVATION = 912 # Variable c_int '912'
_G_VTABLE_LABEL_HAS_LENGTH = 1 # Variable c_int '1'
DER_POINTER = 4096 # Variable c_int '4096'
CKA_DEFAULT_CMS_ATTRIBUTES = 1282 # Variable c_int '1282'
CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN = 2147483657L # Variable c_ulong '-2147483639ul'
PR_IRUSR = 256 # Variable c_int '256'
SECMOD_SHA512_FLAG = 32768 # Variable c_long '32768l'
SSL_RENEGOTIATE_TRANSITIONAL = 3 # Variable c_int '3'
CKF_DERIVE = 524288 # Variable c_int '524288'
AI_ALL = 16 # Variable c_int '16'
CKA_HASH_OF_ISSUER_PUBLIC_KEY = 139 # Variable c_int '139'
IN_LOOPBACKNET = 127 # Variable c_int '127'
PR_CALL_ONCE_ERROR = -5925 # Variable c_long '-0x000001725l'
CKM_RC5_ECB = 817 # Variable c_int '817'
CKM_SHA384_KEY_DERIVATION = 916 # Variable c_int '916'
CKM_PBE_SHA1_RC4_40 = 935 # Variable c_int '935'
CKA_TRUST_KEY_AGREEMENT = 3461571413L # Variable c_uint '-833395883u'
_POSIX_THREAD_PROCESS_SHARED = 200809 # Variable c_long '200809l'
SSL_MAX_CYPHER_ARG_BYTES = 32 # Variable c_int '32'
CKM_CAMELLIA_CBC_PAD = 1365 # Variable c_int '1365'
NS_CERT_TYPE_SSL_CA = 4 # Variable c_int '4'
IP_TTL = 2 # Variable c_int '2'
SEC_ASN1_UTF8_STRING = 12 # Variable c_int '12'
_IOS_NOCREATE = 32 # Variable c_int '32'
DER_CONTEXT_SPECIFIC = 128 # Variable c_int '128'
_POSIX_ADVISORY_INFO = 200809 # Variable c_long '200809l'
AI_ADDRCONFIG = 32 # Variable c_int '32'
SSL_REQUIRE_CERTIFICATE = 10 # Variable c_int '10'
CKM_DES_CBC = 290 # Variable c_int '290'
DER_FORCE = 65536 # Variable c_int '65536'
__USE_LARGEFILE = 1 # Variable c_int '1'
_POSIX_MONOTONIC_CLOCK = 0 # Variable c_int '0'
CK_FALSE = 0 # Variable c_int '0'
SEC_ASN1_GROUP = 8192 # Variable c_int '8192'
CERT_REV_M_TEST_USING_THIS_METHOD = 1 # Variable c_long '1l'
PR_INT16_MIN = -32768 # Variable c_int '-0x000008000'
_POSIX_VDISABLE = '\x00' # Variable c_char "'\\000'"
PR_NSPR_ERROR_BASE = -6000 # Variable c_int '-0x000001770'
SFTK_MAX_USER_SLOT_ID = 100 # Variable c_int '100'
CKA_ALWAYS_AUTHENTICATE = 514 # Variable c_int '514'
CKA_FLAGS_ONLY = 0 # Variable c_int '0'
SSL_MIN_CHALLENGE_BYTES = 16 # Variable c_int '16'
SSL_ROLLBACK_DETECTION = 14 # Variable c_int '14'
TLS_EX_SESS_TICKET_MAC_LENGTH = 32 # Variable c_int '32'
CKK_IDEA = 26 # Variable c_int '26'
IP_MINTTL = 21 # Variable c_int '21'
SEC_CERT_NICKNAMES_USER = 2 # Variable c_int '2'
KU_KEY_AGREEMENT = 8 # Variable c_int '8'
UIO_MAXIOV = 1024 # Variable c_int '1024'
CKA_OBJECT_ID = 18 # Variable c_int '18'
CERT_MAX_SERIAL_NUMBER_BYTES = 20 # Variable c_int '20'
SSL_NO_CACHE = 9 # Variable c_int '9'
_XBS5_ILP32_OFF32 = 1 # Variable c_int '1'
__LP64_OFF64_CFLAGS = '-m64' # Variable STRING '(const char*)"-m64"'
SO_DETACH_FILTER = 27 # Variable c_int '27'
CKM_CAST5_ECB = 801 # Variable c_int '801'
MAX_FRAGMENT_LENGTH = 16384 # Variable c_int '16384'
IP_MULTICAST_TTL = 33 # Variable c_int '33'
CKR_FUNCTION_FAILED = 6 # Variable c_int '6'
CERT_REV_M_IGNORE_IMPLICIT_DEFAULT_SOURCE = 4 # Variable c_long '4l'
CKA_TRUST_NON_REPUDIATION = 3461571410L # Variable c_uint '-833395886u'
MAX_CIPHER_CONTEXT_BYTES = 2080 # Variable c_int '2080'
ssl_SEND_FLAG_NO_BUFFER = 536870912 # Variable c_int '536870912'
CKR_FUNCTION_REJECTED = 512 # Variable c_int '512'
CERT_REV_M_FORBID_NETWORK_FETCHING = 2 # Variable c_long '2l'
WSTOPPED = 2 # Variable c_int '2'
CKO_CERTIFICATE = 1 # Variable c_int '1'
CKM_RIPEMD160_HMAC = 577 # Variable c_int '577'
SSL_SECURITY_STATUS_ON_LOW = 2 # Variable c_int '2'
_POSIX_JOB_CONTROL = 1 # Variable c_int '1'
HT_ENUMERATE_STOP = 1 # Variable c_int '1'
CKR_SAVED_STATE_INVALID = 352 # Variable c_int '352'
SECMOD_MODULE_DB_FUNCTION_RELEASE = 3 # Variable c_int '3'
GS_PAD = 4 # Variable c_int '4'
_POSIX_TIMERS = 200809 # Variable c_long '200809l'
KU_NS_GOVT_APPROVED = 32768 # Variable c_int '32768'
CKK_NSS = 3461563216L # Variable c_uint '-833404080u'
_POSIX_THREAD_ROBUST_PRIO_INHERIT = 200809 # Variable c_long '200809l'
SO_TYPE = 3 # Variable c_int '3'
IPV6_LEAVE_ANYCAST = 28 # Variable c_int '28'
CERT_REV_MI_TEST_ALL_LOCAL_INFORMATION_FIRST = 1 # Variable c_long '1l'
_G_USING_THUNKS = 1 # Variable c_int '1'
PRTRACE_DESC_MAX = 255 # Variable c_int '255'
SEC_CRL_TYPE = 1 # Variable c_int '1'
CERT_REV_MI_NO_OVERALL_INFO_REQUIREMENT = 0 # Variable c_long '0l'
FOPEN_MAX = 16 # Variable c_int '16'
MAX_KEY_LENGTH = 64 # Variable c_int '64'
IP_ADD_SOURCE_MEMBERSHIP = 39 # Variable c_int '39'
CKM_TLS_MASTER_KEY_DERIVE = 885 # Variable c_int '885'
CKM_AES_KEY_GEN = 4224 # Variable c_int '4224'
DER_UTC_TIME = 23 # Variable c_int '23'
CKR_ATTRIBUTE_VALUE_INVALID = 19 # Variable c_int '19'
_POSIX_V6_ILP32_OFF32 = 1 # Variable c_int '1'
CKA_KEY_GEN_MECHANISM = 358 # Variable c_int '358'
_BITS_POSIX_OPT_H = 1 # Variable c_int '1'
GS_HEADER = 1 # Variable c_int '1'
_PATH_HEQUIV = '/etc/hosts.equiv' # Variable STRING '(const char*)"/etc/hosts.equiv"'
CKR_USER_ALREADY_LOGGED_IN = 256 # Variable c_int '256'
_POSIX_REALTIME_SIGNALS = 200809 # Variable c_long '200809l'
_FEATURES_H = 1 # Variable c_int '1'
CKM_DH_PKCS_DERIVE = 33 # Variable c_int '33'
CKA_SUBJECT = 257 # Variable c_int '257'
CKA_PRIME = 304 # Variable c_int '304'
DER_HIGH_TAG_NUMBER = 31 # Variable c_int '31'
CKM_CAMELLIA_CBC_ENCRYPT_DATA = 1367 # Variable c_int '1367'
CKF_RW_SESSION = 2 # Variable c_int '2'
SIOCATMARK = 35077 # Variable c_int '35077'
CKM_RIPEMD128_RSA_PKCS = 7 # Variable c_int '7'
SSL3_SUPPORTED_CURVES_MASK = 58720256 # Variable c_int '58720256'
CKM_PBE_SHA1_DES2_EDE_CBC = 937 # Variable c_int '937'
__timespec_defined = 1 # Variable c_int '1'
IP_HDRINCL = 3 # Variable c_int '3'
CKC_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 242 # Variable c_int '242'
_XBS5_ILP32_OFFBIG = 1 # Variable c_int '1'
CERT_REV_M_SKIP_TEST_ON_MISSING_SOURCE = 0 # Variable c_long '0l'
CKR_GENERAL_ERROR = 5 # Variable c_int '5'
_SYS_UIO_H = 1 # Variable c_int '1'
__SIZEOF_PTHREAD_BARRIERATTR_T = 4 # Variable c_int '4'
PR_AI_ADDRCONFIG = 32 # Variable c_int '32'
SEC_ASN1_NUMERIC_STRING = 18 # Variable c_int '18'
_IO_DONT_CLOSE = 32768 # Variable c_int '32768'
IN_CLASSC_NET = 4294967040L # Variable c_uint '-256u'
_IO_BAD_SEEN = 16384 # Variable c_int '16384'
CKM_SHA512_RSA_PKCS_PSS = 69 # Variable c_int '69'
__BIT_TYPES_DEFINED__ = 1 # Variable c_int '1'
PR_NAME_TOO_LONG_ERROR = -5951 # Variable c_long '-0x00000173fl'
RF_CERTIFICATE_HOLD = 2 # Variable c_int '2'
CK_EFFECTIVELY_INFINITE = 0 # Variable c_int '0'
SCOPE_DELIMITER = '%' # Variable c_char "'%'"
CKR_OK = 0 # Variable c_int '0'
CKF_DONT_BLOCK = 1 # Variable c_int '1'
certificateUsageSSLServer = 2 # Variable c_int '2'
CKM_X9_42_DH_DERIVE = 49 # Variable c_int '49'
P_tmpdir = '/tmp' # Variable STRING '(const char*)"/tmp"'
CKM_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
MCAST_EXCLUDE = 0 # Variable c_int '0'
CKM_IDEA_KEY_GEN = 832 # Variable c_int '832'
SSL_ENABLE_RENEGOTIATION = 20 # Variable c_int '20'
CRL_DECODE_SKIP_ENTRIES = 2 # Variable c_int '2'
PR_PROTOCOL_NOT_SUPPORTED_ERROR = -5964 # Variable c_long '-0x00000174cl'
CKM_SHA224_HMAC = 598 # Variable c_int '598'
CKM_SKIPJACK_CFB64 = 4100 # Variable c_int '4100'
PR_POLL_ERR = 8 # Variable c_int '8'
CKM_JUNIPER_KEY_GEN = 4192 # Variable c_int '4192'
CKM_SHA384_RSA_PKCS_PSS = 68 # Variable c_int '68'
SSL_NUM_WRAP_MECHS = 16 # Variable c_int '16'
CKM_PBE_SHA1_RC4_128 = 934 # Variable c_int '934'
CKA_TRUST_IPSEC_END_SYSTEM = 3461571420L # Variable c_uint '-833395876u'
CKM_SHA224_RSA_PKCS_PSS = 71 # Variable c_int '71'
PR_ILLEGAL_ACCESS_ERROR = -5995 # Variable c_long '-0x00000176bl'
CKM_SHA512 = 624 # Variable c_int '624'
CKM_CAST3_MAC_GENERAL = 788 # Variable c_int '788'
FIOSETOWN = 35073 # Variable c_int '35073'
CKM_CAST128_MAC = 803 # Variable c_int '803'
__USE_XOPEN2K8XSI = 1 # Variable c_int '1'
CKA_RESET_ON_INIT = 769 # Variable c_int '769'
_SYS_CDEFS_H = 1 # Variable c_int '1'
CKK_DSA = 1 # Variable c_int '1'
_IO_IS_FILEBUF = 8192 # Variable c_int '8192'
CKR_RANDOM_NO_RNG = 289 # Variable c_int '289'
_IOS_OUTPUT = 2 # Variable c_int '2'
_POSIX_V6_ILP32_OFFBIG = 1 # Variable c_int '1'
SO_ATTACH_FILTER = 26 # Variable c_int '26'
PK11_PW_AUTHENTICATED = 'AUTH' # Variable STRING '(const char*)"AUTH"'
CKU_SO = 0 # Variable c_int '0'
CKM_CDMF_CBC_PAD = 325 # Variable c_int '325'
PR_UNKNOWN_ERROR = -5994 # Variable c_long '-0x00000176al'
CKA_CHAR_COLUMNS = 1028 # Variable c_int '1028'
CKM_ECMQV_DERIVE = 4178 # Variable c_int '4178'
SO_RCVTIMEO = 20 # Variable c_int '20'
_IO_LEFT = 2 # Variable c_int '2'
CKM_PBE_MD2_DES_CBC = 928 # Variable c_int '928'
CKM_SHA512_HMAC_GENERAL = 626 # Variable c_int '626'
PK11_OWN_PW_DEFAULTS = 536870912 # Variable c_long '536870912l'
CKM_SSL3_MD5_MAC = 896 # Variable c_int '896'
ERROR_TABLE_BASE_nspr = -6000 # Variable c_long '-0x000001770l'
PR_PENDING_INTERRUPT_ERROR = -5993 # Variable c_long '-0x000001769l'
SEC_ASN1_POINTER = 4096 # Variable c_int '4096'
CKA_END_DATE = 273 # Variable c_int '273'
_IO_SHOWPOINT = 256 # Variable c_int '256'
SEC_ASN1_IA5_STRING = 22 # Variable c_int '22'
_POSIX_MEMLOCK = 200809 # Variable c_long '200809l'
_ARPA_INET_H = 1 # Variable c_int '1'
CKM_PBE_MD5_CAST5_CBC = 932 # Variable c_int '932'
DER_SEQUENCE = 16 # Variable c_int '16'
_IO_UNBUFFERED = 2 # Variable c_int '2'
SO_SNDBUFFORCE = 32 # Variable c_int '32'
MCAST_INCLUDE = 1 # Variable c_int '1'
SECMOD_FIPS_NAME = 'NSS Internal FIPS PKCS #11 Module' # Variable STRING '(const char*)"NSS Internal FIPS PKCS #11 Module"'
TRY_AGAIN = 2 # Variable c_int '2'
EAI_INPROGRESS = -100 # Variable c_int '-0x000000064'
_IO_SHOWPOS = 1024 # Variable c_int '1024'
CKM_SHA224_HMAC_GENERAL = 599 # Variable c_int '599'
MD5_LENGTH = 16 # Variable c_int '16'
DER_NULL = 5 # Variable c_int '5'
CKR_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
CKA_TRUST_STEP_UP_APPROVED = 3461571424L # Variable c_uint '-833395872u'
SESS_TICKET_KEY_VAR_NAME_LEN = 12 # Variable c_int '12'
CKR_MECHANISM_INVALID = 112 # Variable c_int '112'
SESS_TICKET_KEY_NAME_LEN = 16 # Variable c_int '16'
_NETDB_H = 1 # Variable c_int '1'
CKM_ECDH1_DERIVE = 4176 # Variable c_int '4176'
CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 260 # Variable c_int '260'
_LFS_ASYNCHRONOUS_IO = 1 # Variable c_int '1'
SECMOD_RESERVED_FLAG = 134217728 # Variable c_long '134217728l'
DER_INDEFINITE = 8192 # Variable c_int '8192'
CKM_JUNIPER_SHUFFLE = 4196 # Variable c_int '4196'
SOMAXCONN = 128 # Variable c_int '128'
__LP64_OFF64_LDFLAGS = '-m64' # Variable STRING '(const char*)"-m64"'
CKT_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
IPV6_RECVDSTOPTS = 58 # Variable c_int '58'
IPV6_MTU = 24 # Variable c_int '24'
__USE_BSD = 1 # Variable c_int '1'
CKR_RANDOM_SEED_NOT_SUPPORTED = 288 # Variable c_int '288'
CKA_WRAP_WITH_TRUSTED = 528 # Variable c_int '528'
__have_sigval_t = 1 # Variable c_int '1'
SSL3_MASTER_SECRET_LENGTH = 48 # Variable c_int '48'
_IOS_NOREPLACE = 64 # Variable c_int '64'
INADDR_UNSPEC_GROUP = 3758096384L # Variable c_uint '-536870912u'
CKM_SKIPJACK_WRAP = 4104 # Variable c_int '4104'
CKA_BASE = 306 # Variable c_int '306'
PR_POLL_HUP = 32 # Variable c_int '32'
CKM_SHA1_RSA_X9_31 = 12 # Variable c_int '12'
CRL_DECODE_KEEP_BAD_CRL = 4 # Variable c_int '4'
CKF_EXTENSION = 2147483648L # Variable c_uint '-2147483648u'
PR_LD_LOCAL = 8 # Variable c_int '8'
PR_INT32_MAX = 2147483647 # Variable c_int '2147483647'
CKM_PBE_SHA1_DES3_EDE_CBC = 936 # Variable c_int '936'
SEC_ASN1_SEQUENCE_OF = 8208 # Variable c_int '8208'
CKM_SSL3_SHA1_MAC = 897 # Variable c_int '897'
__ILP32_OFF32_LDFLAGS = '-m32' # Variable STRING '(const char*)"-m32"'
CKF_LIBRARY_CANT_CREATE_OS_THREADS = 1 # Variable c_int '1'
IPV6_NEXTHOP = 9 # Variable c_int '9'
CKA_NSS_OVERRIDE_EXTENSIONS = 3461563241L # Variable c_uint '-833404055u'
CKM_SKIPJACK_KEY_GEN = 4096 # Variable c_int '4096'
__STDC_IEC_559_COMPLEX__ = 1 # Variable c_int '1'
DER_VISIBLE_STRING = 26 # Variable c_int '26'
CKK_CAMELLIA = 37 # Variable c_int '37'
ssl_SEND_FLAG_MASK = 2130706432 # Variable c_int '2130706432'
SEC_CERT_NICKNAMES_SERVER = 3 # Variable c_int '3'
SEC_CERT_NICKNAMES_CA = 4 # Variable c_int '4'
CKM_DES3_KEY_GEN = 305 # Variable c_int '305'
_XOPEN_XCU_VERSION = 4 # Variable c_int '4'
CRL_IMPORT_BYPASS_CHECKS = 1 # Variable c_int '1'
__SIGEV_PAD_SIZE = 13L # Variable c_uint '13u'
PR_DIRECTORY_OPEN_ERROR = -5988 # Variable c_long '-0x000001764l'
IPV6_CHECKSUM = 7 # Variable c_int '7'
SEC_ASN1_SAVE = 131072 # Variable c_int '131072'
CKA_SIGN = 264 # Variable c_int '264'
CKM_RSA_X9_31_KEY_PAIR_GEN = 10 # Variable c_int '10'
CKA_ENCODING_METHODS = 1153 # Variable c_int '1153'
CKF_SO_PIN_TO_BE_CHANGED = 8388608 # Variable c_int '8388608'
CKZ_SALT_SPECIFIED = 1 # Variable c_int '1'
_XOPEN_CRYPT = 1 # Variable c_int '1'
CKM_SKIPJACK_CFB32 = 4101 # Variable c_int '4101'
SSL_MAX_EXTENSIONS = 5 # Variable c_int '5'
DER_PRIMITIVE = 0 # Variable c_int '0'
_POSIX_IPV6 = 200809 # Variable c_long '200809l'
_G_NEED_STDARG_H = 1 # Variable c_int '1'
CKM_AES_MAC = 4227 # Variable c_int '4227'
CKA_COLOR = 1029 # Variable c_int '1029'
CKD_SHA1_KDF = 2 # Variable c_int '2'
SECMOD_FIPS_FLAGS = 'Flags=internal,critical,fips slotparams=(3={slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]})' # Variable STRING '(const char*)"Flags=internal,critical,fips slotparams=(3={slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]})"'
certificateUsageUserCertImport = 128 # Variable c_int '128'
CKM_MD5_RSA_PKCS = 5 # Variable c_int '5'
CKR_DATA_LEN_RANGE = 33 # Variable c_int '33'
CKM_DSA = 17 # Variable c_int '17'
_ATFILE_SOURCE = 1 # Variable c_int '1'
_KEYTHI_H_ = 1 # Variable c_int '1'
PR_IO_PENDING_ERROR = -5989 # Variable c_long '-0x000001765l'
EXT_KEY_USAGE_TIME_STAMP = 32768 # Variable c_int '32768'
SSL_CONNECTIONID_BYTES = 16 # Variable c_int '16'
SSL_ENABLE_DEFLATE = 19 # Variable c_int '19'
CKM_CAST3_MAC = 787 # Variable c_int '787'
CKF_SO_PIN_LOCKED = 4194304 # Variable c_int '4194304'
CERT_POLICY_FLAG_EXPLICIT = 2 # Variable c_int '2'
PR_MAX_IOVECTOR_SIZE = 16 # Variable c_int '16'
CKA_TRUST = 3461571408L # Variable c_uint '-833395888u'
CKR_SIGNATURE_INVALID = 192 # Variable c_int '192'
DER_OCTET_STRING = 4 # Variable c_int '4'
CKR_INFORMATION_SENSITIVE = 368 # Variable c_int '368'
IP_PASSSEC = 18 # Variable c_int '18'
CKM_SKIPJACK_PRIVATE_WRAP = 4105 # Variable c_int '4105'
__SIZEOF_PTHREAD_CONDATTR_T = 4 # Variable c_int '4'
SSL_CBP_SSL3 = 1 # Variable c_int '1'
F_ULOCK = 0 # Variable c_int '0'
NSS_USE_ALG_IN_CERT_SIGNATURE = 1 # Variable c_int '1'
PR_NSPR_IO_LAYER = 0 # Variable c_int '0'
CERT_REV_M_STOP_TESTING_ON_FRESH_INFO = 0 # Variable c_long '0l'
_PATH_NSSWITCH_CONF = '/etc/nsswitch.conf' # Variable STRING '(const char*)"/etc/nsswitch.conf"'
CKR_SESSION_HANDLE_INVALID = 179 # Variable c_int '179'
SEC_ASN1_PRIMITIVE = 0 # Variable c_int '0'
PR_ALREADY_INITIATED_ERROR = -5933 # Variable c_long '-0x00000172dl'
_POSIX_V7_ILP32_OFFBIG = 1 # Variable c_int '1'
PR_NO_DEVICE_SPACE_ERROR = -5956 # Variable c_long '-0x000001744l'
CERT_POLICY_FLAG_NO_ANY = 4 # Variable c_int '4'
_ALLOCA_H = 1 # Variable c_int '1'
SO_MARK = 36 # Variable c_int '36'
SSL_CBP_TLS1_0 = 2 # Variable c_int '2'
__USE_POSIX199309 = 1 # Variable c_int '1'
DER_BIT_STRING = 3 # Variable c_int '3'
SEC_ASN1_UNIVERSAL = 0 # Variable c_int '0'
PR_POLL_NVAL = 16 # Variable c_int '16'
GS_MAC = 2 # Variable c_int '2'
__ILP32_OFFBIG_LDFLAGS = '-m32' # Variable STRING '(const char*)"-m32"'
CKK_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
MAX_MAC_CONTEXT_BYTES = 400 # Variable c_int '400'
__lldiv_t_defined = 1 # Variable c_int '1'
PR_NSEC_PER_MSEC = 1000000L # Variable c_ulong '1000000ul'
__SIZEOF_PTHREAD_BARRIER_T = 20 # Variable c_int '20'
_IOS_BIN = 128 # Variable c_int '128'
CKM_WTLS_PRF = 979 # Variable c_int '979'
_CTYPE_H = 1 # Variable c_int '1'
MCAST_JOIN_SOURCE_GROUP = 46 # Variable c_int '46'
CKK_AES = 31 # Variable c_int '31'
CKA_SENSITIVE = 259 # Variable c_int '259'
PR_SHM_READONLY = 1 # Variable c_int '1'
NSS_USE_ALG_RESERVED = 4294967292L # Variable c_uint '-4u'
CKR_SESSION_EXISTS = 182 # Variable c_int '182'
CKZ_DATA_SPECIFIED = 1 # Variable c_int '1'
CKR_OBJECT_HANDLE_INVALID = 130 # Variable c_int '130'
SSL_HANDSHAKE_AS_CLIENT = 5 # Variable c_int '5'
__WNOTHREAD = 536870912 # Variable c_int '536870912'
CKM_DES_CBC_ENCRYPT_DATA = 4353 # Variable c_int '4353'
_IOFBF = 0 # Variable c_int '0'
CK_INVALID_SESSION = 0 # Variable c_int '0'
CKA_PUBLIC_EXPONENT = 290 # Variable c_int '290'
CKM_NSS = 3461563216L # Variable c_uint '-833404080u'
CKM_CAST_MAC = 771 # Variable c_int '771'
RF_CA_COMPROMISE = 32 # Variable c_int '32'
CKR_KEY_FUNCTION_NOT_PERMITTED = 104 # Variable c_int '104'
CKM_MD2_HMAC = 513 # Variable c_int '513'
CKM_IDEA_ECB = 833 # Variable c_int '833'
CKR_MUTEX_NOT_LOCKED = 417 # Variable c_int '417'
CKK_JUNIPER = 29 # Variable c_int '29'
CKM_CAMELLIA_MAC_GENERAL = 1364 # Variable c_int '1364'
_POSIX_TRACE_EVENT_FILTER = -1 # Variable c_int '-0x000000001'
__USE_XOPEN_EXTENDED = 1 # Variable c_int '1'
CKM_RIPEMD160_RSA_PKCS = 8 # Variable c_int '8'
SO_DONTROUTE = 5 # Variable c_int '5'
IPV6_2292RTHDR = 5 # Variable c_int '5'
CKM_DES_MAC_GENERAL = 292 # Variable c_int '292'
SEC_CERT_CLASS_CA = 1 # Variable c_int '1'
CKM_RC2_CBC = 258 # Variable c_int '258'
PR_INT32_MIN = -2147483648 # Variable c_int '-0x080000000'
IPV6_PMTUDISC_PROBE = 3 # Variable c_int '3'
NO_RECOVERY = 3 # Variable c_int '3'
_LFS_LARGEFILE = 1 # Variable c_int '1'
CKU_CONTEXT_SPECIFIC = 2 # Variable c_int '2'
CKM_RSA_PKCS_PSS = 13 # Variable c_int '13'
CKM_RSA_PKCS_KEY_PAIR_GEN = 0 # Variable c_int '0'
SFTK_MAX_FIPS_USER_SLOT_ID = 127 # Variable c_int '127'
CKM_IDEA_CBC_PAD = 837 # Variable c_int '837'
_POSIX_PRIORITY_SCHEDULING = 200809 # Variable c_long '200809l'
WEXITED = 4 # Variable c_int '4'
certificateUsageCheckAllUsages = 0 # Variable c_int '0'
CKM_RIPEMD160_HMAC_GENERAL = 578 # Variable c_int '578'
CKM_RC2_MAC = 259 # Variable c_int '259'
CKF_SO_PIN_COUNT_LOW = 1048576 # Variable c_int '1048576'
CKR_PIN_LEN_RANGE = 162 # Variable c_int '162'
PR_ACCESS_FAULT_ERROR = -5997 # Variable c_long '-0x00000176dl'
CKM_CONCATENATE_BASE_AND_KEY = 864 # Variable c_int '864'
_XOPEN_XPG2 = 1 # Variable c_int '1'
_XOPEN_XPG3 = 1 # Variable c_int '1'
_XOPEN_XPG4 = 1 # Variable c_int '1'
CKM_DES_CFB64 = 338 # Variable c_int '338'
_POSIX_NO_TRUNC = 1 # Variable c_int '1'
IPV6_MULTICAST_LOOP = 19 # Variable c_int '19'
_LFS64_LARGEFILE = 1 # Variable c_int '1'
NS_CERT_TYPE_EMAIL_CA = 2 # Variable c_int '2'
ssl_V3_SUITES_IMPLEMENTED = 30 # Variable c_int '30'
SECMOD_AES_FLAG = 8192 # Variable c_long '8192l'
PR_IS_DIRECTORY_ERROR = -5953 # Variable c_long '-0x000001741l'
SEC_ASN1_CLASS_MASK = 192 # Variable c_int '192'
IPPORT_RESERVED = 1024 # Variable c_int '1024'
CKM_RIPEMD160 = 576 # Variable c_int '576'
PR_EXCL = 128 # Variable c_int '128'
EAI_SERVICE = -8 # Variable c_int '-0x000000008'
__USE_XOPEN = 1 # Variable c_int '1'
PR_VERSION = '4.8.6' # Variable STRING '(const char*)"4.8.6"'
CKM_SHA512_KEY_DERIVATION = 917 # Variable c_int '917'
CIS_HAVE_FINISHED = 4 # Variable c_int '4'
____FILE_defined = 1 # Variable c_int '1'
DER_SKIP = 32768 # Variable c_int '32768'
CKR_ATTRIBUTE_READ_ONLY = 16 # Variable c_int '16'
IP_PMTUDISC = 10 # Variable c_int '10'
CKM_RC5_CBC_PAD = 821 # Variable c_int '821'
SO_PRIORITY = 12 # Variable c_int '12'
CKC_WTLS = 2 # Variable c_int '2'
__USE_ATFILE = 1 # Variable c_int '1'
TMP_MAX = 238328 # Variable c_int '238328'
CKM_PKCS5_PBKD2 = 944 # Variable c_int '944'
_IO_NO_WRITES = 8 # Variable c_int '8'
CKM_CAST5_CBC_PAD = 805 # Variable c_int '805'
PK11_ATTR_PRIVATE = 4 # Variable c_long '4l'
_G_HAVE_IO_FILE_OPEN = 1 # Variable c_int '1'
CKM_WTLS_PRE_MASTER_KEY_GEN = 976 # Variable c_int '976'
__FILE_defined = 1 # Variable c_int '1'
DER_IA5_STRING = 22 # Variable c_int '22'
IPV6_PMTUDISC_WANT = 1 # Variable c_int '1'
_POSIX_ASYNCHRONOUS_IO = 200809 # Variable c_long '200809l'
CKM_DES3_MAC_GENERAL = 309 # Variable c_int '309'
SEC_ASN1_ANY_CONTENTS = 66560 # Variable c_int '66560'
_IO_CURRENTLY_PUTTING = 2048 # Variable c_int '2048'
IPV6_IPSEC_POLICY = 34 # Variable c_int '34'
__SOCKADDR_COMMON_SIZE = 2L # Variable c_uint '2u'
CKR_TEMPLATE_INCONSISTENT = 209 # Variable c_int '209'
CKK_TWOFISH = 33 # Variable c_int '33'
SO_BSDCOMPAT = 14 # Variable c_int '14'
PR_SEM_EXCL = 2 # Variable c_int '2'
SO_SNDLOWAT = 19 # Variable c_int '19'
CKA_WRAP = 262 # Variable c_int '262'
SSL3_SESSIONID_BYTES = 32 # Variable c_int '32'
IP_TOS = 1 # Variable c_int '1'
IPV6_RECVPKTINFO = 49 # Variable c_int '49'
CKG_MGF1_SHA256 = 2 # Variable c_int '2'
__USE_ISOC95 = 1 # Variable c_int '1'
PR_NO_SEEK_DEVICE_ERROR = -5954 # Variable c_long '-0x000001742l'
SEC_ASN1_VIDEOTEX_STRING = 21 # Variable c_int '21'
_POSIX_TRACE_LOG = -1 # Variable c_int '-0x000000001'
_G_IO_IO_FILE_VERSION = 131073 # Variable c_int '131073'
_POSIX_C_SOURCE = 200809 # Variable c_long '200809l'
CKS_RW_SO_FUNCTIONS = 4 # Variable c_int '4'
PR_SYS_DESC_TABLE_FULL_ERROR = -5970 # Variable c_long '-0x000001752l'
CKM_CAST5_MAC = 803 # Variable c_int '803'
SEC_ASN1_GRAPHIC_STRING = 25 # Variable c_int '25'
__USE_SVID = 1 # Variable c_int '1'
CKM_CDMF_KEY_GEN = 320 # Variable c_int '320'
_IO_IS_APPENDING = 4096 # Variable c_int '4096'
PR_BAD_ADDRESS_ERROR = -5983 # Variable c_long '-0x00000175fl'
SEC_ASN1_SEQUENCE = 16 # Variable c_int '16'
DER_CONSTRUCTED = 32 # Variable c_int '32'
__USE_ISOC99 = 1 # Variable c_int '1'
KU_ALL = 255 # Variable c_int '255'
L_ctermid = 9 # Variable c_int '9'
CKM_ECDH1_COFACTOR_DERIVE = 4177 # Variable c_int '4177'
__SIZEOF_PTHREAD_RWLOCK_T = 32 # Variable c_int '32'
CKR_USER_NOT_LOGGED_IN = 257 # Variable c_int '257'
SEC_ASN1_EXPLICIT = 512 # Variable c_int '512'
_SYS_SOCKET_H = 1 # Variable c_int '1'
NS_CERT_TYPE_CA = 16391 # Variable c_int '16391'
SEC_CERT_NICKNAMES_ALL = 1 # Variable c_int '1'
CKR_OPERATION_NOT_INITIALIZED = 145 # Variable c_int '145'
SO_SNDTIMEO = 21 # Variable c_int '21'
CKM_X9_42_DH_KEY_PAIR_GEN = 48 # Variable c_int '48'
__USE_EXTERN_INLINES = 1 # Variable c_int '1'
__SIZEOF_PTHREAD_COND_T = 48 # Variable c_int '48'
CKM_DES2_KEY_GEN = 304 # Variable c_int '304'
AI_V4MAPPED = 8 # Variable c_int '8'
CERT_REV_M_IGNORE_MISSING_FRESH_INFO = 0 # Variable c_long '0l'
CKO_MECHANISM = 7 # Variable c_int '7'
SEC_KRL_TYPE = 0 # Variable c_int '0'
RF_CESSATION_OF_OPERATION = 4 # Variable c_int '4'
CKK_CDMF = 30 # Variable c_int '30'
IN_CLASSA_NSHIFT = 24 # Variable c_int '24'
IP_MSFILTER = 41 # Variable c_int '41'
SSL_ENABLE_SSL2 = 7 # Variable c_int '7'
SSL_ENABLE_SSL3 = 8 # Variable c_int '8'
CKM_TLS_PRE_MASTER_KEY_GEN = 884 # Variable c_int '884'
CKA_MODULUS = 288 # Variable c_int '288'
IP_PMTUDISC_DONT = 0 # Variable c_int '0'
PR_INTERVAL_NO_TIMEOUT = 4294967295L # Variable c_ulong '-1ul'
_XOPEN_SOURCE_EXTENDED = 1 # Variable c_int '1'
SEC_ASN1_MAY_STREAM = 262144 # Variable c_int '262144'
SHA256_LENGTH = 32 # Variable c_int '32'
CKM_DES_CFB8 = 339 # Variable c_int '339'
CKR_PIN_INCORRECT = 160 # Variable c_int '160'
SOL_SOCKET = 1 # Variable c_int '1'
CKA_CERT_MD5_HASH = 3461571509L # Variable c_uint '-833395787u'
CKG_MGF1_SHA1 = 1 # Variable c_int '1'
CKM_CAST_CBC = 770 # Variable c_int '770'
PR_USEC_PER_SEC = 1000000L # Variable c_ulong '1000000ul'
CKM_SSL3_MASTER_KEY_DERIVE_DH = 883 # Variable c_int '883'
_BSD_SOURCE = 1 # Variable c_int '1'
IP_ADD_MEMBERSHIP = 35 # Variable c_int '35'
CKU_USER = 1 # Variable c_int '1'
AI_NUMERICSERV = 1024 # Variable c_int '1024'
CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC = 2147483651L # Variable c_ulong '-2147483645ul'
_IO_USER_BUF = 1 # Variable c_int '1'
__USE_LARGEFILE64 = 1 # Variable c_int '1'
_POSIX_CHOWN_RESTRICTED = 0 # Variable c_int '0'
_XOPEN_REALTIME_THREADS = 1 # Variable c_int '1'
NETDB_SUCCESS = 0 # Variable c_int '0'
SESS_TICKET_KEY_NAME_PREFIX_LEN = 4 # Variable c_int '4'
CKA_VERIFY_RECOVER = 267 # Variable c_int '267'
certificateUsageStatusResponder = 1024 # Variable c_int '1024'
CKR_CRYPTOKI_NOT_INITIALIZED = 400 # Variable c_int '400'
CKM_DES_CBC_PAD = 293 # Variable c_int '293'
CKR_PIN_LOCKED = 164 # Variable c_int '164'
IN_CLASSA_NET = 4278190080L # Variable c_uint '-16777216u'
CKR_CANT_LOCK = 10 # Variable c_int '10'
CKR_ATTRIBUTE_SENSITIVE = 17 # Variable c_int '17'
__ILP32_OFF32_CFLAGS = '-m32' # Variable STRING '(const char*)"-m32"'
CKM_FAKE_RANDOM = 2147487486L # Variable c_ulong '-2147479810ul'
CKF_EC_F_2M = 2097152 # Variable c_int '2097152'
_IO_DELETE_DONT_CLOSE = 64 # Variable c_int '64'
CKM_DH_PKCS_KEY_PAIR_GEN = 32 # Variable c_int '32'
SECKEY_CKA_PRIVATE = 2L # Variable c_uint '2u'
IP_RECVTOS = 13 # Variable c_int '13'
PK11_ATTR_UNMODIFIABLE = 32 # Variable c_long '32l'
CKM_NETSCAPE_PBE_SHA1_DES_CBC = 2147483650L # Variable c_ulong '-2147483646ul'
SECMOD_FORTEZZA_FLAG = 64 # Variable c_long '64l'
CKM_CAST3_CBC_PAD = 789 # Variable c_int '789'
CKM_RC4 = 273 # Variable c_int '273'
RF_SUPERSEDED = 8 # Variable c_int '8'
EAI_ALLDONE = -103 # Variable c_int '-0x000000067'
CKF_USER_PIN_INITIALIZED = 8 # Variable c_int '8'
SSL3_RSA_PMS_LENGTH = 48 # Variable c_int '48'
SO_SNDBUF = 7 # Variable c_int '7'
IPV6_UNICAST_HOPS = 16 # Variable c_int '16'
CKA_SECONDARY_AUTH = 512 # Variable c_int '512'
CKA_VALUE_BITS = 352 # Variable c_int '352'
PR_FILE_NOT_FOUND_ERROR = -5950 # Variable c_long '-0x00000173el'
CKM_SHA224_KEY_DERIVATION = 918 # Variable c_int '918'
HT_ENUMERATE_NEXT = 0 # Variable c_int '0'
DER_T61_STRING = 20 # Variable c_int '20'
SOL_ICMPV6 = 58 # Variable c_int '58'
IPV6_ROUTER_ALERT = 22 # Variable c_int '22'
SFTK_MIN_FIPS_USER_SLOT_ID = 101 # Variable c_int '101'
CKF_HW_SLOT = 4 # Variable c_int '4'
DER_DERPTR = 16384 # Variable c_int '16384'
L_tmpnam = 20 # Variable c_int '20'
CKA_TRUST_DATA_ENCIPHERMENT = 3461571412L # Variable c_uint '-833395884u'
DER_TAG_MASK = 255 # Variable c_int '255'
CKA_LABEL = 3 # Variable c_int '3'
__USE_MISC = 1 # Variable c_int '1'
CKA_TRUST_CRL_SIGN = 3461571415L # Variable c_uint '-833395881u'
CKM_PBE_SHA1_CAST5_CBC = 933 # Variable c_int '933'
__USE_EXTERN_INLINES_IN_LIBC = 1 # Variable c_int '1'
NETDB_INTERNAL = -1 # Variable c_int '-0x000000001'
PK11_ATTR_UNEXTRACTABLE = 512 # Variable c_long '512l'
CKR_SESSION_COUNT = 177 # Variable c_int '177'
CKM_JUNIPER_ECB128 = 4193 # Variable c_int '4193'
IN_CLASSB_NET = 4294901760L # Variable c_uint '-65536u'
CKA_TRUSTED = 134 # Variable c_int '134'
CKA_JAVA_MIDP_SECURITY_DOMAIN = 136 # Variable c_int '136'
CKM_CAST3_CBC = 786 # Variable c_int '786'
IP_TRANSPARENT = 19 # Variable c_int '19'
PR_LIBRARY_NOT_LOADED_ERROR = -5926 # Variable c_long '-0x000001726l'
PR_INTERVAL_NO_WAIT = 0L # Variable c_ulong '0ul'
PR_ADDRESS_NOT_AVAILABLE_ERROR = -5986 # Variable c_long '-0x000001762l'
SECMOD_END_WAIT = 1 # Variable c_int '1'
L_cuserid = 9 # Variable c_int '9'
_SYS_SYSMACROS_H = 1 # Variable c_int '1'
CKC_X_509 = 0 # Variable c_int '0'
CKA_NEVER_EXTRACTABLE = 356 # Variable c_int '356'
CKA_UNWRAP = 263 # Variable c_int '263'
PR_DEVICE_IS_LOCKED_ERROR = -5940 # Variable c_long '-0x000001734l'
certificateUsageEmailRecipient = 32 # Variable c_int '32'
__SIGEV_MAX_SIZE = 64 # Variable c_int '64'
__USE_POSIX199506 = 1 # Variable c_int '1'
CKR_SESSION_CLOSED = 176 # Variable c_int '176'
W_OK = 2 # Variable c_int '2'
CKK_INVALID_KEY_TYPE = 4294967295L # Variable c_uint '-1u'
_POSIX_MESSAGE_PASSING = 200809 # Variable c_long '200809l'
_POSIX_THREAD_PRIORITY_SCHEDULING = 200809 # Variable c_long '200809l'
CKH_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
CKF_USER_PIN_TO_BE_CHANGED = 524288 # Variable c_int '524288'
ssl_SHUTDOWN_RCV = 1 # Variable c_int '1'
SEC_ASN1_GENERALIZED_TIME = 24 # Variable c_int '24'
PR_RANGE_ERROR = -5960 # Variable c_long '-0x000001748l'
DER_TAGNUM_MASK = 31 # Variable c_int '31'
_G_HAVE_PRINTF_FP = 1 # Variable c_int '1'
_SECMODT_H_ = 1 # Variable c_int '1'
DER_INLINE = 2048 # Variable c_int '2048'
WCONTINUED = 8 # Variable c_int '8'
CKM_SHA384_HMAC_GENERAL = 610 # Variable c_int '610'
CKR_FUNCTION_NOT_PARALLEL = 81 # Variable c_int '81'
CKM_SHA1_KEY_DERIVATION = 914 # Variable c_int '914'
CKA_NSS = 3461563216L # Variable c_uint '-833404080u'
CKR_SESSION_READ_ONLY = 181 # Variable c_int '181'
PR_INT8_MIN = -128 # Variable c_int '-0x000000080'
EXIT_FAILURE = 1 # Variable c_int '1'
PR_BAD_DESCRIPTOR_ERROR = -5999 # Variable c_long '-0x00000176fl'
CKM_PBE_SHA1_RC2_128_CBC = 938 # Variable c_int '938'
CKR_PIN_INVALID = 161 # Variable c_int '161'
CKP_PKCS5_PBKD2_HMAC_SHA1 = 1 # Variable c_int '1'
CKR_FUNCTION_CANCELED = 80 # Variable c_int '80'
IS_LITTLE_ENDIAN = 1 # Variable c_int '1'
PRTRACE_NAME_MAX = 31 # Variable c_int '31'
INADDR_ALLRTRS_GROUP = 3758096386L # Variable c_uint '-536870910u'
PR_INTERVAL_MAX = 100000L # Variable c_ulong '100000ul'
IP_PMTUDISC_PROBE = 3 # Variable c_int '3'
_POSIX_THREAD_ATTR_STACKSIZE = 200809 # Variable c_long '200809l'
_PKCS11T_H_ = 1 # Variable c_int '1'
_SS_PADSIZE = 120L # Variable c_uint '120u'
CKA_TOKEN = 1 # Variable c_int '1'
CKM_XOR_BASE_AND_DATA = 868 # Variable c_int '868'
PR_NETWORK_DOWN_ERROR = -5930 # Variable c_long '-0x00000172al'
PR_TRUNCATE = 32 # Variable c_int '32'
CKF_RESTORE_KEY_NOT_NEEDED = 32 # Variable c_int '32'
CKR_WRAPPING_KEY_HANDLE_INVALID = 275 # Variable c_int '275'
SECMOD_CAMELLIA_FLAG = 65536 # Variable c_long '65536l'
PR_VMAJOR = 4 # Variable c_int '4'
PR_IWUSR = 128 # Variable c_int '128'
_G_VTABLE_LABEL_PREFIX = '__vt_' # Variable STRING '(const char*)"__vt_"'
CKM_BATON_ECB128 = 4145 # Variable c_int '4145'
_SYS_SELECT_H = 1 # Variable c_int '1'
CKM_JUNIPER_WRAP = 4197 # Variable c_int '4197'
_POSIX_THREAD_ROBUST_PRIO_PROTECT = -1 # Variable c_int '-0x000000001'
CKM_SHA256_KEY_DERIVATION = 915 # Variable c_int '915'
_ISOC95_SOURCE = 1 # Variable c_int '1'
CKF_ARRAY_ATTRIBUTE = 1073741824 # Variable c_int '1073741824'
CKF_DECRYPT = 512 # Variable c_int '512'
CKO_SECRET_KEY = 4 # Variable c_int '4'
CKM_EC_KEY_PAIR_GEN = 4160 # Variable c_int '4160'
CKF_UNWRAP = 262144 # Variable c_int '262144'
AI_CANONNAME = 2 # Variable c_int '2'
CKA_VALUE_LEN = 353 # Variable c_int '353'
__clock_t_defined = 1 # Variable c_int '1'
_STDIO_H = 1 # Variable c_int '1'
AI_PASSIVE = 1 # Variable c_int '1'
ssl_SHUTDOWN_NONE = 0 # Variable c_int '0'
SSL_LOCK_RANK_SPEC = 255 # Variable c_int '255'
_IO_UPPERCASE = 512 # Variable c_int '512'
SEC_ASN1_BOOLEAN = 1 # Variable c_int '1'
SECMOD_EXTERNAL = 0 # Variable c_int '0'
CKR_OPERATION_ACTIVE = 144 # Variable c_int '144'
CKM_BATON_COUNTER = 4148 # Variable c_int '4148'
_IO_EOF_SEEN = 16 # Variable c_int '16'
CKA_TRUST_CLIENT_AUTH = 3461571417L # Variable c_uint '-833395879u'
SEC_ASN1_INNER = 65536 # Variable c_int '65536'
NS_CERT_TYPE_RESERVED = 8 # Variable c_int '8'
INADDR_NONE = 4294967295L # Variable c_uint '-1u'
LL_MAXINT = 9223372036854775807L # Variable c_longlong '0x7fffffffffffffffll'
CKM_RC4_KEY_GEN = 272 # Variable c_int '272'
PR_IN_PROGRESS_ERROR = -5934 # Variable c_long '-0x00000172el'
PR_OUT_OF_MEMORY_ERROR = -6000 # Variable c_long '-0x000001770l'
_SS_SIZE = 128 # Variable c_int '128'
PR_INVALID_ARGUMENT_ERROR = -5987 # Variable c_long '-0x000001763l'
CKM_SHA384_RSA_PKCS = 65 # Variable c_int '65'
CKM_CAMELLIA_ECB_ENCRYPT_DATA = 1366 # Variable c_int '1366'
CKM_CAST_KEY_GEN = 768 # Variable c_int '768'
SSL_SOCKS = 2 # Variable c_int '2'
__USE_UNIX98 = 1 # Variable c_int '1'
CKG_MGF1_SHA384 = 3 # Variable c_int '3'
PR_USEC_PER_MSEC = 1000L # Variable c_ulong '1000ul'
_POSIX_SPIN_LOCKS = 200809 # Variable c_long '200809l'
CKO_NSS = 3461563216L # Variable c_uint '-833404080u'
SSL2_SESSIONID_BYTES = 16 # Variable c_int '16'
_IO_OCT = 32 # Variable c_int '32'
CKR_WRAPPED_KEY_INVALID = 272 # Variable c_int '272'
_POSIX_PRIORITIZED_IO = 200809 # Variable c_long '200809l'
CKM_SHA224_RSA_PKCS = 70 # Variable c_int '70'
CKM_CAMELLIA_MAC = 1363 # Variable c_int '1363'
CKR_USER_TOO_MANY_TYPES = 261 # Variable c_int '261'
AI_IDN_USE_STD3_ASCII_RULES = 512 # Variable c_int '512'
NI_MAXSERV = 32 # Variable c_int '32'
PR_RDONLY = 1 # Variable c_int '1'
EAI_IDN_ENCODE = -105 # Variable c_int '-0x000000069'
CKR_WRAPPED_KEY_LEN_RANGE = 274 # Variable c_int '274'
IPV6_JOIN_ANYCAST = 27 # Variable c_int '27'
_IO_FLAGS2_USER_WBUF = 8 # Variable c_int '8'
CKM_DES_OFB64 = 336 # Variable c_int '336'
_XOPEN_UNIX = 1 # Variable c_int '1'
CKA_CERTIFICATE_TYPE = 128 # Variable c_int '128'
_IO_MAGIC_MASK = 4294901760L # Variable c_uint '-65536u'
PR_IXGRP = 8 # Variable c_int '8'
PR_IWOTH = 2 # Variable c_int '2'
HT_FREE_ENTRY = 1 # Variable c_int '1'
CERT_REV_M_CONTINUE_TESTING_ON_FRESH_INFO = 32 # Variable c_long '32l'
IPV6_XFRM_POLICY = 35 # Variable c_int '35'
CKA_ID = 258 # Variable c_int '258'
LL_ZERO = 0L # Variable c_longlong '0ll'
HOST_NOT_FOUND = 1 # Variable c_int '1'
IP_MULTICAST_IF = 32 # Variable c_int '32'
EAI_BADFLAGS = -1 # Variable c_int '-0x000000001'
_POSIX_TRACE_INHERIT = -1 # Variable c_int '-0x000000001'
SEC_CERT_CLASS_SERVER = 2 # Variable c_int '2'
KU_KEY_CERT_SIGN = 4 # Variable c_int '4'
CKM_CDMF_MAC = 323 # Variable c_int '323'
_POSIX_THREADS = 200809 # Variable c_long '200809l'
_IOLBF = 1 # Variable c_int '1'
_G_int16_t = c_short
_G_int32_t = c_int
_G_uint16_t = c_ushort
_G_uint32_t = c_uint

# values for unnamed enumeration

# values for unnamed enumeration

# values for unnamed enumeration
class ip_opts(Structure):
    pass
class in_addr(Structure):
    pass
uint32_t = c_uint32
in_addr_t = uint32_t
in_addr._fields_ = [
    ('s_addr', in_addr_t),
]
ip_opts._fields_ = [
    ('ip_dst', in_addr),
    ('ip_opts', c_char * 40),
]
class ip_mreqn(Structure):
    pass
ip_mreqn._fields_ = [
    ('imr_multiaddr', in_addr),
    ('imr_address', in_addr),
    ('imr_ifindex', c_int),
]
class in_pktinfo(Structure):
    pass
in_pktinfo._fields_ = [
    ('ipi_ifindex', c_int),
    ('ipi_spec_dst', in_addr),
    ('ipi_addr', in_addr),
]
class netent(Structure):
    pass
netent._fields_ = [
    ('n_name', STRING),
    ('n_aliases', POINTER(STRING)),
    ('n_addrtype', c_int),
    ('n_net', uint32_t),
]
pthread_t = c_ulong
class pthread_attr_t(Union):
    pass
pthread_attr_t._fields_ = [
    ('__size', c_char * 36),
    ('__align', c_long),
]
class __pthread_internal_slist(Structure):
    pass
__pthread_internal_slist._fields_ = [
    ('__next', POINTER(__pthread_internal_slist)),
]
__pthread_slist_t = __pthread_internal_slist
class __pthread_mutex_s(Structure):
    pass
class N15pthread_mutex_t17__pthread_mutex_s3DOT_6E(Union):
    pass
N15pthread_mutex_t17__pthread_mutex_s3DOT_6E._fields_ = [
    ('__spins', c_int),
    ('__list', __pthread_slist_t),
]
__pthread_mutex_s._anonymous_ = ['_0']
__pthread_mutex_s._fields_ = [
    ('__lock', c_int),
    ('__count', c_uint),
    ('__owner', c_int),
    ('__kind', c_int),
    ('__nusers', c_uint),
    ('_0', N15pthread_mutex_t17__pthread_mutex_s3DOT_6E),
]
class pthread_mutex_t(Union):
    pass
pthread_mutex_t._fields_ = [
    ('__data', __pthread_mutex_s),
    ('__size', c_char * 24),
    ('__align', c_long),
]
class pthread_mutexattr_t(Union):
    pass
pthread_mutexattr_t._fields_ = [
    ('__size', c_char * 4),
    ('__align', c_int),
]
class N14pthread_cond_t3DOT_9E(Structure):
    pass
N14pthread_cond_t3DOT_9E._pack_ = 4
N14pthread_cond_t3DOT_9E._fields_ = [
    ('__lock', c_int),
    ('__futex', c_uint),
    ('__total_seq', c_ulonglong),
    ('__wakeup_seq', c_ulonglong),
    ('__woken_seq', c_ulonglong),
    ('__mutex', c_void_p),
    ('__nwaiters', c_uint),
    ('__broadcast_seq', c_uint),
]
class pthread_cond_t(Union):
    pass
pthread_cond_t._pack_ = 4
pthread_cond_t._fields_ = [
    ('__data', N14pthread_cond_t3DOT_9E),
    ('__size', c_char * 48),
    ('__align', c_longlong),
]
class pthread_condattr_t(Union):
    pass
pthread_condattr_t._fields_ = [
    ('__size', c_char * 4),
    ('__align', c_int),
]
pthread_key_t = c_uint
pthread_once_t = c_int
class N16pthread_rwlock_t4DOT_12E(Structure):
    pass
N16pthread_rwlock_t4DOT_12E._fields_ = [
    ('__lock', c_int),
    ('__nr_readers', c_uint),
    ('__readers_wakeup', c_uint),
    ('__writer_wakeup', c_uint),
    ('__nr_readers_queued', c_uint),
    ('__nr_writers_queued', c_uint),
    ('__flags', c_ubyte),
    ('__shared', c_ubyte),
    ('__pad1', c_ubyte),
    ('__pad2', c_ubyte),
    ('__writer', c_int),
]
class pthread_rwlock_t(Union):
    pass
pthread_rwlock_t._fields_ = [
    ('__data', N16pthread_rwlock_t4DOT_12E),
    ('__size', c_char * 32),
    ('__align', c_long),
]
class pthread_rwlockattr_t(Union):
    pass
pthread_rwlockattr_t._fields_ = [
    ('__size', c_char * 8),
    ('__align', c_long),
]
pthread_spinlock_t = c_int
class pthread_barrier_t(Union):
    pass
pthread_barrier_t._fields_ = [
    ('__size', c_char * 20),
    ('__align', c_long),
]
class pthread_barrierattr_t(Union):
    pass
pthread_barrierattr_t._fields_ = [
    ('__size', c_char * 4),
    ('__align', c_int),
]
class sigval(Union):
    pass
sigval._fields_ = [
    ('sival_int', c_int),
    ('sival_ptr', c_void_p),
]
sigval_t = sigval
class sigevent(Structure):
    pass
class N8sigevent4DOT_47E(Union):
    pass
class N8sigevent4DOT_474DOT_48E(Structure):
    pass
N8sigevent4DOT_474DOT_48E._fields_ = [
    ('_function', CFUNCTYPE(None, sigval_t)),
    ('_attribute', c_void_p),
]
N8sigevent4DOT_47E._fields_ = [
    ('_pad', c_int * 13),
    ('_tid', __pid_t),
    ('_sigev_thread', N8sigevent4DOT_474DOT_48E),
]
sigevent._fields_ = [
    ('sigev_value', sigval_t),
    ('sigev_signo', c_int),
    ('sigev_notify', c_int),
    ('_sigev_un', N8sigevent4DOT_47E),
]
sigevent_t = sigevent

# values for unnamed enumeration
__sig_atomic_t = c_int
class __sigset_t(Structure):
    pass
__sigset_t._fields_ = [
    ('__val', c_ulong * 32),
]
sa_family_t = c_ushort
__socklen_t = c_uint
socklen_t = __socklen_t

# values for enumeration '__socket_type'
__socket_type = c_int # enum
class sockaddr(Structure):
    pass
sockaddr._fields_ = [
    ('sa_family', sa_family_t),
    ('sa_data', c_char * 14),
]
class sockaddr_storage(Structure):
    pass
sockaddr_storage._fields_ = [
    ('ss_family', sa_family_t),
    ('__ss_align', c_ulong),
    ('__ss_padding', c_char * 120),
]

# values for unnamed enumeration
class msghdr(Structure):
    pass
class iovec(Structure):
    pass
msghdr._fields_ = [
    ('msg_name', c_void_p),
    ('msg_namelen', socklen_t),
    ('msg_iov', POINTER(iovec)),
    ('msg_iovlen', size_t),
    ('msg_control', c_void_p),
    ('msg_controllen', size_t),
    ('msg_flags', c_int),
]
class mmsghdr(Structure):
    pass
mmsghdr._fields_ = [
    ('msg_hdr', msghdr),
    ('msg_len', c_uint),
]
class cmsghdr(Structure):
    pass
cmsghdr._fields_ = [
    ('cmsg_len', size_t),
    ('cmsg_level', c_int),
    ('cmsg_type', c_int),
    ('__cmsg_data', c_ubyte * 0),
]

# values for unnamed enumeration
class ucred(Structure):
    pass
pid_t = __pid_t
uid_t = __uid_t
__gid_t = c_uint
gid_t = __gid_t
ucred._fields_ = [
    ('pid', pid_t),
    ('uid', uid_t),
    ('gid', gid_t),
]
class linger(Structure):
    pass
linger._fields_ = [
    ('l_onoff', c_int),
    ('l_linger', c_int),
]
class timeval(Structure):
    pass
__time_t = c_long
__suseconds_t = c_long
timeval._fields_ = [
    ('tv_sec', __time_t),
    ('tv_usec', __suseconds_t),
]
__u_char = c_ubyte
__u_short = c_ushort
__u_int = c_uint
__u_long = c_ulong
__int8_t = c_byte
__uint8_t = c_ubyte
__int16_t = c_short
__uint16_t = c_ushort
__int32_t = c_int
__uint32_t = c_uint
__int64_t = c_longlong
__uint64_t = c_ulonglong
__dev_t = __u_quad_t
__ino_t = c_ulong
__ino64_t = __u_quad_t
__mode_t = c_uint
__nlink_t = c_uint
class __fsid_t(Structure):
    pass
__fsid_t._fields_ = [
    ('__val', c_int * 2),
]
__clock_t = c_long
__rlim_t = c_ulong
__rlim64_t = __u_quad_t
__id_t = c_uint
__useconds_t = c_uint
__daddr_t = c_int
__swblk_t = c_long
__key_t = c_int
__clockid_t = c_int
__timer_t = c_void_p
__blksize_t = c_long
__blkcnt_t = c_long
__blkcnt64_t = __quad_t
__fsblkcnt_t = c_ulong
__fsblkcnt64_t = __u_quad_t
__fsfilcnt_t = c_ulong
__fsfilcnt64_t = __u_quad_t
__loff_t = __off64_t
__qaddr_t = POINTER(__quad_t)
__caddr_t = STRING
__intptr_t = c_int
iovec._fields_ = [
    ('iov_base', c_void_p),
    ('iov_len', size_t),
]
class wait(Union):
    pass
class N4wait4DOT_20E(Structure):
    pass
N4wait4DOT_20E._fields_ = [
    ('__w_termsig', c_uint, 7),
    ('__w_coredump', c_uint, 1),
    ('__w_retcode', c_uint, 8),
    ('', c_uint, 16),
]
class N4wait4DOT_21E(Structure):
    pass
N4wait4DOT_21E._fields_ = [
    ('__w_stopval', c_uint, 8),
    ('__w_stopsig', c_uint, 8),
    ('', c_uint, 16),
]
wait._fields_ = [
    ('w_status', c_int),
    ('__wait_terminated', N4wait4DOT_20E),
    ('__wait_stopped', N4wait4DOT_21E),
]

# values for unnamed enumeration
class _IO_jump_t(Structure):
    pass
_IO_jump_t._fields_ = [
]
_IO_lock_t = None
class _IO_marker(Structure):
    pass
class _IO_FILE(Structure):
    pass
_IO_marker._fields_ = [
    ('_next', POINTER(_IO_marker)),
    ('_sbuf', POINTER(_IO_FILE)),
    ('_pos', c_int),
]

# values for enumeration '__codecvt_result'
__codecvt_result = c_int # enum
_IO_FILE._pack_ = 4
_IO_FILE._fields_ = [
    ('_flags', c_int),
    ('_IO_read_ptr', STRING),
    ('_IO_read_end', STRING),
    ('_IO_read_base', STRING),
    ('_IO_write_base', STRING),
    ('_IO_write_ptr', STRING),
    ('_IO_write_end', STRING),
    ('_IO_buf_base', STRING),
    ('_IO_buf_end', STRING),
    ('_IO_save_base', STRING),
    ('_IO_backup_base', STRING),
    ('_IO_save_end', STRING),
    ('_markers', POINTER(_IO_marker)),
    ('_chain', POINTER(_IO_FILE)),
    ('_fileno', c_int),
    ('_flags2', c_int),
    ('_old_offset', __off_t),
    ('_cur_column', c_ushort),
    ('_vtable_offset', c_byte),
    ('_shortbuf', c_char * 1),
    ('_lock', POINTER(_IO_lock_t)),
    ('_offset', __off64_t),
    ('__pad1', c_void_p),
    ('__pad2', c_void_p),
    ('__pad3', c_void_p),
    ('__pad4', c_void_p),
    ('__pad5', size_t),
    ('_mode', c_int),
    ('_unused2', c_char * 40),
]
class _IO_FILE_plus(Structure):
    pass
_IO_FILE_plus._fields_ = [
]
__io_read_fn = CFUNCTYPE(__ssize_t, c_void_p, STRING, size_t)
__io_write_fn = CFUNCTYPE(__ssize_t, c_void_p, STRING, size_t)
__io_seek_fn = CFUNCTYPE(c_int, c_void_p, POINTER(__off64_t), c_int)
__io_close_fn = CFUNCTYPE(c_int, c_void_p)
cookie_read_function_t = __io_read_fn
cookie_write_function_t = __io_write_fn
cookie_seek_function_t = __io_seek_fn
cookie_close_function_t = __io_close_fn
class _IO_cookie_io_functions_t(Structure):
    pass
_IO_cookie_io_functions_t._fields_ = [
    ('read', POINTER(__io_read_fn)),
    ('write', POINTER(__io_write_fn)),
    ('seek', POINTER(__io_seek_fn)),
    ('close', POINTER(__io_close_fn)),
]
cookie_io_functions_t = _IO_cookie_io_functions_t
class _IO_cookie_file(Structure):
    pass
_IO_cookie_file._fields_ = [
]
class hostent(Structure):
    pass
hostent._fields_ = [
    ('h_name', STRING),
    ('h_aliases', POINTER(STRING)),
    ('h_addrtype', c_int),
    ('h_length', c_int),
    ('h_addr_list', POINTER(STRING)),
]
class servent(Structure):
    pass
servent._fields_ = [
    ('s_name', STRING),
    ('s_aliases', POINTER(STRING)),
    ('s_port', c_int),
    ('s_proto', STRING),
]
class protoent(Structure):
    pass
protoent._fields_ = [
    ('p_name', STRING),
    ('p_aliases', POINTER(STRING)),
    ('p_proto', c_int),
]
class addrinfo(Structure):
    pass
addrinfo._fields_ = [
    ('ai_flags', c_int),
    ('ai_family', c_int),
    ('ai_socktype', c_int),
    ('ai_protocol', c_int),
    ('ai_addrlen', socklen_t),
    ('ai_addr', POINTER(sockaddr)),
    ('ai_canonname', STRING),
    ('ai_next', POINTER(addrinfo)),
]
class gaicb(Structure):
    pass
gaicb._fields_ = [
    ('ar_name', STRING),
    ('ar_service', STRING),
    ('ar_request', POINTER(addrinfo)),
    ('ar_result', POINTER(addrinfo)),
    ('__return', c_int),
    ('__unused', c_int * 5),
]

# values for unnamed enumeration
uint16_t = c_uint16
in_port_t = uint16_t

# values for unnamed enumeration
class in6_addr(Structure):
    pass
class N8in6_addr4DOT_46E(Union):
    pass
uint8_t = c_uint8
N8in6_addr4DOT_46E._fields_ = [
    ('__u6_addr8', uint8_t * 16),
    ('__u6_addr16', uint16_t * 8),
    ('__u6_addr32', uint32_t * 4),
]
in6_addr._fields_ = [
    ('__in6_u', N8in6_addr4DOT_46E),
]
class sockaddr_in(Structure):
    pass
sockaddr_in._fields_ = [
    ('sin_family', sa_family_t),
    ('sin_port', in_port_t),
    ('sin_addr', in_addr),
    ('sin_zero', c_ubyte * 8),
]
class sockaddr_in6(Structure):
    pass
sockaddr_in6._fields_ = [
    ('sin6_family', sa_family_t),
    ('sin6_port', in_port_t),
    ('sin6_flowinfo', uint32_t),
    ('sin6_addr', in6_addr),
    ('sin6_scope_id', uint32_t),
]
class ip_mreq(Structure):
    pass
ip_mreq._fields_ = [
    ('imr_multiaddr', in_addr),
    ('imr_interface', in_addr),
]
class ip_mreq_source(Structure):
    pass
ip_mreq_source._fields_ = [
    ('imr_multiaddr', in_addr),
    ('imr_interface', in_addr),
    ('imr_sourceaddr', in_addr),
]
class ipv6_mreq(Structure):
    pass
ipv6_mreq._fields_ = [
    ('ipv6mr_multiaddr', in6_addr),
    ('ipv6mr_interface', c_uint),
]
class group_req(Structure):
    pass
group_req._fields_ = [
    ('gr_interface', uint32_t),
    ('gr_group', sockaddr_storage),
]
class group_source_req(Structure):
    pass
group_source_req._fields_ = [
    ('gsr_interface', uint32_t),
    ('gsr_group', sockaddr_storage),
    ('gsr_source', sockaddr_storage),
]
class ip_msfilter(Structure):
    pass
ip_msfilter._fields_ = [
    ('imsf_multiaddr', in_addr),
    ('imsf_interface', in_addr),
    ('imsf_fmode', uint32_t),
    ('imsf_numsrc', uint32_t),
    ('imsf_slist', in_addr * 1),
]
class group_filter(Structure):
    pass
group_filter._fields_ = [
    ('gf_interface', uint32_t),
    ('gf_group', sockaddr_storage),
    ('gf_fmode', uint32_t),
    ('gf_numsrc', uint32_t),
    ('gf_slist', sockaddr_storage * 1),
]
class in6_pktinfo(Structure):
    pass
in6_pktinfo._fields_ = [
    ('ipi6_addr', in6_addr),
    ('ipi6_ifindex', c_uint),
]
class ip6_mtuinfo(Structure):
    pass
ip6_mtuinfo._fields_ = [
    ('ip6m_addr', sockaddr_in6),
    ('ip6m_mtu', uint32_t),
]
PRUintn = c_uint
uintn = PRUintn
intn = PRIntn
uint64 = PRUint64
PRInt64 = c_longlong
int64 = PRInt64
int32 = PRInt32
PRInt16 = c_short
int16 = PRInt16
PRInt8 = c_byte
int8 = PRInt8
PRFloat64 = c_double
float64 = PRFloat64
PRUptrdiff = c_ulong
uptrdiff_t = PRUptrdiff
PRUword = c_ulong
uprword_t = PRUword
PRWord = c_long
prword_t = PRWord
PLArena._fields_ = [
    ('next', POINTER(PLArena)),
    ('base', PRUword),
    ('limit', PRUword),
    ('avail', PRUword),
]
PLArenaPool._fields_ = [
    ('first', PLArena),
    ('current', POINTER(PLArena)),
    ('arenasize', PRUint32),
    ('mask', PRUword),
]
PRSize = size_t
PLHashAllocOps._fields_ = [
    ('allocTable', CFUNCTYPE(c_void_p, c_void_p, PRSize)),
    ('freeTable', CFUNCTYPE(None, c_void_p, c_void_p)),
    ('allocEntry', CFUNCTYPE(POINTER(PLHashEntry), c_void_p, c_void_p)),
    ('freeEntry', CFUNCTYPE(None, c_void_p, POINTER(PLHashEntry), PRUintn)),
]
PLHashEntry._fields_ = [
    ('next', POINTER(PLHashEntry)),
    ('keyHash', PLHashNumber),
    ('key', c_void_p),
    ('value', c_void_p),
]
PLHashTable._fields_ = [
    ('buckets', POINTER(POINTER(PLHashEntry))),
    ('nentries', PRUint32),
    ('shift', PRUint32),
    ('keyHash', PLHashFunction),
    ('keyCompare', PLHashComparator),
    ('valueCompare', PLHashComparator),
    ('allocOps', POINTER(PLHashAllocOps)),
    ('allocPriv', c_void_p),
]
class PRStackElemStr(Structure):
    pass
PRStackElem = PRStackElemStr
PRStackElemStr._fields_ = [
    ('prstk_elem_next', POINTER(PRStackElem)),
]
class PRStackStr(Structure):
    pass
PRStackStr._fields_ = [
]
PRStack = PRStackStr
prbitmap_t = c_ulong
class PRCListStr(Structure):
    pass
PRCList = PRCListStr
PRCListStr._fields_ = [
    ('next', POINTER(PRCList)),
    ('prev', POINTER(PRCList)),
]
PRCondVar._fields_ = [
]
PRErrorCode = PRInt32
PRLanguageCode = PRUint32
class PRErrorMessage(Structure):
    pass
PRErrorMessage._fields_ = [
    ('name', STRING),
    ('en_text', STRING),
]
class PRErrorTable(Structure):
    pass
PRErrorTable._fields_ = [
    ('msgs', POINTER(PRErrorMessage)),
    ('name', STRING),
    ('base', PRErrorCode),
    ('n_msgs', c_int),
]
class PRErrorCallbackPrivate(Structure):
    pass
PRErrorCallbackPrivate._fields_ = [
]
class PRErrorCallbackTablePrivate(Structure):
    pass
PRErrorCallbackTablePrivate._fields_ = [
]
PRErrorCallbackLookupFn = CFUNCTYPE(STRING, PRErrorCode, PRLanguageCode, POINTER(PRErrorTable), POINTER(PRErrorCallbackPrivate), POINTER(PRErrorCallbackTablePrivate))
PRErrorCallbackNewTableFn = CFUNCTYPE(POINTER(PRErrorCallbackTablePrivate), POINTER(PRErrorTable), POINTER(PRErrorCallbackPrivate))
PRVersionCheck = CFUNCTYPE(PRBool, STRING)
PRPrimordialFn = CFUNCTYPE(PRIntn, PRIntn, POINTER(STRING))
class PRCallOnceType(Structure):
    pass

# values for enumeration 'PRStatus'
PRStatus = c_int # enum
PRCallOnceType._fields_ = [
    ('initialized', PRIntn),
    ('inProgress', PRInt32),
    ('status', PRStatus),
]
PRCallOnceFN = CFUNCTYPE(PRStatus)
PRCallOnceWithArgFN = CFUNCTYPE(PRStatus, c_void_p)
class PRDir(Structure):
    pass
PRDir._fields_ = [
]
class PRDirEntry(Structure):
    pass
class PRFileInfo(Structure):
    pass
class PRFileInfo64(Structure):
    pass
class PRIOMethods(Structure):
    pass
class PRPollDesc(Structure):
    pass
class PRFilePrivate(Structure):
    pass
PRFilePrivate._fields_ = [
]
class PRSendFileData(Structure):
    pass
PRDescIdentity = PRIntn
PRFileDesc._fields_ = [
    ('methods', POINTER(PRIOMethods)),
    ('secret', POINTER(PRFilePrivate)),
    ('lower', POINTER(PRFileDesc)),
    ('higher', POINTER(PRFileDesc)),
    ('dtor', CFUNCTYPE(None, POINTER(PRFileDesc))),
    ('identity', PRDescIdentity),
]

# values for enumeration 'PRTransmitFileFlags'
PRTransmitFileFlags = c_int # enum
class N9PRNetAddr4DOT_51E(Structure):
    pass
N9PRNetAddr4DOT_51E._fields_ = [
    ('family', PRUint16),
    ('data', c_char * 14),
]
class N9PRNetAddr4DOT_52E(Structure):
    pass
N9PRNetAddr4DOT_52E._fields_ = [
    ('family', PRUint16),
    ('port', PRUint16),
    ('ip', PRUint32),
    ('pad', c_char * 8),
]
class N9PRNetAddr4DOT_53E(Structure):
    pass
N9PRNetAddr4DOT_53E._fields_ = [
    ('family', PRUint16),
    ('port', PRUint16),
    ('flowinfo', PRUint32),
    ('ip', PRIPv6Addr),
    ('scope_id', PRUint32),
]
class N9PRNetAddr4DOT_54E(Structure):
    pass
N9PRNetAddr4DOT_54E._fields_ = [
    ('family', PRUint16),
    ('path', c_char * 104),
]
PRNetAddr._fields_ = [
    ('raw', N9PRNetAddr4DOT_51E),
    ('inet', N9PRNetAddr4DOT_52E),
    ('ipv6', N9PRNetAddr4DOT_53E),
    ('local', N9PRNetAddr4DOT_54E),
]

# values for enumeration 'PRSockOption'
PRSockOption = c_int # enum
class PRLinger(Structure):
    pass
PRLinger._fields_ = [
    ('polarity', PRBool),
    ('linger', PRIntervalTime),
]
class PRMcastRequest(Structure):
    pass
PRMcastRequest._fields_ = [
    ('mcaddr', PRNetAddr),
    ('ifaddr', PRNetAddr),
]
class PRSocketOptionData(Structure):
    pass
class N18PRSocketOptionData4DOT_55E(Union):
    pass
N18PRSocketOptionData4DOT_55E._fields_ = [
    ('ip_ttl', PRUintn),
    ('mcast_ttl', PRUintn),
    ('tos', PRUintn),
    ('non_blocking', PRBool),
    ('reuse_addr', PRBool),
    ('keep_alive', PRBool),
    ('mcast_loopback', PRBool),
    ('no_delay', PRBool),
    ('broadcast', PRBool),
    ('max_segment', PRSize),
    ('recv_buffer_size', PRSize),
    ('send_buffer_size', PRSize),
    ('linger', PRLinger),
    ('add_member', PRMcastRequest),
    ('drop_member', PRMcastRequest),
    ('mcast_if', PRNetAddr),
]
PRSocketOptionData._fields_ = [
    ('option', PRSockOption),
    ('value', N18PRSocketOptionData4DOT_55E),
]
class PRIOVec(Structure):
    pass
PRIOVec._fields_ = [
    ('iov_base', STRING),
    ('iov_len', c_int),
]

# values for enumeration 'PRDescType'
PRDescType = c_int # enum

# values for enumeration 'PRSeekWhence'
PRSeekWhence = c_int # enum
PRCloseFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc))
PRReadFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), c_void_p, PRInt32)
PRWriteFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), c_void_p, PRInt32)
PRAvailableFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc))
PRAvailable64FN = CFUNCTYPE(PRInt64, POINTER(PRFileDesc))
PRFsyncFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc))
PROffset32 = PRInt32
PRSeekFN = CFUNCTYPE(PROffset32, POINTER(PRFileDesc), PROffset32, PRSeekWhence)
PROffset64 = PRInt64
PRSeek64FN = CFUNCTYPE(PROffset64, POINTER(PRFileDesc), PROffset64, PRSeekWhence)
PRFileInfoFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRFileInfo))
PRFileInfo64FN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRFileInfo64))
PRWritevFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), POINTER(PRIOVec), PRInt32, PRIntervalTime)
PRConnectFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRNetAddr), PRIntervalTime)
PRAcceptFN = CFUNCTYPE(POINTER(PRFileDesc), POINTER(PRFileDesc), POINTER(PRNetAddr), PRIntervalTime)
PRBindFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRNetAddr))
PRListenFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), PRIntn)
PRShutdownFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), PRIntn)
PRRecvFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), c_void_p, PRInt32, PRIntn, PRIntervalTime)
PRSendFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), c_void_p, PRInt32, PRIntn, PRIntervalTime)
PRRecvfromFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), c_void_p, PRInt32, PRIntn, POINTER(PRNetAddr), PRIntervalTime)
PRSendtoFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), c_void_p, PRInt32, PRIntn, POINTER(PRNetAddr), PRIntervalTime)
PRPollFN = CFUNCTYPE(PRInt16, POINTER(PRFileDesc), PRInt16, POINTER(PRInt16))
PRAcceptreadFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), POINTER(POINTER(PRFileDesc)), POINTER(POINTER(PRNetAddr)), c_void_p, PRInt32, PRIntervalTime)
PRTransmitfileFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), POINTER(PRFileDesc), c_void_p, PRInt32, PRTransmitFileFlags, PRIntervalTime)
PRGetsocknameFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRNetAddr))
PRGetpeernameFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRNetAddr))
PRGetsocketoptionFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRSocketOptionData))
PRSetsocketoptionFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), POINTER(PRSocketOptionData))
PRSendfileFN = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), POINTER(PRSendFileData), PRTransmitFileFlags, PRIntervalTime)
PRConnectcontinueFN = CFUNCTYPE(PRStatus, POINTER(PRFileDesc), PRInt16)
PRReservedFN = CFUNCTYPE(PRIntn, POINTER(PRFileDesc))
PRIOMethods._fields_ = [
    ('file_type', PRDescType),
    ('close', PRCloseFN),
    ('read', PRReadFN),
    ('write', PRWriteFN),
    ('available', PRAvailableFN),
    ('available64', PRAvailable64FN),
    ('fsync', PRFsyncFN),
    ('seek', PRSeekFN),
    ('seek64', PRSeek64FN),
    ('fileInfo', PRFileInfoFN),
    ('fileInfo64', PRFileInfo64FN),
    ('writev', PRWritevFN),
    ('connect', PRConnectFN),
    ('accept', PRAcceptFN),
    ('bind', PRBindFN),
    ('listen', PRListenFN),
    ('shutdown', PRShutdownFN),
    ('recv', PRRecvFN),
    ('send', PRSendFN),
    ('recvfrom', PRRecvfromFN),
    ('sendto', PRSendtoFN),
    ('poll', PRPollFN),
    ('acceptread', PRAcceptreadFN),
    ('transmitfile', PRTransmitfileFN),
    ('getsockname', PRGetsocknameFN),
    ('getpeername', PRGetpeernameFN),
    ('reserved_fn_6', PRReservedFN),
    ('reserved_fn_5', PRReservedFN),
    ('getsocketoption', PRGetsocketoptionFN),
    ('setsocketoption', PRSetsocketoptionFN),
    ('sendfile', PRSendfileFN),
    ('connectcontinue', PRConnectcontinueFN),
    ('reserved_fn_3', PRReservedFN),
    ('reserved_fn_2', PRReservedFN),
    ('reserved_fn_1', PRReservedFN),
    ('reserved_fn_0', PRReservedFN),
]

# values for enumeration 'PRSpecialFD'
PRSpecialFD = c_int # enum

# values for enumeration 'PRFileType'
PRFileType = c_int # enum
PRTime = PRInt64
PRFileInfo._pack_ = 4
PRFileInfo._fields_ = [
    ('type', PRFileType),
    ('size', PROffset32),
    ('creationTime', PRTime),
    ('modifyTime', PRTime),
]
PRFileInfo64._pack_ = 4
PRFileInfo64._fields_ = [
    ('type', PRFileType),
    ('size', PROffset64),
    ('creationTime', PRTime),
    ('modifyTime', PRTime),
]

# values for enumeration 'PRAccessHow'
PRAccessHow = c_int # enum
PRDirEntry._fields_ = [
    ('name', STRING),
]

# values for enumeration 'PRDirFlags'
PRDirFlags = c_int # enum

# values for enumeration 'PRShutdownHow'
PRShutdownHow = c_int # enum
PRSendFileData._fields_ = [
    ('fd', POINTER(PRFileDesc)),
    ('file_offset', PRUint32),
    ('file_nbytes', PRSize),
    ('header', c_void_p),
    ('hlen', PRInt32),
    ('trailer', c_void_p),
    ('tlen', PRInt32),
]
class PRFileMap(Structure):
    pass
PRFileMap._fields_ = [
]

# values for enumeration 'PRFileMapProtect'
PRFileMapProtect = c_int # enum
PRPollDesc._fields_ = [
    ('fd', POINTER(PRFileDesc)),
    ('in_flags', PRInt16),
    ('out_flags', PRInt16),
]
class PRSem(Structure):
    pass
PRSem._fields_ = [
]
PRThreadDumpProc = CFUNCTYPE(None, POINTER(PRFileDesc), POINTER(PRThread), c_void_p)
PREnumerator = CFUNCTYPE(PRStatus, POINTER(PRThread), c_int, c_void_p)
PRScanStackFun = CFUNCTYPE(PRStatus, POINTER(PRThread), POINTER(c_void_p), PRUword, c_void_p)
class _PRCPU(Structure):
    pass
_PRCPU._fields_ = [
]
class PRLibrary(Structure):
    pass
PRLibrary._fields_ = [
]
class PRStaticLinkTable(Structure):
    pass
PRStaticLinkTable._fields_ = [
    ('name', STRING),
    ('fp', CFUNCTYPE(None)),
]

# values for enumeration 'PRLibSpecType'
PRLibSpecType = c_int # enum
class FSSpec(Structure):
    pass
FSSpec._fields_ = [
]
class PRLibSpec(Structure):
    pass
class N9PRLibSpec4DOT_16E(Union):
    pass
class N9PRLibSpec4DOT_164DOT_17E(Structure):
    pass
N9PRLibSpec4DOT_164DOT_17E._fields_ = [
    ('fsspec', POINTER(FSSpec)),
    ('name', STRING),
]
class N9PRLibSpec4DOT_164DOT_18E(Structure):
    pass
N9PRLibSpec4DOT_164DOT_18E._fields_ = [
    ('fsspec', POINTER(FSSpec)),
    ('index', PRUint32),
]
PRUnichar = PRUint16
N9PRLibSpec4DOT_16E._fields_ = [
    ('pathname', STRING),
    ('mac_named_fragment', N9PRLibSpec4DOT_164DOT_17E),
    ('mac_indexed_fragment', N9PRLibSpec4DOT_164DOT_18E),
    ('pathname_u', POINTER(PRUnichar)),
]
PRLibSpec._fields_ = [
    ('type', PRLibSpecType),
    ('value', N9PRLibSpec4DOT_16E),
]
PRFuncPtr = CFUNCTYPE(None)
PRLock._fields_ = [
]

# values for enumeration 'PRLogModuleLevel'
PRLogModuleLevel = c_int # enum
class PRLogModuleInfo(Structure):
    pass
PRLogModuleInfo._fields_ = [
    ('name', STRING),
    ('level', PRLogModuleLevel),
    ('next', POINTER(PRLogModuleInfo)),
]
PRMonitor._fields_ = [
]
class PRWaitGroup(Structure):
    pass
PRWaitGroup._fields_ = [
]

# values for enumeration 'PRMWStatus'
PRMWStatus = c_int # enum
class PRMemoryDescriptor(Structure):
    pass
PRMemoryDescriptor._fields_ = [
    ('start', c_void_p),
    ('length', PRSize),
]
class PRMWaitClientData(Structure):
    pass
PRMWaitClientData._fields_ = [
]
class PRRecvWait(Structure):
    pass
PRRecvWait._fields_ = [
    ('internal', PRCList),
    ('fd', POINTER(PRFileDesc)),
    ('outcome', PRMWStatus),
    ('timeout', PRIntervalTime),
    ('bytesRecv', PRInt32),
    ('buffer', PRMemoryDescriptor),
    ('client', POINTER(PRMWaitClientData)),
]
class PRMWaitEnumerator(Structure):
    pass
PRMWaitEnumerator._fields_ = [
]
class PRHostEnt(Structure):
    pass
PRHostEnt._fields_ = [
    ('h_name', STRING),
    ('h_aliases', POINTER(STRING)),
    ('h_addrtype', PRInt32),
    ('h_length', PRInt32),
    ('h_addr_list', POINTER(STRING)),
]

# values for enumeration 'PRNetAddrValue'
PRNetAddrValue = c_int # enum
class PRProtoEnt(Structure):
    pass
PRProtoEnt._fields_ = [
    ('p_name', STRING),
    ('p_aliases', POINTER(STRING)),
    ('p_num', PRInt32),
]
class PRAddrInfo(Structure):
    pass
PRAddrInfo._fields_ = [
]
PRStuffFunc = CFUNCTYPE(PRIntn, c_void_p, STRING, PRUint32)
class PRProcess(Structure):
    pass
PRProcess._fields_ = [
]
class PRProcessAttr(Structure):
    pass
PRProcessAttr._fields_ = [
]
class PRRWLock(Structure):
    pass
PRRWLock._fields_ = [
]
class PRSharedMemory(Structure):
    pass
PRSharedMemory._fields_ = [
]

# values for enumeration 'PRSysInfo'
PRSysInfo = c_int # enum
PRThread._fields_ = [
]
class PRThreadStack(Structure):
    pass
PRThreadStack._fields_ = [
]

# values for enumeration 'PRThreadType'
PRThreadType = c_int # enum

# values for enumeration 'PRThreadScope'
PRThreadScope = c_int # enum

# values for enumeration 'PRThreadState'
PRThreadState = c_int # enum

# values for enumeration 'PRThreadPriority'
PRThreadPriority = c_int # enum
PRThreadPrivateDTOR = CFUNCTYPE(None, c_void_p)
class PRTimeParameters(Structure):
    pass
PRTimeParameters._fields_ = [
    ('tp_gmt_offset', PRInt32),
    ('tp_dst_offset', PRInt32),
]
class PRExplodedTime(Structure):
    pass
PRExplodedTime._fields_ = [
    ('tm_usec', PRInt32),
    ('tm_sec', PRInt32),
    ('tm_min', PRInt32),
    ('tm_hour', PRInt32),
    ('tm_mday', PRInt32),
    ('tm_month', PRInt32),
    ('tm_year', PRInt16),
    ('tm_wday', PRInt8),
    ('tm_yday', PRInt16),
    ('tm_params', PRTimeParameters),
]
PRTimeParamFn = CFUNCTYPE(PRTimeParameters, POINTER(PRExplodedTime))
class PRJobIoDesc(Structure):
    pass
PRJobIoDesc._fields_ = [
    ('socket', POINTER(PRFileDesc)),
    ('error', PRErrorCode),
    ('timeout', PRIntervalTime),
]
class PRThreadPool(Structure):
    pass
PRThreadPool._fields_ = [
]
class PRJob(Structure):
    pass
PRJob._fields_ = [
]
PRJobFn = CFUNCTYPE(None, c_void_p)
PRTraceHandle = c_void_p
class PRTraceEntry(Structure):
    pass
PRTraceEntry._pack_ = 4
PRTraceEntry._fields_ = [
    ('thread', POINTER(PRThread)),
    ('handle', PRTraceHandle),
    ('time', PRTime),
    ('userData', PRUint32 * 8),
]

# values for enumeration 'PRTraceOption'
PRTraceOption = c_int # enum
ptrdiff_t = c_int
PRPtrdiff = ptrdiff_t
PRPackedBool = PRUint8
CERTImportCertificateFunc = CFUNCTYPE(SECStatus, c_void_p, POINTER(POINTER(SECItem)), c_int)
CERTPolicyStringCallback = CFUNCTYPE(STRING, STRING, c_ulong, c_void_p)
CERTSortCallback = CFUNCTYPE(PRBool, POINTER(CERTCertificate), POINTER(CERTCertificate), c_void_p)
class NSSCertificateStr(Structure):
    pass
NSSCertificateStr._fields_ = [
]
NSSTrustDomainStr._fields_ = [
]
class CERTAVAStr(Structure):
    pass
CERTAVA = CERTAVAStr
class CERTAttributeStr(Structure):
    pass
CERTAttribute = CERTAttributeStr
class CERTAuthInfoAccessStr(Structure):
    pass
CERTAuthInfoAccess = CERTAuthInfoAccessStr
class CERTAuthKeyIDStr(Structure):
    pass
CERTAuthKeyID = CERTAuthKeyIDStr
class CERTBasicConstraintsStr(Structure):
    pass
CERTBasicConstraints = CERTBasicConstraintsStr
class CERTCertExtensionStr(Structure):
    pass
CERTCertExtension = CERTCertExtensionStr
class CERTCertKeyStr(Structure):
    pass
CERTCertKey = CERTCertKeyStr
class CERTCertListStr(Structure):
    pass
CERTCertList = CERTCertListStr
class CERTCertListNodeStr(Structure):
    pass
CERTCertListNode = CERTCertListNodeStr
class CERTCertNicknamesStr(Structure):
    pass
CERTCertNicknames = CERTCertNicknamesStr
class CERTCertTrustStr(Structure):
    pass
CERTCertTrust = CERTCertTrustStr
class CERTCertificateRequestStr(Structure):
    pass
CERTCertificateRequest = CERTCertificateRequestStr
class CERTCrlStr(Structure):
    pass
CERTCrl = CERTCrlStr
class CERTCrlDistributionPointsStr(Structure):
    pass
CERTCrlDistributionPoints = CERTCrlDistributionPointsStr
class CERTCrlEntryStr(Structure):
    pass
CERTCrlEntry = CERTCrlEntryStr
class CERTCrlHeadNodeStr(Structure):
    pass
CERTCrlHeadNode = CERTCrlHeadNodeStr
class CERTCrlKeyStr(Structure):
    pass
CERTCrlKey = CERTCrlKeyStr
class CERTCrlNodeStr(Structure):
    pass
CERTCrlNode = CERTCrlNodeStr
class CERTDERCertsStr(Structure):
    pass
CERTDERCerts = CERTDERCertsStr
class CERTGeneralNameStr(Structure):
    pass
CERTGeneralName = CERTGeneralNameStr
class CERTGeneralNameListStr(Structure):
    pass
CERTGeneralNameList = CERTGeneralNameListStr
class CERTIssuerAndSNStr(Structure):
    pass
CERTIssuerAndSN = CERTIssuerAndSNStr
class CERTNameStr(Structure):
    pass
CERTName = CERTNameStr
class CERTNameConstraintStr(Structure):
    pass
CERTNameConstraint = CERTNameConstraintStr
class CERTNameConstraintsStr(Structure):
    pass
CERTNameConstraints = CERTNameConstraintsStr
class CERTOKDomainNameStr(Structure):
    pass
CERTOKDomainName = CERTOKDomainNameStr
class CERTPrivKeyUsagePeriodStr(Structure):
    pass
CERTPrivKeyUsagePeriod = CERTPrivKeyUsagePeriodStr
class CERTPublicKeyAndChallengeStr(Structure):
    pass
CERTPublicKeyAndChallenge = CERTPublicKeyAndChallengeStr
class CERTRDNStr(Structure):
    pass
CERTRDN = CERTRDNStr
class CERTSignedCrlStr(Structure):
    pass
CERTSignedCrl = CERTSignedCrlStr
class CERTSignedDataStr(Structure):
    pass
CERTSignedData = CERTSignedDataStr
class CERTStatusConfigStr(Structure):
    pass
CERTStatusConfig = CERTStatusConfigStr
class CERTSubjectListStr(Structure):
    pass
CERTSubjectList = CERTSubjectListStr
class CERTSubjectNodeStr(Structure):
    pass
CERTSubjectNode = CERTSubjectNodeStr
class CERTSubjectPublicKeyInfoStr(Structure):
    pass
CERTSubjectPublicKeyInfo = CERTSubjectPublicKeyInfoStr
class CERTValidityStr(Structure):
    pass
CERTValidity = CERTValidityStr
class CERTVerifyLogStr(Structure):
    pass
CERTVerifyLog = CERTVerifyLogStr
class CERTVerifyLogNodeStr(Structure):
    pass
CERTVerifyLogNode = CERTVerifyLogNodeStr
class CRLDistributionPointStr(Structure):
    pass
CRLDistributionPoint = CRLDistributionPointStr
CERTCrlNumber = c_ulong
CERTAVAStr._fields_ = [
    ('type', SECItem),
    ('value', SECItem),
]
CERTRDNStr._fields_ = [
    ('avas', POINTER(POINTER(CERTAVA))),
]
CERTNameStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('rdns', POINTER(POINTER(CERTRDN))),
]
CERTValidityStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('notBefore', SECItem),
    ('notAfter', SECItem),
]
CERTCertKeyStr._fields_ = [
    ('serialNumber', SECItem),
    ('derIssuer', SECItem),
]
class SECAlgorithmIDStr(Structure):
    pass
SECAlgorithmIDStr._fields_ = [
    ('algorithm', SECItem),
    ('parameters', SECItem),
]
SECAlgorithmID = SECAlgorithmIDStr
CERTSignedDataStr._fields_ = [
    ('data', SECItem),
    ('signatureAlgorithm', SECAlgorithmID),
    ('signature', SECItem),
]
CERTSubjectPublicKeyInfoStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('algorithm', SECAlgorithmID),
    ('subjectPublicKey', SECItem),
]
CERTPublicKeyAndChallengeStr._fields_ = [
    ('spki', SECItem),
    ('challenge', SECItem),
]
CERTCertTrustStr._fields_ = [
    ('sslFlags', c_uint),
    ('emailFlags', c_uint),
    ('objectSigningFlags', c_uint),
]

# values for enumeration 'SECTrustTypeEnum'
SECTrustTypeEnum = c_int # enum
SECTrustType = SECTrustTypeEnum
CERTCertExtensionStr._fields_ = [
    ('id', SECItem),
    ('critical', SECItem),
    ('value', SECItem),
]
CERTSubjectNodeStr._fields_ = [
    ('next', POINTER(CERTSubjectNodeStr)),
    ('prev', POINTER(CERTSubjectNodeStr)),
    ('certKey', SECItem),
    ('keyID', SECItem),
]
CERTSubjectListStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('ncerts', c_int),
    ('emailAddr', STRING),
    ('head', POINTER(CERTSubjectNode)),
    ('tail', POINTER(CERTSubjectNode)),
    ('entry', c_void_p),
]
class N18CERTCertificateStr4DOT_56E(Union):
    pass
class N18CERTCertificateStr4DOT_564DOT_57E(Structure):
    pass
N18CERTCertificateStr4DOT_564DOT_57E._fields_ = [
    ('hasUnsupportedCriticalExt', c_uint, 1),
]
N18CERTCertificateStr4DOT_56E._fields_ = [
    ('apointer', c_void_p),
    ('bits', N18CERTCertificateStr4DOT_564DOT_57E),
]
class PK11SlotInfoStr(Structure):
    pass
PK11SlotInfo = PK11SlotInfoStr
CK_OBJECT_HANDLE = CK_ULONG
CERTCertificateStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('subjectName', STRING),
    ('issuerName', STRING),
    ('signatureWrap', CERTSignedData),
    ('derCert', SECItem),
    ('derIssuer', SECItem),
    ('derSubject', SECItem),
    ('derPublicKey', SECItem),
    ('certKey', SECItem),
    ('version', SECItem),
    ('serialNumber', SECItem),
    ('signature', SECAlgorithmID),
    ('issuer', CERTName),
    ('validity', CERTValidity),
    ('subject', CERTName),
    ('subjectPublicKeyInfo', CERTSubjectPublicKeyInfo),
    ('issuerID', SECItem),
    ('subjectID', SECItem),
    ('extensions', POINTER(POINTER(CERTCertExtension))),
    ('emailAddr', STRING),
    ('dbhandle', POINTER(CERTCertDBHandle)),
    ('subjectKeyID', SECItem),
    ('keyIDGenerated', PRBool),
    ('keyUsage', c_uint),
    ('rawKeyUsage', c_uint),
    ('keyUsagePresent', PRBool),
    ('nsCertType', PRUint32),
    ('keepSession', PRBool),
    ('timeOK', PRBool),
    ('domainOK', POINTER(CERTOKDomainName)),
    ('isperm', PRBool),
    ('istemp', PRBool),
    ('nickname', STRING),
    ('dbnickname', STRING),
    ('nssCertificate', POINTER(NSSCertificateStr)),
    ('trust', POINTER(CERTCertTrust)),
    ('referenceCount', c_int),
    ('subjectList', POINTER(CERTSubjectList)),
    ('authKeyID', POINTER(CERTAuthKeyID)),
    ('isRoot', PRBool),
    ('options', N18CERTCertificateStr4DOT_56E),
    ('series', c_int),
    ('slot', POINTER(PK11SlotInfo)),
    ('pkcs11ID', CK_OBJECT_HANDLE),
    ('ownSlot', PRBool),
]
CERTDERCertsStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('numcerts', c_int),
    ('rawCerts', POINTER(SECItem)),
]
CERTAttributeStr._fields_ = [
    ('attrType', SECItem),
    ('attrValue', POINTER(POINTER(SECItem))),
]
CERTCertificateRequestStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('version', SECItem),
    ('subject', CERTName),
    ('subjectPublicKeyInfo', CERTSubjectPublicKeyInfo),
    ('attributes', POINTER(POINTER(CERTAttribute))),
]
CERTCertificateListStr._fields_ = [
    ('certs', POINTER(SECItem)),
    ('len', c_int),
    ('arena', POINTER(PLArenaPool)),
]
CERTCertListNodeStr._fields_ = [
    ('links', PRCList),
    ('cert', POINTER(CERTCertificate)),
    ('appData', c_void_p),
]
CERTCertListStr._fields_ = [
    ('list', PRCList),
    ('arena', POINTER(PLArenaPool)),
]
CERTCrlEntryStr._fields_ = [
    ('serialNumber', SECItem),
    ('revocationDate', SECItem),
    ('extensions', POINTER(POINTER(CERTCertExtension))),
]
CERTCrlStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('version', SECItem),
    ('signatureAlg', SECAlgorithmID),
    ('derName', SECItem),
    ('name', CERTName),
    ('lastUpdate', SECItem),
    ('nextUpdate', SECItem),
    ('entries', POINTER(POINTER(CERTCrlEntry))),
    ('extensions', POINTER(POINTER(CERTCertExtension))),
]
CERTCrlKeyStr._fields_ = [
    ('derName', SECItem),
    ('dummy', SECItem),
]
CERTSignedCrlStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('crl', CERTCrl),
    ('reserved1', c_void_p),
    ('reserved2', PRBool),
    ('isperm', PRBool),
    ('istemp', PRBool),
    ('referenceCount', c_int),
    ('dbhandle', POINTER(CERTCertDBHandle)),
    ('signatureWrap', CERTSignedData),
    ('url', STRING),
    ('derCrl', POINTER(SECItem)),
    ('slot', POINTER(PK11SlotInfo)),
    ('pkcs11ID', CK_OBJECT_HANDLE),
    ('opaque', c_void_p),
]
CERTCrlHeadNodeStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('dbhandle', POINTER(CERTCertDBHandle)),
    ('first', POINTER(CERTCrlNode)),
    ('last', POINTER(CERTCrlNode)),
]
CERTCrlNodeStr._fields_ = [
    ('next', POINTER(CERTCrlNode)),
    ('type', c_int),
    ('crl', POINTER(CERTSignedCrl)),
]
CERTDistNamesStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('nnames', c_int),
    ('names', POINTER(SECItem)),
    ('head', c_void_p),
]

# values for enumeration 'SECCertUsageEnum'
SECCertUsageEnum = c_int # enum
SECCertUsage = SECCertUsageEnum
SECCertificateUsage = PRInt64

# values for enumeration 'CERTCertOwnerEnum'
CERTCertOwnerEnum = c_int # enum
CERTCertOwner = CERTCertOwnerEnum

# values for enumeration 'SECCertTimeValidityEnum'
SECCertTimeValidityEnum = c_int # enum
SECCertTimeValidity = SECCertTimeValidityEnum

# values for enumeration 'CERTCompareValidityStatusEnum'
CERTCompareValidityStatusEnum = c_int # enum
CERTCompareValidityStatus = CERTCompareValidityStatusEnum
CERTCertNicknamesStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('head', c_void_p),
    ('numnicknames', c_int),
    ('nicknames', POINTER(STRING)),
    ('what', c_int),
    ('totallen', c_int),
]
CERTIssuerAndSNStr._fields_ = [
    ('derIssuer', SECItem),
    ('issuer', CERTName),
    ('serialNumber', SECItem),
]
CERTBasicConstraintsStr._fields_ = [
    ('isCA', PRBool),
    ('pathLenConstraint', c_int),
]

# values for enumeration 'CERTCRLEntryReasonCodeEnum'
CERTCRLEntryReasonCodeEnum = c_int # enum
CERTCRLEntryReasonCode = CERTCRLEntryReasonCodeEnum

# values for enumeration 'CERTGeneralNameTypeEnum'
CERTGeneralNameTypeEnum = c_int # enum
CERTGeneralNameType = CERTGeneralNameTypeEnum
class OtherNameStr(Structure):
    pass
OtherNameStr._fields_ = [
    ('name', SECItem),
    ('oid', SECItem),
]
OtherName = OtherNameStr
class N18CERTGeneralNameStr4DOT_58E(Union):
    pass
N18CERTGeneralNameStr4DOT_58E._fields_ = [
    ('directoryName', CERTName),
    ('OthName', OtherName),
    ('other', SECItem),
]
CERTGeneralNameStr._fields_ = [
    ('type', CERTGeneralNameType),
    ('name', N18CERTGeneralNameStr4DOT_58E),
    ('derDirectoryName', SECItem),
    ('l', PRCList),
]
CERTGeneralNameListStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('name', POINTER(CERTGeneralName)),
    ('refCount', c_int),
    ('len', c_int),
    ('lock', POINTER(PRLock)),
]
CERTNameConstraintStr._fields_ = [
    ('name', CERTGeneralName),
    ('DERName', SECItem),
    ('min', SECItem),
    ('max', SECItem),
    ('l', PRCList),
]
CERTNameConstraintsStr._fields_ = [
    ('permited', POINTER(CERTNameConstraint)),
    ('excluded', POINTER(CERTNameConstraint)),
    ('DERPermited', POINTER(POINTER(SECItem))),
    ('DERExcluded', POINTER(POINTER(SECItem))),
]
CERTPrivKeyUsagePeriodStr._fields_ = [
    ('notBefore', SECItem),
    ('notAfter', SECItem),
    ('arena', POINTER(PLArenaPool)),
]
CERTAuthKeyIDStr._fields_ = [
    ('keyID', SECItem),
    ('authCertIssuer', POINTER(CERTGeneralName)),
    ('authCertSerialNumber', SECItem),
    ('DERAuthCertIssuer', POINTER(POINTER(SECItem))),
]

# values for enumeration 'DistributionPointTypesEnum'
DistributionPointTypesEnum = c_int # enum
DistributionPointTypes = DistributionPointTypesEnum
class N23CRLDistributionPointStr4DOT_59E(Union):
    pass
N23CRLDistributionPointStr4DOT_59E._fields_ = [
    ('fullName', POINTER(CERTGeneralName)),
    ('relativeName', CERTRDN),
]
CRLDistributionPointStr._fields_ = [
    ('distPointType', DistributionPointTypes),
    ('distPoint', N23CRLDistributionPointStr4DOT_59E),
    ('reasons', SECItem),
    ('crlIssuer', POINTER(CERTGeneralName)),
    ('derDistPoint', SECItem),
    ('derRelativeName', SECItem),
    ('derCrlIssuer', POINTER(POINTER(SECItem))),
    ('derFullName', POINTER(POINTER(SECItem))),
    ('bitsmap', SECItem),
]
CERTCrlDistributionPointsStr._fields_ = [
    ('distPoints', POINTER(POINTER(CRLDistributionPoint))),
]
CERTVerifyLogNodeStr._fields_ = [
    ('cert', POINTER(CERTCertificate)),
    ('error', c_long),
    ('depth', c_uint),
    ('arg', c_void_p),
    ('next', POINTER(CERTVerifyLogNodeStr)),
    ('prev', POINTER(CERTVerifyLogNodeStr)),
]
CERTVerifyLogStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('count', c_uint),
    ('head', POINTER(CERTVerifyLogNodeStr)),
    ('tail', POINTER(CERTVerifyLogNodeStr)),
]
CERTOKDomainNameStr._fields_ = [
    ('next', POINTER(CERTOKDomainName)),
    ('name', c_char * 1),
]
CERTStatusChecker = CFUNCTYPE(SECStatus, POINTER(CERTCertDBHandle), POINTER(CERTCertificate), PRTime, c_void_p)
CERTStatusDestroy = CFUNCTYPE(SECStatus, POINTER(CERTStatusConfig))
CERTStatusConfigStr._fields_ = [
    ('statusChecker', CERTStatusChecker),
    ('statusDestroy', CERTStatusDestroy),
    ('statusContext', c_void_p),
]
CERTAuthInfoAccessStr._fields_ = [
    ('method', SECItem),
    ('derLocation', SECItem),
    ('location', POINTER(CERTGeneralName)),
]
CERTDBNameFunc = CFUNCTYPE(STRING, c_void_p, c_int)

# values for enumeration 'CERTPackageTypeEnum'
CERTPackageTypeEnum = c_int # enum
CERTPackageType = CERTPackageTypeEnum
class CERTPolicyQualifier(Structure):
    pass

# values for enumeration 'SECOidTag'
SECOidTag = c_int # enum
CERTPolicyQualifier._fields_ = [
    ('oid', SECOidTag),
    ('qualifierID', SECItem),
    ('qualifierValue', SECItem),
]
class CERTPolicyInfo(Structure):
    pass
CERTPolicyInfo._fields_ = [
    ('oid', SECOidTag),
    ('policyID', SECItem),
    ('policyQualifiers', POINTER(POINTER(CERTPolicyQualifier))),
]
class CERTCertificatePolicies(Structure):
    pass
CERTCertificatePolicies._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('policyInfos', POINTER(POINTER(CERTPolicyInfo))),
]
class CERTNoticeReference(Structure):
    pass
CERTNoticeReference._fields_ = [
    ('organization', SECItem),
    ('noticeNumbers', POINTER(POINTER(SECItem))),
]
class CERTUserNotice(Structure):
    pass
CERTUserNotice._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('noticeReference', CERTNoticeReference),
    ('derNoticeReference', SECItem),
    ('displayText', SECItem),
]
class CERTOidSequence(Structure):
    pass
CERTOidSequence._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('oids', POINTER(POINTER(SECItem))),
]
class CERTPolicyMap(Structure):
    pass
CERTPolicyMap._fields_ = [
    ('issuerDomainPolicy', SECItem),
    ('subjectDomainPolicy', SECItem),
]
class CERTCertificatePolicyMappings(Structure):
    pass
CERTCertificatePolicyMappings._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('policyMaps', POINTER(POINTER(CERTPolicyMap))),
]
class CERTCertificateInhibitAny(Structure):
    pass
CERTCertificateInhibitAny._fields_ = [
    ('inhibitAnySkipCerts', SECItem),
]
class CERTCertificatePolicyConstraints(Structure):
    pass
CERTCertificatePolicyConstraints._fields_ = [
    ('explicitPolicySkipCerts', SECItem),
    ('inhibitMappingSkipCerts', SECItem),
]

# values for enumeration 'CERTValParamInType'
CERTValParamInType = c_int # enum

# values for enumeration 'CERTValParamOutType'
CERTValParamOutType = c_int # enum

# values for enumeration 'CERTRevocationMethodIndex'
CERTRevocationMethodIndex = c_int # enum
class CERTRevocationTests(Structure):
    pass
CERTRevocationTests._pack_ = 4
CERTRevocationTests._fields_ = [
    ('number_of_defined_methods', PRUint32),
    ('cert_rev_flags_per_method', POINTER(PRUint64)),
    ('number_of_preferred_methods', PRUint32),
    ('preferred_methods', POINTER(CERTRevocationMethodIndex)),
    ('cert_rev_method_independent_flags', PRUint64),
]
class CERTRevocationFlags(Structure):
    pass
CERTRevocationFlags._fields_ = [
    ('leafTests', CERTRevocationTests),
    ('chainTests', CERTRevocationTests),
]
class CERTValParamInValueStr(Structure):
    pass
class N22CERTValParamInValueStr4DOT_75E(Union):
    pass
N22CERTValParamInValueStr4DOT_75E._pack_ = 4
N22CERTValParamInValueStr4DOT_75E._fields_ = [
    ('b', PRBool),
    ('i', PRInt32),
    ('ui', PRUint32),
    ('l', PRInt64),
    ('ul', PRUint64),
    ('time', PRTime),
]
class N22CERTValParamInValueStr4DOT_76E(Union):
    pass
N22CERTValParamInValueStr4DOT_76E._fields_ = [
    ('p', c_void_p),
    ('s', STRING),
    ('cert', POINTER(CERTCertificate)),
    ('chain', POINTER(CERTCertList)),
    ('revocation', POINTER(CERTRevocationFlags)),
]
class N22CERTValParamInValueStr4DOT_77E(Union):
    pass
N22CERTValParamInValueStr4DOT_77E._fields_ = [
    ('pi', POINTER(PRInt32)),
    ('pui', POINTER(PRUint32)),
    ('pl', POINTER(PRInt64)),
    ('pul', POINTER(PRUint64)),
    ('oids', POINTER(SECOidTag)),
]
CERTValParamInValueStr._fields_ = [
    ('scalar', N22CERTValParamInValueStr4DOT_75E),
    ('pointer', N22CERTValParamInValueStr4DOT_76E),
    ('array', N22CERTValParamInValueStr4DOT_77E),
    ('arraySize', c_int),
]
CERTValParamInValue = CERTValParamInValueStr
class CERTValParamOutValueStr(Structure):
    pass
class N23CERTValParamOutValueStr4DOT_78E(Union):
    pass
N23CERTValParamOutValueStr4DOT_78E._pack_ = 4
N23CERTValParamOutValueStr4DOT_78E._fields_ = [
    ('b', PRBool),
    ('i', PRInt32),
    ('ui', PRUint32),
    ('l', PRInt64),
    ('ul', PRUint64),
    ('usages', SECCertificateUsage),
]
class N23CERTValParamOutValueStr4DOT_79E(Union):
    pass
N23CERTValParamOutValueStr4DOT_79E._fields_ = [
    ('p', c_void_p),
    ('s', STRING),
    ('log', POINTER(CERTVerifyLog)),
    ('cert', POINTER(CERTCertificate)),
    ('chain', POINTER(CERTCertList)),
]
class N23CERTValParamOutValueStr4DOT_80E(Union):
    pass
N23CERTValParamOutValueStr4DOT_80E._fields_ = [
    ('p', c_void_p),
    ('oids', POINTER(SECOidTag)),
]
CERTValParamOutValueStr._fields_ = [
    ('scalar', N23CERTValParamOutValueStr4DOT_78E),
    ('pointer', N23CERTValParamOutValueStr4DOT_79E),
    ('array', N23CERTValParamOutValueStr4DOT_80E),
    ('arraySize', c_int),
]
CERTValParamOutValue = CERTValParamOutValueStr
class CERTValInParam(Structure):
    pass
CERTValInParam._fields_ = [
    ('type', CERTValParamInType),
    ('value', CERTValParamInValue),
]
class CERTValOutParam(Structure):
    pass
CERTValOutParam._fields_ = [
    ('type', CERTValParamOutType),
    ('value', CERTValParamOutValue),
]

# values for enumeration 'CertStrictnessLevels'
CertStrictnessLevels = c_int # enum
CertStrictnessLevel = CertStrictnessLevels
CERT_StringFromCertFcn = CFUNCTYPE(STRING, POINTER(CERTCertificate))

# values for enumeration 'KeyType'
KeyType = c_int # enum
class SECKEYRSAPublicKeyStr(Structure):
    pass
SECKEYRSAPublicKeyStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('modulus', SECItem),
    ('publicExponent', SECItem),
]
SECKEYRSAPublicKey = SECKEYRSAPublicKeyStr
class SECKEYPQGParamsStr(Structure):
    pass
SECKEYPQGParamsStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('prime', SECItem),
    ('subPrime', SECItem),
    ('base', SECItem),
]
SECKEYPQGParams = SECKEYPQGParamsStr
class SECKEYDSAPublicKeyStr(Structure):
    pass
SECKEYDSAPublicKeyStr._fields_ = [
    ('params', SECKEYPQGParams),
    ('publicValue', SECItem),
]
SECKEYDSAPublicKey = SECKEYDSAPublicKeyStr
class SECKEYDHParamsStr(Structure):
    pass
SECKEYDHParamsStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('prime', SECItem),
    ('base', SECItem),
]
SECKEYDHParams = SECKEYDHParamsStr
class SECKEYDHPublicKeyStr(Structure):
    pass
SECKEYDHPublicKeyStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('prime', SECItem),
    ('base', SECItem),
    ('publicValue', SECItem),
]
SECKEYDHPublicKey = SECKEYDHPublicKeyStr
SECKEYECParams = SECItem
class SECKEYECPublicKeyStr(Structure):
    pass
SECKEYECPublicKeyStr._fields_ = [
    ('DEREncodedParams', SECKEYECParams),
    ('size', c_int),
    ('publicValue', SECItem),
]
SECKEYECPublicKey = SECKEYECPublicKeyStr
class SECKEYFortezzaPublicKeyStr(Structure):
    pass
SECKEYFortezzaPublicKeyStr._fields_ = [
    ('KEAversion', c_int),
    ('DSSversion', c_int),
    ('KMID', c_ubyte * 8),
    ('clearance', SECItem),
    ('KEApriviledge', SECItem),
    ('DSSpriviledge', SECItem),
    ('KEAKey', SECItem),
    ('DSSKey', SECItem),
    ('params', SECKEYPQGParams),
    ('keaParams', SECKEYPQGParams),
]
SECKEYFortezzaPublicKey = SECKEYFortezzaPublicKeyStr
class SECKEYDiffPQGParamsStr(Structure):
    pass
SECKEYDiffPQGParamsStr._fields_ = [
    ('DiffKEAParams', SECKEYPQGParams),
    ('DiffDSAParams', SECKEYPQGParams),
]
SECKEYDiffPQGParams = SECKEYDiffPQGParamsStr
class SECKEYPQGDualParamsStr(Structure):
    pass
SECKEYPQGDualParamsStr._fields_ = [
    ('CommParams', SECKEYPQGParams),
    ('DiffParams', SECKEYDiffPQGParams),
]
SECKEYPQGDualParams = SECKEYPQGDualParamsStr
class SECKEYKEAParamsStr(Structure):
    pass
SECKEYKEAParamsStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('hash', SECItem),
]
SECKEYKEAParams = SECKEYKEAParamsStr
class SECKEYKEAPublicKeyStr(Structure):
    pass
SECKEYKEAPublicKeyStr._fields_ = [
    ('params', SECKEYKEAParams),
    ('publicValue', SECItem),
]
SECKEYKEAPublicKey = SECKEYKEAPublicKeyStr
class N18SECKEYPublicKeyStr4DOT_84E(Union):
    pass
N18SECKEYPublicKeyStr4DOT_84E._fields_ = [
    ('rsa', SECKEYRSAPublicKey),
    ('dsa', SECKEYDSAPublicKey),
    ('dh', SECKEYDHPublicKey),
    ('kea', SECKEYKEAPublicKey),
    ('fortezza', SECKEYFortezzaPublicKey),
    ('ec', SECKEYECPublicKey),
]
SECKEYPublicKeyStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('keyType', KeyType),
    ('pkcs11Slot', POINTER(PK11SlotInfo)),
    ('pkcs11ID', CK_OBJECT_HANDLE),
    ('u', N18SECKEYPublicKeyStr4DOT_84E),
]
SECKEYPrivateKeyStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('keyType', KeyType),
    ('pkcs11Slot', POINTER(PK11SlotInfo)),
    ('pkcs11ID', CK_OBJECT_HANDLE),
    ('pkcs11IsTemp', PRBool),
    ('wincx', c_void_p),
    ('staticflags', PRUint32),
]
class SECKEYPrivateKeyListNode(Structure):
    pass
SECKEYPrivateKeyListNode._fields_ = [
    ('links', PRCList),
    ('key', POINTER(SECKEYPrivateKey)),
]
class SECKEYPrivateKeyList(Structure):
    pass
SECKEYPrivateKeyList._fields_ = [
    ('list', PRCList),
    ('arena', POINTER(PLArenaPool)),
]
class SECKEYPublicKeyListNode(Structure):
    pass
SECKEYPublicKeyListNode._fields_ = [
    ('links', PRCList),
    ('key', POINTER(SECKEYPublicKey)),
]
class SECKEYPublicKeyList(Structure):
    pass
SECKEYPublicKeyList._fields_ = [
    ('list', PRCList),
    ('arena', POINTER(PLArenaPool)),
]

# values for enumeration 'nssILockType'
nssILockType = c_int # enum
nssRWLockStr._fields_ = [
]
CK_TRUST = CK_ULONG
SECMODModuleDBFunc = CFUNCTYPE(POINTER(STRING), c_ulong, STRING, c_void_p)
CK_BYTE = c_ubyte
CK_CHAR = CK_BYTE
CK_UTF8CHAR = CK_BYTE
CK_BBOOL = CK_BYTE
CK_LONG = c_long
CK_FLAGS = CK_ULONG
CK_BYTE_PTR = POINTER(CK_BYTE)
CK_CHAR_PTR = POINTER(CK_CHAR)
CK_UTF8CHAR_PTR = POINTER(CK_UTF8CHAR)
CK_ULONG_PTR = POINTER(CK_ULONG)
CK_VOID_PTR = c_void_p
CK_VOID_PTR_PTR = POINTER(CK_VOID_PTR)
class CK_VERSION(Structure):
    pass
CK_VERSION._fields_ = [
    ('major', CK_BYTE),
    ('minor', CK_BYTE),
]
CK_VERSION_PTR = POINTER(CK_VERSION)
class CK_INFO(Structure):
    pass
CK_INFO._fields_ = [
    ('cryptokiVersion', CK_VERSION),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('flags', CK_FLAGS),
    ('libraryDescription', CK_UTF8CHAR * 32),
    ('libraryVersion', CK_VERSION),
]
CK_INFO_PTR = POINTER(CK_INFO)
CK_NOTIFICATION = CK_ULONG
CK_SLOT_ID_PTR = POINTER(CK_SLOT_ID)
class CK_SLOT_INFO(Structure):
    pass
CK_SLOT_INFO._fields_ = [
    ('slotDescription', CK_UTF8CHAR * 64),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('flags', CK_FLAGS),
    ('hardwareVersion', CK_VERSION),
    ('firmwareVersion', CK_VERSION),
]
CK_SLOT_INFO_PTR = POINTER(CK_SLOT_INFO)
class CK_TOKEN_INFO(Structure):
    pass
CK_TOKEN_INFO._fields_ = [
    ('label', CK_UTF8CHAR * 32),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('model', CK_UTF8CHAR * 16),
    ('serialNumber', CK_CHAR * 16),
    ('flags', CK_FLAGS),
    ('ulMaxSessionCount', CK_ULONG),
    ('ulSessionCount', CK_ULONG),
    ('ulMaxRwSessionCount', CK_ULONG),
    ('ulRwSessionCount', CK_ULONG),
    ('ulMaxPinLen', CK_ULONG),
    ('ulMinPinLen', CK_ULONG),
    ('ulTotalPublicMemory', CK_ULONG),
    ('ulFreePublicMemory', CK_ULONG),
    ('ulTotalPrivateMemory', CK_ULONG),
    ('ulFreePrivateMemory', CK_ULONG),
    ('hardwareVersion', CK_VERSION),
    ('firmwareVersion', CK_VERSION),
    ('utcTime', CK_CHAR * 16),
]
CK_TOKEN_INFO_PTR = POINTER(CK_TOKEN_INFO)
CK_SESSION_HANDLE = CK_ULONG
CK_SESSION_HANDLE_PTR = POINTER(CK_SESSION_HANDLE)
CK_USER_TYPE = CK_ULONG
CK_STATE = CK_ULONG
class CK_SESSION_INFO(Structure):
    pass
CK_SESSION_INFO._fields_ = [
    ('slotID', CK_SLOT_ID),
    ('state', CK_STATE),
    ('flags', CK_FLAGS),
    ('ulDeviceError', CK_ULONG),
]
CK_SESSION_INFO_PTR = POINTER(CK_SESSION_INFO)
CK_OBJECT_HANDLE_PTR = POINTER(CK_OBJECT_HANDLE)
CK_OBJECT_CLASS = CK_ULONG
CK_OBJECT_CLASS_PTR = POINTER(CK_OBJECT_CLASS)
CK_HW_FEATURE_TYPE = CK_ULONG
CK_KEY_TYPE = CK_ULONG
CK_CERTIFICATE_TYPE = CK_ULONG
CK_ATTRIBUTE_TYPE = CK_ULONG
class CK_ATTRIBUTE(Structure):
    pass
CK_ATTRIBUTE._fields_ = [
    ('type', CK_ATTRIBUTE_TYPE),
    ('pValue', CK_VOID_PTR),
    ('ulValueLen', CK_ULONG),
]
CK_ATTRIBUTE_PTR = POINTER(CK_ATTRIBUTE)
class CK_DATE(Structure):
    pass
CK_DATE._fields_ = [
    ('year', CK_CHAR * 4),
    ('month', CK_CHAR * 2),
    ('day', CK_CHAR * 2),
]
CK_MECHANISM_TYPE_PTR = POINTER(CK_MECHANISM_TYPE)
class CK_MECHANISM(Structure):
    pass
CK_MECHANISM._fields_ = [
    ('mechanism', CK_MECHANISM_TYPE),
    ('pParameter', CK_VOID_PTR),
    ('ulParameterLen', CK_ULONG),
]
CK_MECHANISM_PTR = POINTER(CK_MECHANISM)
class CK_MECHANISM_INFO(Structure):
    pass
CK_MECHANISM_INFO._fields_ = [
    ('ulMinKeySize', CK_ULONG),
    ('ulMaxKeySize', CK_ULONG),
    ('flags', CK_FLAGS),
]
CK_MECHANISM_INFO_PTR = POINTER(CK_MECHANISM_INFO)
CK_RV = CK_ULONG
CK_NOTIFY = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR)
class CK_FUNCTION_LIST(Structure):
    pass
CK_FUNCTION_LIST._fields_ = [
]
CK_FUNCTION_LIST_PTR = POINTER(CK_FUNCTION_LIST)
CK_FUNCTION_LIST_PTR_PTR = POINTER(CK_FUNCTION_LIST_PTR)
CK_CREATEMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR_PTR)
CK_DESTROYMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_LOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_UNLOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
class CK_C_INITIALIZE_ARGS(Structure):
    pass
CK_C_INITIALIZE_ARGS._fields_ = [
    ('CreateMutex', CK_CREATEMUTEX),
    ('DestroyMutex', CK_DESTROYMUTEX),
    ('LockMutex', CK_LOCKMUTEX),
    ('UnlockMutex', CK_UNLOCKMUTEX),
    ('flags', CK_FLAGS),
    ('LibraryParameters', POINTER(CK_CHAR_PTR)),
    ('pReserved', CK_VOID_PTR),
]
CK_C_INITIALIZE_ARGS_PTR = POINTER(CK_C_INITIALIZE_ARGS)
CK_RSA_PKCS_MGF_TYPE = CK_ULONG
CK_RSA_PKCS_MGF_TYPE_PTR = POINTER(CK_RSA_PKCS_MGF_TYPE)
CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG
CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR = POINTER(CK_RSA_PKCS_OAEP_SOURCE_TYPE)
class CK_RSA_PKCS_OAEP_PARAMS(Structure):
    pass
CK_RSA_PKCS_OAEP_PARAMS._fields_ = [
    ('hashAlg', CK_MECHANISM_TYPE),
    ('mgf', CK_RSA_PKCS_MGF_TYPE),
    ('source', CK_RSA_PKCS_OAEP_SOURCE_TYPE),
    ('pSourceData', CK_VOID_PTR),
    ('ulSourceDataLen', CK_ULONG),
]
CK_RSA_PKCS_OAEP_PARAMS_PTR = POINTER(CK_RSA_PKCS_OAEP_PARAMS)
class CK_RSA_PKCS_PSS_PARAMS(Structure):
    pass
CK_RSA_PKCS_PSS_PARAMS._fields_ = [
    ('hashAlg', CK_MECHANISM_TYPE),
    ('mgf', CK_RSA_PKCS_MGF_TYPE),
    ('sLen', CK_ULONG),
]
CK_RSA_PKCS_PSS_PARAMS_PTR = POINTER(CK_RSA_PKCS_PSS_PARAMS)
CK_EC_KDF_TYPE = CK_ULONG
class CK_ECDH1_DERIVE_PARAMS(Structure):
    pass
CK_ECDH1_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_ECDH1_DERIVE_PARAMS_PTR = POINTER(CK_ECDH1_DERIVE_PARAMS)
class CK_ECDH2_DERIVE_PARAMS(Structure):
    pass
CK_ECDH2_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
]
CK_ECDH2_DERIVE_PARAMS_PTR = POINTER(CK_ECDH2_DERIVE_PARAMS)
class CK_ECMQV_DERIVE_PARAMS(Structure):
    pass
CK_ECMQV_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
    ('publicKey', CK_OBJECT_HANDLE),
]
CK_ECMQV_DERIVE_PARAMS_PTR = POINTER(CK_ECMQV_DERIVE_PARAMS)
CK_X9_42_DH_KDF_TYPE = CK_ULONG
CK_X9_42_DH_KDF_TYPE_PTR = POINTER(CK_X9_42_DH_KDF_TYPE)
class CK_X9_42_DH1_DERIVE_PARAMS(Structure):
    pass
CK_X9_42_DH1_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_X9_42_DH1_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH1_DERIVE_PARAMS)
class CK_X9_42_DH2_DERIVE_PARAMS(Structure):
    pass
CK_X9_42_DH2_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
]
CK_X9_42_DH2_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH2_DERIVE_PARAMS)
class CK_X9_42_MQV_DERIVE_PARAMS(Structure):
    pass
CK_X9_42_MQV_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
    ('publicKey', CK_OBJECT_HANDLE),
]
CK_X9_42_MQV_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_MQV_DERIVE_PARAMS)
class CK_KEA_DERIVE_PARAMS(Structure):
    pass
CK_KEA_DERIVE_PARAMS._fields_ = [
    ('isSender', CK_BBOOL),
    ('ulRandomLen', CK_ULONG),
    ('pRandomA', CK_BYTE_PTR),
    ('pRandomB', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_KEA_DERIVE_PARAMS_PTR = POINTER(CK_KEA_DERIVE_PARAMS)
CK_RC2_PARAMS = CK_ULONG
CK_RC2_PARAMS_PTR = POINTER(CK_RC2_PARAMS)
class CK_RC2_CBC_PARAMS(Structure):
    pass
CK_RC2_CBC_PARAMS._fields_ = [
    ('ulEffectiveBits', CK_ULONG),
    ('iv', CK_BYTE * 8),
]
CK_RC2_CBC_PARAMS_PTR = POINTER(CK_RC2_CBC_PARAMS)
class CK_RC2_MAC_GENERAL_PARAMS(Structure):
    pass
CK_RC2_MAC_GENERAL_PARAMS._fields_ = [
    ('ulEffectiveBits', CK_ULONG),
    ('ulMacLength', CK_ULONG),
]
CK_RC2_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC2_MAC_GENERAL_PARAMS)
class CK_RC5_PARAMS(Structure):
    pass
CK_RC5_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
]
CK_RC5_PARAMS_PTR = POINTER(CK_RC5_PARAMS)
class CK_RC5_CBC_PARAMS(Structure):
    pass
CK_RC5_CBC_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
    ('pIv', CK_BYTE_PTR),
    ('ulIvLen', CK_ULONG),
]
CK_RC5_CBC_PARAMS_PTR = POINTER(CK_RC5_CBC_PARAMS)
class CK_RC5_MAC_GENERAL_PARAMS(Structure):
    pass
CK_RC5_MAC_GENERAL_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
    ('ulMacLength', CK_ULONG),
]
CK_RC5_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC5_MAC_GENERAL_PARAMS)
CK_MAC_GENERAL_PARAMS = CK_ULONG
CK_MAC_GENERAL_PARAMS_PTR = POINTER(CK_MAC_GENERAL_PARAMS)
class CK_DES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass
CK_DES_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 8),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_DES_CBC_ENCRYPT_DATA_PARAMS)
class CK_AES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass
CK_AES_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 16),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_AES_CBC_ENCRYPT_DATA_PARAMS)
class CK_SKIPJACK_PRIVATE_WRAP_PARAMS(Structure):
    pass
CK_SKIPJACK_PRIVATE_WRAP_PARAMS._fields_ = [
    ('ulPasswordLen', CK_ULONG),
    ('pPassword', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPAndGLen', CK_ULONG),
    ('ulQLen', CK_ULONG),
    ('ulRandomLen', CK_ULONG),
    ('pRandomA', CK_BYTE_PTR),
    ('pPrimeP', CK_BYTE_PTR),
    ('pBaseG', CK_BYTE_PTR),
    ('pSubprimeQ', CK_BYTE_PTR),
]
CK_SKIPJACK_PRIVATE_WRAP_PTR = POINTER(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)
class CK_SKIPJACK_RELAYX_PARAMS(Structure):
    pass
CK_SKIPJACK_RELAYX_PARAMS._fields_ = [
    ('ulOldWrappedXLen', CK_ULONG),
    ('pOldWrappedX', CK_BYTE_PTR),
    ('ulOldPasswordLen', CK_ULONG),
    ('pOldPassword', CK_BYTE_PTR),
    ('ulOldPublicDataLen', CK_ULONG),
    ('pOldPublicData', CK_BYTE_PTR),
    ('ulOldRandomLen', CK_ULONG),
    ('pOldRandomA', CK_BYTE_PTR),
    ('ulNewPasswordLen', CK_ULONG),
    ('pNewPassword', CK_BYTE_PTR),
    ('ulNewPublicDataLen', CK_ULONG),
    ('pNewPublicData', CK_BYTE_PTR),
    ('ulNewRandomLen', CK_ULONG),
    ('pNewRandomA', CK_BYTE_PTR),
]
CK_SKIPJACK_RELAYX_PARAMS_PTR = POINTER(CK_SKIPJACK_RELAYX_PARAMS)
class CK_PBE_PARAMS(Structure):
    pass
CK_PBE_PARAMS._fields_ = [
    ('pInitVector', CK_BYTE_PTR),
    ('pPassword', CK_UTF8CHAR_PTR),
    ('ulPasswordLen', CK_ULONG),
    ('pSalt', CK_BYTE_PTR),
    ('ulSaltLen', CK_ULONG),
    ('ulIteration', CK_ULONG),
]
CK_PBE_PARAMS_PTR = POINTER(CK_PBE_PARAMS)
class CK_KEY_WRAP_SET_OAEP_PARAMS(Structure):
    pass
CK_KEY_WRAP_SET_OAEP_PARAMS._fields_ = [
    ('bBC', CK_BYTE),
    ('pX', CK_BYTE_PTR),
    ('ulXLen', CK_ULONG),
]
CK_KEY_WRAP_SET_OAEP_PARAMS_PTR = POINTER(CK_KEY_WRAP_SET_OAEP_PARAMS)
class CK_SSL3_RANDOM_DATA(Structure):
    pass
CK_SSL3_RANDOM_DATA._fields_ = [
    ('pClientRandom', CK_BYTE_PTR),
    ('ulClientRandomLen', CK_ULONG),
    ('pServerRandom', CK_BYTE_PTR),
    ('ulServerRandomLen', CK_ULONG),
]
class CK_SSL3_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass
CK_SSL3_MASTER_KEY_DERIVE_PARAMS._fields_ = [
    ('RandomInfo', CK_SSL3_RANDOM_DATA),
    ('pVersion', CK_VERSION_PTR),
]
CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)
class CK_SSL3_KEY_MAT_OUT(Structure):
    pass
CK_SSL3_KEY_MAT_OUT._fields_ = [
    ('hClientMacSecret', CK_OBJECT_HANDLE),
    ('hServerMacSecret', CK_OBJECT_HANDLE),
    ('hClientKey', CK_OBJECT_HANDLE),
    ('hServerKey', CK_OBJECT_HANDLE),
    ('pIVClient', CK_BYTE_PTR),
    ('pIVServer', CK_BYTE_PTR),
]
CK_SSL3_KEY_MAT_OUT_PTR = POINTER(CK_SSL3_KEY_MAT_OUT)
class CK_SSL3_KEY_MAT_PARAMS(Structure):
    pass
CK_SSL3_KEY_MAT_PARAMS._fields_ = [
    ('ulMacSizeInBits', CK_ULONG),
    ('ulKeySizeInBits', CK_ULONG),
    ('ulIVSizeInBits', CK_ULONG),
    ('bIsExport', CK_BBOOL),
    ('RandomInfo', CK_SSL3_RANDOM_DATA),
    ('pReturnedKeyMaterial', CK_SSL3_KEY_MAT_OUT_PTR),
]
CK_SSL3_KEY_MAT_PARAMS_PTR = POINTER(CK_SSL3_KEY_MAT_PARAMS)
class CK_TLS_PRF_PARAMS(Structure):
    pass
CK_TLS_PRF_PARAMS._fields_ = [
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pOutput', CK_BYTE_PTR),
    ('pulOutputLen', CK_ULONG_PTR),
]
CK_TLS_PRF_PARAMS_PTR = POINTER(CK_TLS_PRF_PARAMS)
class CK_WTLS_RANDOM_DATA(Structure):
    pass
CK_WTLS_RANDOM_DATA._fields_ = [
    ('pClientRandom', CK_BYTE_PTR),
    ('ulClientRandomLen', CK_ULONG),
    ('pServerRandom', CK_BYTE_PTR),
    ('ulServerRandomLen', CK_ULONG),
]
CK_WTLS_RANDOM_DATA_PTR = POINTER(CK_WTLS_RANDOM_DATA)
class CK_WTLS_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass
CK_WTLS_MASTER_KEY_DERIVE_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('RandomInfo', CK_WTLS_RANDOM_DATA),
    ('pVersion', CK_BYTE_PTR),
]
CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_WTLS_MASTER_KEY_DERIVE_PARAMS)
class CK_WTLS_PRF_PARAMS(Structure):
    pass
CK_WTLS_PRF_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pOutput', CK_BYTE_PTR),
    ('pulOutputLen', CK_ULONG_PTR),
]
CK_WTLS_PRF_PARAMS_PTR = POINTER(CK_WTLS_PRF_PARAMS)
class CK_WTLS_KEY_MAT_OUT(Structure):
    pass
CK_WTLS_KEY_MAT_OUT._fields_ = [
    ('hMacSecret', CK_OBJECT_HANDLE),
    ('hKey', CK_OBJECT_HANDLE),
    ('pIV', CK_BYTE_PTR),
]
CK_WTLS_KEY_MAT_OUT_PTR = POINTER(CK_WTLS_KEY_MAT_OUT)
class CK_WTLS_KEY_MAT_PARAMS(Structure):
    pass
CK_WTLS_KEY_MAT_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('ulMacSizeInBits', CK_ULONG),
    ('ulKeySizeInBits', CK_ULONG),
    ('ulIVSizeInBits', CK_ULONG),
    ('ulSequenceNumber', CK_ULONG),
    ('bIsExport', CK_BBOOL),
    ('RandomInfo', CK_WTLS_RANDOM_DATA),
    ('pReturnedKeyMaterial', CK_WTLS_KEY_MAT_OUT_PTR),
]
CK_WTLS_KEY_MAT_PARAMS_PTR = POINTER(CK_WTLS_KEY_MAT_PARAMS)
class CK_CMS_SIG_PARAMS(Structure):
    pass
CK_CMS_SIG_PARAMS._fields_ = [
    ('certificateHandle', CK_OBJECT_HANDLE),
    ('pSigningMechanism', CK_MECHANISM_PTR),
    ('pDigestMechanism', CK_MECHANISM_PTR),
    ('pContentType', CK_UTF8CHAR_PTR),
    ('pRequestedAttributes', CK_BYTE_PTR),
    ('ulRequestedAttributesLen', CK_ULONG),
    ('pRequiredAttributes', CK_BYTE_PTR),
    ('ulRequiredAttributesLen', CK_ULONG),
]
CK_CMS_SIG_PARAMS_PTR = POINTER(CK_CMS_SIG_PARAMS)
class CK_KEY_DERIVATION_STRING_DATA(Structure):
    pass
CK_KEY_DERIVATION_STRING_DATA._fields_ = [
    ('pData', CK_BYTE_PTR),
    ('ulLen', CK_ULONG),
]
CK_KEY_DERIVATION_STRING_DATA_PTR = POINTER(CK_KEY_DERIVATION_STRING_DATA)
CK_EXTRACT_PARAMS = CK_ULONG
CK_EXTRACT_PARAMS_PTR = POINTER(CK_EXTRACT_PARAMS)
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = CK_ULONG
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR = POINTER(CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE)
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR = POINTER(CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE)
class CK_PKCS5_PBKD2_PARAMS(Structure):
    pass
CK_PKCS5_PBKD2_PARAMS._fields_ = [
    ('saltSource', CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE),
    ('pSaltSourceData', CK_VOID_PTR),
    ('ulSaltSourceDataLen', CK_ULONG),
    ('iterations', CK_ULONG),
    ('prf', CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE),
    ('pPrfData', CK_VOID_PTR),
    ('ulPrfDataLen', CK_ULONG),
    ('pPassword', CK_UTF8CHAR_PTR),
    ('ulPasswordLen', CK_ULONG_PTR),
]
CK_PKCS5_PBKD2_PARAMS_PTR = POINTER(CK_PKCS5_PBKD2_PARAMS)
class sec_ASN1Template_struct(Structure):
    pass
sec_ASN1Template_struct._fields_ = [
    ('kind', c_ulong),
    ('offset', c_ulong),
    ('sub', c_void_p),
    ('size', c_uint),
]
SEC_ASN1Template = sec_ASN1Template_struct
SEC_ASN1TemplateChooser = CFUNCTYPE(POINTER(SEC_ASN1Template), c_void_p, PRBool)
SEC_ASN1TemplateChooserPtr = POINTER(SEC_ASN1TemplateChooser)
class sec_DecoderContext_struct(Structure):
    pass
sec_DecoderContext_struct._fields_ = [
]
SEC_ASN1DecoderContext = sec_DecoderContext_struct
class sec_EncoderContext_struct(Structure):
    pass
SEC_ASN1EncoderContext = sec_EncoderContext_struct
sec_EncoderContext_struct._fields_ = [
]

# values for enumeration 'SEC_ASN1EncodingPart'
SEC_ASN1EncodingPart = c_int # enum
SEC_ASN1NotifyProc = CFUNCTYPE(None, c_void_p, PRBool, c_void_p, c_int)
SEC_ASN1WriteProc = CFUNCTYPE(None, c_void_p, STRING, c_ulong, c_int, SEC_ASN1EncodingPart)

# values for enumeration '_SECComparison'
_SECComparison = c_int # enum
SECComparison = _SECComparison
class DERTemplateStr(Structure):
    pass
DERTemplate = DERTemplateStr
DERTemplateStr._fields_ = [
    ('kind', c_ulong),
    ('offset', c_uint),
    ('sub', POINTER(DERTemplate)),
    ('arg', c_ulong),
]
class SECMODModuleStr(Structure):
    pass
SECMODModule = SECMODModuleStr
class SECMODModuleListStr(Structure):
    pass
SECMODModuleList = SECMODModuleListStr
SECMODListLock = NSSRWLock
PK11SlotInfoStr._fields_ = [
]
class PK11PreSlotInfoStr(Structure):
    pass
PK11PreSlotInfoStr._fields_ = [
]
PK11PreSlotInfo = PK11PreSlotInfoStr
PK11SymKeyStr._fields_ = [
]
PK11ContextStr._fields_ = [
]
class PK11SlotListStr(Structure):
    pass
PK11SlotList = PK11SlotListStr
class PK11SlotListElementStr(Structure):
    pass
PK11SlotListElement = PK11SlotListElementStr
class PK11RSAGenParamsStr(Structure):
    pass
PK11RSAGenParams = PK11RSAGenParamsStr
class PK11DefaultArrayEntryStr(Structure):
    pass
PK11DefaultArrayEntry = PK11DefaultArrayEntryStr
class PK11GenericObjectStr(Structure):
    pass
PK11GenericObjectStr._fields_ = [
]
PK11GenericObject = PK11GenericObjectStr
PK11FreeDataFunc = CFUNCTYPE(None, c_void_p)
SECMODModuleStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('internal', PRBool),
    ('loaded', PRBool),
    ('isFIPS', PRBool),
    ('dllName', STRING),
    ('commonName', STRING),
    ('library', c_void_p),
    ('functionList', c_void_p),
    ('refLock', POINTER(PRLock)),
    ('refCount', c_int),
    ('slots', POINTER(POINTER(PK11SlotInfo))),
    ('slotCount', c_int),
    ('slotInfo', POINTER(PK11PreSlotInfo)),
    ('slotInfoCount', c_int),
    ('moduleID', SECMODModuleID),
    ('isThreadSafe', PRBool),
    ('ssl', c_ulong * 2),
    ('libraryParams', STRING),
    ('moduleDBFunc', c_void_p),
    ('parent', POINTER(SECMODModule)),
    ('isCritical', PRBool),
    ('isModuleDB', PRBool),
    ('moduleDBOnly', PRBool),
    ('trustOrder', c_int),
    ('cipherOrder', c_int),
    ('evControlMask', c_ulong),
    ('cryptokiVersion', CK_VERSION),
]
SECMODModuleListStr._fields_ = [
    ('next', POINTER(SECMODModuleList)),
    ('module', POINTER(SECMODModule)),
]
PK11SlotListStr._fields_ = [
    ('head', POINTER(PK11SlotListElement)),
    ('tail', POINTER(PK11SlotListElement)),
    ('lock', POINTER(PRLock)),
]
PK11SlotListElementStr._fields_ = [
    ('next', POINTER(PK11SlotListElement)),
    ('prev', POINTER(PK11SlotListElement)),
    ('slot', POINTER(PK11SlotInfo)),
    ('refCount', c_int),
]
PK11RSAGenParamsStr._fields_ = [
    ('keySizeInBits', c_int),
    ('pe', c_ulong),
]

# values for enumeration 'PK11CertListType'
PK11CertListType = c_int # enum
PK11DefaultArrayEntryStr._fields_ = [
    ('name', STRING),
    ('flag', c_ulong),
    ('mechanism', c_ulong),
]
PK11AttrFlags = PRUint32

# values for enumeration 'PK11Origin'
PK11Origin = c_int # enum

# values for enumeration 'PK11DisableReasons'
PK11DisableReasons = c_int # enum

# values for enumeration 'PK11ObjectType'
PK11ObjectType = c_int # enum
PK11PasswordFunc = CFUNCTYPE(STRING, POINTER(PK11SlotInfo), PRBool, c_void_p)
PK11VerifyPasswordFunc = CFUNCTYPE(PRBool, POINTER(PK11SlotInfo), c_void_p)
PK11IsLoggedInFunc = CFUNCTYPE(PRBool, POINTER(PK11SlotInfo), c_void_p)
class SECKEYAttributeStr(Structure):
    pass
SECKEYAttributeStr._fields_ = [
    ('attrType', SECItem),
    ('attrValue', POINTER(POINTER(SECItem))),
]
SECKEYAttribute = SECKEYAttributeStr
class SECKEYPrivateKeyInfoStr(Structure):
    pass
SECKEYPrivateKeyInfoStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('version', SECItem),
    ('algorithm', SECAlgorithmID),
    ('privateKey', SECItem),
    ('attributes', POINTER(POINTER(SECKEYAttribute))),
]
SECKEYPrivateKeyInfo = SECKEYPrivateKeyInfoStr
class SECKEYEncryptedPrivateKeyInfoStr(Structure):
    pass
SECKEYEncryptedPrivateKeyInfoStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('algorithm', SECAlgorithmID),
    ('encryptedData', SECItem),
]
SECKEYEncryptedPrivateKeyInfo = SECKEYEncryptedPrivateKeyInfoStr

# values for enumeration 'PK11TokenStatus'
PK11TokenStatus = c_int # enum

# values for enumeration 'PK11TokenEvent'
PK11TokenEvent = c_int # enum
class PK11MergeLogStr(Structure):
    pass
PK11MergeLog = PK11MergeLogStr
class PK11MergeLogNodeStr(Structure):
    pass
PK11MergeLogNode = PK11MergeLogNodeStr
PK11MergeLogNodeStr._fields_ = [
    ('next', POINTER(PK11MergeLogNode)),
    ('prev', POINTER(PK11MergeLogNode)),
    ('object', POINTER(PK11GenericObject)),
    ('error', c_int),
    ('reserved1', CK_RV),
    ('reserved2', c_ulong),
    ('reserved3', c_ulong),
    ('reserved4', c_void_p),
    ('reserved5', c_void_p),
]
PK11MergeLogStr._fields_ = [
    ('head', POINTER(PK11MergeLogNode)),
    ('tail', POINTER(PK11MergeLogNode)),
    ('arena', POINTER(PLArenaPool)),
    ('version', c_int),
    ('reserved1', c_ulong),
    ('reserved2', c_ulong),
    ('reserved3', c_ulong),
    ('reserverd4', c_void_p),
    ('reserverd5', c_void_p),
]
class SECOidDataStr(Structure):
    pass
SECOidData = SECOidDataStr

# values for enumeration 'SECSupportExtenTag'
SECSupportExtenTag = c_int # enum
SECOidDataStr._fields_ = [
    ('oid', SECItem),
    ('offset', SECOidTag),
    ('desc', STRING),
    ('mechanism', c_ulong),
    ('supportedExtension', SECSupportExtenTag),
]
PORTCharConversionWSwapFunc = CFUNCTYPE(PRBool, PRBool, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint, POINTER(c_uint), PRBool)
PORTCharConversionFunc = CFUNCTYPE(PRBool, PRBool, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint, POINTER(c_uint))
class SSL3StatisticsStr(Structure):
    pass
SSL3StatisticsStr._fields_ = [
    ('sch_sid_cache_hits', c_long),
    ('sch_sid_cache_misses', c_long),
    ('sch_sid_cache_not_ok', c_long),
    ('hsh_sid_cache_hits', c_long),
    ('hsh_sid_cache_misses', c_long),
    ('hsh_sid_cache_not_ok', c_long),
    ('hch_sid_cache_hits', c_long),
    ('hch_sid_cache_misses', c_long),
    ('hch_sid_cache_not_ok', c_long),
    ('sch_sid_stateless_resumes', c_long),
    ('hsh_sid_stateless_resumes', c_long),
    ('hch_sid_stateless_resumes', c_long),
    ('hch_sid_ticket_parse_failures', c_long),
]
SSL3Statistics = SSL3StatisticsStr

# values for enumeration 'SSLAuthType'
SSLAuthType = c_int # enum
class SSLChannelInfoStr(Structure):
    pass
SSLChannelInfoStr._fields_ = [
    ('length', PRUint32),
    ('protocolVersion', PRUint16),
    ('cipherSuite', PRUint16),
    ('authKeyBits', PRUint32),
    ('keaKeyBits', PRUint32),
    ('creationTime', PRUint32),
    ('lastAccessTime', PRUint32),
    ('expirationTime', PRUint32),
    ('sessionIDLength', PRUint32),
    ('sessionID', PRUint8 * 32),
    ('compressionMethodName', STRING),
    ('compressionMethod', SSLCompressionMethod),
]
SSLChannelInfo = SSLChannelInfoStr
class SSLCipherSuiteInfoStr(Structure):
    pass
SSLCipherSuiteInfoStr._fields_ = [
    ('length', PRUint16),
    ('cipherSuite', PRUint16),
    ('cipherSuiteName', STRING),
    ('authAlgorithmName', STRING),
    ('authAlgorithm', SSLAuthType),
    ('keaTypeName', STRING),
    ('keaType', SSLKEAType),
    ('symCipherName', STRING),
    ('symCipher', SSLCipherAlgorithm),
    ('symKeyBits', PRUint16),
    ('symKeySpace', PRUint16),
    ('effectiveKeyBits', PRUint16),
    ('macAlgorithmName', STRING),
    ('macAlgorithm', SSLMACAlgorithm),
    ('macBits', PRUint16),
    ('isFIPS', PRUintn, 1),
    ('isExportable', PRUintn, 1),
    ('nonStandard', PRUintn, 1),
    ('reservedBits', PRUintn, 29),
]
SSLCipherSuiteInfo = SSLCipherSuiteInfoStr

# values for enumeration 'SSLSniNameType'
SSLSniNameType = c_int # enum

# values for enumeration 'SSLExtensionType'
SSLExtensionType = c_int # enum
class rpcent(Structure):
    pass
rpcent._fields_ = [
    ('r_name', STRING),
    ('r_aliases', POINTER(STRING)),
    ('r_number', c_int),
]
uint64_t = c_uint64
int_least8_t = c_byte
int_least16_t = c_short
int_least32_t = c_int
int_least64_t = c_longlong
uint_least8_t = c_ubyte
uint_least16_t = c_ushort
uint_least32_t = c_uint
uint_least64_t = c_ulonglong
int_fast8_t = c_byte
int_fast16_t = c_int
int_fast32_t = c_int
int_fast64_t = c_longlong
uint_fast8_t = c_ubyte
uint_fast16_t = c_uint
uint_fast32_t = c_uint
uint_fast64_t = c_ulonglong
intptr_t = c_int
uintptr_t = c_uint
intmax_t = c_longlong
uintmax_t = c_ulonglong
FILE = _IO_FILE
__FILE = _IO_FILE
va_list = __gnuc_va_list
fpos_t = _G_fpos_t
fpos64_t = _G_fpos64_t
class obstack(Structure):
    pass
obstack._fields_ = [
]
class div_t(Structure):
    pass
div_t._fields_ = [
    ('quot', c_int),
    ('rem', c_int),
]
class ldiv_t(Structure):
    pass
ldiv_t._fields_ = [
    ('quot', c_long),
    ('rem', c_long),
]
class lldiv_t(Structure):
    pass
lldiv_t._pack_ = 4
lldiv_t._fields_ = [
    ('quot', c_longlong),
    ('rem', c_longlong),
]
class random_data(Structure):
    pass
int32_t = c_int32
random_data._fields_ = [
    ('fptr', POINTER(int32_t)),
    ('rptr', POINTER(int32_t)),
    ('state', POINTER(int32_t)),
    ('rand_type', c_int),
    ('rand_deg', c_int),
    ('rand_sep', c_int),
    ('end_ptr', POINTER(int32_t)),
]
class drand48_data(Structure):
    pass
drand48_data._pack_ = 4
drand48_data._fields_ = [
    ('__x', c_ushort * 3),
    ('__old_x', c_ushort * 3),
    ('__c', c_ushort),
    ('__init', c_ushort),
    ('__a', c_ulonglong),
]
__compar_fn_t = CFUNCTYPE(c_int, c_void_p, c_void_p)
comparison_fn_t = __compar_fn_t
__compar_d_fn_t = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
sigset_t = __sigset_t
__fd_mask = c_long
class fd_set(Structure):
    pass
fd_set._fields_ = [
    ('fds_bits', __fd_mask * 32),
]
fd_mask = __fd_mask
class osockaddr(Structure):
    pass
osockaddr._fields_ = [
    ('sa_family', c_ushort),
    ('sa_data', c_ubyte * 14),
]

# values for unnamed enumeration
u_char = __u_char
u_short = __u_short
u_int = __u_int
u_long = __u_long
quad_t = __quad_t
u_quad_t = __u_quad_t
fsid_t = __fsid_t
loff_t = __loff_t
ino_t = __ino_t
ino64_t = __ino64_t
dev_t = __dev_t
mode_t = __mode_t
nlink_t = __nlink_t
off_t = __off_t
off64_t = __off64_t
id_t = __id_t
ssize_t = __ssize_t
daddr_t = __daddr_t
caddr_t = __caddr_t
key_t = __key_t
useconds_t = __useconds_t
suseconds_t = __suseconds_t
ulong = c_ulong
ushort = c_ushort
uint = c_uint
int8_t = c_int8
int16_t = c_int16
int64_t = c_int64
u_int8_t = c_ubyte
u_int16_t = c_ushort
u_int32_t = c_uint
u_int64_t = c_ulonglong
register_t = c_int
blksize_t = __blksize_t
blkcnt_t = __blkcnt_t
fsblkcnt_t = __fsblkcnt_t
fsfilcnt_t = __fsfilcnt_t
blkcnt64_t = __blkcnt64_t
fsblkcnt64_t = __fsblkcnt64_t
fsfilcnt64_t = __fsfilcnt64_t
clock_t = __clock_t
time_t = __time_t
clockid_t = __clockid_t
timer_t = __timer_t
class timespec(Structure):
    pass
timespec._fields_ = [
    ('tv_sec', __time_t),
    ('tv_nsec', c_long),
]
class __locale_struct(Structure):
    pass
class __locale_data(Structure):
    pass
__locale_struct._fields_ = [
    ('__locales', POINTER(__locale_data) * 13),
    ('__ctype_b', POINTER(c_ushort)),
    ('__ctype_tolower', POINTER(c_int)),
    ('__ctype_toupper', POINTER(c_int)),
    ('__names', STRING * 13),
]
__locale_data._fields_ = [
]
__locale_t = POINTER(__locale_struct)
locale_t = __locale_t
__all__ = ['certRFC822Name', 'decode_error', 'PR_INT8_MIN',
           'SEC_OID_PKCS9_MESSAGE_DIGEST', 'PK11SlotInfo', 'PRJob',
           'AI_CANONIDN', 'SSL_ENABLE_RENEGOTIATION', 'CKO_NSS',
           'SEC_OID_X509_HOLD_INSTRUCTION_CODE', '_CS_V7_ENV',
           'SO_RCVBUF', 'CKA_NSS_PASSWORD_CHECK', 'siVisibleString',
           '__off64_t', 'CLIENT_AUTH_ANONYMOUS', 'ssl3StateStr',
           '_SC_XOPEN_VERSION', 'CKM_CONCATENATE_DATA_AND_BASE',
           'SECMOD_SSL_FLAG', 'CKR_TOKEN_NOT_PRESENT',
           'SEC_ASN1_CONSTRUCTED', 'PR_PROTOCOL_NOT_SUPPORTED_ERROR',
           'SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE',
           'CKM_DSA_PARAMETER_GEN', 'SECKEYDiffPQGParams',
           'SSL_ERROR_DECRYPT_ERROR_ALERT', 'SEC_ASN1TemplateChooser',
           '__USE_SVID', 'CERTCertificateStr', 'ssl_sign_rsa',
           '_IO_BUFSIZ', 'SEC_ERROR_BAD_KEY', '__FILE',
           'N22CERTValParamInValueStr4DOT_76E', '_IO_off64_t',
           'CERTSubjectPublicKeyInfo', 'MSG_CTRUNC',
           'CKM_PBE_MD5_CAST3_CBC', 'BITS_PER_WORD_LOG2',
           'PK11SlotListElementStr', 'SSL_ERROR_LIMIT',
           'CERTPolicyMap', 'PRStackElem', 'CKR_KEY_NOT_WRAPPABLE',
           'CKR_USER_ALREADY_LOGGED_IN', '__NFDBITS',
           'SEC_OID_PKCS12_OIDS',
           'SSL_ERROR_CERTIFICATE_UNOBTAINABLE_ALERT',
           '_IO_cookie_io_functions_t', 'illegal_parameter',
           '_POSIX_THREAD_PRIO_PROTECT', 'IPPORT_TTYLINK',
           'ssl_SEND_FLAG_FORCE_INTO_BUFFER', 'trustObjectSigning',
           'fd_set', 'PRInt32', 'PRSendtoFN', 'PR_IS_CONNECTED_ERROR',
           'CKT_NSS', 'PRProtoEnt', 'nssILockKeyDB', '__OFF64_T_TYPE',
           'LL_MAXUINT', 'CERTCrlHeadNode', 'CKM_BATON_WRAP',
           'SEC_OID_SECG_EC_SECP112R2', 'AF_BLUETOOTH',
           'CERTCertificatePolicyConstraints',
           'SEC_OID_PKIX_OCSP_NO_CHECK', 'CK_WTLS_PRF_PARAMS',
           '_POSIX_THREAD_ROBUST_PRIO_INHERIT', 'CKM_DES_CBC_PAD',
           'CKK_X9_42_DH', 'mac_null', 'siUnsignedInteger',
           '_CS_POSIX_V6_LP64_OFF64_LINTFLAGS', 'NI_IDN',
           'cert_pi_useAIACertFetch', 'SIGEV_NONE', 'CKK_DH',
           'PRTraceEntry', 'CKM_SHA_1_HMAC', 'CKA_PIXEL_Y',
           'PR_AF_INET', 'SEC_CERT_CLASS_USER', 'CKR_DATA_INVALID',
           'SSLAppOpHeader', 'CKF_USER_PIN_LOCKED', 'siUTF8String',
           'CKM_JUNIPER_KEY_GEN', '_SC_THREADS',
           'CKA_TRUST_SERVER_AUTH', 'CKA_NETSCAPE_EMAIL',
           'SessionTicketDataStr', 'SECMOD_INT_FLAGS',
           '_SC_2_FORT_RUN', 'CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR',
           'ssl3CertNodeStr', '_SC_PASS_MAX',
           'PK11_OriginFortezzaHack', 'PR_INADDR_ANY',
           '_SC_XOPEN_XCU_VERSION', '_IO_SHOWBASE', '_PC_SOCK_MAXBUF',
           '_SC_THREAD_KEYS_MAX', 'SSL_ERROR_SESSION_NOT_FOUND',
           'in6_addr', 'CKA_RESOLUTION', 'EXPORT_KEY_LENGTH',
           '__codecvt_partial', 'SEC_OID_PKCS12_V1_KEY_BAG_ID',
           'AF_KEY', '_KEYTHI_H_', 'in_addr', 'kea_ecdh_rsa',
           'be64toh', 'SOCK_CLOEXEC', '__useconds_t',
           'PR_FILE_TOO_BIG_ERROR', '_SC_REGEXP', 'IPPROTO_ENCAP',
           'IPPROTO_ESP', '_CS_POSIX_V6_LP64_OFF64_CFLAGS',
           'SEC_OID_AES_128_KEY_WRAP', 'CKF_SERIAL_SESSION',
           'PRErrorCallbackPrivate', '_POSIX_RAW_SOCKETS',
           'SEC_OID_PKCS5_PBKDF2', '__isgraph_l',
           'CKM_SEED_CBC_ENCRYPT_DATA', 'CK_VOID_PTR',
           'SSL_ERROR_INSUFFICIENT_SECURITY_ALERT', 'ip_mreq_source',
           'SEC_ASN1_EXPLICIT', 'SEC_OID_PKCS7_ENCRYPTED_DATA',
           'SEC_OID_SECG_EC_SECP128R1', 'SEC_OID_SECG_EC_SECP128R2',
           'SEC_ASN1_PRINTABLE_STRING', 'CKM_SHA256', 'IPV6_RTHDR',
           '_SC_POLL', 'PK11CertListRootUnique',
           'CKA_TRUST_EMAIL_PROTECTION', 'CKM_X9_42_DH_HYBRID_DERIVE',
           'CK_MECHANISM_INFO', 'CERT_MAX_DN_BYTES',
           'wait_hello_done', '__P', 'SSL_REQUIRE_FIRST_HANDSHAKE',
           'CKM_KEA_KEY_DERIVE', 'PR_HOST_UNREACHABLE_ERROR',
           'PRHashFunction', 'SEC_ERROR_BAD_EXPORT_ALGORITHM',
           'CK_ECDH1_DERIVE_PARAMS_PTR', 'SSLSniNameType',
           'SSL_ERROR_BAD_CERTIFICATE', 'siEncodedNameBuffer',
           '_SC_MB_LEN_MAX', '_IO_DEC', 'SSL_MAX_CACHED_CERT_LEN',
           'CKG_MGF1_SHA1', 'CKM_TLS_PRE_MASTER_KEY_GEN',
           'SECKEYPQGDualParamsStr', 'SEC_ERROR_NO_MODULE',
           'SEC_ERROR_CRL_UNKNOWN_CRITICAL_EXTENSION',
           'NSSCK_VENDOR_NSS', 'SSL_ERROR_SOCKET_WRITE_FAILURE',
           'certificateUsageVerifyCA', 'cipher_aes_128',
           'SEC_OID_PKCS12_X509_CERT_CRL_BAG', '_IO_ERR_SEEN',
           'SEC_OID_NS_CERT_EXT_USER_PICTURE', 'PR_DESC_LAYERED',
           'BITS_PER_SHORT_LOG2', 'SSL_MAX_MASTER_KEY_BYTES',
           '_SC_STREAMS', 'PK11_ATTR_SESSION',
           'SEC_OID_X509_CERTIFICATE_POLICIES', 'SEC_ERROR_INPUT_LEN',
           'CERTCertificateInhibitAny', 'SSL3MACAlgorithm',
           'isblank_l', 'SEC_ERROR_UNKNOWN_ISSUER',
           'N15sslSessionIDStr5DOT_155E', 'sockaddr_in',
           'PK11SlotListStr', 'SECKEY_Attributes_Cached',
           'SECCertTimeValidity', '_ISlower', 'CKK_SEED',
           '_G_va_list', 'SEC_OID_PKIX_USER_NOTICE_QUALIFIER',
           'RF_CA_COMPROMISE', 'CK_INFO', 'BITS_PER_DOUBLE_LOG2',
           'SO_TIMESTAMPING', '__iscntrl_l', 'int_fast64_t',
           'PRFileInfoFN', 'CKA_EXTRACTABLE', 'CKM_AES_MAC',
           'SEC_ERROR_PKCS12_DECODING_PFX', 'NI_IDN_ALLOW_UNASSIGNED',
           '__WTERMSIG', 'PR_LOG_TEST', 'CKA_TRUST_TIME_STAMPING',
           'PK11TokenEvent', 'SSL_MAX_CHALLENGE_BYTES',
           '_PC_PATH_MAX', 'SEC_ASN1TemplateChooserPtr',
           'CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC',
           'CKM_RIPEMD128_HMAC', 'CKA_VERIFY', 'sslOptionsStr',
           'SECKEYECPublicKeyStr', 'PR_INT16_MAX', 'PR_AF_LOCAL',
           '_IO_FILE', 'SEC_OID_X509_ISSUER_ALT_NAME',
           'bad_certificate_hash_value', 'CK_X9_42_MQV_DERIVE_PARAMS',
           'PK11CertListCAUnique', '_SC_VERSION',
           'SEC_ERROR_INVALID_ARGS', '_IO_BOOLALPHA', '_SC_CLK_TCK',
           'PF_APPLETALK', '_SC_THREAD_ROBUST_PRIO_PROTECT',
           'SEC_OID_AES_128_ECB',
           'SEC_OID_NS_KEY_USAGE_GOVT_APPROVED',
           'SSL_ERROR_ACCESS_DENIED_ALERT', 'SYS_INFO_BUFFER_LENGTH',
           'CKG_MGF1_SHA256', 'PR_TRUE', 'EXPORT_RSA_KEY_LENGTH',
           'CKF_VERIFY', 'off_t', '_SC_AIO_MAX', 'siAsciiNameString',
           'CKA_WRAP_TEMPLATE', 'PK11_ATTR_EXTRACTABLE',
           '__fsblkcnt_t', 'PR_FILE_OTHER', 'PRAvailable64FN',
           'never_cached', 'CK_WTLS_KEY_MAT_OUT', 'SEC_ASN1Template',
           'CKM_JUNIPER_CBC128', 'CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'ssl_hmac_md5', 'CKM_BATON_KEY_GEN',
           'CK_WTLS_KEY_MAT_PARAMS', 'SEC_OID_SECG_EC_SECT163R2',
           'SEC_OID_SECG_EC_SECT163R1', 'CK_C_INITIALIZE_ARGS_PTR',
           '_PC_2_SYMLINKS', 'PR_PRIORITY_URGENT',
           'SSL_ERROR_SERVER_CACHE_NOT_CONFIGURED', 'AF_LLC',
           'CK_RC2_CBC_PARAMS_PTR', 'CKR_KEY_PARAMS_INVALID',
           'SSL_ERROR_RX_UNEXPECTED_UNCOMPRESSED_RECORD',
           'CKM_DSA_SHA1', 'CKM_PBE_SHA1_CAST128_CBC',
           'CKT_NSS_TRUSTED_DELEGATOR', 'PLHashFunction',
           'PK11RSAGenParams', 'pthread_attr_t', 'sslServerCertsStr',
           'CERT_StringFromCertFcn', '_XOPEN_SOURCE', 'u_short',
           'SECAlgorithmID', '_UNISTD_H', 'CKG_MGF1_SHA512',
           'CKA_BASE', 'SEC_OID_ANSIX962_EC_C2ONB191V4',
           'SEC_OID_AVA_GENERATION_QUALIFIER', 'CKF_GENERATE',
           'IN_CLASSA_MAX', 'PR_MSEC_PER_SEC', 'PF_X25',
           'IPPORT_CMDSERVER', '_POSIX_TRACE_LOG',
           'PR_LIBRARY_NOT_LOADED_ERROR',
           'CRL_IMPORT_DEFAULT_OPTIONS', '__GLIBC__',
           'pthread_rwlockattr_t', 'PR_BYTES_PER_INT64',
           'CK_OBJECT_HANDLE', 'CK_TLS_PRF_PARAMS_PTR',
           'SO_OOBINLINE', 'PR_CALLOC',
           'N15pthread_mutex_t17__pthread_mutex_s3DOT_6E',
           '_SC_NL_ARGMAX', 'SSLExtensionType', 'PR_PRIORITY_LOW',
           '__u_int', 'CKA_BITS_PER_PIXEL',
           '_CS_POSIX_V6_WIDTH_RESTRICTED_ENVS', 'SEC_ASN1_SKIP',
           '_SC_DEVICE_IO', '_SC_SELECT', '_XLOCALE_H',
           'CERTGeneralNameListStr', 'CKM_AES_CBC',
           'PK11CertListUnique', 'CK_ULONG_PTR',
           'SSL_ERROR_RX_MALFORMED_HANDSHAKE', 'KU_KEY_CERT_SIGN',
           'SSL_ERROR_SIGN_HASHES_FAILURE', 'CERTCertificateListStr',
           'IPPROTO_AH', '_SC_MONOTONIC_CLOCK',
           'SEC_OID_X509_SUBJECT_DIRECTORY_ATTR',
           'CKH_MONOTONIC_COUNTER', 'CKM_SKIPJACK_OFB64', 'PR_IWGRP',
           '_IONBF', 'CKR_BUFFER_TOO_SMALL', 'pthread_mutexattr_t',
           'CK_CHAR', 'PR_SYS_DESC_TABLE_FULL_ERROR',
           'UNSUPPORTED_CERT_EXTENSION', 'PF_ROSE', 'MAX_IV_LENGTH',
           '_BITS_UIO_H', 'SEC_OID_PKCS9_FRIENDLY_NAME',
           'CK_CALLBACK_FUNCTION', 'CERTVerifyLogStr', '__USE_POSIX2',
           'CKA_ALWAYS_SENSITIVE', '__USE_XOPEN2K8XSI', 'cipher_3des',
           'PR_SockOpt_Keepalive', 'IPV6_RECVRTHDR',
           'SEC_OID_PKIX_OCSP_ARCHIVE_CUTOFF', 'CERTRDN',
           'SSL3Opaque', 'PR_BYTES_PER_WORD', 'kg_null',
           'SECKEYDHPublicKeyStr', 'SSL_RENEGOTIATE_NEVER',
           'SSL_BYPASS_PKCS11', 'NS_CERT_TYPE_SSL_SERVER',
           'CKM_MD2_HMAC_GENERAL', 'in_port_t', 'SEC_OID_PKIX_OCSP',
           'MD2_LENGTH', 'AF_PHONET', 'u_char',
           'SSLWrappedSymWrappingKey', 'CK_UNLOCKMUTEX',
           'SEC_OID_AVA_HOUSE_IDENTIFIER',
           'CKR_MECHANISM_PARAM_INVALID', 'PZ_NewCondVar',
           'BITS_PER_DOUBLE', 'SECAlgorithmIDStr', 'SECStatus',
           'CKM_SEED_ECB_ENCRYPT_DATA', 'CERTValParamOutValueStr',
           'CERTCrlStr', 'SSL_ERROR_INTERNAL_ERROR_ALERT',
           'CKM_CAST5_MAC', 'SECTrustTypeEnum', 'CKF_RNG',
           'SEC_ASN1_NULL', 'CKA_HAS_RESET',
           '_CS_V5_WIDTH_RESTRICTED_ENVS', 'EAI_FAIL', 'IP_RECVOPTS',
           'CERTCertDBHandle', 'SEC_OID_ANSIX962_EC_C2PNB368W1',
           'PRFloat64', '_SC_FSYNC', 'IPPROTO_IP',
           'SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH',
           'SEC_ERROR_OCSP_UNAUTHORIZED_RESPONSE', 'PRCList',
           'IP_PMTUDISC_WANT', 'TLS_EX_SESS_TICKET_LIFETIME_HINT',
           'SEC_ERROR_BAD_INFO_ACCESS_METHOD',
           'SEC_OID_PKCS9_EMAIL_ADDRESS',
           'SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST', 'EAI_FAMILY',
           'PRCallOnceFN', 'CK_INVALID_SESSION',
           'NS_CERT_TYPE_SSL_CLIENT', 'SSL3Alert', 'CERTDERCertsStr',
           'PR_BYTES_PER_FLOAT',
           'N18CERTCertificateStr4DOT_564DOT_57E', 'ssl3SidKeys',
           '__ILP32_OFFBIG_CFLAGS', 'IPV6_RTHDR_STRICT',
           'SEC_ERROR_NO_NODELOCK', 'WIFSIGNALED', 'uint_fast16_t',
           'PK11SlotInfoStr', 'SSL_ERROR_CLOSE_NOTIFY_ALERT',
           'SSL_ERROR_UNKNOWN_CA_ALERT', 'DER_ANY', 'uint_fast32_t',
           'crlEntryReasonRemoveFromCRL', 'cipher_rc2_40',
           'unsupported_extension', '_SC_INT_MAX',
           'PRMWaitEnumerator', 'CKF_EC_UNCOMPRESS',
           'CERT_N2A_INVERTIBLE', 'AF_IPX', 'SSLAppOpPost',
           'SEC_ASN1_OBJECT_DESCRIPTOR', 'IP_MULTICAST_LOOP',
           '_POSIX_FSYNC', 'IPPORT_DISCARD', 'PK11TokenPresent',
           'SEC_OID_SECG_EC_SECT131R2', 'CKA_ISSUER',
           'SEC_ERROR_OUT_OF_SEARCH_LIMITS', 'IN_CLASSA',
           'PR_BITS_PER_DOUBLE_LOG2', 'IN_CLASSC', 'IN_CLASSB',
           '_SC_TRACE_EVENT_FILTER', 'CKA_NSS_PQG_SEED',
           'CK_PKCS5_PBKD2_PARAMS', '_SC_LEVEL1_ICACHE_LINESIZE',
           'SO_DEBUG', 'PR_SockOpt_McastLoopback',
           'cert_pi_revocationFlags', 'PR_NO_MORE_FILES_ERROR',
           'cipher_rc4_40', 'CKA_SIGN_RECOVER', 'PRSetsocketoptionFN',
           'certRegisterID', 'CKK_NETSCAPE_PKCS8',
           'SEC_OID_SECG_EC_SECP224R1', 'CKM_RC5_MAC', 'CERTCrlNode',
           'SEC_ERROR_OCSP_INVALID_SIGNING_CERT', 'SEC_OID_MISSI_KEA',
           '_SC_TIMERS', 'SEC_ASN1_SEQUENCE', 'SEC_ERROR_CERT_VALID',
           'CKO_NSS_CRL', 'SSL_ERROR_DECOMPRESSION_FAILURE_ALERT',
           'AF_INET', 'htobe16', '_SC_SHARED_MEMORY_OBJECTS',
           'PRCloseFN', 'nssILockLast', 'PRConnectFN',
           'SEC_OID_PKCS7_DATA', 'CKR_SESSION_READ_ONLY',
           'SIOCGSTAMPNS', 'CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN',
           'cert_po_trustAnchor', 'EAI_NOTCANCELED', 'ino_t',
           '_PC_ALLOC_SIZE_MIN', 'CERT_N2A_STRICT',
           'SEC_ERROR_CRL_V1_CRITICAL_EXTENSION', 'PZ_EnterMonitor',
           '_SC_READER_WRITER_LOCKS', 'PRStuffFunc',
           'SEC_ERROR_CRL_BAD_SIGNATURE', 'CKA_NSS_KRL',
           'PR_BITS_PER_INT64_LOG2', 'SEC_OID_SECG_EC_SECT193R1',
           'PRIntervalTime', '_SC_PII_INTERNET', 'PRFileMapProtect',
           'CKT_NETSCAPE_VALID',
           'SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC',
           'PR_TPD_RANGE_ERROR', 'cert_pi_nbioContext',
           '_PC_VDISABLE', 'CKR_KEY_TYPE_INCONSISTENT',
           '__pthread_slist_t', 'BITS_PER_BYTE',
           'SEC_ERROR_INVALID_PASSWORD', 'CK_ATTRIBUTE_TYPE',
           'SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT', '_PC_MAX_CANON',
           'SSL2_SESSIONID_BYTES', 'CKM_PBE_MD5_CAST_CBC',
           'CK_MAC_GENERAL_PARAMS',
           'SEC_OID_PKCS1_SHA224_WITH_RSA_ENCRYPTION',
           'PRTraceEnable', 'CKM_SHA224', 'SECKEYPQGParamsStr',
           'calg_rc4', 'PRRecvFN', 'ino64_t', '_PATH_HOSTS',
           'ALIGN_OF_INT', 'IN_CLASSA_NSHIFT',
           'ssl_renegotiation_info_xtn', 'CKM_SEED_CBC_PAD',
           'SEC_OID_ANSIX962_EC_PRIME256V1', '_SC_SHELL', 'KU_ALL',
           'CERTCrlDistributionPointsStr',
           'SEC_ERROR_FAILED_TO_ENCODE_DATA',
           'SEC_OID_PKIX_REGINFO_CERT_REQUEST',
           'SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID', 'NI_DGRAM',
           'CKN_SURRENDER', 'CKA_TRUST_DIGITAL_SIGNATURE',
           'HASH_AlgMD5', 'PR_BITS_PER_FLOAT_LOG2', 'HASH_AlgMD2',
           '__STDC_ISO_10646__', 'kea_ecdhe_ecdsa',
           'CKM_GENERIC_SECRET_KEY_GEN',
           'SEC_ERROR_REVOKED_CERTIFICATE_OCSP', '_IO_TIED_PUT_GET',
           'SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO', 'PRSpecialFD',
           'ssl_kea_rsa', 'CERTCertKeyStr', '__FD_ISSET',
           'SSL_MIN_MASTER_KEY_BYTES', 'CKC_NSS', '_SC_HOST_NAME_MAX',
           '_IO_BE', 'SSLHandshakeCallback', 'MAX_MAC_CONTEXT_BYTES',
           'CKM_RIPEMD128', '_SC_TIMEOUTS', 'uint64_t',
           '_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS',
           'SEC_ERROR_BAD_HTTP_RESPONSE', 'CKM_CDMF_CBC_PAD',
           'PR_DESC_SOCKET_TCP', 'crlEntryReasonAffiliationChanged',
           'group_source_req', '_BITS_TYPES_H',
           'IP_DEFAULT_MULTICAST_LOOP', '__have_sigevent_t',
           'PDP_ENDIAN', '_SC_2_C_DEV', 'sslGather', 'CKK_DES',
           'CERTAuthInfoAccess', 'SECMODModuleList', '__rlim_t',
           '__FLOAT_WORD_ORDER',
           'SSL_ERROR_INIT_CIPHER_SUITE_FAILURE',
           'sslSessionIDCacheFunc', 'CKF_ENCRYPT', 'CKO_NSS_TRUST',
           'CKO_DATA', 'PR_DIRECTORY_NOT_EMPTY_ERROR',
           'cert_po_policyOID', 'SEC_ASN1NotifyProc',
           'MCAST_UNBLOCK_SOURCE', 'CK_ULONG', '__isspace_l',
           'SSL3Ciphertext', 'PZMonitor', '_SC_SSIZE_MAX',
           'SEC_ASN1_ANY', 'SSLCipherSuiteInfo', 'ssl_hmac_sha',
           'PZ_DestroyLock', 'INADDR_ALLHOSTS_GROUP',
           'CKA_CHAR_COLUMNS', 'hmac_sha', 'ssl3MACDef', '_IOS_ATEND',
           'PRUptrdiff', 'FIOGETOWN', 'CERTSignedCrl',
           'ssl3CipherSuiteDefStr', 'PK11_ATTR_SENSITIVE',
           'SEC_ERROR_PKCS12_UNABLE_TO_WRITE', 'SEC_OID_HMAC_SHA512',
           'CERTCertTrust', 'SOL_ICMPV6',
           'CK_X9_42_DH1_DERIVE_PARAMS', 'SECMOD_RC2_FLAG',
           'SSL_ERROR_UNKNOWN_CIPHER_SUITE',
           'SEC_OID_PKCS12_V1_CERT_BAG_ID', 'HT_ENUMERATE_REMOVE',
           'CKA_PRIVATE_EXPONENT', 'CK_DESTROYMUTEX', '_IO_INTERNAL',
           'IPPORT_ECHO', 'CKA_APPLICATION', 'MAX_PADDING_LENGTH',
           'dev_t', 'PR_OPERATION_NOT_SUPPORTED_ERROR',
           '_POSIX_SAVED_IDS', 'PF_NETROM', 'SEC_ERROR_INVALID_AVA',
           'IPPROTO_RAW', 'CKC_X_509_ATTR_CERT', 'SECMOD_SHA256_FLAG',
           'PR_SHUTDOWN_RCV', 'SSL_V2_COMPATIBLE_HELLO', 'AF_IRDA',
           'DER_OPTIONAL', 'CERTStatusDestroy', '__GNU_LIBRARY__',
           '_BITS_TYPESIZES_H', 'SSL_REQUIRE_NO_ERROR',
           'CERTNameConstraintsStr',
           'SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY',
           'PZ_DestroyCondVar', 'SEC_ASN1_DEFAULT_ARENA_SIZE',
           'cipher_rc4_56', 'PRStack', 'PRUintn',
           'SEC_OID_SECG_EC_SECT239K1', '_SC_TRACE_LOG', 'certURI',
           'SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION',
           'BITS_PER_WORD', 'SEC_ERROR_JS_ADD_MOD_FAILURE',
           'PRStackStr', 'ssl_server_name_xtn',
           'PR_INVALID_DEVICE_STATE_ERROR',
           'CKA_NETSCAPE_MODULE_SPEC', 'SSLChannelInfo',
           'CERTOidSequence', 'IP_ORIGDSTADDR', 'AF_AX25',
           'PR_DEADLOCK_ERROR',
           'CERT_REV_M_ALLOW_IMPLICIT_DEFAULT_SOURCE',
           'CKR_DEVICE_REMOVED', 'CKF_SIGN', 'SSL3Random',
           'SEC_OID_CERT_RENEWAL_LOCATOR', 'PR_FILE_IS_BUSY_ERROR',
           'SEC_OID_ISO_SHA1_WITH_RSA_SIGNATURE',
           'XP_SEC_FORTEZZA_PERSON_ERROR', 'NS_CERT_TYPE_APP',
           'PR_ACCESS_EXISTS', 'nssILockOther', 'CKF_RW_SESSION',
           '_SC_BC_STRING_MAX', '_CS_XBS5_LPBIG_OFFBIG_LIBS',
           'CKR_KEY_CHANGED', 'SEC_OID_SEED_CBC', 'user_canceled',
           'SEC_ERROR_NO_KEY', 'CERTAuthKeyID', 'SHA512_LENGTH',
           'SEC_OID_NS_CERT_EXT_BASE_URL', 'CK_ATTRIBUTE_PTR',
           'SEC_ERROR_PKCS12_CORRUPT_PFX_STRUCTURE',
           'SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION', '_POSIX_TRACE',
           'fortezzaKey', 'IPPROTO_MAX',
           'N23CRLDistributionPointStr4DOT_59E',
           '__SIZEOF_PTHREAD_CONDATTR_T', '_SC_ARG_MAX',
           'PR_ACCESS_WRITE_OK', 'PR_NOT_SAME_DEVICE_ERROR',
           '__timer_t', 'CK_BYTE', 'SSL_ERROR_TX_RECORD_TOO_LONG',
           'SEC_OID_PKIX_OCSP_RESPONSE', '__W_CONTINUED',
           'PRSendfileFN', 'IPPORT_WHOIS', 'ssl_calg_aes', 'CK_TRUST',
           'SSL_RESTRICTED', 'PR_LOG_NONE', 'ALIGN_OF_POINTER',
           'SEC_OID_PKCS12_CERT_BAG_IDS',
           'SEC_ERROR_INADEQUATE_KEY_USAGE', 'ssl_SHUTDOWN_SEND',
           'PRPrimordialFn', 'SSL3SessionID', 'SECKEYKEAParamsStr',
           'SECComparison', 'PR_TEST_BIT',
           'CK_KEY_DERIVATION_STRING_DATA_PTR',
           'SSL_ERROR_BAD_MAC_READ', 'ssl_calg_des',
           'SEC_CERTIFICATE_REQUEST_VERSION', 'PR_BITS_PER_DOUBLE',
           '_CS_POSIX_V6_LP64_OFF64_LDFLAGS', 'CKM_INVALID_MECHANISM',
           'PRScanStackFun', 'PR_SEM_CREATE', 'MSG_ERRQUEUE',
           'OtherName', 'PK11_TypePubKey', 'CKA_CHAR_SETS',
           'IPPROTO_IGMP', 'IP_FREEBIND',
           'SSL_ERROR_DECRYPTION_FAILURE', 'PR_LANGUAGE_I_DEFAULT',
           'SEC_ERROR_OCSP_OLD_RESPONSE', '_PC_FILESIZEBITS',
           '__FD_SETSIZE', 'N8sigevent4DOT_474DOT_48E',
           'IPV6_PKTINFO', 'SEC_CERTIFICATE_VERSION_2',
           'cipher_camellia_256', 'SEC_CERTIFICATE_VERSION_1',
           'sender_server', '_POSIX_CLOCK_SELECTION', 'PF_CAN',
           'PRStatus', 'XP_SEC_FORTEZZA_NO_MORE_INFO',
           '_POSIX_THREAD_PRIO_INHERIT',
           'SEC_OID_VERISIGN_USER_NOTICES', 'PRArenaPool',
           'CKM_CAMELLIA_CBC', 'CERTRevocationFlags', 'type_stream',
           '_IO_va_list', 'CKO_NETSCAPE_NEWSLOT',
           'CK_DECLARE_FUNCTION_POINTER',
           'SEC_OID_PKCS9_SIGNING_TIME', 'SEC_ERROR_DIGEST_NOT_FOUND',
           'PR_ADDRESS_IN_USE_ERROR', 'CKO_MECHANISM',
           'DER_OBJECT_ID', '_POSIX_THREAD_SAFE_FUNCTIONS',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4', 'msghdr',
           'SO_TIMESTAMP', 'cipher_seed',
           'SEC_OID_NETSCAPE_RECOVERY_REQUEST', 'SCM_TIMESTAMPING',
           'NI_NUMERICHOST', 'nssILockRefLock',
           'CKR_NETSCAPE_KEYDB_FAILED', 'int32_t', 'off64_t',
           'PL_HASH_BITS', 'MAX_CIPHER_CONTEXT_LLONGS',
           'sslSessionIDStr', 'SEC_OID_NETSCAPE_AOLSCREENNAME',
           'ssl_auth_dsa', 'DER_SET', '__locale_data',
           'CERTAttributeStr', 'PF_IPX', 'htole64',
           'SSL_SNI_CURRENT_CONFIG_IS_USED', 'PR_BYTES_PER_SHORT',
           'SSL_HANDSHAKE_AS_SERVER', 'SOL_DECNET', 'IPPROTO_EGP',
           'XP_SEC_FORTEZZA_MORE_INFO', 'sslSecurityInfoStr',
           '_SC_LEVEL1_ICACHE_ASSOC', 'putc', 'PRStaticLinkTable',
           '_CS_POSIX_V7_LP64_OFF64_CFLAGS', '_IO_HEX', 'AF_LOCAL',
           '_SC_V6_LPBIG_OFFBIG', '_SC_2_PBS_MESSAGE', 'PR_AI_ALL',
           'CKA_MODIFIABLE', 'PR_BITS_PER_SHORT_LOG2',
           '_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS', 'PK11CertListCA',
           'calg_null', 'WNOHANG', 'CERT_ENABLE_LDAP_FETCH',
           'sslSocket',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC',
           'CKM_EXTRACT_KEY_FROM_KEY', '_CS_V6_WIDTH_RESTRICTED_ENVS',
           'FILENAME_MAX', 'PRCListStr', 'CKM_CAST128_ECB',
           'EXIT_SUCCESS', '__suseconds_t',
           'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR',
           'LL_GE_ZERO', 'SSL3_RECORD_HEADER_LENGTH',
           'XP_SEC_FORTEZZA_NONE_SELECTED', 'CKM_RC2_MAC_GENERAL',
           'SSLAuthCertificate', 'DER_METHOD_MASK',
           'SSL3HelloRequest', 'cipher_des40',
           'CKT_NETSCAPE_VALID_DELEGATOR', 'AF_ROSE',
           'CKM_SSL3_MASTER_KEY_DERIVE', 'CKM_CAMELLIA_MAC',
           'HT_ENUMERATE_UNHASH', 'AF_UNSPEC', 'CKR_DEVICE_MEMORY',
           'CKM_RSA_PKCS', 'PR_UNLOAD_LIBRARY_ERROR',
           'SEC_ERROR_PKCS12_CERT_COLLISION',
           'SSL_ERROR_UNSUPPORTED_VERSION', 'CKA_COEFFICIENT',
           'CKM_TLS_PRF', 'PR_IO_TIMEOUT_ERROR', 'SECKEYDSAPublicKey',
           'MAX_CERT_TYPES', 'IPV6_RECVHOPLIMIT',
           'SO_SECURITY_AUTHENTICATION', 'PRTraceBufSize',
           'PRThreadPool', 'SO_SECURITY_ENCRYPTION_NETWORK',
           'blksize_t', 'CKM_BATON_CBC128', 'PR_BITS_PER_FLOAT',
           'AF_DECnet', 'PZ_Wait', 'CERTDistNames',
           'SSL_ERROR_SYM_KEY_UNWRAP_FAILURE',
           'SUPPORTED_CERT_EXTENSION', '_IO_marker', 'CKA_CLASS',
           'uprword_t', 'PR_POLL_NVAL', 'CERTAttribute',
           'SSL_REQUIRE_ALWAYS', '_SC_TZNAME_MAX', '_POSIX_BARRIERS',
           '__SIZEOF_PTHREAD_ATTR_T', 'SO_PROTOCOL',
           'ssl3CipherSuiteCfg', 'siCipherDataBuffer',
           'ssl3CipherSuite', 'PK11_OriginGenerated', 'CKA_NSS_PQG_H',
           'ucred', 'sslHandshakingUndetermined', 'ALIGN_OF_INT64',
           '_IO_lock_t', 'PR_IRUSR', 'calg_rc2',
           'PR_SockOpt_IpTimeToLive', '_CS_XBS5_LPBIG_OFFBIG_LDFLAGS',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC',
           'PR_VMINOR', 'N16SSL3ServerParams5DOT_120E',
           'CERTCertTrustStr', '_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS',
           'SEC_ERROR_BASE', 'uint_fast64_t',
           'SEC_OID_NS_CERT_EXT_COMMENT',
           'SEC_OID_PKCS7_ENVELOPED_DATA', 'SEC_OID_PKCS12_BAG_IDS',
           'SEC_OID_PKCS7', 'CKM_NSS', 'CKK_RC2', 'AF_RXRPC',
           'PK11_DISABLE_FLAG', 'sslSendFunc', 'PR_SHM_CREATE',
           'SEC_OID_ANSIX962_EC_C2PNB208W1', 'CK_CREATEMUTEX',
           'IPV6_PMTUDISC_DO', 'CKR_DOMAIN_PARAMS_INVALID',
           'CKH_USER_INTERFACE', '_XOPEN_SOURCE_EXTENDED', 'PF_FILE',
           '__USE_XOPEN2KXSI', 'AI_NUMERICHOST',
           'PR_NOT_CONNECTED_ERROR', 'SSL_ERROR_UNSAFE_NEGOTIATION',
           'PR_AI_DEFAULT', '_SC_RTSIG_MAX', 'CKA_NSS_PQG_SEED_BITS',
           'CKM_FORTEZZA_TIMESTAMP', 'pthread_condattr_t',
           '_SC_LEVEL4_CACHE_ASSOC', '__fsid_t', 'CK_EC_KDF_TYPE',
           'cert_po_nbioContext', 'ispunct_l',
           'CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC', 'ssl_auth_rsa',
           '_CS_XBS5_ILP32_OFFBIG_CFLAGS', '__USE_XOPEN2K8',
           '_SC_XBS5_ILP32_OFF32', 'PR_WRONLY', 'PRThreadPriority',
           'crlEntryReasonKeyCompromise',
           'SEC_ERROR_CERT_NOT_IN_NAME_SPACE', 'cipher_aes_256',
           'CK_VERSION', 'RAND_MAX', 'uint16', 'PRHashEnumerator',
           'SEC_OID_AVA_COUNTRY_NAME', 'ssl3KeyPair',
           'CKR_WRAPPING_KEY_HANDLE_INVALID',
           'SSL_ERROR_RX_MALFORMED_ALERT', 'CKA_DERIVE',
           'SECMOD_TLS_FLAG', 'CKA_NSS_PKCS8_SALT', 'PRThreadState',
           '_SC_V6_ILP32_OFF32', 'CK_SSL3_KEY_MAT_OUT_PTR',
           'SSL_RENEGOTIATE_REQUIRES_XTN', 'L_INCR',
           'SECMOD_RC5_FLAG', 'int_least32_t', '__STDC_IEC_559__',
           'CKA_ECDSA_PARAMS', 'SECMOD_RANDOM_FLAG', '_SC_PII_XTI',
           'CKM_X9_42_DH_PARAMETER_GEN', 'PRAcceptFN',
           'CK_UTF8CHAR_PTR', 'PR_POLL_WRITE', 'keaKey', 'PF_LOCAL',
           'CERTAuthKeyIDStr', 'PRVersionCheck', 'SO_PEERSEC',
           'MCAST_BLOCK_SOURCE',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4', '_SC_TRACE',
           'CKM_CAMELLIA_KEY_GEN', 'SEC_ASN1_MAY_STREAM',
           'SEC_ERROR_PKCS12_UNABLE_TO_READ',
           'SEC_ERROR_NO_SLOT_SELECTED', 'CKK_ECDSA', 'CKM_CMS_SIG',
           'wait_finished', '_SIGSET_H_types',
           '_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS',
           'SEC_OID_SECG_EC_SECP160K1', 'KU_DATA_ENCIPHERMENT',
           'INADDR_LOOPBACK', 'SHA256_LENGTH', 'PF_ATMPVC',
           'DER_UNIVERSAL', '__SIZEOF_PTHREAD_RWLOCK_T',
           'PR_WOULD_BLOCK_ERROR', 'IPV6_ADD_MEMBERSHIP',
           'SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE',
           'SSL_ERROR_GENERATE_RANDOM_FAILURE',
           'SEC_OID_PKIX_REGCTRL_PROTOCOL_ENC_KEY', 'IPPORT_SMTP',
           'SEC_ERROR_CRL_IMPORT_FAILED',
           'PR_READ_ONLY_FILESYSTEM_ERROR', 'PLHashNumber',
           'SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_TRIPLE_DES',
           'IP_PKTOPTIONS',
           'CERT_REV_MI_TEST_ALL_LOCAL_INFORMATION_FIRST',
           'EAI_ADDRFAMILY', 'CKM_CAST3_KEY_GEN', 'PRInt64',
           'SEC_OID_DES_EDE', 'MSG_CMSG_CLOEXEC', 'rsaKey',
           'SEC_OID_PKCS9_X509_CRL', '_ISOC99_SOURCE', 'AF_NETBEUI',
           'SEC_OID_CAMELLIA_128_CBC', 'SEC_OID_CAMELLIA_256_CBC',
           'CKA_NSS_MODULE_SPEC', 'SEC_ERROR_CERT_NICKNAME_COLLISION',
           '_IO_FIXED', 'nssILockType', 'SSLGetClientAuthData',
           'server_key_exchange', 'SEC_OID_PKCS1_MGF1', 'CKA_DECRYPT',
           'CERTGeneralName', 'CKM_SHA512_RSA_PKCS',
           'CKM_KEA_KEY_PAIR_GEN',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC',
           'DER_FORCE', 'FD_ISSET', 'PRErrorCode', 'CKT_NSS_VALID',
           'SEC_ERROR_KEY_NICKNAME_COLLISION',
           'SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH',
           '__codecvt_result', 'SCM_CREDENTIALS', 'CKA_MODULUS_BITS',
           'PR_FILE_EXISTS_ERROR', '__USE_EXTERN_INLINES_IN_LIBC',
           'SO_RXQ_OVFL', 'PK11_DIS_COULD_NOT_INIT_TOKEN',
           'CKS_RO_PUBLIC_SESSION', 'IP_HDRINCL', 'IPPORT_FINGER',
           'CKM_SHA384_HMAC', 'N14ClientIdentity5DOT_136E',
           'SSL_ERROR_MAC_COMPUTATION_FAILURE', 'int64',
           'CERTNoticeReference', 'AF_FILE', 'PR_RWLOCK_RANK_NONE',
           '_POSIX2_VERSION', '_BITS_SOCKADDR_H', 'PR_FAILURE',
           'CK_SESSION_INFO_PTR', 'SEC_ASN1_GENERAL_STRING',
           'PK11DefaultArrayEntry', '_SC_PII', '_POSIX2_CHAR_TERM',
           'PZ_NewMonitor', '_IO_IN_BACKUP', 'CKA_AUTH_PIN_FLAGS',
           'CERT_REV_M_ALLOW_NETWORK_FETCHING',
           'SEC_OID_DES_EDE3_CBC', 'CKM_PBA_SHA1_WITH_SHA1_HMAC',
           'SECKEYECParams', 'PRTraceOption',
           'CERT_REV_M_FAIL_ON_MISSING_FRESH_INFO', '_RPC_NETDB_H',
           'PRSeekFN', 'SEC_ASN1_DEBUG_BREAK', 'SEC_OID_HMAC_SHA1',
           'SOCK_RAW', 'AF_ECONET', 'kt_kea_size',
           'sslHandshakingType', 'SEC_ERROR_OLD_KRL',
           'CK_ECMQV_DERIVE_PARAMS',
           'SEC_OID_X509_PRIVATE_KEY_USAGE_PERIOD',
           'PR_NOT_TCP_SOCKET_ERROR', '_POSIX_CPUTIME',
           'PK11GenericObject', 'kea_rsa_export',
           'SSL_ERROR_USER_CANCELED_ALERT', 'AF_WANPIPE',
           '_CS_XBS5_LP64_OFF64_LIBS', 'SEC_OID_AES_192_ECB',
           '_SC_LEVEL2_CACHE_ASSOC', 'siDERCertBuffer', 'PR_LOG_MAX',
           'CKF_OS_LOCKING_OK', 'SSLAppOpRDWR', 'CKM_CAST3_ECB',
           'PR_ALIGN_OF_INT', 'CERTStatusConfig',
           '_SC_CHARCLASS_NAME_MAX',
           '_CS_XBS5_ILP32_OFFBIG_LINTFLAGS', 'CKM_SEED_KEY_GEN',
           '_IOS_APPEND', 'CKM_CAST128_CBC', 'kea_rsa_export_1024',
           'PF_BRIDGE', '_POSIX_SPAWN', 'certUsageAnyCA',
           '_SC_THREAD_ROBUST_PRIO_INHERIT', 'htobe32', 'SSLSignType',
           'PR_SockOpt_Nonblocking', 'BUFSIZ',
           '_CS_XBS5_ILP32_OFF32_LDFLAGS', '_SC_COLL_WEIGHTS_MAX',
           'IPPORT_TELNET', 'PR_NSEC_PER_SEC',
           'CKF_USER_PIN_COUNT_LOW', 'PK11_PW_RETRY',
           'CKR_NSS_KEYDB_FAILED', 'SSL_ERROR_MD5_DIGEST_FAILURE',
           'CK_TRUE', 'SSL_ERROR_WEAK_SERVER_EPHEMERAL_DH_KEY',
           'SEC_ERROR_BAD_INFO_ACCESS_LOCATION', 'HASH_AlgNULL',
           'CK_MECHANISM_TYPE', 'SSL3KeyGenMode', 'SOL_IRDA',
           '_ENDIAN_H', 'PR_MAX_IOVECTOR_SIZE', 'SSL_REQUIRE_NEVER',
           'SSL3ChangeCipherSpecChoice', 'CK_SESSION_HANDLE_PTR',
           'CKM_AES_CBC_PAD', 'CKO_PRIVATE_KEY', '_IO_SHOWPOS',
           'u_quad_t', '_POSIX_TIMEOUTS', 'SEC_ASN1_HIGH_TAG_NUMBER',
           'PF_KEY', 'SEC_OID_X509_BASIC_CONSTRAINTS',
           'PR_ALIGN_OF_SHORT', 'IP_RETOPTS', 'IPV6_JOIN_GROUP',
           'SEC_OID_PKCS12_PBE_IDS', 'SEC_OID_SECG_EC_SECP384R1',
           'KU_ENCIPHER_ONLY', 'SEC_OID_AVA_SERIAL_NUMBER',
           'PR_REMOTE_FILE_ERROR', '_IO_MAGIC', 'WEXITSTATUS',
           'BYTE_ORDER', '_SC_BASE', 'isupper_l', 'STDOUT_FILENO',
           'SOL_X25', 'cert_pi_end', 'MCAST_JOIN_GROUP',
           '_G_NEED_STDARG_H', 'ip6_mtuinfo',
           'TLS_STE_NO_SERVER_NAME', '__SIZEOF_PTHREAD_RWLOCKATTR_T',
           '__u_quad_t', '__u_short', '__USE_FORTIFY_LEVEL',
           'N18CERTCertificateStr4DOT_56E', 'PRTraceResume',
           'AF_BRIDGE', '_BSD_SOURCE', 'CKK_KEA', '_POSIX_VERSION',
           'CKM_PBE_SHA1_RC2_40_CBC', 'PR_ALIGN_OF_LONG', '_IScntrl',
           'SEC_ERROR_UNKNOWN_OBJECT_TYPE', 'int32', 'AF_ASH',
           'uint8', 'SECFailure', 'PF_WANPIPE', 'CKM_MD2',
           'EAI_CANCELED', 'PR_BITMASK', 'MAX_MAC_CONTEXT_LLONGS',
           'CKK_BATON', 'XP_JAVA_REMOVE_PRINCIPAL_ERROR',
           'kea_dhe_dss_export', 'PRTraceUnLockHandles',
           'IP_ADD_MEMBERSHIP', 'SECKEYFortezzaPublicKeyStr',
           'CKM_RIPEMD128_HMAC_GENERAL', 'IPPROTO_NONE', '_ISpunct',
           '__toascii', '_LFS64_ASYNCHRONOUS_IO', 'SO_PASSSEC',
           'SEC_OID_BOGUS_KEY_USAGE', 'sslConnectInfo',
           'ct_DSS_fixed_DH', 'SEC_ASN1_UNIVERSAL_STRING',
           'SIOCSPGRP', 'offsetof', 'SECEqual', '_SC_TTY_NAME_MAX',
           'NFDBITS', 'CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN',
           '_SC_SYSTEM_DATABASE', 'PR_GLOBAL_THREAD',
           'SEC_ERROR_OCSP_NO_DEFAULT_RESPONDER', 'SO_PASSCRED',
           '__io_seek_fn', 'PRPollDesc', 'iscntrl_l', 'CERTCrlKeyStr',
           'AF_ISDN', 'ct_RSA_ephemeral_DH', 'nssILockOID',
           'KU_KEY_ENCIPHERMENT', 'AF_PACKET',
           'CKM_TLS_MASTER_KEY_DERIVE_DH', '_G_ssize_t',
           'SEC_ERROR_BAD_PASSWORD', 'AI_NUMERICSERV', 'CKF_EC_F_P',
           'crlEntryReasoncertificatedHold', 'sslSessionIDLookupFunc',
           'sslGatherStr', 'CKA_MECHANISM_TYPE', 'CKA_ENCRYPT',
           'CKM_SHA256_HMAC', 'in_pktinfo', '_IO_FILE_plus',
           'SEC_ERROR_KRL_NOT_YET_VALID', 'KU_NON_REPUDIATION',
           'SSL_ERROR_TOKEN_INSERTION_REMOVAL', '__timer_t_defined',
           'PRCallOnceWithArgFN', 'BITS_PER_INT64_LOG2',
           'SECItemType', 'CERTCertificateRequest', 'content_alert',
           'SOL_AAL', 'PR_LD_ALT_SEARCH_PATH', 'uint64',
           'SECMOD_MD5_FLAG', '_SC_NZERO', 'SECKEYPrivateKeyStr',
           '_SC_NPROCESSORS_CONF', 'nssRWLockStr', 'CKT_NSS_TRUSTED',
           '_IO_fpos64_t', '__mbstate_t_defined', 'PR_StandardError',
           '_CS_POSIX_V6_LP64_OFF64_LIBS',
           'SEC_OID_SECG_EC_SECT233K1', '__time_t_defined',
           '__time_t', '_SC_ULONG_MAX', '__GLIBC_PREREQ',
           'CKA_NETSCAPE_SMIME_TIMESTAMP', 'MSG_RST',
           'SSL3ServerParams', 'PK11TokenPresentEvent',
           'PRReservedFN', 'PRErrorCallbackTablePrivate',
           'SEC_OID_PKIX_REGINFO_UTF8_PAIRS', 'SEC_ASN1_OBJECT_ID',
           '_CS_LFS_LINTFLAGS', 'PF_ISDN', 'pthread_rwlock_t',
           'IP_PKTINFO', 'cert_pi_policyOID',
           'SEC_OID_ANSIX9_DSA_SIGNATURE',
           'SEC_OID_EXT_KEY_USAGE_SERVER_AUTH',
           'CK_KEY_WRAP_SET_OAEP_PARAMS', 'SEC_ASN1_REAL',
           'CKM_RSA_9796', '_SC_MEMLOCK', 'timespec',
           'DistributionPointTypes', 'NI_MAXSERV',
           '_POSIX2_LOCALEDEF', 'nssILockDBM', 'CK_SLOT_INFO',
           '_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS',
           '_SC_PII_INTERNET_STREAM', 'SEC_ERROR_LIMIT', 'PRUint8',
           'SEC_OID_HMAC_SHA224', '_IO_USER_BUF', 'CKM_DES3_MAC',
           'CERTSignedDataStr', 'N9PRLibSpec4DOT_16E',
           'ssl_calg_idea', 'CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE',
           'PRAccessHow', 'IPPROTO_TP', '__POSIX2_THIS_VERSION',
           'SO_BROADCAST', 'CKM_MD5_HMAC_GENERAL', 'LL_MININT',
           '_SC_SS_REPL_MAX', '_G_ARGS', 'CERTSortCallback',
           'PR_AI_NOCANONNAME', 'CKM_RC2_CBC_PAD',
           'SEC_ASN1_Identifier', '_G_HAVE_MMAP', '__u_char',
           'CK_X9_42_MQV_DERIVE_PARAMS_PTR',
           '__attribute_format_strfmon__', 'certPackageCert',
           'CKA_SUBPRIME', 'certIPAddress',
           'CKM_WTLS_MASTER_KEY_DERIVE',
           'CKR_USER_ANOTHER_ALREADY_LOGGED_IN', '_SC_TRACE_INHERIT',
           'CRLDistributionPointStr', 'SSL_SNI_SEND_ALERT',
           'SEC_OID_DES_MAC', 'SECMOD_MODULE_DB_FUNCTION_DEL',
           'PK11IsLoggedInFunc', 'NS_CERT_TYPE_EMAIL',
           'N4wait4DOT_20E', '_SC_LEVEL4_CACHE_LINESIZE', 'SO_ERROR',
           'CERTStatusChecker', 'pr_bitscan_clz32', 'SCM_TIMESTAMP',
           'secCertTimeValid', 'SEC_OID_NETSCAPE_NICKNAME',
           'SSL3StatisticsStr', 'AF_IEEE802154',
           'CKM_RSA_PKCS_KEY_PAIR_GEN', 'CKA_NETSCAPE_KRL',
           'SECCertTimeValidityEnum',
           'SEC_OID_PKIX_OCSP_BASIC_RESPONSE',
           'N10PRIPv6Addr4DOT_50E', 'N9PRNetAddr4DOT_52E',
           'ssl3KeyMaterial', '_G_FSTAT64', 'CKR_KEY_SIZE_RANGE',
           'prword_t', 'SECKEYDHParamsStr', 'IPV6_RTHDR_LOOSE',
           'PRHostEnt', '_G_HAVE_SYS_WAIT', 'IP_MTU', 'rsaPssKey',
           'GS_DATA', 'PR_NO_ACCESS_RIGHTS_ERROR', 'SOMAXCONN',
           'SEC_ERROR_LIBPKIX_INTERNAL', 'SIGEV_THREAD_ID',
           '_POSIX_ASYNC_IO', 'CERTCertificateRequestStr', '__off_t',
           'PR_CONNECT_RESET_ERROR', 'uptrdiff_t', 'random_data',
           'PK11_ATTR_INSENSITIVE', 'CKA_START_DATE',
           '_SC_LEVEL4_CACHE_SIZE', 'CKA_EC_PARAMS', 'PR_LANGUAGE_EN',
           'sslSocketOpsStr', 'INADDR_BROADCAST',
           'CERTCertificatePolicies',
           'SSL_ERROR_RX_UNEXPECTED_CHANGE_CIPHER',
           'PR_LOAD_LIBRARY_ERROR', 'CK_SKIPJACK_RELAYX_PARAMS_PTR',
           'SEC_OID_SECG_EC_SECP256K1', '_IOS_TRUNC',
           'CERTPackageTypeEnum', '_SC_2_LOCALEDEF',
           'SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE',
           'SEC_OID_X509_CERT_ISSUER', 'uint_least32_t',
           'SEC_OID_ANSIX962_EC_C2PNB176V1', 'NI_NOFQDN', 'PR_APPEND',
           'CKM_BATON_ECB96', '_CS_POSIX_V7_ILP32_OFF32_LIBS',
           'SECMOD_SHA1_FLAG', 'ssl_SHUTDOWN_RCV',
           'SEC_OID_AES_256_KEY_WRAP', 'CKA_CERT_MD5_HASH',
           'CKO_CERTIFICATE', 'SEC_OID_PKCS9_EXTENSION_REQUEST',
           'CertStrictnessLevel', 'SEC_OID_AES_256_CBC',
           '_SC_WORD_BIT', 'SEC_OID_FORTEZZA_SKIPJACK',
           'SSL_ERROR_NO_SERVER_KEY_FOR_ALG',
           '_CS_XBS5_ILP32_OFF32_LIBS', 'MSG_SYN',
           'SESS_TICKET_KEY_NAME_PREFIX', 'nssILockSession',
           '__USE_POSIX', '_SC_SPORADIC_SERVER', 'PR_ROTATE_LEFT32',
           '_SC_PII_SOCKET', 'CK_CERTIFICATE_TYPE',
           'SEC_OID_PKCS12_V1_SECRET_BAG_ID',
           'PR_SI_HOSTNAME_UNTRUNCATED', 'PF_IRDA', 'ulong',
           'IPV6_RXDSTOPTS', 'SSL_ERROR_TOKEN_SLOT_NOT_FOUND',
           'pthread_key_t', 'PK11SymKey',
           'SSL_ERROR_EXPORT_ONLY_SERVER', 'CERTCertListNode',
           'ClientIdentity', 'u_int8_t', 'pthread_mutex_t',
           'CK_OBJECT_CLASS', '__WALL', 'PR_LibSpec_PathnameU',
           'BITS_PER_LONG', 'uint32_t', 'IPPORT_TIMESERVER',
           'intptr_t', 'IPPORT_NETSTAT', 'CERTIssuerAndSNStr',
           'CK_FUNCTION_LIST_PTR', 'FD_ZERO', 'SEC_ASN1_INTEGER',
           'SSL3KeyExchangeAlgorithm',
           'certificateUsageStatusResponder', 'PRSendFileData',
           '_SC_THREAD_PRIO_INHERIT',
           'EXT_KEY_USAGE_STATUS_RESPONDER',
           'certUsageSSLServerWithStepUp',
           'PR_NETWORK_UNREACHABLE_ERROR', '_IO_UNBUFFERED',
           'PZCondVar', 'sa_family_t',
           'CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4',
           'SSL3ChangeCipherSpec', 'PRProcess', '__isprint_l',
           'SEC_OID_OCSP_RESPONDER', 'CERTCrlHeadNodeStr',
           'cert_po_certList', 'DERTemplate', 'certificate_revoked',
           'CKA_NETSCAPE_EXPIRES', 'CERTValInParam',
           'SEC_OID_ANSIX962_EC_PUBLIC_KEY',
           'NSS_USE_ALG_IN_CMS_SIGNATURE', 'socklen_t',
           'SO_KEEPALIVE', 'CK_INVALID_HANDLE', 'L_XTND',
           'ct_RSA_sign', 'CIS_HAVE_VERIFY', 'PR_AF_UNSPEC', 'uint',
           'AF_TIPC', '_G_off64_t', 'PRTraceLockHandles',
           'nssILockRWLock', 'CKM_SKIPJACK_CFB16',
           '_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS', 'SIGEV_THREAD',
           'kea_ecdhe_rsa', 'CKR_KEY_NEEDED',
           'CERT_POLICY_FLAG_NO_MAPPING',
           'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE',
           'CERT_REV_M_DO_NOT_TEST_USING_THIS_METHOD', 'explicit',
           'PR_SI_RELEASE', 'CERTGeneralNameType',
           'SEC_ERROR_KRL_INVALID', 'SEC_ASN1EncodingPart',
           'PRNetAddrValue', 'PK11_TypePrivKey',
           'CKR_CRYPTOKI_ALREADY_INITIALIZED',
           'SEC_ERROR_UNRECOGNIZED_OID', 'IPV6_HOPOPTS',
           'SEC_ERROR_CERT_NO_RESPONSE',
           'SEC_OID_NS_CERT_EXT_SCOPE_OF_USE',
           'SEC_ERROR_PKCS7_BAD_SIGNATURE', 'PR_LOOP_ERROR',
           '_G_HAVE_IO_GETLINE_INFO', 'SECMOD_DES_FLAG',
           'SEC_ERROR_IO', '_POSIX2_C_DEV', '_SC_PII_OSI_M',
           'N9PRLibSpec4DOT_164DOT_17E', 'IN_CLASSB_HOST', 'FILE',
           'size_t', 'sslBuffer', '__GLIBC_HAVE_LONG_LONG',
           'PK11_OriginUnwrap', 'IN_CLASSA_HOST', 'SOCK_SEQPACKET',
           'PR_TRANSMITFILE_CLOSE_SOCKET', 'DER_INTEGER',
           'CKO_VENDOR_DEFINED', 'CKA_CHAR_ROWS',
           '_SC_MEMORY_PROTECTION', 'IPV6_RECVTCLASS', 'SSL3Finished',
           'CKM_SKIPJACK_WRAP', 'PR_FILE_SEEK_ERROR',
           'SEC_OID_PKCS12_MODE_IDS', '_POSIX_MEMLOCK_RANGE',
           'SEC_OID_AVA_COMMON_NAME',
           'SEC_OID_ANSIX962_EC_PRIME239V2',
           'SEC_ERROR_OCSP_SERVER_ERROR', 'CKF_EC_F_2M', 'CERTName',
           'netent', 'DistributionPointTypesEnum',
           'N18SECKEYPublicKeyStr4DOT_84E', 'PR_POLL_HUP',
           'PZ_NotifyCondVar', 'PRWord', 'siBMPString',
           'pr_bitscan_ctz32', '_SC_SPIN_LOCKS', 'CKA_SECONDARY_AUTH',
           'cert_po_usages', 'kea_ecdh_anon',
           '_CS_XBS5_LP64_OFF64_CFLAGS', 'SSL3SequenceNumber',
           'IN_CLASSB_MAX', 'cookie_write_function_t', 'isxdigit_l',
           'u_long', 'CERTValParamInType', 'SEEK_CUR',
           'SSLChannelInfoStr', 'SSL3_RANDOM_LENGTH',
           'CKA_EXPONENT_1', 'OtherNameStr', 'CKM_DES2_KEY_GEN',
           'MSG_OOB', '_SC_LEVEL1_ICACHE_SIZE', 'sigset_t',
           'SEC_OID_X509_INVALID_DATE', 'CERTNameConstraints',
           'PRStackElemStr', 'SEC_OID_NS_TYPE_JPEG', 'CKM_SHA_1',
           'PR_SOCKET_SHUTDOWN_ERROR', 'NSSTrustDomainStr',
           'CKR_FUNCTION_NOT_SUPPORTED', 'pthread_barrierattr_t',
           '_SC_GETGR_R_SIZE_MAX', 'L_SET',
           'SEC_OID_PKCS9_UNSTRUCTURED_NAME', 'SEC_OID_RFC1274_MAIL',
           '__uint32_t', 'SEC_ERROR_CERT_USAGES_INVALID',
           'PROffset32', 'CKF_VERIFY_RECOVER',
           'SEC_OID_NS_CERT_EXT_CA_REVOCATION_URL', 'PK11SymKeyStr',
           'SSL_ERROR_BAD_BLOCK_PADDING', '_SC_BC_BASE_MAX',
           'MCAST_LEAVE_SOURCE_GROUP', 'CK_WTLS_RANDOM_DATA_PTR',
           'SSL_ENABLE_FALSE_START', 'CKM_KEY_WRAP_SET_OAEP',
           'CKM_TLS_PRF_GENERAL', '_CS_XBS5_LP64_OFF64_LINTFLAGS',
           'SEC_OID_PKCS5_PBMAC1', 'SEC_ERROR_UNKNOWN_CERT',
           '_SC_XOPEN_STREAMS', 'content_change_cipher_spec',
           'NI_NUMERICSERV', 'CKM_SHA256_HMAC_GENERAL',
           'SSL_ERROR_RX_MALFORMED_CERT_VERIFY', 'CERTCrlNodeStr',
           'PRDescType', 'CERT_UNLIMITED_PATH_CONSTRAINT',
           'IPV6_RECVHOPOPTS', 'secCertTimeNotValidYet',
           'CKD_SHA1_KDF_CONCATENATE', '_BITS_WCHAR_H',
           '_SC_XBS5_ILP32_OFFBIG', 'CK_RC5_CBC_PARAMS_PTR',
           'SEC_ERROR_OCSP_UNKNOWN_CERT', 'SECMOD_FORTEZZA_FLAG',
           'int16', '__clockid_t_defined', 'CKM_RSA_X9_31',
           'PK11SlotListElement', 'CKR_NO_EVENT',
           'SSL_ERROR_RX_UNKNOWN_HANDSHAKE', '__SQUAD_TYPE',
           'PR_POLL_EXCEPT', 'uint32', 'uint_least8_t',
           '_SC_CHAR_MAX', 'PR_PROC_DESC_TABLE_FULL_ERROR',
           'nssILockCertDB', 'PRThreadStack', 'ecKey',
           'PRGetsocketoptionFN',
           'SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID', 'PR_IROTH',
           'SO_RCVLOWAT', 'SHUT_RDWR', 'SECKEYPrivateKey',
           'trustTypeNone', 'IN_CLASSB_NSHIFT', '_SC_RE_DUP_MAX',
           'PR_SockOpt_McastTimeToLive', 'PRErrorMessage',
           'CKA_NSS_URL', 'PF_NETBEUI', 'siBuffer',
           'SEC_OID_SECG_EC_SECT571R1', 'SEC_OID_PKCS9_CONTENT_TYPE',
           'protoent', '_SC_TRACE_EVENT_NAME_MAX', 'CKA_MIME_TYPES',
           'AF_ATMSVC', 'PR_DESC_PIPE', 'PRSeek64FN',
           'CKM_TWOFISH_CBC', 'NS_CERT_TYPE_RESERVED', '__USE_GNU',
           'N14pthread_cond_t3DOT_9E', 'WUNTRACED',
           'certUsageEmailSigner', 'CKA_TRUST_CODE_SIGNING',
           'CKS_RO_USER_FUNCTIONS', 'SSL_ERROR_BAD_SERVER',
           '__attribute_format_arg__', 'SEC_ERROR_SAFE_NOT_CREATED',
           'CKR_SESSION_READ_ONLY_EXISTS', 'ssl_kea_null', 'SOL_IPV6',
           'SSL3ClientHello', 'AF_CAN',
           'SEC_OID_X509_AUTH_INFO_ACCESS', 'CK_WTLS_KEY_MAT_OUT_PTR',
           'SECErrorCodes', 'PR_BYTES_PER_INT', 'IPPROTO_ICMP',
           'SECHashObjectStr', 'CKA_VALUE', 'be32toh',
           'IPPROTO_HOPOPTS', '__W_STOPCODE', 'CKF_TOKEN_PRESENT',
           'SEC_ERROR_NO_KRL', 'SSL_ERROR_RX_MALFORMED_CERT_REQUEST',
           'PR_BUFFER_OVERFLOW_ERROR', 'ssl_calg_3des',
           '_SC_THREAD_ATTR_STACKADDR', '__ldiv_t_defined',
           'ssl_calg_fortezza', 'PRAvailableFN',
           'CKR_TEMPLATE_INCOMPLETE', '_SS_PADSIZE',
           'certificateUsageProtectedObjectSigner', 'SOCK_DGRAM',
           'EAI_INTR', 'SO_TIMESTAMPNS', 'type_block', 'pthread_t',
           'N21SSL3ClientKeyExchange5DOT_130E', 'CKA_SUBPRIME_BITS',
           '__isalpha_l', 'SSL_ERROR_NO_CERTIFICATE', 'le16toh',
           'SEC_ERROR_JS_INVALID_DLL', 'IP_BLOCK_SOURCE',
           'internal_error', 'CKG_MGF1_SHA224', 'PR_VERSION',
           '_POSIX_SPORADIC_SERVER', 'SSL_ERROR_NO_CYPHER_OVERLAP',
           '__mbstate_t', 'CKM_CAST_MAC_GENERAL',
           'SSL_ERROR_BAD_CLIENT', '_CS_GNU_LIBC_VERSION',
           'SSL_ENV_VAR_NAME', 'CKM_SSL3_SHA1_MAC', 'PLHashTable',
           '_SC_SEM_VALUE_MAX', 'PRDirFlags', 'decompression_failure',
           'PR_TOP_IO_LAYER', '_G_uid_t', 'kea_dh_dss',
           'BYTES_PER_DWORD', 'PRTraceResumeRecording',
           '_CS_POSIX_V7_ILP32_OFF32_CFLAGS', 'CERTCertOwnerEnum',
           'SEC_ERROR_CRL_NOT_FOUND', 'quad_t', 'PRUnichar',
           '_CS_XBS5_ILP32_OFF32_CFLAGS', 'IN_CLASSC_HOST',
           'PRJobIoDesc', 'IPV6_MTU_DISCOVER', 'dsaKey',
           'CKR_PIN_EXPIRED', 'CERTAVA', 'CKM_AES_MAC_GENERAL',
           'CKM_DSA_KEY_PAIR_GEN', 'CKM_DES3_CBC_PAD',
           'IP_ROUTER_ALERT', 'BPB', 'pthread_cond_t', 'PR_MALLOC',
           '__pthread_internal_slist', 'crlEntryReasonCaCompromise',
           'CKF_LOGIN_REQUIRED', 'group_filter', 'CERTCertificate',
           'SSL_ERROR_IV_PARAM_FAILURE',
           'SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE',
           'SEC_OID_X500_RSA_ENCRYPTION', '_POSIX_V7_ILP32_OFF32',
           'PK11ObjectType', 'SSL_ERROR_SSL_DISABLED', 'nlink_t',
           'PR_INVALID_METHOD_ERROR', 'CKA_CERTIFICATE_CATEGORY',
           'CK_SESSION_INFO', '__UQUAD_TYPE', 'CKR_DEVICE_ERROR',
           'sslConnectInfoStr',
           'SEC_OID_X509_ISSUING_DISTRIBUTION_POINT', 'RF_SUPERSEDED',
           'SEC_ERROR_OCSP_MALFORMED_RESPONSE', 'CKM_JUNIPER_COUNTER',
           'BYTES_PER_INT', 'SECKEY_CKA_PRIVATE',
           'SEC_OID_PKCS12_SIGNATURE_IDS',
           'CERT_REV_M_STOP_TESTING_ON_FRESH_INFO',
           '_CS_XBS5_ILP32_OFFBIG_LDFLAGS',
           'CKR_TOKEN_NOT_RECOGNIZED', 'SECMOD_SEED_FLAG',
           'CKF_SIGN_RECOVER', 'SEC_ERROR_BAD_DATABASE',
           'PR_SI_ARCHITECTURE', 'cert_po_end',
           'CKR_FUNCTION_REJECTED', 'PR_IO_ERROR',
           'CKR_SESSION_PARALLEL_NOT_SUPPORTED',
           'CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4', 'PK11PreSlotInfoStr',
           'CK_STATE', 'IPV6_TCLASS', 'SECKEYAttribute',
           'CKA_CHECK_VALUE', 'CKM_DES3_CBC', '_PC_ASYNC_IO',
           'int8_t', 'PK11CertListUser', 'ssl_InMonitor', 'SO_SNDBUF',
           'PK11_PW_TRY', 'CERTGeneralNameTypeEnum',
           'CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE',
           'CKM_NSS_AES_KEY_WRAP', 'PRTraceStopRecording',
           '_POSIX_READER_WRITER_LOCKS',
           'SEC_ERROR_EXTENSION_NOT_FOUND', 'generalName',
           'IPV6_2292DSTOPTS', '__fsfilcnt_t',
           'NS_CERT_TYPE_OBJECT_SIGNING', '_SC_MAPPED_FILES',
           'IPPORT_RJE', 'PK11_ATTR_PUBLIC', 'SIOCGPGRP',
           'CKM_AES_CBC_ENCRYPT_DATA', 'PK11MergeLogStr',
           'IPV6_RECVERR', '__FD_ZERO_STOS', 'PRBindFN', 'WTERMSIG',
           'PR_SEEK_SET', 'isprint_l', '_G_HAVE_SYS_CDEFS',
           'SECKEYAttributeStr', 'SECMOD_DSA_FLAG', 'fsfilcnt_t',
           '__swblk_t', 'IP_RECVTTL', 'CKR_ATTRIBUTE_TYPE_INVALID',
           'nssILockCache', '_XOPEN_SHM', 'CERT_POLICY_FLAG_EXPLICIT',
           'PR_INTERVAL_MIN', 'SEC_ERROR_BAD_DATA',
           'CKM_SHA256_KEY_DERIVATION', 'PF_ROUTE',
           'MCAST_LEAVE_GROUP', 'PRThreadScope',
           '__STDC_IEC_559_COMPLEX__', 'SECKEYDiffPQGParamsStr',
           '_IO_LINE_BUF', 'IPPROTO_ICMPV6', '_CS_LFS64_LIBS',
           'PZLock', 'CKM_DES_OFB8', 'uintptr_t', 'CMSG_NXTHDR',
           'SOCK_DCCP', 'PRListenFN', '_POSIX_THREAD_CPUTIME',
           'N22CERTValParamInValueStr4DOT_77E', 'SessionTicket',
           'idle_handshake', 'ssl_sign_dsa', 'sigval',
           'SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION',
           'CERTGeneralNameList', 'CKK_BLOWFISH',
           'CKF_CLOCK_ON_TOKEN', '_IO_FLAGS2_MMAP', 'PRSendFN',
           'CKM_DES_ECB_ENCRYPT_DATA', '_SC_UIO_MAXIOV', 'GS_MAC',
           '_POSIX_MEMORY_PROTECTION', 'CKT_NSS_UNTRUSTED',
           '_SC_2_SW_DEV', 'SEC_ERROR_ADDING_CERT', '__WCLONE',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC',
           'PR_LibSpec_MacNamedFragment', 'CKA_EXPONENT_2',
           '__WCOREDUMP', 'PR_JOINABLE_THREAD',
           'PK11_ATTR_UNEXTRACTABLE',
           'CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC', 'ip_mreqn',
           'TLSFinished', 'CKF_WRAP', 'CKM_SHA256_RSA_PKCS',
           'SEC_ERROR_OCSP_BAD_SIGNATURE', 'PR_INT8_MAX',
           '_IO_UNIFIED_JUMPTABLES', 'SO_REUSEADDR',
           'CERTCertExtensionStr', 'CKA_DIGEST', 'BITS_PER_LONG_LOG2',
           '_STDLIB_H', 'PF_PPPOX', 'SEC_ERROR_OCSP_TRY_SERVER_LATER',
           'SEC_ERROR_EXTENSION_VALUE_INVALID', '_SC_THREAD_CPUTIME',
           'CKR_SESSION_COUNT', 'SEC_OID_PKIX_OCSP_SERVICE_LOCATOR',
           'sslServerCerts', '_CS_POSIX_V7_ILP32_OFFBIG_LIBS',
           'PF_RXRPC', 'SEC_OID_AVA_STREET_ADDRESS', 'PR_RDWR',
           '_CS_POSIX_V6_ILP32_OFF32_LIBS', 'BITS_PER_SHORT',
           'SSL_ERROR_ENCRYPTION_FAILURE',
           'PK11_DIS_TOKEN_VERIFY_FAILED', 'ssl_SEND_FLAG_MASK',
           'SSL_SECURITY_STATUS_OFF', 'CK_SSL3_KEY_MAT_PARAMS',
           'CKO_NETSCAPE_BUILTIN_ROOT_LIST', 'GS_INIT',
           'certificateUsageSSLClient',
           '_CS_POSIX_V6_ILP32_OFF32_CFLAGS',
           'SEC_ERROR_OCSP_MALFORMED_REQUEST', 'certDNSName',
           'ldiv_t', 'CK_KEY_TYPE', '__USE_XOPEN2K',
           'PR_LibSpec_MacIndexedFragment',
           'SEC_OID_AVA_POST_OFFICE_BOX', 'CK_SSL3_RANDOM_DATA',
           'IPV6_RTHDRDSTOPTS', 'CK_WTLS_RANDOM_DATA',
           'CKR_WRAPPING_KEY_SIZE_RANGE', 'certificate_unobtainable',
           'cookie_read_function_t', 'SEC_ERROR_UNTRUSTED_CERT',
           'SEC_OID_PKCS1_RSA_PSS_SIGNATURE', '_POSIX_JOB_CONTROL',
           'PK11TokenNotRemovable', 'PR_SEEK_END', 'EAI_MEMORY',
           'kt_null', 'CKF_DIGEST',
           'PR_SOCKET_ADDRESS_IS_BOUND_ERROR', '__qaddr_t',
           'SEC_ERROR_PKCS12_UNABLE_TO_EXPORT_KEY',
           'SEC_OID_ANSIX962_EC_C2PNB163V1',
           'SEC_OID_ANSIX962_EC_C2PNB163V2',
           'SEC_OID_ANSIX962_EC_C2PNB163V3',
           'NS_CERT_TYPE_OBJECT_SIGNING_CA', 'dhKey', 'STDERR_FILENO',
           '__blkcnt_t', 'PR_AF_INET6', '_SC_V7_LP64_OFF64',
           'kg_export', '_G_config_h', 'SEC_OID_SECG_EC_SECT283R1',
           'CERTBasicConstraints', 'PZ_NotifyAllCondVar',
           '_POSIX_REENTRANT_FUNCTIONS', 'blkcnt64_t',
           'SEC_ERROR_NO_EVENT', 'CKM_IDEA_CBC',
           'CK_KEY_WRAP_SET_OAEP_PARAMS_PTR', 'CKR_STATE_UNSAVEABLE',
           'SEC_OID_SECG_EC_SECT193R2', 'CKM_CDMF_MAC',
           'SEC_OID_NS_CERT_EXT_CERT_TYPE', 'CKM_RC5_MAC_GENERAL',
           'SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER', 'LL_EQ',
           'SEC_OID_PKCS5_PBES2', 'IPV6_MULTICAST_HOPS', '_ISgraph',
           'SSL_ERROR_RX_UNEXPECTED_HANDSHAKE', 'PR_DESC_FILE',
           'CKK_CAST3', 'SEC_ASN1_SUB',
           'SSL_RENEGOTIATE_UNRESTRICTED', 'CERTCertOwner',
           '_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS', 'PRTransmitfileFN',
           'CKM_AES_ECB', 'SECSuccess', 'PRFuncPtr',
           'SSL_NO_STEP_DOWN', 'CKF_EC_FP', 'SSL_MAX_MAC_BYTES',
           'SEC_ASN1_METHOD_MASK', 'SOL_SOCKET', 'CKO_NSS_DELSLOT',
           '_SC_CLOCK_SELECTION', '_PC_PRIO_IO',
           'CKF_EC_ECPARAMETERS', 'CK_SLOT_INFO_PTR',
           'CLIENT_AUTH_CERTIFICATE', 'CKK_CAST128', 'PRTime',
           '_STDINT_H', 'SEC_ERROR_LIBRARY_FAILURE',
           'CERTPolicyStringCallback', 'SEC_OID_X509_CRL_NUMBER',
           'ssl_mac_null', 'certUsageVerifyCA',
           'CKF_PROTECTED_AUTHENTICATION_PATH', '_IO_LINKED',
           'SEC_OID_SECG_EC_SECP112R1',
           'SEC_ERROR_UNSUPPORTED_KEYALG', 'CERTDERCerts',
           'certValidityEqual', 'ip_msfilter', 'CKM_FASTHASH',
           'CKF_SECONDARY_AUTHENTICATION', '_SC_DELAYTIMER_MAX',
           'SEC_ERROR_UNSUPPORTED_EC_POINT_FORM',
           'SSL_ERROR_BAD_CERT_HASH_VALUE_ALERT', 'PF_IEEE802154',
           'CERTPolicyInfo', 'CKR_NSS', 'PR_SHUTDOWN_SEND',
           'SEC_OID_MISSI_KEA_DSS_OLD', 'certEDIPartyName',
           'SEC_ASN1_TAG_MASK', 'CKA_UNWRAP_TEMPLATE',
           'CKM_CAST5_CBC', 'gaicb', 'PR_LD_GLOBAL', 'PR_NAME',
           'access_denied', 'SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE',
           '_SC_SHRT_MIN', 'CKT_NSS_VALID_DELEGATOR', 'PRLibSpec',
           'SECMOD_MD2_FLAG', 'SEC_OID_NS_TYPE_HTML', 'PF_NETLINK',
           '_SC_LEVEL3_CACHE_LINESIZE', 'CKM_DES_KEY_GEN',
           'SEC_ERROR_PKCS7_KEYALG_MISMATCH', 'PR_LOG_DEBUG',
           'CKA_KEY_TYPE', 'SEC_ASN1_XTRN', 'SO_RCVBUFFORCE',
           'SSL_ERROR_RX_MALFORMED_FINISHED', 'NUM_MIXERS',
           '_SC_XBS5_LP64_OFF64', 'PRPackedBool', 'STDIN_FILENO',
           'CKA_TRUST_IPSEC_USER', 'time_t',
           'SEC_OID_SECG_EC_SECT163K1',
           'SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST',
           'PR_ROUNDUP', 'CKA_NETSCAPE_DB', 'PR_BITS_PER_INT64',
           'ct_DSS_sign', 'SECKEYRSAPublicKey', 'PR_MSG_PEEK',
           'IPV6_PMTUDISC_DONT', 'calg_camellia', 'EAI_OVERFLOW',
           '_PARAMS', 'CKM_TWOFISH_KEY_GEN',
           '_POSIX_TYPED_MEMORY_OBJECTS', '_PATH_SERVICES',
           'BITS_PER_INT', 'PR_BITS_PER_INT', 'PR_MAX_ERROR',
           'SECMOD_DH_FLAG', '_OLD_STDIO_MAGIC', '_CS_PATH',
           '_G_pid_t', 'CKM_KEY_WRAP_LYNKS', 'CK_ATTRIBUTE',
           'PR_LD_NOW', 'PR_BETA', '_SC_SCHAR_MAX',
           'SEC_ASN1_UTC_TIME', 'SSL_ERROR_SSL2_DISABLED',
           'EAI_NODATA', 'sslSecurityInfo', 'CERTUserNotice',
           'SECMOD_FRIENDLY_FLAG', '_SC_PHYS_PAGES',
           'CKF_WRITE_PROTECTED', '_SC_THREAD_SAFE_FUNCTIONS',
           '__toascii_l', 'SEC_OID_PKIX_OCSP_CRL',
           'PR_SockOpt_SendBufferSize', 'CKS_RW_USER_FUNCTIONS',
           'SEC_OID_PKCS12_PKCS8_SHROUDED_KEY_BAG_ID', '_PC_NAME_MAX',
           'cert_pi_trustAnchors', 'SEC_OID_NS_CERT_EXT_SUBJECT_LOGO',
           'in6_pktinfo', 'PR_IpAddrAny', 'PF_LLC', '__int64_t',
           'SSL3ClientKeyExchange', 'certificate_verify',
           'SEC_OID_SHA1', 'CERTSubjectNode', 'record_overflow',
           'SO_LINGER', '_SC_AVPHYS_PAGES', '_SC_LEVEL1_DCACHE_ASSOC',
           'CKA_HASH_OF_ISSUER_PUBLIC_KEY', 'uid_t',
           'SEC_OID_AVA_ORGANIZATION_NAME', '_SC_LEVEL1_DCACHE_SIZE',
           '__LITTLE_ENDIAN', 'PR_BITS_PER_LONG_LOG2', 'MSG_PEEK',
           '_SC_PRIORITIZED_IO', 'SECKEYPrivateKeyList', 'PF_ATMSVC',
           'CKM_SEED_MAC', 'PK11RSAGenParamsStr', 'PR_UINT32_MAX',
           'PRThreadType', 'invalid_cache', 'IP_RECVORIGDSTADDR',
           'CKM_DES3_CBC_ENCRYPT_DATA',
           'SEC_OID_NS_CERT_EXT_SSL_SERVER_NAME',
           'SEC_ASN1_TELETEX_STRING', 'CKR_USER_TYPE_INVALID',
           'IP_MAX_MEMBERSHIPS', 'CKR_ATTRIBUTE_VALUE_INVALID',
           'SEC_ERROR_NO_MEMORY', 'SEC_OID_ANSIX962_EC_PRIME192V1',
           'SEC_OID_ANSIX962_EC_PRIME192V2',
           'SEC_OID_ANSIX962_EC_PRIME192V3', 'SessionTicketData',
           'AF_RDS', 'kea_dh_rsa_export', 'HASH_HashType',
           'CKF_USER_PIN_FINAL_TRY', 'protocol_version',
           'hello_request', 'certPackageNSCertWrap',
           'IP_IPSEC_POLICY', 'CKH_CLOCK', '_SC_2_PBS_LOCATE',
           'CKA_ENCODING_METHODS',
           'SSL_ERROR_RX_UNEXPECTED_HELLO_DONE',
           'PK11_DIS_TOKEN_NOT_PRESENT', '_BITS_PTHREADTYPES_H',
           '_PC_SYNC_IO', '_IO_FLAGS2_NOTCANCEL', 'va_start',
           '_SC_SEM_NSEMS_MAX', 'SEC_ERROR_NOT_FORTEZZA_ISSUER',
           '_G_uint32_t', 'IPV6_RTHDR_TYPE_0', '_SC_IOV_MAX',
           'PR_BITS_PER_SHORT', 'SECMOD_INTERNAL', 'SECKEYKEAParams',
           'CKA_PRIVATE', 'SECMOD_SLOT_FLAGS', 'SEC_ASN1_APPLICATION',
           '_LFS64_STDIO', 'CERT_REV_M_IGNORE_MISSING_FRESH_INFO',
           '_SC_UCHAR_MAX', '_IO_CURRENTLY_PUTTING', 'PRAcceptreadFN',
           'SECTrustType', 'NSS_USE_ALG_IN_CERT_SIGNATURE',
           'CK_SSL3_KEY_MAT_OUT', 'SSL_ERROR_HANDSHAKE_NOT_COMPLETED',
           'sslBufferStr', '__nlink_t',
           'SEC_ERROR_BAGGAGE_NOT_CREATED', 'AF_IUCV',
           'SHA384_LENGTH', 'SSL3PublicValueEncoding',
           'CERT_REV_M_REQUIRE_INFO_ON_MISSING_SOURCE',
           '_POSIX2_SW_DEV', 'PF_PACKET', 'CKK_DES2', 'CKK_DES3',
           'CKZ_SALT_SPECIFIED', 'PRTraceSuspend', 'PR_VPATCH',
           'PRFileType', 'SEC_OID_SECG_EC_SECT409R1', 'DER_OUTER',
           'CKM_PBE_MD5_CAST128_CBC', '__U64_TYPE', 'PR_UPTRDIFF',
           'SEC_ERROR_NEED_RANDOM', 'cookie_io_functions_t',
           'SECKEYPQGParams', 'CKM_CDMF_ECB',
           'CK_KEA_DERIVE_PARAMS_PTR', '_SC_LINE_MAX',
           'CKA_NETSCAPE_PQG_SEED_BITS', 'CK_NOTIFY',
           'siEncodedCertBuffer', 'PK11_ATTR_MODIFIABLE',
           'SEC_ERROR_PKCS12_IMPORTING_CERT_CHAIN', 'CK_BYTE_PTR',
           'CERTPrivKeyUsagePeriodStr',
           'SSL_ERROR_DECRYPTION_FAILED_ALERT',
           'MAX_COMPRESSION_METHODS',
           'CK_X9_42_DH1_DERIVE_PARAMS_PTR', 'int_least16_t',
           'SEC_ERROR_OCSP_RESPONDER_CERT_INVALID', 'MCAST_MSFILTER',
           'cipher_rc4', 'PR_UINT16_MAX',
           'SSL_ERROR_RX_MALFORMED_CERTIFICATE', 'cipher_rc2',
           'SEC_OID_PKCS1_MD4_WITH_RSA_ENCRYPTION', '_SVID_SOURCE',
           'CKM_SSL3_KEY_AND_MAC_DERIVE', 'SEC_INTERNAL_ONLY',
           'nssILockArena', 'SEC_OID_PKCS9_CHALLENGE_PASSWORD',
           'IP_DEFAULT_MULTICAST_TTL', 'PK11_ATTR_UNMODIFIABLE',
           'IPV6_V6ONLY', 'PR_BITS_PER_INT_LOG2',
           'SEC_OID_AVA_POSTAL_ADDRESS', 'CERTValOutParam',
           'ssl_SHUTDOWN_NONE', 'PRDir', '_SC_PII_OSI',
           '_CS_LFS_LIBS', 'CKM_SHA1_RSA_PKCS',
           'CERTAuthInfoAccessStr', 'cipher_idea', 'CKM_SHA384',
           'certOwnerPeer', 'PR_ROTATE_RIGHT32', 'SECMOD_RSA_FLAG',
           'CK_VOID_PTR_PTR', 'CKA_COLOR', 'mac_md5',
           'HASH_AlgSHA256', 'IP_MTU_DISCOVER', '_SC_2_FORT_DEV',
           '_SC_FILE_SYSTEM', '__socket_type', 'NI_MAXHOST',
           'PR_UINT32', 'SSL_ERROR_RX_UNKNOWN_RECORD_TYPE',
           'SEC_OID_X509_NAME_CONSTRAINTS', 'calg_seed', 'SOL_RAW',
           'CKM_CDMF_MAC_GENERAL', 'BYTES_PER_WORD_LOG2',
           'SSLAuthType', 'CKA_TRUST_KEY_CERT_SIGN',
           'CKR_WRAPPED_KEY_INVALID',
           'SSL_ERROR_PROTOCOL_VERSION_ALERT', 'useconds_t',
           'SSL_ERROR_EXPORT_RESTRICTION_ALERT', 'MSG_CONFIRM',
           'PR_PRIORITY_NORMAL', '__bos0', '__u_long',
           '__SIZEOF_PTHREAD_MUTEX_T', '_IO_STDIO', 'SSL3ContentType',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS',
           'PR_MAX_DIRECTORY_ENTRIES_ERROR', 'IPPORT_BIFFUDP',
           'SSL_ERROR_CERT_KEA_MISMATCH',
           'CK_RC5_MAC_GENERAL_PARAMS_PTR', 'CKM_SKIPJACK_CBC64',
           '_SC_THREAD_PROCESS_SHARED', '_SC_JOB_CONTROL', 'PRRWLock',
           'CKA_LOCAL', 'PRPtrdiff',
           'SSL_ERROR_RX_MALFORMED_APPLICATION_DATA',
           'SEC_OID_AES_256_ECB', '__sig_atomic_t', 'IP_XFRM_POLICY',
           'CK_CHAR_PTR', 'IP_TRANSPARENT', 'PRIntn', 'SOCK_PACKET',
           'SSL_ERROR_RX_MALFORMED_HELLO_DONE', 'PR_ALIGN_OF_DOUBLE',
           '_SC_ADVISORY_INFO', 'SEC_OID_RC5_CBC_PAD',
           'CKT_NETSCAPE_TRUSTED', 'cert_pi_certStores',
           '_PC_SYMLINK_MAX', 'PRHashComparator', 'sigevent', 'X_OK',
           'PR_IO_LAYER_HEAD', 'SSLAppOperation', 'CKM_DES3_ECB',
           '_SC_V7_LPBIG_OFFBIG', 'PR_SockOpt_MaxSegment',
           'SSLKEAType', 'RF_KEY_COMPROMISE', 'PR_IXOTH',
           'SSLMACAlgorithm', 'CKT_VENDOR_DEFINED',
           'SSL_ERROR_SYM_KEY_CONTEXT_FAILURE', 'CKM_RC2_ECB',
           '_SC_XOPEN_REALTIME', 'CK_SKIPJACK_PRIVATE_WRAP_PARAMS',
           'MSG_FIN', 'PZ_Unlock', 'PR_SYNC', 'HASH_AlgSHA384',
           'SEC_ERROR_NO_RECIPIENT_CERTS_QUERY',
           'SSL_ERROR_RX_UNEXPECTED_NEW_SESSION_TICKET', 'PF_PHONET',
           '_PC_PIPE_BUF', 'IN_CLASSB_NET',
           'SEC_OID_SECG_EC_SECP160R1', 'SEC_OID_SECG_EC_SECP160R2',
           'CKR_ENCRYPTED_DATA_INVALID', 'INET6_ADDRSTRLEN',
           'SEC_ASN1DecoderContext', '_SC_2_PBS_ACCOUNTING',
           'PRTraceSuspendRecording', 'cert_po_errorLog',
           '_SC_LEVEL2_CACHE_LINESIZE', '_SC_FD_MGMT', '__STRING',
           'CK_KEY_DERIVATION_STRING_DATA', 'CERTGeneralNameStr',
           'SEC_OID_ANSIX962_EC_C2PNB272W1', '__WCHAR_MIN',
           'SSL_SECURITY_STATUS_ON_HIGH', 'CKM_DES3_ECB_ENCRYPT_DATA',
           '__GNUC_PREREQ', 'EAI_SOCKTYPE', '__BLKCNT64_T_TYPE',
           'CKM_CAST128_CBC_PAD', 'PRHashAllocOps',
           'SSL_ERROR_NO_CIPHERS_SUPPORTED', '_SC_REGEX_VERSION',
           'SECMODModuleDBFunc', 'certPackageNSCertSeq',
           '_SC_CPUTIME', 'CK_X9_42_DH2_DERIVE_PARAMS_PTR',
           'CKM_MD2_RSA_PKCS', 'SSLErrorCodes', 'IPV6_RECVPKTINFO',
           'SECCertificateUsage', 'CK_OBJECT_CLASS_PTR', 'loff_t',
           'certUsageEmailRecipient', '__pid_t', '__va_arg_pack',
           'CipherType', 'CKM_RC5_CBC', 'CKM_SSL3_PRE_MASTER_KEY_GEN',
           '_SC_TYPED_MEMORY_OBJECTS',
           'SEC_OID_ANSIX962_EC_C2TNB191V3',
           'SEC_OID_ANSIX962_EC_C2TNB191V2',
           'SEC_OID_ANSIX962_EC_C2TNB191V1',
           'AI_IDN_ALLOW_UNASSIGNED', 'SEC_ERROR_EXPIRED_PASSWORD',
           'PR_INVALID_ARGUMENT_ERROR', '_SIGSET_NWORDS', 'GAI_WAIT',
           'iovec', 'SECMODModule', 'SEC_OID_HMAC_SHA256',
           'PR_ADDRESS_NOT_SUPPORTED_ERROR', 'no_renegotiation',
           'CKA_TRUST_IPSEC_TUNNEL', '_SC_BC_SCALE_MAX',
           '_POSIX_SYNCHRONIZED_IO', 'CKO_NSS_BUILTIN_ROOT_LIST',
           'PR_IRWXG', 'sslHandshakeFunc', 'CERT_ENABLE_HTTP_FETCH',
           'SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE',
           'CKT_NETSCAPE_TRUSTED_DELEGATOR', 'SECMOD_END_WAIT',
           'SEC_OID_AES_192_KEY_WRAP', 'SEC_ERROR_NOT_A_RECIPIENT',
           'CKR_WRAPPING_KEY_TYPE_INCONSISTENT', 'PR_IRWXU',
           'SSL3HandshakeType', '_NETINET_IN_H', 'SEC_OID_RC4',
           '__INO64_T_TYPE', '__dev_t', 'wait_server_key',
           'CKR_SESSION_EXISTS', 'CKM_CAST5_MAC_GENERAL',
           'SSL_MIN_CYPHER_ARG_BYTES', '_IO_USER_LOCK', 'cmsghdr',
           'siClearDataBuffer', 'int_fast32_t', 'lldiv_t',
           'N8sigevent4DOT_47E', 'CERTCrlKey', 'PR_StandardInput',
           '_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS', 'EOF', 'PRMWStatus',
           'SEC_OID_MD2', 'SEC_OID_MD5', 'SEC_OID_MD4', 'uint8_t',
           'SEC_ERROR_INVALID_TIME', '_G_HAVE_MREMAP',
           '_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS', 'SO_ACCEPTCONN',
           'CERTRevocationTests', 'L_cuserid', '_SC_BARRIERS',
           'CKA_OWNER', 'CK_RC2_PARAMS_PTR', 'CK_WTLS_PRF_PARAMS_PTR',
           'IPPORT_ROUTESERVER', 'PR_UINT8_MAX', 'CKO_HW_FEATURE',
           'CKF_REMOVABLE_DEVICE', 'makedev', 'PR_SHM_EXCL',
           'SEC_ERROR_OCSP_BAD_HTTP_RESPONSE', 'CKO_PUBLIC_KEY',
           'CKM_RSA_PKCS_OAEP', 'SEC_ASN1_ENUMERATED', 'trustEmail',
           'CERTSignedCrlStr', 'IPPROTO_RSVP', 'PR_MW_INTERRUPT',
           'CERT_REV_MI_REQUIRE_SOME_FRESH_INFO_AVAILABLE',
           'IP_RECVERR', 'SSLDestroy', '_CS_LFS64_LINTFLAGS',
           'SOCK_RDM', 'ct_RSA_fixed_DH', 'IPV6_MULTICAST_IF',
           'TEST_BIT', 'PR_TRANSMITFILE_KEEP_OPEN', '__WSTOPSIG',
           'CK_UNAVAILABLE_INFORMATION',
           'SEC_OID_NS_CERT_EXT_REVOCATION_URL',
           'SEC_OID_NS_CERT_EXT_HOMEPAGE_URL',
           'PR_CONNECT_REFUSED_ERROR', 'IPPORT_MTP', 'PR_IWUSR',
           'ssl3MACDefStr', 'PR_INVALID_IO_LAYER', 'htole32',
           '__SIZEOF_PTHREAD_MUTEXATTR_T', 'PR_PROT_WRITECOPY',
           '_POSIX_SOURCE', '_IO_jump_t', '_ISdigit',
           'SEC_OID_X509_KEY_USAGE', 'PRGetsocknameFN',
           'SEC_ASN1_VISIBLE_STRING', 'SEC_OID_SECG_EC_SECT131R1',
           'SSL_ERROR_RX_MALFORMED_HELLO_REQUEST',
           'SEC_OID_ANSIX962_EC_C2TNB239V2',
           'SEC_OID_ANSIX962_EC_C2TNB239V3', 'CKR_KEY_INDIGESTIBLE',
           'SEC_OID_ANSIX962_EC_C2TNB239V1', 'CKM_CDMF_CBC',
           'PK11_OriginDerive', 'ALIGN_OF_DOUBLE',
           '_CS_V7_WIDTH_RESTRICTED_ENVS', 'CKD_NULL',
           'INADDR_MAX_LOCAL_GROUP', 'certificateUsageEmailRecipient',
           'PR_IRGRP', 'ssl_compression_null', 'CKA_VENDOR_DEFINED',
           'SSL_ENABLE_SESSION_TICKETS', 'SSL3BulkCipher',
           'SSL_NO_LOCKS', '_IO_off_t', 'PR_CONNECT_TIMEOUT_ERROR',
           'IN_CLASSD', 'PR_USEC_PER_SEC', '__clockid_t',
           '_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS', '_SC_INT_MIN',
           'PK11FreeDataFunc', 'CKM_SKIPJACK_ECB64',
           'CK_C_INITIALIZE_ARGS', '_SC_UINT_MAX',
           'SSL3EncryptedPreMasterSecret', 'PK11GenericObjectStr',
           'CKA_TRUST', 'CRL_DECODE_DONT_COPY_DER',
           'PR_CONNECT_ABORTED_ERROR',
           'SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE', 'CKM_RSA_X_509',
           'CK_RC5_PARAMS_PTR', '__WEXITSTATUS',
           'CK_KEA_DERIVE_PARAMS', 'HASHContextStr',
           'SEC_OID_PKCS12_PKCS8_KEY_SHROUDING', 'rpcent',
           '_SC_2_PBS', '_IO_pos_t', 'SEC_ASN1_SET', 'PRLinger',
           'nssILockSlot', 'PR_SockOpt_AddMember', '_POSIX_REGEXP',
           '_ISxdigit', '_SC_BC_DIM_MAX', '_SC_V7_ILP32_OFFBIG',
           'ct_ECDSA_sign', 'SHUT_RD', 'CK_NULL_PTR', 'PR_INT32',
           '_IO_SKIPWS', 'SEC_ASN1_BIT_STRING', '__WIFEXITED',
           'SCM_RIGHTS', 'CKR_NEED_TO_CREATE_THREADS',
           '_IO_SCIENTIFIC', 'SEC_ERROR_CRL_ALREADY_EXISTS', 'LL_NE',
           'SSL_SECURITY', 'CKA_SUB_PRIME_BITS', 'isspace_l',
           'CKM_BLOWFISH_CBC', 'CKA_PRIME_BITS',
           'CKF_DUAL_CRYPTO_OPERATIONS', 'CKM_SHA224_HMAC', 'CK_LONG',
           'IPPROTO_TCP', 'PORTCharConversionFunc',
           'PR_ALIGN_OF_WORD', '__mode_t',
           'SEC_OID_NS_CERT_EXT_CA_CRL_URL', 'CKM_DES_ECB',
           'ssl3CipherSuiteDef', 'SEC_ASN1_EMBEDDED_PDV',
           'N18CERTGeneralNameStr4DOT_58E', 'NewSessionTicket',
           'PRDirEntry', 'secCertTimeUndetermined', 'uintn',
           'CKM_MD5_HMAC', 'osockaddr', 'SECMOD_WAIT_SIMULATED_EVENT',
           'INET_ADDRSTRLEN', '_SC_2_PBS_CHECKPOINT', 'PR_PIPE_ERROR',
           'SEC_ERROR_OCSP_FUTURE_RESPONSE',
           'CKA_NSS_SMIME_TIMESTAMP', 'IN_EXPERIMENTAL',
           'CERTCertList', 'PR_INSUFFICIENT_RESOURCES_ERROR',
           'CKM_ECDSA', 'CK_OBJECT_HANDLE_PTR',
           'CK_ECDH1_DERIVE_PARAMS', 'ssl_session_ticket_xtn',
           'PRRecvfromFN', 'minor', 'SECMOD_FIPS',
           'CK_SKIPJACK_RELAYX_PARAMS',
           'SEC_OID_NS_CERT_EXT_CERT_RENEWAL_URL',
           'CK_RC2_CBC_PARAMS',
           'SEC_OID_PKCS12_V1_SAFE_CONTENTS_BAG_ID',
           'certPackagePKCS7', 'PRErrorTable', 'SEC_ASN1_PRIVATE',
           'EAI_SYSTEM', 'uintmax_t', 'CKM_RC2_KEY_GEN',
           'CKR_UNWRAPPING_KEY_SIZE_RANGE',
           'PR_DIRECTORY_CORRUPTED_ERROR', 'CKM_SHA256_RSA_PKCS_PSS',
           'RF_AFFILIATION_CHANGED',
           'SEC_OID_PKCS7_SIGNED_ENVELOPED_DATA', 'PK11Context',
           'rsaOaepKey', 'CKM_CONCATENATE_BASE_AND_DATA',
           '__FSBLKCNT64_T_TYPE', 'CKR_KEY_HANDLE_INVALID',
           'certUsageSSLServer', 'SEC_ASN1_T61_STRING', 'pid_t',
           'PRRecvWait', 'AF_X25', 'SECKEYECPublicKey',
           'SEC_ASN1_CONTEXT_SPECIFIC', '__fsfilcnt64_t',
           '_POSIX_MAPPED_FILES', '_CS_POSIX_V6_LPBIG_OFFBIG_LIBS',
           '_PC_MAX_INPUT', 'CKM_ECDSA_SHA1', 'F_TLOCK',
           'cert_pi_nbioAbort', 'CKA_TRUST_KEY_ENCIPHERMENT',
           'CKA_HW_FEATURE_TYPE', 'PF_IUCV',
           'SEC_ERROR_RETRY_PASSWORD', 'IPV6_2292RTHDR', 'unknown_ca',
           'IPPORT_TFTP', 'PRShutdownFN', 'servent',
           'SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_40_BIT_RC4',
           'CK_TLS_PRF_PARAMS',
           'SEC_OID_PKIX_REGCTRL_PKI_ARCH_OPTIONS', 'SECHashObject',
           '_CS_XBS5_ILP32_OFFBIG_LIBS', 'SSL_CBP_SSL3', 'kt_ecdh',
           'SEC_ERROR_OUTPUT_LEN',
           'SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION', 'PZ_NewLock',
           'wait_client_hello', 'SEC_ASN1D_MAX_DEPTH', 'siDEROID',
           'sec_DecoderContext_struct', 'PRHashNumber', 'kea_dhe_rsa',
           'cert_revocation_method_ocsp',
           'CKA_NETSCAPE_PASSWORD_CHECK',
           'SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE',
           'PR_SockOpt_Broadcast', 'AF_SNA',
           'SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY',
           'SEC_OID_ANSIX962_EC_PRIME239V3',
           'SEC_OID_ANSIX962_EC_PRIME239V1', 'PR_BITS_PER_WORD',
           'PRExplodedTime', 'SSL3ClientCertificateType',
           'CK_SLOT_ID', 'SSL3AlertLevel', 'PR_IXUSR', 'ipv6_mreq',
           'PR_LOG_ERROR', 'PR_MW_PENDING', 'PR_INVALID_STATE_ERROR',
           'CKR_ENCRYPTED_DATA_LEN_RANGE', '_POSIX_SEMAPHORES',
           '_SC_SPAWN', 'SSLBadCertHandler',
           '_CS_POSIX_V7_ILP32_OFF32_LDFLAGS', 'CKK_RC4',
           '_CS_POSIX_V6_ILP32_OFF32_LDFLAGS',
           'CERTCRLEntryReasonCodeEnum', 'CERTCertificateList',
           'PR_LibSpec_Pathname', 'CKA_URL', 'CKS_RW_PUBLIC_SESSION',
           'certValidityUndetermined', 'CKM_CAST128_KEY_GEN',
           'IN_CLASSC_NSHIFT', 'PRArena', 'cert_pi_certList',
           'CKM_AES_ECB_ENCRYPT_DATA', 'SEC_OID_SHA256', '__rlim64_t',
           'close_notify', 'PR_ACCEPT_READ_BUF_OVERHEAD',
           'PRTraceDisable', 'PRMemoryDescriptor',
           'unsupported_certificate', 'CKK_RC5', 'CKA_PRIME_1',
           'SSL_ERROR_DECODE_ERROR_ALERT',
           'CKR_UNWRAPPING_KEY_HANDLE_INVALID', 'CKA_PRIME_2',
           '_SC_LEVEL3_CACHE_ASSOC', 'CKA_ALLOWED_MECHANISMS',
           '_ISspace', '__clock_t', 'IPV6_ADDRFORM', 'CKM_CAST_ECB',
           'PZ_InMonitor', '_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS',
           'SSL3GenericBlockCipher', 'getc', '__STDLIB_MB_LEN_MAX',
           '_SC_AIO_PRIO_DELTA_MAX',
           'SEC_OID_NS_CERT_EXT_ENTITY_LOGO',
           'SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION',
           'SSL_ERROR_RENEGOTIATION_NOT_ALLOWED',
           '_POSIX_THREAD_SPORADIC_SERVER', 'MAX_MAC_LENGTH',
           '__LONG_LONG_PAIR', 'bad_record_mac',
           'CKM_IDEA_MAC_GENERAL', 'CERTCrlNumber', 'IP_MINTTL',
           'CERTPackageType', 'CKM_BATON_SHUFFLE', 'CKK_SKIPJACK',
           'PR_POLL_READ', 'SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED',
           'CKF_EC_COMPRESS', 'SEC_OID_X509_SUBJECT_ALT_NAME',
           'SEC_ERROR_TOKEN_NOT_LOGGED_IN', 'SEC_ASN1_INLINE',
           '_SC_T_IOV_MAX', 'PR_ALIGN_OF_FLOAT',
           'SEC_ERROR_INVALID_ALGORITHM', 'PRUint32',
           'IP_UNBLOCK_SOURCE', 'CKM_X9_42_MQV_DERIVE',
           'CERTNameConstraintStr', 'F_OK', '__intptr_t',
           'fsblkcnt64_t', 'SECKEYPrivateKeyListNode',
           'PK11_TypeGeneric', 'SECKEYPrivateKeyInfoStr',
           '_G_HAVE_LONG_DOUBLE_IO', 'in_client_cache',
           'IPV6_2292PKTINFO', 'SECItemStr', 'wait_change_cipher',
           'CKH_VENDOR_DEFINED',
           'SSL_ERROR_RX_MALFORMED_NEW_SESSION_TICKET',
           'CKR_NSS_CERTDB_FAILED',
           '_CS_POSIX_V7_LP64_OFF64_LINTFLAGS', '_SECComparison',
           'PR_CREATE_FILE', '_SC_XOPEN_SHM', 'fpos64_t',
           'cipher_camellia_128', 'CKR_CANCEL',
           'SSL_RENEGOTIATE_TRANSITIONAL', 'SIOCGSTAMP', '_G_BUFSIZ',
           'CKA_AC_ISSUER', 'KU_DIGITAL_SIGNATURE', '_PC_LINK_MAX',
           'cert_pi_keyusage', 'SEC_OID_NS_CERT_EXT_CA_POLICY_URL',
           'PR_NOT_DIRECTORY_ERROR', 'RF_UNUSED',
           'kea_dhe_rsa_export', 'PRLibSpecType', '__blksize_t',
           'SEC_OID_PKCS12_KEY_BAG_ID', '_XOPEN_VERSION',
           'wait_new_session_ticket', '_SC_PII_INTERNET_DGRAM',
           'SEC_ERROR_CKL_CONFLICT', 'DER_PRINTABLE_STRING',
           'SEC_OID_DES_ECB', 'PR_LD_LAZY',
           'SEC_OID_PKIX_TIMESTAMPING', '_SC_TRACE_NAME_MAX',
           'CK_RSA_PKCS_OAEP_PARAMS', 'SEC_OID_AVA_STATE_OR_PROVINCE',
           'PR_InMonitor', 'SO_PEERNAME', 'NI_NAMEREQD',
           'SOCK_STREAM', 'PRTraceHandle',
           'ssl3HelloExtensionHandler', 'isalnum_l', 'IPV6_AUTHHDR',
           'PR_SockOpt_Linger', 'CKM_CAST5_KEY_GEN',
           'IPV6_2292PKTOPTIONS', 'PK11DisableReasons',
           'handshake_failure', 'SEC_OID_X509_EXT_KEY_USAGE',
           '_IO_NO_READS', '_SC_PAGE_SIZE',
           'CKF_USER_PIN_TO_BE_CHANGED', 'SSL_SECURITY_STATUS_NOOPT',
           'CERT_REV_MI_TEST_EACH_METHOD_SEPARATELY',
           'DER_CLASS_MASK', 'AI_IDN', '__GLIBC_MINOR__',
           'CK_LOCKMUTEX',
           'SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM',
           'certX400Address', 'BYTES_PER_FLOAT', 'SEC_ASN1_SKIP_REST',
           'decryption_failed_RESERVED', 'IPPORT_SUPDUP',
           'cert_pi_policyFlags', 'HASH_LENGTH_MAX', 'HASH_AlgSHA1',
           'SSL_ERROR_SESSION_KEY_GEN_FAILURE',
           'CKM_BLOWFISH_KEY_GEN', 'SSL_ERROR_RX_UNKNOWN_ALERT',
           'SEC_OID_PKCS12_KEY_USAGE', 'pthread_barrier_t',
           'SEC_ASN1_GENERALIZED_TIME', 'IP_OPTIONS', 'toascii_l',
           'SEC_ASN1_NO_STREAM', 'SEC_ERROR_BAD_LDAP_RESPONSE',
           '_SC_NL_NMAX', 'CKR_NETSCAPE_CERTDB_FAILED',
           'SEC_OID_SECG_EC_SECP192R1',
           'CKR_USER_PIN_NOT_INITIALIZED',
           'SSL3ClientDiffieHellmanPublic', 'CKM_MD5_KEY_DERIVATION',
           'CK_MECHANISM_INFO_PTR', '_G_VTABLE_LABEL_HAS_LENGTH',
           'CKM_NETSCAPE_AES_KEY_WRAP', 'DER_POINTER', 'WNOWAIT',
           'CKA_DEFAULT_CMS_ATTRIBUTES', 'CRLDistributionPoint',
           'SEC_ERROR_PKCS11_DEVICE_ERROR', 'MSG_WAITALL',
           'CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN', '_G_HAVE_PRINTF_FP',
           'PR_ALREADY_INITIATED_ERROR', '_SC_XBS5_LPBIG_OFFBIG',
           'SEC_ERROR_PKCS12_DUPLICATE_DATA', 'R_OK', 'PRSeekWhence',
           'CK_USER_TYPE', 'certUsageUserCertImport',
           'PK11CertListUserUnique', 'sockaddr_in6',
           'nssILockFreelist', 'AF_MAX', '_LARGEFILE64_SOURCE',
           'major', '_SC_LEVEL3_CACHE_SIZE',
           'CK_RC2_MAC_GENERAL_PARAMS', 'PR_SUCCESS',
           'SEC_OID_SECG_EC_SECP224K1', 'CK_PBE_PARAMS_PTR',
           '_SC_NL_LANGMAX', 'IPPORT_DAYTIME', 'CK_MECHANISM',
           'AI_ALL', 'pthread_spinlock_t', 'sslSocketStr',
           'PRFileInfo64FN', 'SessionTicketStr', 'IN_LOOPBACKNET',
           'IPPROTO_IDP', 'AF_UNIX',
           'SSL_ERROR_UNRECOGNIZED_NAME_ALERT',
           'SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH',
           'CKA_NETSCAPE_PQG_H', 'PR_CALL_ONCE_ERROR', '_ALLOCA_H',
           'CKM_RC5_ECB', 'PR_NOT_IMPLEMENTED_ERROR',
           'CKM_SHA384_KEY_DERIVATION', 'CERTVerifyLogNodeStr',
           'client_hello', '_PC_NO_TRUNC', 'EAI_AGAIN',
           'CKM_PBE_SHA1_RC4_40', 'N22CERTValParamInValueStr4DOT_75E',
           '_SC_V7_ILP32_OFF32', 'SSL_ENABLE_SSL2',
           'SSL_ERROR_BAD_CERT_STATUS_RESPONSE_ALERT',
           'SSL_REQUEST_CERTIFICATE', 'PR_PRIORITY_FIRST',
           'CKK_GENERIC_SECRET', 'CKA_TRUST_KEY_AGREEMENT',
           '_POSIX_THREAD_PROCESS_SHARED', 'SSL_MAX_CYPHER_ARG_BYTES',
           '_SC_V6_LP64_OFF64', 'CKM_CAMELLIA_CBC_PAD',
           '_SC_SINGLE_PROCESS', 'NS_CERT_TYPE_SSL_CA', 'IP_TTL',
           'PORTCharConversionWSwapFunc', 'PF_TIPC',
           'certificate_unknown', 'SEC_ERROR_PKCS11_FUNCTION_FAILED',
           'SECKEYDSAPublicKeyStr', '_IOS_NOCREATE', 'CERTDBNameFunc',
           'DER_CONTEXT_SPECIFIC', 'group_req', 'SSL_ERROR_BASE',
           '_POSIX_ADVISORY_INFO', 'wait_cert_request', 'CK_DATE',
           'SO_MARK', 'SSL_REQUIRE_CERTIFICATE',
           'SEC_ERROR_OCSP_NOT_ENABLED', 'isalpha_l',
           'certificateUsageHighest', '__USE_LARGEFILE',
           'CKA_NETSCAPE_PQG_SEED',
           'SEC_OID_NS_CERT_EXT_LOST_PASSWORD_URL',
           'NSSCertificateStr', '_SC_THREAD_STACK_MIN', 'CK_FALSE',
           'CKM_RC5_KEY_GEN', 'kea_dh_anon', 'PR_INT16_MIN',
           'WCONTINUED', 'IPV6_HOPLIMIT',
           'SEC_ERROR_CANNOT_MOVE_SENSITIVE_KEY', 'mac_sha',
           'PRInt16', 'SEC_CRL_VERSION_2', 'CERTIssuerAndSN',
           'SFTK_MAX_USER_SLOT_ID', 'CKA_ALWAYS_AUTHENTICATE',
           'CKK_EC', 'SSL_MIN_CHALLENGE_BYTES',
           'SSL_ROLLBACK_DETECTION', 'ssl_calg_camellia',
           'PR_USER_THREAD', 'CKK_IDEA',
           'SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC',
           'PR_SKIP_DOT_DOT', 'SEC_OID_PKIX_CA_ISSUERS',
           'ssl_auth_kea', 'SEC_OID_X509_POLICY_MAPPINGS',
           'KU_KEY_AGREEMENT', 'AF_APPLETALK', 'CKA_VERIFY_RECOVER',
           'UIO_MAXIOV', '_SC_REALTIME_SIGNALS',
           'N11__mbstate_t4DOT_28E', 'SEC_OID_SHA512',
           'SEC_ERROR_CERT_NOT_VALID', 'PZ_Notify', 'calg_des',
           'SSL_ALLOWED', 'CERT_MAX_SERIAL_NUMBER_BYTES', '__id_t',
           'F_LOCK', 'CERTSignedData', 'ptrdiff_t', 'SSL_NO_CACHE',
           'IPPROTO_MTP', 'PR_SockOpt_Reuseaddr', '_XBS5_ILP32_OFF32',
           '__LP64_OFF64_CFLAGS', 'SO_DETACH_FILTER', 'CKM_CAST5_ECB',
           '__WIFSTOPPED', '_CS_LFS_CFLAGS', 'MAX_FRAGMENT_LENGTH',
           'SEC_OID_AVA_POSTAL_CODE', 'PRDescIdentity',
           'SEC_OID_DES_OFB', 'SEC_CRL_VERSION_1',
           'CK_RSA_PKCS_MGF_TYPE_PTR', 'ssl3HelloExtensionSenderFunc',
           'DER_BOOLEAN', 'siAsciiString', 'client_key_exchange',
           'SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION', 'fsblkcnt_t',
           'siUTCTime', 'IP_MULTICAST_TTL', 'CKR_FUNCTION_FAILED',
           'SEC_ASN1_DYNAMIC', '__blkcnt64_t',
           'CERT_REV_M_IGNORE_IMPLICIT_DEFAULT_SOURCE',
           '_SC_NGROUPS_MAX', '_SC_DEVICE_SPECIFIC_R',
           'MAX_CIPHER_CONTEXT_BYTES', 'CK_WTLS_KEY_MAT_PARAMS_PTR',
           '_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS', '__locale_t',
           'ssl_SEND_FLAG_NO_BUFFER', 'PF_ECONET', 'certOwnerUser',
           'ct_RSA_fixed_ECDH', 'CERT_REV_M_FORBID_NETWORK_FETCHING',
           'intn', 'PK11TokenChanged', 'CKA_TRUST_NON_REPUDIATION',
           'SEC_ASN1_UTF8_STRING', 'CERTValidity', 'WSTOPPED',
           'SSL3SignType', 'kea_dhe_dss', 'CKM_RIPEMD160_HMAC',
           'mode_t', 'CK_RC5_PARAMS', 'SEC_OID_NS_TYPE_CERT_SEQUENCE',
           '_SC_C_LANG_SUPPORT', 'sec_ASN1Template_struct',
           'sec_EncoderContext_struct', 'isascii_l',
           'CK_CMS_SIG_PARAMS_PTR', 'certificateUsageAnyCA',
           'PR_BITS_PER_WORD_LOG2', 'HT_ENUMERATE_STOP',
           'PZ_DestroyMonitor', 'CKR_SAVED_STATE_INVALID',
           'SECMOD_MODULE_DB_FUNCTION_RELEASE',
           'SEC_OID_PKCS9_SMIME_CAPABILITIES', 'PR_SYSTEM_THREAD',
           'GS_PAD', 'CERTCrlDistributionPoints', '_POSIX_TIMERS',
           'KU_NS_GOVT_APPROVED', 'CKK_NSS',
           'PR_BAD_DESCRIPTOR_ERROR',
           'CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR', 'PZ_ExitMonitor',
           '__loff_t', 'SO_TYPE', 'IPV6_LEAVE_ANYCAST',
           'SEC_ERROR_CRL_INVALID_VERSION',
           '_CS_XBS5_ILP32_OFF32_LINTFLAGS', 'IP_DROP_MEMBERSHIP',
           'cookie_seek_function_t', 'CKF_USER_PIN_INITIALIZED',
           'PR_StandardOutput', 'SEC_ERROR_INVALID_POLICY_MAPPING',
           'AI_ADDRCONFIG', 'N21SSL3ServerKeyExchange5DOT_123E',
           'MSG_TRYHARD', 'PRTRACE_DESC_MAX', 'GAI_NOWAIT',
           'ssl3CipherSpec', 'IPPROTO_UDPLITE',
           'CKM_DH_PKCS_PARAMETER_GEN', 'FOPEN_MAX', 'calg_fortezza',
           'SEC_OID_NS_CERT_EXT_ISSUER_LOGO', 'MAX_KEY_LENGTH',
           'SSL_REQUIRE_SAFE_NEGOTIATION', 'nssILockSSL', 'va_list',
           'SSL_ERROR_POST_WARNING', 'PR_SKIP_BOTH',
           'SEC_OID_MISSI_KEA_DSS', 'fd_mask', 'PR_POLL_ERR',
           'IP_ADD_SOURCE_MEMBERSHIP', 'CKM_DES_CBC', '__int16_t',
           'SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT',
           'IPV6_DROP_MEMBERSHIP', 'CKM_AES_KEY_GEN',
           'BITS_PER_INT64', '__isupper_l', 'PR_MW_FAILURE',
           'CKR_KEY_FUNCTION_NOT_PERMITTED', '_POSIX_V6_ILP32_OFF32',
           'CKA_KEY_GEN_MECHANISM', '__FDELT', 'CERTCertExtension',
           'BITS_PER_FLOAT', 'CK_ECDH2_DERIVE_PARAMS_PTR',
           'SEC_ERROR_OCSP_UNAUTHORIZED_REQUEST',
           'NSS_RWLOCK_RANK_NONE', 'PR_ATOMIC_DECREMENT', 'PRPollFN',
           '_PATH_HEQUIV', 'SEC_OID_NETSCAPE_SMIME_KEA',
           '_POSIX_REALTIME_SIGNALS', 'SEC_OID_DES_CFB',
           'SEC_ERROR_CRL_EXPIRED', 'Cached',
           'CERTRevocationMethodIndex', 'WIFCONTINUED', 'PLArenaPool',
           '_POSIX_MONOTONIC_CLOCK', 'IS_LITTLE_ENDIAN',
           'CKM_DH_PKCS_DERIVE', 'in_server_cache', 'PRFileInfo',
           'PRProcessAttr', 'in_addr_t', 'CKA_PRIME',
           'SEC_ASN1_GROUP', 'DER_HIGH_TAG_NUMBER',
           'CERT_REV_M_SKIP_TEST_ON_MISSING_SOURCE',
           'PR_SockOpt_IpTypeOfService',
           'CKM_CAMELLIA_CBC_ENCRYPT_DATA', 'SHA1_LENGTH',
           'SEC_OID_RC2_CBC', 'SEC_OID_PKCS12', 'htole16',
           'CK_RC2_MAC_GENERAL_PARAMS_PTR', 'CKM_RIPEMD128_RSA_PKCS',
           '__USE_ISOC99', '_G_USING_THUNKS', 'trustSSL',
           'CERT_REV_M_TEST_USING_THIS_METHOD',
           'SSL3_SUPPORTED_CURVES_MASK', 'PR_DIRECTORY_LOOKUP_ERROR',
           'PF_SNA', 'PRLock', '__timespec_defined',
           'SSL_LOCK_RANK_GLOBAL', 'CKC_VENDOR_DEFINED',
           'CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT',
           '_XBS5_ILP32_OFFBIG', 'CK_RSA_PKCS_OAEP_PARAMS_PTR',
           'SECLessThan', 'SO_NO_CHECK', 'CKM_MD2_KEY_DERIVATION',
           'ssl3HelloExtensionHandlerFunc', 'CKR_GENERAL_ERROR',
           '_SYS_UIO_H', '__SIZEOF_PTHREAD_BARRIERATTR_T',
           'SSL_ERROR_SHA_DIGEST_FAILURE', '_SC_XOPEN_UNIX',
           'KeyType', 'PR_AI_ADDRCONFIG', 'ct_ECDSA_fixed_ECDH',
           'PRShutdownHow', 'SECSupportExtenTag',
           'CKM_SHA_1_HMAC_GENERAL', 'SEC_ASN1_NUMERIC_STRING',
           '_IO_DONT_CLOSE', 'alloca', 'BYTES_PER_DOUBLE',
           'IPPORT_EXECSERVER',
           'SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST',
           'SEC_OID_MISSI_DSS', '_IO_BAD_SEEN',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC',
           'PR_NSPR_ERROR_BASE', '__BIT_TYPES_DEFINED__',
           'SEC_ASN1EncoderContext', '_IO_RIGHT',
           'PR_NAME_TOO_LONG_ERROR', 'PK11_OriginNULL',
           'SEC_OID_PKIX_REGCTRL_AUTHENTICATOR', 'SO_PEERCRED',
           '_ISupper', 'CK_EFFECTIVELY_INFINITE', 'SCOPE_DELIMITER',
           'SSL_ERROR_BAD_CERT_ALERT', '_SC_NL_SETMAX', 'wait',
           'SEC_OID_SECG_EC_SECP256R1', 'CKR_OK', 'CKF_DONT_BLOCK',
           'SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE',
           'sockaddr_storage', '_SC_EXPR_NEST_MAX', 'decrypt_error',
           'P_tmpdir', 'CKM_VENDOR_DEFINED', 'CertStrictnessLevels',
           'MCAST_EXCLUDE', '__ino64_t', 'SSLAppOpRead',
           'SSL3WaitState', 'N9PRNetAddr4DOT_51E', 'CK_VERSION_PTR',
           'SEC_OID_AVA_TITLE', 'CRL_DECODE_SKIP_ENTRIES',
           'CKM_SEED_MAC_GENERAL', 'SEC_OID_PKIX_CA_REPOSITORY',
           'CKM_SEED_CBC', 'SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH',
           '_CS_GNU_LIBPTHREAD_VERSION', '_PC_REC_MAX_XFER_SIZE',
           'CERTValParamInValue', 'CKM_SKIPJACK_CFB64',
           'CRL_DECODE_DEFAULT_OPTIONS',
           'SEC_ERROR_RETRY_OLD_PASSWORD',
           'relativeDistinguishedName', 'CKM_SHA384_RSA_PKCS_PSS',
           'SSL3ProtocolVersion', 'PR_SockOpt_RecvBufferSize',
           'SEC_OID_PKCS12_RSA_SIGNATURE_WITH_SHA1_DIGEST',
           'uint_least16_t', '_SC_TIMER_MAX', 'CERTCertNicknamesStr',
           '_SC_LONG_BIT', 'PZ_NotifyAll', 'CKM_PBE_SHA1_RC4_128',
           'PR_LOG_DEFINE', 'IPV6_RXHOPOPTS',
           'SEC_ERROR_PKCS12_INVALID_MAC', '__DEV_T_TYPE',
           'CK_INFO_PTR', 'SEC_ERROR_IMPORTING_CERTIFICATES',
           '_IO_uid_t', 'PF_MAX', 'CKK_AES', 'AF_NETROM',
           'PRThreadPrivateDTOR', 'CKF_EC_NAMEDCURVE',
           'CKA_TRUST_IPSEC_END_SYSTEM', 'CKM_SHA224_RSA_PKCS_PSS',
           'CERT_N2A_READABLE', 'PR_ILLEGAL_ACCESS_ERROR',
           'ssl_kea_dh', 'drand48_data', 'wait_client_key',
           'CKM_SHA512', 'PROffset64', 'CKM_CAST3_MAC_GENERAL',
           '_SC_SIGQUEUE_MAX', 'CKM_CAST128_MAC',
           'SEC_OID_ANSIX962_ECDSA_SIGNATURE_WITH_SHA1_DIGEST',
           'CKA_RESET_ON_INIT', 'PRLanguageCode',
           'SECMOD_WAIT_PKCS11_EVENT', '_G_size_t', '_SYS_CDEFS_H',
           'INADDR_UNSPEC_GROUP', 'va_copy', 'CKK_DSA',
           '__pthread_mutex_s', 'CIS_HAVE_MASTER_KEY', '_IO_OCT',
           '_IO_IS_FILEBUF', 'SEEK_SET', 'INVALID_CERT_EXTENSION',
           '__io_write_fn', 'CKR_RANDOM_NO_RNG',
           'SSL3PreSignedCertificateVerify', '_IOS_OUTPUT',
           'SEC_CERT_NICKNAMES_USER', 'ssl_sign_ecdsa',
           '_POSIX_V6_ILP32_OFFBIG', 'CERTCrl',
           'SEC_OID_PKCS9_SDSI_CERT', '_SC_MESSAGE_PASSING',
           'SO_ATTACH_FILTER', 'certDirectoryName', 'PRMonitor',
           'new_session_ticket', 'PK11_PW_AUTHENTICATED',
           'PR_NO_SEEK_DEVICE_ERROR', '_G_HAVE_BOOL',
           'CKM_PBE_MD5_DES_CBC', 'PR_UNKNOWN_ERROR',
           'SEC_OID_PKCS9_UNSTRUCTURED_ADDRESS',
           'SEC_ASN1_EndOfContents', '_SC_TRACE_USER_EVENT_MAX',
           'CKK_CAST5', 'uint_fast8_t', 'PR_BYTES_PER_BYTE',
           'SEC_OID_ANSIX962_EC_C2ONB191V5', '_LARGEFILE_SOURCE',
           'suseconds_t', 'PK11VerifyPasswordFunc',
           'CKT_NSS_MUST_VERIFY', 'CK_AES_CBC_ENCRYPT_DATA_PARAMS',
           '_SC_RAW_SOCKETS', 'float64', 'CKM_ECMQV_DERIVE',
           'PRFileInfo64', 'CKR_SESSION_READ_WRITE_SO_EXISTS',
           'SO_RCVTIMEO', '_IO_LEFT', '_STRING_H', '__isdigit_l',
           'CKO_NETSCAPE_TRUST', '_G_off_t', 'CKM_PBE_MD2_DES_CBC',
           'PR_OPERATION_ABORTED_ERROR', 'CKM_SHA512_HMAC_GENERAL',
           'certUsageProtectedObjectSigner',
           'sslSessionIDUncacheFunc', 'SECKEYDHParams',
           'PK11_OWN_PW_DEFAULTS', 'CKT_NETSCAPE_TRUST_UNKNOWN',
           'mmsghdr', 'sslHandshakingAsClient', 'PRCondVar',
           'CKM_RC4', 'PRFileDesc', 'SECMODModuleID',
           'PR_IpAddrLoopback', 'SFTK_MIN_USER_SLOT_ID',
           '_G_VTABLE_LABEL_PREFIX', 'CERTVerifyLogNode',
           'CKM_SSL3_MD5_MAC', 'ssl3KeyPairStr',
           'ERROR_TABLE_BASE_nspr', 'IPPROTO_COMP',
           'PR_PENDING_INTERRUPT_ERROR', 'SEC_OID_X509_REASON_CODE',
           'SEC_ASN1_POINTER', 'CKA_END_DATE',
           'SEC_ERROR_NO_EMAIL_CERT', '_IO_SHOWPOINT',
           'SEC_ASN1_IA5_STRING', 'PR_MW_TIMEOUT',
           'CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'SSL3CertificateVerify', 'CK_X9_42_DH_KDF_TYPE',
           'PLHashEntry', 'SSLCipherAlgorithm',
           'SSL_ERROR_UNSUPPORTED_CERT_ALERT', 'CK_SLOT_ID_PTR',
           'PK11TokenRemovedOrChangedEvent', 'nssILockSelfServ',
           'register_t', 'PRLibrary', '_POSIX_MEMLOCK',
           'ALIGN_OF_SHORT', '_ARPA_INET_H', 'CKM_PBE_MD5_CAST5_CBC',
           'SEC_OID_X509_AUTH_KEY_ID', 'DER_SEQUENCE',
           '__SIGEV_MAX_SIZE', 'AF_SECURITY', 'PR_ATOMIC_SET',
           '_SC_FIFO', 'SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO',
           'SEC_ERROR_MODULE_STUCK', 'CKR_SLOT_ID_INVALID',
           'CKA_PIXEL_X', 'xplicit', '_SC_FILE_ATTRIBUTES',
           'SEC_ERROR_KEYGEN_FAIL', 'PR_BYTES_PER_LONG',
           'CKA_NSS_OVERRIDE_EXTENSIONS',
           'SEC_OID_PKCS12_V1_CRL_BAG_ID', 'MCAST_INCLUDE',
           'CERTImportCertificateFunc',
           'SEC_OID_PKCS12_CERT_AND_CRL_BAG_ID',
           'crlEntryReasonAaCompromise', 'SECMOD_FIPS_NAME',
           'PRIPv6Addr', 'IPPORT_EFSSERVER', '_SC_MQ_PRIO_MAX',
           'SEC_OID_SECG_EC_SECT571K1', 'SEC_ERROR_REVOKED_KEY',
           '_IO_pid_t', 'TRY_AGAIN', 'intmax_t', 'EAI_INPROGRESS',
           'CKM_SHA1_RSA_PKCS_PSS', '_G_HAVE_ATEXIT',
           'CKM_SHA224_HMAC_GENERAL', 'MD5_LENGTH', 'DER_NULL',
           'CKR_VENDOR_DEFINED', 'HASH_AlgSHA512',
           'CKM_SKIPJACK_PRIVATE_WRAP',
           'CK_SKIPJACK_PRIVATE_WRAP_PTR',
           'SSL_ERROR_RECORD_OVERFLOW_ALERT',
           'CKA_TRUST_STEP_UP_APPROVED', 'int_least8_t',
           'SECMOD_SHA512_FLAG', '__bswap_constant_16', 'PRUint16',
           '__ILP32_OFF32_CFLAGS', 'CK_MECHANISM_TYPE_PTR',
           'CKR_MECHANISM_INVALID', 'IN_MULTICAST',
           'IPV6_LEAVE_GROUP', 'SESS_TICKET_KEY_NAME_LEN',
           'u_int64_t', '_CTYPE_H', '_NETDB_H',
           'SEC_OID_X509_POLICY_CONSTRAINTS', 'CKM_ECDH1_DERIVE',
           'PR_PRIORITY_HIGH', '_G_uint16_t', '_XOPEN_REALTIME',
           '_LFS_ASYNCHRONOUS_IO', 'CKA_NSS_EXPIRES',
           'SECMOD_RESERVED_FLAG', 'DER_INDEFINITE',
           'CKM_JUNIPER_SHUFFLE', 'SEC_ASN1_TAGNUM_MASK',
           '__LP64_OFF64_LDFLAGS', 'CKR_KEY_UNEXTRACTABLE',
           'SECMOD_RC4_FLAG', 'SSL_ERROR_NO_TRUSTED_SSL_CLIENT_CA',
           'SECKEYPQGDualParams', 'CK_X9_42_DH_KDF_TYPE_PTR',
           'SSL_ERROR_RX_UNEXPECTED_APPLICATION_DATA', 'IPV6_MTU',
           '_IO_peekc', 'SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT',
           '__USE_BSD', 'CKR_RANDOM_SEED_NOT_SUPPORTED',
           'CKF_DECRYPT', '__CONCAT', 'CKA_WRAP_WITH_TRUSTED',
           'BITS_PER_FLOAT_LOG2', 'SSL3_MASTER_SECRET_LENGTH',
           'SSL3ServerKeyExchange', '_IOS_NOREPLACE',
           'crlEntryReasonSuperseded', 'AF_INET6',
           'CERTCompareValidityStatusEnum', '_SC_ATEXIT_MAX',
           'SSL3Certificate', '__ispunct_l', 'CKF_GENERATE_KEY_PAIR',
           'CERTCrlEntryStr', '_SC_SAVED_IDS', 'PR_SI_SYSNAME',
           'CKM_SHA1_RSA_X9_31', '__locale_struct',
           'CRL_DECODE_KEEP_BAD_CRL',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR', 'CK_PBE_PARAMS',
           'CKF_EXTENSION', 'PR_LD_LOCAL', 'IPV6_2292HOPLIMIT',
           'CKM_PBE_SHA1_DES3_EDE_CBC', '_SC_2_PBS_TRACK',
           'SEC_ASN1_SEQUENCE_OF', 'SEC_ERROR_EXPORTING_CERTIFICATES',
           'SSL3Hashes', 'PRWritevFN', 'CERTCertKey',
           'CERTStatusConfigStr', 'SECKEYPublicKeyStr',
           '_IO_cookie_file', 'SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE',
           'SECMOD_INT_NAME', 'alert_warning',
           '__ILP32_OFF32_LDFLAGS', 'SESS_TICKET_KEY_VAR_NAME_LEN',
           'CKF_LIBRARY_CANT_CREATE_OS_THREADS', 'IPV6_NEXTHOP',
           'PK11Origin', 'SIGEV_SIGNAL', '__uint16_t', 'CK_BBOOL',
           'u_int', 'N23CERTValParamOutValueStr4DOT_78E',
           'CERTSubjectPublicKeyInfoStr', 'nssILockAttribute',
           'PR_ATOMIC_INCREMENT', '_CS_LFS64_CFLAGS',
           'SEC_ERROR_UNKNOWN_AIA_LOCATION_TYPE', '_XOPEN_LEGACY',
           'CKM_SKIPJACK_KEY_GEN', 'gid_t', 'HASH_AlgTOTAL',
           'SEC_OID_AVA_DN_QUALIFIER', 'DER_VISIBLE_STRING',
           'CKA_VALUE_LEN', 'PZ_Lock', 'SSLCipher', 'PK11TokenStatus',
           'calg_idea', 'XP_SEC_FORTEZZA_BAD_PIN',
           'SEC_ERROR_POLICY_VALIDATION_FAILED', 'DER_APPLICATION',
           'SEC_OID_PKCS12_ESPVK_IDS', 'SEC_CERT_NICKNAMES_SERVER',
           'sign_null', 'SEC_OID_EXT_KEY_USAGE_CODE_SIGN',
           'CKM_DES3_KEY_GEN', 'htonl', 'alert_fatal',
           '_XOPEN_XCU_VERSION', 'PR_FIND_SYMBOL_ERROR', '_STDIO_H',
           'PRFilePrivate', '__SIGEV_PAD_SIZE',
           'SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE',
           'cookie_close_function_t', 'PR_DIRECTORY_OPEN_ERROR',
           'IPV6_CHECKSUM', 'islower_l', 'SECKEYFortezzaPublicKey',
           'PRJobFn', 'SEC_ASN1_SAVE', 'htons', 'SEC_OID_UNKNOWN',
           'SSLWrappedSymWrappingKeyStr', 'CKA_SIGN', 'u_int16_t',
           'PR_SEEK_CUR', '_SC_PII_OSI_CLTS',
           'CKM_RSA_X9_31_KEY_PAIR_GEN',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4',
           'CK_ECDH2_DERIVE_PARAMS', 'ssl_kea_size',
           'SEC_ERROR_END_OF_LIST', 'CKM_IDEA_ECB', 'AI_PASSIVE',
           'DER_PRIVATE', 'PR_SockOpt_DropMember',
           'RF_CERTIFICATE_HOLD', 'AF_PPPOX', '__key_t',
           'SEC_ERROR_UNSUPPORTED_ELLIPTIC_CURVE', 'PR_BITS_PER_LONG',
           '_XOPEN_CRYPT', 'PR_NOT_SOCKET_ERROR',
           'CKM_SKIPJACK_CFB32', 'SSL_MAX_EXTENSIONS',
           '__fsblkcnt64_t', 'DER_PRIMITIVE', '_POSIX_IPV6',
           '_SC_ASYNCHRONOUS_IO', 'SO_SECURITY_ENCRYPTION_TRANSPORT',
           'PRErrorCallbackLookupFn', '_SC_2_CHAR_TERM',
           'SEC_ASN1_OCTET_STRING', 'SEC_ASN1WriteProc',
           '__io_close_fn', '__va_arg_pack_len', 'CKD_SHA1_KDF',
           'CKO_NSS_SMIME', 'N15sslSessionIDStr5DOT_1555DOT_157E',
           'PR_MW_SUCCESS', 'CKK_CAST', 'SECMOD_FIPS_FLAGS',
           'CKA_SERIAL_NUMBER', '_G_int16_t', 'CKA_ID', '__socklen_t',
           'NSPR_API', 'SECKEYEncryptedPrivateKeyInfo',
           'certificateUsageUserCertImport', 'CKK_JUNIPER',
           'ssl_kea_ecdh', 'PR_FILESYSTEM_MOUNTED_ERROR',
           'CKM_MD5_RSA_PKCS', '__codecvt_noconv',
           'CKR_DATA_LEN_RANGE', 'SFTK_MIN_FIPS_USER_SLOT_ID',
           'CKM_DSA', 'CK_RC2_PARAMS', 'SEC_OID_AVA_LOCALITY',
           'SECCertUsageEnum', '_IO_UPPERCASE', '_ATFILE_SOURCE',
           'SEC_ASN1_SET_OF', 'PR_IO_PENDING_ERROR',
           'EXT_KEY_USAGE_TIME_STAMP', 'SSL_CONNECTIONID_BYTES',
           'SEC_OID_NS_CERT_EXT_NETSCAPE_OK', 'SSL_ENABLE_DEFLATE',
           'CKM_CAST3_MAC', 'sign_ecdsa', 'PR_REALLOC', 'CKF_HW',
           'MSG_DONTROUTE', 'PRBool', 'PR_SHUTDOWN_BOTH',
           'CKA_NETSCAPE_TRUST', '_SC_XOPEN_LEGACY', 'PF_SECURITY',
           'ssl3BulkCipherDef', 'CKO_NETSCAPE_DELSLOT',
           'CKA_CERTIFICATE_TYPE', 'sigval_t', 'fpos_t',
           'CERTCertNicknames', 'CKR_INFORMATION_SENSITIVE',
           'CERTPrivKeyUsagePeriod', 'IP_PASSSEC',
           'SEC_ERROR_CERT_ADDR_MISMATCH', 'va_end', 'IPV6_DSTOPTS',
           '_FEATURES_H', 'PLArena', 'CKA_ATTR_TYPES',
           'SSL_ERROR_RX_MALFORMED_CLIENT_HELLO', 'F_ULOCK',
           'SEC_ERROR_CERT_BAD_ACCESS_LOCATION', 'PR_NSPR_IO_LAYER',
           'CKT_NSS_TRUST_UNKNOWN', 'CKM_PKCS5_PBKD2', 'F_TEST',
           'PORT_Strlen', 'calg_aes', '_POSIX_SHARED_MEMORY_OBJECTS',
           'SEC_OID_PKIX_REGCTRL_REGTOKEN', 'BITS_PER_BYTE_LOG2',
           'CKR_SESSION_HANDLE_INVALID', 'SEC_ASN1_PRIMITIVE',
           '__ASMNAME', 'SSL3HandshakeStateStr', 'CK_TOKEN_INFO',
           '_PC_REC_MIN_XFER_SIZE', 'SEC_OID_TOTAL',
           '_SC_V6_ILP32_OFFBIG', 'CK_SSL3_KEY_MAT_PARAMS_PTR',
           'certificate_expired', '_CS_LFS_LDFLAGS', 'SECOidData',
           'SECKEYPublicKey', 'PRSocketOptionData',
           'SSL_ERROR_WRONG_CERTIFICATE', '_POSIX_V7_ILP32_OFFBIG',
           'PR_NO_DEVICE_SPACE_ERROR', 'CERT_POLICY_FLAG_NO_ANY',
           'XP_SEC_FORTEZZA_PERSON_NOT_FOUND', 'CKO_NSS_NEWSLOT',
           'CK_RV', 'ssl_mac_sha', 'DER_EXPLICIT', 'AF_ATMPVC',
           '_SC_CHAR_MIN', 'SEC_OID_MISSI_DSS_OLD', '__have_sigval_t',
           'SSL_CBP_TLS1_0', 'SSL_SECURITY_STATUS_ON_LOW',
           'CIS_HAVE_CERTIFICATE', 'DER_OCTET_STRING', 'HASHContext',
           'MSG_NOSIGNAL', 'ssize_t', 'SEC_OID_HMAC_SHA384',
           'certificateUsageEmailSigner', 'XP_SEC_FORTEZZA_BAD_CARD',
           'DER_BIT_STRING', 'SO_BINDTODEVICE',
           '_SC_NPROCESSORS_ONLN', 'SEC_ERROR_UNTRUSTED_ISSUER',
           'SEC_ERROR_USER_CANCELLED', 'CERT_MAX_CERT_CHAIN',
           'SEC_OID_SECG_EC_SECT283K1', 'ct_DSS_ephemeral_DH', 'id_t',
           'SEC_OID_X509_SUBJECT_KEY_ID', 'PLHashComparator',
           'certUsageObjectSigner', '_G_fpos_t', 'CKK_VENDOR_DEFINED',
           'BYTES_PER_SHORT', 'PK11ContextStr',
           'ssl_compression_deflate', 'wait_server_hello',
           'IP_RECVRETOPTS', 'SSL3ServerDHParams',
           '__lldiv_t_defined', 'PR_NSEC_PER_MSEC',
           '__SIZEOF_PTHREAD_BARRIER_T', 'blkcnt_t',
           'SEC_OID_CAMELLIA_192_CBC', 'no_certificate',
           'CK_HW_FEATURE_TYPE', 'ALIGN_OF_FLOAT', 'CKM_WTLS_PRF',
           '_SYS_TYPES_H', '_ISblank', 'implicit',
           'PR_INADDR_BROADCAST', 'CKA_HASH_OF_SUBJECT_PUBLIC_KEY',
           'PR_SKIP_HIDDEN', 'MCAST_JOIN_SOURCE_GROUP',
           'SEC_OID_MISSI_ALT_KEA', 'PRUint64', 'CKF_SO_PIN_LOCKED',
           'PR_SI_HOSTNAME', 'PRAddrInfo', '_SC_XOPEN_CRYPT',
           'SSLCompressionMethod', 'SEC_OID_SECG_EC_SECT113R2',
           'IPPROTO_DSTOPTS', 'SEC_OID_SECG_EC_SECT113R1', 'PRUword',
           'CK_RSA_PKCS_PSS_PARAMS', '_PC_CHOWN_RESTRICTED',
           'SSL3Statistics', 'CKA_SENSITIVE', '__PMT',
           'PR_SHM_READONLY', 'NSS_USE_ALG_RESERVED',
           'CERTSubjectNodeStr', '_XOPEN_ENH_I18N', 'ALIGN_OF_WORD',
           'CKZ_DATA_SPECIFIED', 'PR_NETDB_BUF_SIZE',
           'SEC_OID_PKCS12_SDSI_CERT_BAG',
           'N23CERTValParamOutValueStr4DOT_79E',
           'CKR_OBJECT_HANDLE_INVALID', 'SSL3Compressed',
           'CERTPolicyQualifier', 'SSL_HANDSHAKE_AS_CLIENT',
           'SECKEYKEAPublicKeyStr', 'SO_DOMAIN',
           'CK_EXTRACT_PARAMS_PTR', 'fsid_t', '__WNOTHREAD',
           'certificate', 'certOtherName', 'CKM_DES_CBC_ENCRYPT_DATA',
           'fsfilcnt64_t', 'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR',
           'SSL_ERROR_RX_UNEXPECTED_FINISHED', '_SC_FILE_LOCKING',
           '_IO_UNITBUF', 'CKA_PUBLIC_EXPONENT',
           'N18PRSocketOptionData4DOT_55E', '_SC_STREAM_MAX',
           'PR_LOG_MIN', 'CKM_CAST_MAC', 'SEC_CERT_NICKNAMES_CA',
           'SSL_ERROR_FORTEZZA_PQG', 'PR_UNJOINABLE_THREAD',
           '_POSIX2_C_BIND', 'SEC_ERROR_INADEQUATE_CERT_TYPE',
           'CKM_RC4_KEY_GEN', 'SEC_ERROR_PKCS11_GENERAL_ERROR',
           'CERTRDNStr', 'isgraph_l', 'CKR_MUTEX_NOT_LOCKED',
           'PR_ACCESS_READ_OK', 'MSG_EOR', 'PR_FILE_FILE', 'CK_FLAGS',
           'CKM_CAMELLIA_MAC_GENERAL', 'BIG_ENDIAN',
           '_POSIX_TRACE_EVENT_FILTER', 'SECMOD_EXTERNAL',
           'SSL_ERROR_RX_MALFORMED_SERVER_HELLO',
           '__USE_XOPEN_EXTENDED', 'CKM_RIPEMD160_RSA_PKCS',
           '_CS_POSIX_V6_ILP32_OFFBIG_LIBS', 'CKA_NSS_EMAIL',
           '_SC_EQUIV_CLASS_MAX', 'siGeneralizedTime', 'timer_t',
           'unrecognized_name', 'CK_MAC_GENERAL_PARAMS_PTR',
           'PF_BLUETOOTH', 'SSL_ERROR_NO_COMPRESSION_OVERLAP',
           'SO_DONTROUTE', 'SECKEYPrivateKeyInfo',
           'SEC_OID_AVA_SURNAME', 'SEC_ERROR_BAD_TEMPLATE',
           'CKM_DES_MAC_GENERAL', 'CKF_DERIVE',
           'SSL_ERROR_RX_UNEXPECTED_ALERT', 'PRSize', 'NO_RECOVERY',
           'N16pthread_rwlock_t4DOT_12E', 'SEC_CERT_CLASS_CA',
           'CKM_RC2_CBC', 'PR_INT32_MIN', 'SEC_OID_AVA_INITIALS',
           '_PATH_NETWORKS', 'IPV6_PMTUDISC_PROBE',
           'SECMODModuleListStr', 'content_application_data',
           'N29SSL3ClientDiffieHellmanPublic5DOT_128E',
           'N15sslSessionIDStr5DOT_1555DOT_156E', 'FD_CLR',
           '__islower_l', '_LFS_LARGEFILE', 'PRWaitGroup',
           'CKU_CONTEXT_SPECIFIC', 'certOwnerCA', 'PK11_ATTR_TOKEN',
           '__WIFCONTINUED', 'SSL3AlertDescription',
           'SFTK_MAX_FIPS_USER_SLOT_ID', 'sslOptions',
           '_SC_THREAD_PRIO_PROTECT',
           'SEC_OID_PKCS9_COUNTER_SIGNATURE', 'CKM_SKIPJACK_RELAYX',
           'CKM_CAMELLIA_ECB', '_POSIX_PRIORITY_SCHEDULING',
           'WEXITED', 'SSL_CHALLENGE_BYTES', 'kea_dh_rsa',
           'SEC_OID_X942_DIFFIE_HELMAN_KEY', 'CKM_RSA_PKCS_PSS',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC',
           'CKM_RIPEMD160_HMAC_GENERAL', 'CKM_RC2_MAC',
           'PK11_TypeSymKey', '_SC_THREAD_DESTRUCTOR_ITERATIONS',
           'key_t', 'CKF_SO_PIN_COUNT_LOW', 'SOL_PACKET',
           'PR_ACCESS_FAULT_ERROR', 'CKM_CONCATENATE_BASE_AND_KEY',
           'hmac_md5', '_XOPEN_XPG3',
           'SECKEYEncryptedPrivateKeyInfoStr',
           'SEC_OID_ANSIX962_EC_C2ONB239V5', 'PR_ATOMIC_ADD',
           'SECOidTag', 'content_handshake', '_IO_fpos_t', 'PF_AX25',
           '_SC_TRACE_SYS_MAX', '_POSIX_NO_TRUNC',
           'SEC_OID_ANSIX962_EC_C2PNB304W1', 'IPV6_MULTICAST_LOOP',
           'SEC_OID_AVA_GIVEN_NAME', 'SEC_OID_SECG_EC_SECP521R1',
           'SEC_ERROR_OCSP_UNKNOWN_RESPONSE_STATUS',
           'PK11CertListAll', 'ip_mreq', 'PRLogModuleInfo',
           'CK_RSA_PKCS_OAEP_SOURCE_TYPE', 'PR_BYTES_PER_WORD_LOG2',
           'ssl_V3_SUITES_IMPLEMENTED', 'CKA_SUBJECT',
           '_SC_USER_GROUPS', '_BITS_BYTESWAP_H',
           'SEC_OID_PKCS7_SIGNED_DATA', 'SSL3GenericStreamCipher',
           'PR_IS_DIRECTORY_ERROR', 'SEC_OID_X509_ANY_POLICY',
           'CK_PKCS5_PBKD2_PARAMS_PTR', 'CKM_SHA384_RSA_PKCS',
           'SEC_ASN1_CLASS_MASK', 'IPPORT_RESERVED',
           'SEC_OID_CMS_RC2_KEY_WRAP', 'CKM_PBE_SHA1_DES2_EDE_CBC',
           'ssl3HelloExtensionSender', 'SEC_ASN1_Contents',
           '_POSIX_SHELL', 'PRCallOnceType', 'PR_EXCL',
           'server_hello_done', '_SC_XOPEN_ENH_I18N',
           'SSL_ERROR_REVOKED_CERT_ALERT', '__USE_XOPEN',
           'CKR_SIGNATURE_LEN_RANGE', 'CKM_SHA512_KEY_DERIVATION',
           'PRMcastRequest', 'SEC_OID_PKCS12_SAFE_CONTENTS_ID',
           'CERTVerifyLog', 'CERTDistNamesStr', 'PRFileMap',
           'CIS_HAVE_FINISHED', 'CKM_IDEA_CBC_PAD',
           'CERT_REV_MI_NO_OVERALL_INFO_REQUIREMENT',
           '__USE_POSIX199309', '____FILE_defined', 'SEC_CRL_TYPE',
           'PR_INADDR_LOOPBACK', 'SEC_OID_EXT_KEY_USAGE_TIME_STAMP',
           'certPackageNone', 'CK_FUNCTION_LIST', 'IPV6_2292HOPOPTS',
           '_IOS_INPUT', 'SECMOD_MODULE_DB_FUNCTION_FIND',
           'IP_PMTUDISC', 'PR_SockOpt_Last', 'PR_ALIGN_OF_INT64',
           '__W_EXITCODE', 'IPPORT_NAMESERVER', 'CKM_RC5_CBC_PAD',
           'CRL_DECODE_ADOPT_HEAP_DER',
           'SEC_OID_PKCS9_EXTENDED_CERTIFICATE_ATTRIBUTES',
           'SO_PRIORITY', 'LITTLE_ENDIAN', 'MSG_TRUNC',
           'PR_END_OF_FILE_ERROR', 'SSL3ServerRSAParams',
           'SSL3ServerHello', 'TMP_MAX', '__fd_mask',
           'certificateUsageSSLCA', 'FIOSETOWN', 'CKM_CAST_KEY_GEN',
           '__ILP32_OFFBIG_LDFLAGS', 'CKM_TLS_KEY_AND_MAC_DERIVE',
           'kt_fortezza', '_IO_NO_WRITES',
           'SEC_OID_NS_CERT_EXT_CERT_RENEWAL_TIME',
           'SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE',
           'SSL_ERROR_CERTIFICATE_UNKNOWN_ALERT', 'SEC_OID_DES_CBC',
           'PK11_ATTR_PRIVATE', 'SECCertUsage', 'CERT_LIST_EMPTY',
           '_G_HAVE_IO_FILE_OPEN', 'PR_PROT_READONLY',
           'N21SSL3HandshakeStateStr5DOT_161E',
           'SEC_OID_PKCS12_ENVELOPING_IDS', '__FILE_defined',
           'CK_X9_42_DH2_DERIVE_PARAMS', 'DER_IA5_STRING',
           'IPV6_PMTUDISC_WANT', '_SC_DEVICE_SPECIFIC',
           '_SC_GETPW_R_SIZE_MAX', '_POSIX_ASYNCHRONOUS_IO',
           'IP_DROP_SOURCE_MEMBERSHIP', 'CKM_DES3_MAC_GENERAL',
           'IPPROTO_PUP', 'certificateUsageCheckAllUsages', 'timeval',
           'isdigit_l', 'SSL3HandshakeState', 'SEC_ASN1_ANY_CONTENTS',
           'SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_128_BIT_RC4',
           'sign_rsa', 'CKG_MGF1_SHA384', 'PR_DESC_SOCKET_UDP',
           '__SOCKADDR_COMMON_SIZE', 'SSL_ERROR_EXPIRED_CERT_ALERT',
           '_SC_PII_OSI_COTS', 'ssl_mac_md5', '__BYTE_ORDER',
           'CERTCertListNodeStr', 'DERTemplateStr',
           'CK_RC5_MAC_GENERAL_PARAMS', 'CKR_TEMPLATE_INCONSISTENT',
           '_SC_OPEN_MAX', '_G_NAMES_HAVE_UNDERSCORE', 'CKK_TWOFISH',
           'SO_BSDCOMPAT', 'PREnumerator', 'CKM_DES_MAC',
           'PR_SEM_EXCL', 'siDERNameBuffer', '__gnuc_va_list',
           'CERTValParamOutValue', 'CKA_WRAP', 'SSL3_SESSIONID_BYTES',
           'IP_TOS', 'SEC_ERROR_FILING_KEY', 'CERTValParamInValueStr',
           'CERTNameConstraint', '__uint64_t', '_SECStatus',
           'ssl_calg_null', 'CKM_NETSCAPE_AES_KEY_WRAP_PAD',
           'PR_LOG_ALWAYS', 'cert_revocation_method_count',
           'CKM_CAST128_MAC_GENERAL', '__USE_ISOC95',
           'CKM_TLS_MASTER_KEY_DERIVE', '_SC_XOPEN_XPG4',
           'SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE',
           'CKR_PIN_LEN_RANGE', '_SC_XOPEN_XPG2', '_SC_XOPEN_XPG3',
           'SEC_ASN1_VIDEOTEX_STRING', 'SSL_ERROR_BAD_MAC_ALERT',
           'IN_BADCLASS', '_G_IO_IO_FILE_VERSION',
           'certificate_request', '_POSIX_C_SOURCE',
           'SEC_ERROR_OCSP_UNKNOWN_RESPONSE_TYPE',
           'CKS_RW_SO_FUNCTIONS', '_SC_NETWORKING', 'addrinfo',
           'PRErrorCallbackNewTableFn', 'SECKEYPublicKeyList',
           '_IO_ssize_t', 'sslSocketOps', '_SC_MEMLOCK_RANGE',
           '_SC_PRIORITY_SCHEDULING', 'SSL_sni_host_name',
           '_BITS_POSIX_OPT_H', '_XOPEN_XPG2',
           'SEC_ASN1_GRAPHIC_STRING', 'PK11_DIS_NONE',
           'CKM_CDMF_KEY_GEN', '_CS_V6_ENV', 'AF_ROUTE',
           'BYTES_PER_INT64', 'SSL_ERROR_RX_UNEXPECTED_CERTIFICATE',
           '_IO_IS_APPENDING', 'PR_BAD_ADDRESS_ERROR',
           'N23CERTValParamOutValueStr4DOT_80E',
           '_SC_THREAD_THREADS_MAX', 'DER_UTC_TIME',
           '_SC_LOGIN_NAME_MAX', 'insufficient_security', 'PF_UNSPEC',
           'SEC_ERROR_JS_INVALID_MODULE_NAME', 'ntohl',
           '__bswap_constant_32', '_SC_2_C_BIND', 'ntohs',
           '_CS_LFS64_LDFLAGS', 'IPPORT_WHOSERVER',
           'SEC_ERROR_KRL_EXPIRED', 'SOL_IP', 'L_ctermid',
           'SEC_OID_ANSIX962_EC_C2ONB239V4',
           'CKM_ECDH1_COFACTOR_DERIVE', 'nullKey', '__uint8_t',
           '_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS', 'SEC_OID_SHA384',
           'CKR_USER_NOT_LOGGED_IN', 'PRHashEntry', 'sslSessionID',
           '_SYS_SOCKET_H', 'NS_CERT_TYPE_CA', 'BITS_PER_INT_LOG2',
           'CK_ECMQV_DERIVE_PARAMS_PTR', 'nssILockObject',
           'SEC_CERT_NICKNAMES_ALL', '_SC_C_LANG_SUPPORT_R',
           'CKR_OPERATION_NOT_INITIALIZED', 'SO_SNDTIMEO',
           '_SC_MQ_OPEN_MAX', '__WCOREFLAG', 'nssILockPK11cxt',
           'CERTOKDomainName', 'calg_3des',
           'CKM_X9_42_DH_KEY_PAIR_GEN', 'CKO_DOMAIN_PARAMETERS',
           'PR_FILEMAP_STRING_BUFSIZE', 'SEC_OID_PKCS9_LOCAL_KEY_ID',
           'CKM_DES_CFB64', 'SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH',
           'IPV6_RECVDSTOPTS', '__USE_EXTERN_INLINES',
           '__SIZEOF_PTHREAD_COND_T', 'SEC_ASN1_Length',
           '__FSFILCNT64_T_TYPE', 'XP_JAVA_DELETE_PRIVILEGE_ERROR',
           'AI_V4MAPPED', 'SEC_OID_PKIX_REGCTRL_PKIPUBINFO',
           '_SC_IPV6', 'SEC_OID_X509_INHIBIT_ANY_POLICY',
           'TLS_EX_SESS_TICKET_VERSION', '_SC_CHILD_MAX',
           '__REDIRECT_NTH_LDBL', 'SEC_KRL_TYPE',
           'RF_CESSATION_OF_OPERATION', 'ssl_auth_null',
           'unexpected_message', 'SEC_OID_ANSIX962_EC_C2TNB431R1',
           'IP_MSFILTER', 'PF_DECnet', 'CKR_ARGUMENTS_BAD',
           'SSL_ENABLE_SSL3', 'ClientAuthenticationType',
           'SEC_OID_AES_192_CBC', 'CKM_SHA224_RSA_PKCS',
           'CKR_KEY_NOT_NEEDED', 'MSG_DONTWAIT', 'PR_IpAddrNull',
           'AF_NETLINK', '_LFS64_LARGEFILE', 'CKA_MODULUS',
           'BYTES_PER_BYTE', 'IP_PMTUDISC_DONT', 'EAI_SERVICE',
           'CKM_SKIPJACK_CFB8', '_PC_REC_XFER_ALIGN',
           'PR_INTERVAL_NO_TIMEOUT',
           'certificateUsageSSLServerWithStepUp',
           'NS_CERT_TYPE_EMAIL_CA', 'NO_DATA',
           '_SC_XOPEN_REALTIME_THREADS', 'TLSExtensionData',
           'SEC_ERROR_OLD_CRL', 'PK11_DIS_USER_SELECTED',
           'PRSockOption', 'SEC_ERROR_DUPLICATE_CERT_NAME', '_PRCPU',
           '_SC_LEVEL2_CACHE_SIZE',
           'SEC_ERROR_PKCS12_KEY_DATABASE_NOT_INITIALIZED',
           '_SC_NL_MSGMAX', 'IPPROTO_SCTP', 'certUsageSSLCA',
           'SSL3DistinquishedName', 'PR_GLOBAL_BOUND_THREAD',
           '_SC_SCHAR_MIN', 'CERTCertificatePolicyMappings', 'PRSem',
           'CKM_DES_CFB8', 'CKM_IDEA_MAC', 'sigevent_t',
           'CKR_PIN_INVALID',
           'SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST',
           'CKK_CDMF', 'GS_HEADER', 'CKR_PIN_INCORRECT',
           '_XOPEN_XPG4', 'CKA_CERT_SHA1_HASH',
           'CKA_NETSCAPE_PQG_COUNTER', 'PR_FILE_DIRECTORY',
           '_SC_NL_TEXTMAX', 'CKM_CAST_CBC', 'KU_CRL_SIGN',
           'IPPROTO_UDP', 'AI_IDN_USE_STD3_ASCII_RULES',
           'CKM_SSL3_MASTER_KEY_DERIVE_DH',
           'SEC_OID_SDN702_DSA_SIGNATURE', '__quad_t',
           'PR_SockOpt_NoDelay', '__uid_t', 'SEC_OID_NS_TYPE_GIF',
           '__int8_t', 'CERTOKDomainNameStr', 'CKU_USER', 'div_t',
           '_SC_SEMAPHORES', 'SSL_ENABLE_TLS',
           'SEC_ERROR_CRL_NOT_YET_VALID', 'SECMOD_AES_FLAG',
           'SEC_ERROR_NOT_INITIALIZED', 'SEC_ERROR_CRL_INVALID',
           '__WORDSIZE', 'SEC_ERROR_NO_TOKEN',
           'CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC', 'SECOidDataStr',
           'CKA_REQUIRED_CMS_ATTRIBUTES', 'le32toh',
           '__USE_LARGEFILE64', 'PK11PreSlotInfo', 'SSLCompressor',
           '_ISalpha', '_POSIX_CHOWN_RESTRICTED',
           '_XOPEN_REALTIME_THREADS', 'CKM_NSS_AES_KEY_WRAP_PAD',
           'CKR_SIGNATURE_INVALID', 'htobe64',
           'SEC_OID_PKCS1_PSPECIFIED',
           'SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST',
           'CKR_PIN_LOCKED', 'DER_DEFAULT_CHUNKSIZE', '_SC_CHAR_BIT',
           'PRLogModuleLevel', 'SEC_ERROR_DUPLICATE_CERT',
           'SECGreaterThan', 'NI_IDN_USE_STD3_ASCII_RULES',
           '_SC_PIPE', 'PR_LOG_WARNING',
           '_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS', 'CKM_RIPEMD160',
           'SSL_ERROR_UNSUPPORTED_EXTENSION_ALERT',
           'CKR_CRYPTOKI_NOT_INITIALIZED', 'daddr_t', 'int_fast8_t',
           '__RLIM64_T_TYPE', 'SSL3Sender', 'SECKEYDHPublicKey',
           'CKA_EC_POINT', 'IN_CLASSA_NET', 'CKR_CANT_LOCK',
           'CKR_ATTRIBUTE_SENSITIVE', 'wait_client_cert',
           'CERTCrlEntry', 'kg_strong', 'SEC_ERROR_READ_ONLY',
           'cert_pi_max', 'CK_RSA_PKCS_MGF_TYPE', 'CKM_FAKE_RANDOM',
           'NSSRWLock', 'CK_EXTRACT_PARAMS', 'PRHashTable',
           '_IO_DELETE_DONT_CLOSE', 'CKM_DH_PKCS_KEY_PAIR_GEN',
           'SEC_ASN1_BMP_STRING', 'IP_RECVTOS',
           'change_cipher_spec_choice', 'PR_BYTES_PER_DOUBLE',
           'PRTransmitFileFlags', 'kea_null',
           'CKM_NETSCAPE_PBE_SHA1_DES_CBC', '_ISprint',
           'PR_INT32_MAX', 'PR_ALIGN_OF_POINTER', 'CKM_CAST3_CBC_PAD',
           'PRInt8', 'SEC_ERROR_BAD_SIGNATURE',
           '_SC_THREAD_PRIORITY_SCHEDULING', 'CERTAVAStr',
           'SEC_OID_CMS_3DES_KEY_WRAP', 'kea_dh_dss_export', '__bos',
           'SEC_ERROR_PKCS12_UNSUPPORTED_VERSION',
           'secCertTimeExpired', '_CS_POSIX_V7_WIDTH_RESTRICTED_ENVS',
           '__ssize_t', 'kt_rsa', 'ssl_SHUTDOWN_BOTH', 'EAI_ALLDONE',
           'CERTCRLEntryReasonCode', 'CKM_ECDSA_KEY_PAIR_GEN',
           'sign_dsa', 'SSL_NUM_WRAP_MECHS', 'int16_t', '__warnattr',
           'cert_pi_extendedKeyusage', '__sigset_t',
           'SSL3_RSA_PMS_LENGTH', 'SEC_OID_AES_128_CBC',
           '_SC_SYNCHRONIZED_IO', '__isalnum_l', 'SOCK_NONBLOCK',
           'PRTimeParameters', 'CKA_NETSCAPE_SMIME_INFO',
           'wait_server_cert', 'PK11SlotList', 'PLHashEnumerator',
           'SEC_OID_PKCS1_RSA_OAEP_ENCRYPTION', 'IPV6_UNICAST_HOPS',
           'certificateUsageObjectSigner', 'BYTES_PER_LONG',
           'EAI_NONAME', 'EncryptedSessionTicket',
           'sslHandshakingAsServer', 'PRThreadDumpProc', 'CKM_MD5',
           'N9PRNetAddr4DOT_53E', 'CKA_VALUE_BITS',
           'CK_DES_CBC_ENCRYPT_DATA_PARAMS', 'CERTNameStr',
           'CK_RC5_CBC_PARAMS', 'CKA_SUPPORTED_CMS_ATTRIBUTES',
           'PR_FILE_NOT_FOUND_ERROR',
           'SSL_ERROR_HANDSHAKE_FAILURE_ALERT',
           'SEC_ERROR_EXTRA_INPUT',
           'SEC_OID_X509_DELTA_CRL_INDICATOR', 'IPPROTO_IPV6',
           'CERTValidityStr', 'ushort', 'HT_ENUMERATE_NEXT',
           'DER_T61_STRING', 'SOL_ATM',
           'SEC_OID_CMS_EPHEMERAL_STATIC_DIFFIE_HELLMAN',
           'PK11PasswordFunc', 'PR_LOG_NOTICE', 'sender_client',
           'SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST', 'SSL_NOT_ALLOWED',
           '_SC_USHRT_MAX', '_CS_XBS5_LPBIG_OFFBIG_CFLAGS',
           'SEC_OID_PKCS7_DIGESTED_DATA', 'SEC_OID_RFC1274_UID',
           'clockid_t', '_IO_size_t', 'cert_pi_date',
           'CKF_TOKEN_INITIALIZED', 'IPV6_ROUTER_ALERT', 'caddr_t',
           'SIOCATMARK', 'uint16_t', 'CK_MECHANISM_PTR',
           'CKF_HW_SLOT', 'DER_DERPTR', 'CKA_NETSCAPE_PKCS8_SALT',
           'SSL_ERROR_DECOMPRESSION_FAILURE', 'L_tmpnam',
           'CKA_TRUST_DATA_ENCIPHERMENT', 'DER_TAG_MASK', 'CKA_LABEL',
           'SEC_CERTIFICATE_VERSION_3', 'PF_INET',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4',
           '__USE_MISC', 'CKA_NSS_SMIME_INFO', 'CKA_TRUST_CRL_SIGN',
           'PZ_WaitCondVar', 'CKM_PBE_SHA1_CAST5_CBC',
           '_PATH_PROTOCOLS', 'PF_INET6', 'NETDB_INTERNAL',
           '__compar_d_fn_t', 'obstack', 'PR_PROT_READWRITE',
           'WIFEXITED', 'va_arg', 'SSL3KEAType',
           'PK11MergeLogNodeStr', 'SECItem', 'FD_SET', '__caddr_t',
           'CERTCompareValidityStatus',
           'SEC_ERROR_EXPIRED_CERTIFICATE', 'CKM_JUNIPER_ECB128',
           'ALIGN_OF_LONG', 'SEC_ASN1_GET', 'PRIOMethods',
           'CKA_TRUSTED', 'CKA_JAVA_MIDP_SECURITY_DOMAIN',
           'bad_certificate_status_response', 'CKM_CAST3_CBC',
           'CERTSubjectList', 'PR_LOCAL_THREAD', 'PF_UNIX', 'hostent',
           'WSTOPSIG', 'PR_INTERVAL_NO_WAIT',
           'PR_ADDRESS_NOT_AVAILABLE_ERROR', 'finished',
           'PR_SockOpt_McastInterface', 'CKF_SO_PIN_FINAL_TRY',
           'DER_SKIP', 'CKK_RSA', '_IO_HAVE_SYS_WAIT',
           'CKR_ATTRIBUTE_READ_ONLY', '_SYS_SYSMACROS_H', 'CKC_X_509',
           '_IOFBF', 'CKA_NEVER_EXTRACTABLE',
           'cert_po_extendedKeyusage', 'CKA_UNWRAP', '_SC_PAGESIZE',
           'SECMOD_MODULE_DB_FUNCTION_ADD', 'prbitmap_t',
           'PR_DEVICE_IS_LOCKED_ERROR',
           'SEC_ERROR_PKCS12_UNABLE_TO_LOCATE_OBJECT_BY_NAME',
           'CKT_NETSCAPE_UNTRUSTED', 'PRWriteFN', 'PRFsyncFN',
           'SEC_OID_NS_CERT_EXT_CA_CERT_URL', 'CERTCertListStr',
           'PRConnectcontinueFN', 'CKM_SHA512_HMAC',
           'SEC_OID_PKCS9_X509_CERT', 'PR_PRIORITY_LAST',
           'PR_SKIP_NONE', 'kt_dh', '__USE_POSIX199506',
           'crlEntryReasonUnspecified', 'CKR_SESSION_CLOSED',
           'PK11_TypeCert', '__S64_TYPE', 'PK11DefaultArrayEntryStr',
           '__BIG_ENDIAN', 'CK_WTLS_MASTER_KEY_DERIVE_PARAMS', 'W_OK',
           'SEC_ERROR_BUSY', 'SEC_OID_NS_TYPE_URL',
           'PR_CurrentThread', 'CERTBasicConstraintsStr',
           'CKK_NSS_PKCS8', 'SEC_ASN1_UNIVERSAL',
           'SEC_OID_PKCS1_RSA_ENCRYPTION', 'CKM_BATON_COUNTER',
           'PRTimeParamFn', 'CKK_INVALID_KEY_TYPE', 'CKM_DES_OFB64',
           'int8', 'certUsageStatusResponder', 'wait_cert_verify',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC',
           '_CS_POSIX_V7_LPBIG_OFFBIG_LIBS',
           'CERTPublicKeyAndChallengeStr', 'CKA_NETSCAPE_URL',
           '_POSIX_MESSAGE_PASSING', 'PLHashAllocOps',
           'SEC_ERROR_LOCKED_PASSWORD',
           '_POSIX_THREAD_PRIORITY_SCHEDULING', 'ssl3State',
           'MSG_WAITFORONE', 'SO_SNDLOWAT', 'TLSExtensionDataStr',
           '__isblank_l', 'ip_opts', 'nssILockList', 'cipher_des',
           '_SC_SYSTEM_DATABASE_R',
           'CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC',
           'CKM_CAST_CBC_PAD', 'IPPROTO_ROUTING', 'PR_AI_V4MAPPED',
           'PR_RANGE_ERROR', 'DER_TAGNUM_MASK', 'IPPROTO_DCCP',
           'PRSharedMemory', 'N9PRLibSpec4DOT_164DOT_18E', '__ino_t',
           '_SECMODT_H_', '__io_read_fn', '__REDIRECT_LDBL',
           'comparison_fn_t', 'SEC_OID_X509_SUBJECT_INFO_ACCESS',
           '_SC_SYMLOOP_MAX',
           'SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE',
           'SEC_ERROR_BAD_DER', 'DER_INLINE', '_POSIX_VDISABLE',
           'DER_CONSTRUCTED', 'CKM_SHA384_HMAC_GENERAL',
           'SEC_ERROR_CA_CERT_INVALID', 'CKR_FUNCTION_NOT_PARALLEL',
           'CKM_SHA1_KEY_DERIVATION', 'MSG_MORE', 'PK11TokenRemoved',
           'CKA_NSS', '_SS_SIZE', 'be16toh', 'CKA_NSS_PQG_COUNTER',
           'NSPR_DATA_API', 'CKC_WTLS', '_SC_2_C_VERSION',
           'ssl3BulkCipherDefStr', '__USE_ATFILE', '__USE_ANSI',
           'CKM_PBE_SHA1_RC2_128_CBC', 'CKR_MUTEX_BAD',
           'CKP_PKCS5_PBKD2_HMAC_SHA1', 'PR_BYTES_PER_DWORD_LOG2',
           'PF_RDS', 'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE',
           'bad_certificate', 'TLS_EX_SESS_TICKET_MAC_LENGTH',
           'CKR_FUNCTION_CANCELED', 'SSLCipherSuiteInfoStr',
           '_PC_REC_INCR_XFER_SIZE', 'SHUT_WR', 'PRTRACE_NAME_MAX',
           'INADDR_ALLRTRS_GROUP', '_PATH_NSSWITCH_CONF',
           'IPPROTO_IPIP', 'SECMODModuleStr', 'PR_INTERVAL_MAX',
           'IP_PMTUDISC_PROBE', '_POSIX_THREAD_ATTR_STACKSIZE',
           '_SC_USER_GROUPS_R', 'SEC_OID_AVA_PSEUDONYM',
           'SEC_OID_PKIX_OCSP_NONCE', '_CS_POSIX_V7_LP64_OFF64_LIBS',
           'SEC_OID_PKIX_CPS_POINTER_QUALIFIER',
           'SSL_ERROR_BAD_CERT_DOMAIN', '__PDP_ENDIAN',
           'SEC_ERROR_MESSAGE_SEND_ABORTED',
           'SEC_ERROR_PKCS12_UNSUPPORTED_PBE_ALGORITHM', 'CKA_TOKEN',
           'CKM_XOR_BASE_AND_DATA', 'IPPROTO_FRAGMENT', 'PR_LOG_WARN',
           'PR_NETWORK_DOWN_ERROR', 'PR_TRUNCATE',
           'SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE', 'PR_IXGRP',
           'CKF_RESTORE_KEY_NOT_NEEDED', 'BYTES_PER_DWORD_LOG2',
           'SECWouldBlock', 'SECMOD_CAMELLIA_FLAG', 'SSLAppOpWrite',
           'WIFSTOPPED', 'u_int32_t', 'PR_VMAJOR', '_SC_2_UPE',
           'CK_SESSION_HANDLE', 'SEC_ERROR_BAD_NICKNAME',
           'CK_TOKEN_INFO_PTR', 'SEC_OID_AVA_DC', 'CKM_BATON_ECB128',
           'CK_FUNCTION_LIST_PTR_PTR', '_SYS_SELECT_H',
           '__isxdigit_l', 'CKM_JUNIPER_WRAP',
           '_POSIX_THREAD_ROBUST_PRIO_PROTECT', 'SO_SNDBUFFORCE',
           '_G_fpos64_t', 'NO_ADDRESS', 'IN_CLASSC_NET',
           '_ISOC95_SOURCE', 'CKF_ARRAY_ATTRIBUTE', 'ssl3CertNode',
           '_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS', '__compar_fn_t',
           'ssl_kea_fortezza', 'SSLSNISocketConfig',
           'CERTValParamOutType', 'PRMWaitClientData', 'PR_IWOTH',
           'CKO_SECRET_KEY', 'SEC_OID_X509_CRL_DIST_POINTS',
           'HT_FREE_ENTRY', 'CKF_UNWRAP', 'SEC_ERROR_INVALID_KEY',
           'CK_UTF8CHAR', 'AI_CANONNAME', 'CKK_CAMELLIA', 'kea_rsa',
           '__clock_t_defined', '__codecvt_ok', 'PK11AttrFlags',
           'PRSysInfo', '_SC_THREAD_SPORADIC_SERVER',
           'SEC_ERROR_REVOKED_CERTIFICATE', 'PR_BITS_PER_BYTE_LOG2',
           'CKM_SHA224_KEY_DERIVATION', 'PRIOVec', 'ssl_calg_rc2',
           'SSL_LOCK_RANK_SPEC', 'certValidityChooseB',
           'SEC_ERROR_OCSP_REQUEST_NEEDS_SIG', 'certValidityChooseA',
           'SEC_ASN1_BOOLEAN', '__int32_t', 'cipher_missing',
           'CKR_OPERATION_ACTIVE', 'XP_SEC_FORTEZZA_NO_CARD',
           'PR_BYTES_PER_DWORD', '_IO_EOF_SEEN',
           'SEC_OID_SECG_EC_SECT409K1', 'int_least64_t',
           'CKM_SHA512_RSA_PKCS_PSS', 'CKA_TRUST_CLIENT_AUTH',
           'SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME',
           'SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC',
           'CK_NOTIFICATION',
           'SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION',
           'SEC_ASN1_INNER', '_CS_XBS5_LP64_OFF64_LDFLAGS',
           'IPV6_XFRM_POLICY', 'PRThread', 'SEC_ASN1_OPTIONAL',
           '_SC_SIGNALS', 'PR_IpAddrV4Mapped', 'INADDR_NONE',
           'SEC_OID_SECG_EC_SECT233R1', 'PR_BITS_PER_BYTE',
           'LL_MAXINT', '_SC_LEVEL1_DCACHE_LINESIZE',
           'CKA_FLAGS_ONLY', 'SEC_OID_SECG_EC_SECP192K1',
           'PR_INSERT_LINK', 'CKM_MD2_HMAC', 'PK11MergeLogNode',
           'PR_IN_PROGRESS_ERROR', 'SEEK_END', 'linger',
           'PR_OUT_OF_MEMORY_ERROR', 'CKM_CAST5_CBC_PAD',
           '_STRUCT_TIMEVAL', 'N9PRNetAddr4DOT_54E',
           'CKM_X9_42_DH_DERIVE', 'SEC_ERROR_KRL_BAD_SIGNATURE',
           'cert_revocation_method_crl', 'CKM_SEED_ECB', 'FSSpec',
           'SESS_TICKET_KEY_NAME_PREFIX_LEN',
           'SEC_ERROR_REUSED_ISSUER_AND_SERIAL', 'int_fast16_t',
           'SSL_ENABLE_FDX', 'SSL_sni_type_total', 'IPPROTO_GRE',
           'SEC_OID_PKCS12_SECRET_BAG_ID', '_SC_SHRT_MAX', '_ISalnum',
           'SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE',
           'kea_dh_anon_export', 'CERTSubjectListStr',
           'SEC_ERROR_DECRYPTION_DISALLOWED', 'NETDB_SUCCESS',
           'uint_least64_t', 'CK_CMS_SIG_PARAMS',
           'crlEntryReasonPrivilegeWithdrawn', 'SSL_SOCKS',
           'SECMODListLock', 'IPPORT_USERRESERVED', '__USE_UNIX98',
           'SSL_ERROR_NO_RENEGOTIATION_ALERT', '_IOS_BIN', 'PF_ASH',
           '__gid_t', 'CKU_SO', 'PK11MergeLog', 'PR_USEC_PER_MSEC',
           'kea_rsa_fips', '_POSIX_SPIN_LOCKS',
           'CKM_WTLS_PRE_MASTER_KEY_GEN',
           'KU_KEY_AGREEMENT_OR_ENCIPHERMENT',
           '_CS_POSIX_V5_WIDTH_RESTRICTED_ENVS', 'CKO_NETSCAPE_CRL',
           '__daddr_t', 'SEC_ERROR_INCOMPATIBLE_PKCS11',
           'PR_FILE_IS_LOCKED_ERROR', 'export_restriction',
           '_SC_MULTI_PROCESS', 'SSL3MasterSecret',
           'SEC_OID_ANSIX962_EC_C2TNB359V1', '_POSIX_PRIORITIZED_IO',
           'IPPORT_FTP', 'CKO_KG_PARAMETERS', 'SSL_ERROR_END_OF_LIST',
           'crlEntryReasonCessationOfOperation',
           'SSL_SECURITY_STATUS_FORTEZZA', 'IP_MULTICAST_IF',
           'CKR_USER_TOO_MANY_TYPES', '__isascii_l',
           'CKF_SO_PIN_TO_BE_CHANGED', 'SCM_TIMESTAMPNS', '__isascii',
           'CKD_SHA1_KDF_ASN1', 'SECKEYKEAPublicKey', 'PR_FALSE',
           'ssl_sign_null', 'IPPORT_SYSTAT',
           'CRL_IMPORT_BYPASS_CHECKS', 'SEC_ASN1_CHOICE',
           'cert_po_max', 'N4wait4DOT_21E', 'INADDR_ANY',
           'certUsageSSLClient', 'BYTES_PER_WORD', 'MSG_PROXY',
           'PR_RDONLY', 'CK_RSA_PKCS_PSS_PARAMS_PTR',
           'CERTPublicKeyAndChallenge', 'pthread_once_t',
           'EAI_BADFLAGS', 'PR_GROUP_EMPTY_ERROR', 'cipher_null',
           'N8in6_addr4DOT_46E', '_PKCS11T_H_',
           'CKM_CAMELLIA_ECB_ENCRYPT_DATA', 'EAI_IDN_ENCODE',
           'CKR_WRAPPED_KEY_LEN_RANGE', 'PRReadFN', 'ssl_auth_ecdsa',
           'sockaddr', 'IPV6_JOIN_ANYCAST', 'nssILockCert',
           'IPPORT_LOGINSERVER', 'PR_IRWXO', 'SECKEYRSAPublicKeyStr',
           'XP_JAVA_CERT_NOT_EXISTS_ERROR',
           'SSL_ERROR_ILLEGAL_PARAMETER_ALERT', 'clock_t',
           'PR_SKIP_DOT', '_IO_FLAGS2_USER_WBUF', 'int64_t',
           'SEC_OID_X509_FRESHEST_CRL',
           '_POSIX_THREAD_ATTR_STACKADDR', 'SSL3RSAPreMasterSecret',
           'SEC_ERROR_REVOKED_CERTIFICATE_CRL', 'le64toh',
           'SSL_IS_SSL2_CIPHER', 'HT_FREE_VALUE', 'CKA_OBJECT_ID',
           '_XOPEN_UNIX', '__va_copy', 'kea_ecdh_ecdsa',
           '_SC_THREAD_ATTR_STACKSIZE', 'PK11CertListType',
           '_IO_MAGIC_MASK', 'certificateUsageSSLServer',
           'SEC_ERROR_JS_DEL_MOD_FAILURE', '_SC_2_VERSION',
           'cert_po_keyUsage', 'SSL_ERROR_RX_RECORD_TOO_LONG',
           '_POSIX_THREADS', 'SECKEYPublicKeyListNode',
           'CKR_TOKEN_WRITE_PROTECTED', 'ssl_calg_rc4',
           'CKM_EC_KEY_PAIR_GEN', 'IP_PMTUDISC_DO',
           'CERT_REV_M_CONTINUE_TESTING_ON_FRESH_INFO', 'FD_SETSIZE',
           'PRGetpeernameFN', '__codecvt_error',
           'CKT_NETSCAPE_MUST_VERIFY', 'ssl_calg_seed',
           'SSL3Plaintext', 'SEC_ERROR_UNKNOWN_SIGNER',
           '_SC_AIO_LISTIO_MAX', 'LL_ZERO', 'SEC_CERT_CLASS_EMAIL',
           'HOST_NOT_FOUND', 'SSL_ERROR_US_ONLY_SERVER', 'ssl3KEADef',
           'locale_t', 'IPPROTO_PIM', 'server_hello',
           '_POSIX_TRACE_INHERIT', 'PRNetAddr',
           'SEC_CERT_CLASS_SERVER', 'EXIT_FAILURE',
           'IPV6_IPSEC_POLICY', 'CKR_HOST_MEMORY',
           'SEC_OID_PKIX_REGCTRL_OLD_CERT_ID', 'CKO_NETSCAPE_SMIME',
           '_IOLBF', '_G_int32_t', 'CKM_IDEA_KEY_GEN',
           'PR_APPEND_LINK', '_CS_POSIX_V7_LP64_OFF64_LDFLAGS',
           'LL_IS_ZERO']
