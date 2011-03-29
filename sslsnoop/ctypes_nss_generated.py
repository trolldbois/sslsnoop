from ctypes import *
#STRING = c_char_p
from model import CString
STRING = CString

def htole16(x): return (x) # macro
def _G_FSTAT64(fd,buf): return __fxstat64 (_STAT_VER, fd, buf) # macro
SEC_OID_ANSIX962_EC_C2TNB431R1 = 241
def __warnattr(msg): return __attribute__((__warning__ (msg))) # macro
IPPROTO_PUP = 12
PR_LOG_ALWAYS = 1
SEC_ASN1_T61_STRING = 20 # Variable c_int '20'
SEC_ASN1_TELETEX_STRING = SEC_ASN1_T61_STRING # alias
SEC_OID_PKIX_REGCTRL_OLD_CERT_ID = 142
SEC_OID_SECG_EC_SECP256K1 = 219
def PR_LOG_TEST(module,level): return 0 # macro
# __INO_T_TYPE = __ULONGWORD_TYPE # alias
def __P(args): return args # macro
rsaPssKey = 7
SEC_OID_PKCS7 = 24
CKA_NSS_PKCS8_SALT = 3461563221L # Variable c_uint '-833404075u'
CKA_NETSCAPE_PKCS8_SALT = CKA_NSS_PKCS8_SALT # alias
SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE = 279
# def __WAIT_INT(status): return (*(int *) &(status)) # macro
PR_ACCESS_READ_OK = 3
SOCK_DGRAM = 2
SOCK_DGRAM = SOCK_DGRAM # alias
SEC_OID_ANSIX962_EC_PRIME256V1 = 208
SEC_OID_SECG_EC_SECP256R1 = SEC_OID_ANSIX962_EC_PRIME256V1 # alias
SEC_ASN1_Length = 1
certUsageEmailSigner = 4
SEC_OID_SECG_EC_SECP112R1 = 209
# DSSprivilege = DSSpriviledge # alias
# def IN6_IS_ADDR_MC_ORGLOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x8)) # macro
# def CERT_LIST_HEAD(l): return ((CERTCertListNode *)PR_LIST_HEAD(&l->list)) # macro
SECLessThan = -1
SEC_OID_ANSIX962_EC_PRIME239V2 = 206
CKM_NSS_AES_KEY_WRAP = 3461563217L # Variable c_uint '-833404079u'
CKM_NETSCAPE_AES_KEY_WRAP = CKM_NSS_AES_KEY_WRAP # alias
siGeneralizedTime = 12
PF_IUCV = 32 # Variable c_int '32'
AF_IUCV = PF_IUCV # alias
cert_pi_revocationFlags = 9
# def __ASMNAME2(prefix,cname): return __STRING (prefix) cname # macro
IPPROTO_SCTP = 132
IPPROTO_SCTP = IPPROTO_SCTP # alias
# NULL = __null # alias
# def PORT_ArenaNew(poolp,type): return (type*) PORT_ArenaAlloc(poolp, sizeof(type)) # macro
MSG_TRYHARD = 4
SEC_OID_NS_TYPE_URL = 51
SOCK_PACKET = 10
SOCK_PACKET = SOCK_PACKET # alias
SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION = 195
# def IN6_IS_ADDR_MC_NODELOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x1)) # macro
cert_pi_extendedKeyusage = 7
ssl_calg_des = 3
# def LL_AND(r,a,b): return ((r) = (a) & (b)) # macro
IPPROTO_MAX = 256
# def __isctype(c,type): return ((*__ctype_b_loc ())[(int) (c)] & (unsigned short int) type) # macro
MSG_CMSG_CLOEXEC = 1073741824
def htons(x): return __bswap_16 (x) # macro
SEC_OID_X509_INVALID_DATE = 96
PR_SEEK_CUR = 1
class PLArena(Structure):
    pass
PRUword = c_ulong
PLArena._fields_ = [
    ('next', POINTER(PLArena)),
    ('base', PRUword),
    ('limit', PRUword),
    ('avail', PRUword),
]
PRArena = PLArena # alias
SEC_OID_SHA384 = 192
PR_LOG_WARNING = 3
SCM_RIGHTS = 1
PR_BITS_PER_WORD = 32 # Variable c_int '32'
BITS_PER_WORD = PR_BITS_PER_WORD # alias
def PR_UINT32(x): return x ## U # macro
def __toascii_l(c,l): return ((l), __toascii (c)) # macro
cert_pi_useAIACertFetch = 12
SEC_OID_NS_CERT_EXT_ENTITY_LOGO = 72
SECEqual = 0
MSG_PEEK = 2
MSG_PEEK = MSG_PEEK # alias
# def PR_INIT_CLIST(_l): return PR_BEGIN_MACRO (_l)->next = (_l); (_l)->prev = (_l); PR_END_MACRO # macro
PR_BITS_PER_INT64 = 64 # Variable c_int '64'
BITS_PER_INT64 = PR_BITS_PER_INT64 # alias
def _G_ARGS(ARGLIST): return ARGLIST # macro
PR_StandardInput = 0
SEC_OID_TOTAL = 309
# PR_FinishArenaPool = PL_FinishArenaPool # alias
# _G_LSEEK64 = __lseek64 # alias
# PORT_Strpbrk = strpbrk # alias
certPackageCert = 1
SEC_OID_SECG_EC_SECT283K1 = 254
cert_pi_nbioAbort = 2
PF_TIPC = 30 # Variable c_int '30'
AF_TIPC = PF_TIPC # alias
CKA_NSS_MODULE_SPEC = 3461563240L # Variable c_uint '-833404056u'
CKA_NETSCAPE_MODULE_SPEC = CKA_NSS_MODULE_SPEC # alias
def be64toh(x): return __bswap_64 (x) # macro
IPPORT_DISCARD = 9
crlEntryReasonCessationOfOperation = 5
# def __u_intN_t(N,MODE): return typedef unsigned int u_int ##N ##_t __attribute__ ((__mode__ (MODE))) # macro
# PORT_Strchr = strchr # alias
SEC_OID_MISSI_DSS_OLD = 55
ssl_calg_null = 0
# def CERT_LIST_END(n,l): return (((void *)n) == ((void *)&l->list)) # macro
SEC_OID_PKCS9_UNSTRUCTURED_NAME = 32
# def __errordecl(name,msg): return extern void name (void) __attribute__((__error__ (msg))) # macro
__LITTLE_ENDIAN = 1234 # Variable c_int '1234'
__BYTE_ORDER = __LITTLE_ENDIAN # alias
BYTE_ORDER = __BYTE_ORDER # alias
SEC_OID_PKCS7_DATA = 25
SEC_OID_PKIX_REGINFO_CERT_REQUEST = 145
SEC_OID_X509_POLICY_MAPPINGS = 89
IPPROTO_UDP = 17
PR_BITS_PER_SHORT_LOG2 = 4 # Variable c_int '4'
BITS_PER_SHORT_LOG2 = PR_BITS_PER_SHORT_LOG2 # alias
SEC_OID_PKCS9_COUNTER_SIGNATURE = 36
# PR_HashTableRemove = PL_HashTableRemove # alias
SEC_OID_MD2 = 1
__uid_t = c_uint
_G_uid_t = __uid_t # alias
# def _ISbit(bit): return ((bit) < 8 ? ((1 << (bit)) << 8) : ((1 << (bit)) >> 8)) # macro
PR_BITS_PER_SHORT = 16 # Variable c_int '16'
BITS_PER_SHORT = PR_BITS_PER_SHORT # alias
# def PR_ASSERT(expr): return ((void) 0) # macro
SEC_OID_PKCS7_SIGNED_DATA = 26
IPPROTO_IGMP = 2
IPPROTO_IGMP = IPPROTO_IGMP # alias
IPPROTO_DCCP = 33
IPPROTO_DCCP = IPPROTO_DCCP # alias
PK11TokenPresentEvent = 1
IPPORT_FINGER = 79
SEC_OID_ANSIX962_EC_C2ONB239V4 = 235
PF_IRDA = 23 # Variable c_int '23'
AF_IRDA = PF_IRDA # alias
def __islower_l(c,l): return __isctype_l((c), _ISlower, (l)) # macro
def __iscntrl_l(c,l): return __isctype_l((c), _IScntrl, (l)) # macro
size_t = c_uint
_G_size_t = size_t # alias
_IO_size_t = _G_size_t # alias
def __isspace_l(c,l): return __isctype_l((c), _ISspace, (l)) # macro
# def SECKEY_ATTRIBUTES_CACHED(key): return (0 != (key->staticflags & SECKEY_Attributes_Cached)) # macro
def __WEXITSTATUS(status): return (((status) & 0xff00) >> 8) # macro
secCertTimeUndetermined = 3
certPackageNSCertSeq = 3
__FD_SETSIZE = 1024 # Variable c_int '1024'
FD_SETSIZE = __FD_SETSIZE # alias
certificateUsageAnyCA = 2048 # Variable c_int '2048'
certificateUsageHighest = certificateUsageAnyCA # alias
# def PL_ARENA_ALLOCATE(p,pool,nb): return PR_BEGIN_MACRO PLArena *_a = (pool)->current; PRUint32 _nb = PL_ARENA_ALIGN(pool, nb); PRUword _p = _a->avail; PRUword _q = _p + _nb; if (_q > _a->limit) _p = (PRUword)PL_ArenaAllocate(pool, _nb); else _a->avail = _q; p = (void *)_p; PL_ArenaCountAllocation(pool, nb); PR_END_MACRO # macro
# def CMSG_SPACE(len): return (CMSG_ALIGN (len) + CMSG_ALIGN (sizeof (struct cmsghdr))) # macro
SEC_OID_PKCS12_KEY_BAG_ID = 110
PF_ASH = 18 # Variable c_int '18'
AF_ASH = PF_ASH # alias
SEC_OID_ISO_SHA1_WITH_RSA_SIGNATURE = 301
PR_SHUTDOWN_SEND = 1
IPPORT_CMDSERVER = 514
SEC_OID_NS_TYPE_CERT_SEQUENCE = 53
SEC_OID_ANSIX962_EC_C2ONB191V4 = 229
PF_ECONET = 19 # Variable c_int '19'
AF_ECONET = PF_ECONET # alias
IPPROTO_TP = 29
IPPROTO_TP = IPPROTO_TP # alias
def __attribute_format_arg__(x): return __attribute__ ((__format_arg__ (x))) # macro
def PZ_WaitCondVar(v,t): return PR_WaitCondVar((v),(t)) # macro
SEC_OID_NS_TYPE_HTML = 52
PR_SockOpt_IpTypeOfService = 7
PR_ALIGN_OF_POINTER = 4 # Variable c_int '4'
ALIGN_OF_POINTER = PR_ALIGN_OF_POINTER # alias
nssILockList = 9
# def LL_D2L(l,d): return ((l) = (PRInt64)(d)) # macro
siUnsignedInteger = 10
crlEntryReasonPrivilegeWithdrawn = 9
PR_SockOpt_Nonblocking = 0
SEC_OID_CERT_RENEWAL_LOCATOR = 177
SEC_OID_NS_CERT_EXT_SSL_SERVER_NAME = 74
SEC_OID_AVA_POSTAL_CODE = 266
IPPROTO_IDP = 22
IPPROTO_IDP = IPPROTO_IDP # alias
IPPROTO_PIM = 103
IPPROTO_PIM = IPPROTO_PIM # alias
# PORT_Strcpy = strcpy # alias
CKO_NSS_NEWSLOT = 3461563221L # Variable c_uint '-833404075u'
CKO_NETSCAPE_NEWSLOT = CKO_NSS_NEWSLOT # alias
IPPORT_LOGINSERVER = 513
SEC_OID_AVA_GIVEN_NAME = 268
SEC_OID_DES_OFB = 11
ssl_sign_rsa = 1
def __W_STOPCODE(sig): return ((sig) << 8 | 0x7f) # macro
def le16toh(x): return (x) # macro
# def PL_ARENA_RELEASE(pool,mark): return PR_BEGIN_MACRO char *_m = (char *)(mark); PLArena *_a = (pool)->current; if (PR_UPTRDIFF(_m, _a->base) <= PR_UPTRDIFF(_a->avail, _a->base)) { _a->avail = (PRUword)PL_ARENA_ALIGN(pool, _m); PL_CLEAR_UNUSED(_a); PL_ArenaCountRetract(pool, _m); } else { PL_ArenaRelease(pool, _m); } PL_ArenaCountRelease(pool, _m); PR_END_MACRO # macro
# PR_ARENA_RELEASE = PL_ARENA_RELEASE # alias
PK11_DIS_NONE = 0
siUTF8String = 14
# __S32_TYPE = int # alias
# __DADDR_T_TYPE = __S32_TYPE # alias
def __PMT(args): return args # macro
def htobe16(x): return __bswap_16 (x) # macro
SOCK_SEQPACKET = 5
ssl_kea_rsa = 1
# def LL_L2I(i,l): return ((i) = (PRInt32)(l)) # macro
SOCK_STREAM = 1
ssl_calg_aes = 7
SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH = 147
PR_StandardError = 2
# def PR_INSERT_BEFORE(_e,_l): return PR_BEGIN_MACRO (_e)->next = (_l); (_e)->prev = (_l)->prev; (_l)->prev->next = (_e); (_l)->prev = (_e); PR_END_MACRO # macro
cert_revocation_method_ocsp = 1
IPPROTO_GRE = 47
IPPROTO_GRE = IPPROTO_GRE # alias
rsaKey = 1
SEC_OID_PKCS9_MESSAGE_DIGEST = 34
crlEntryReasoncertificatedHold = 6
PR_SKIP_HIDDEN = 4
# def IN6_IS_ADDR_MC_GLOBAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0xe)) # macro
# PR_HashTableRawRemove = PL_HashTableRawRemove # alias
# __UID_T_TYPE = __U32_TYPE # alias
kt_rsa = ssl_kea_rsa # alias
SEC_OID_X509_AUTH_KEY_ID = 91
# SET_BIT = PR_SET_BIT # alias
# _IO_HAVE_ST_BLKSIZE = _G_HAVE_ST_BLKSIZE # alias
SOCK_NONBLOCK = 2048
def CERT_LIST_EMPTY(l): return CERT_LIST_END(CERT_LIST_HEAD(l), l) # macro
IPPORT_TFTP = 69
SEC_OID_PKCS9_UNSTRUCTURED_ADDRESS = 38
CKF_EC_F_P = 1048576 # Variable c_int '1048576'
CKF_EC_FP = CKF_EC_F_P # alias
SEC_OID_ANSIX962_EC_C2ONB239V5 = 236
SEC_OID_X942_DIFFIE_HELMAN_KEY = 174
PK11_DIS_TOKEN_VERIFY_FAILED = 3
nssILockRefLock = 3
# def LL_ISHL(r,a,b): return ((r) = (PRInt64)(a) << (b)) # macro
# def PR_IMPLEMENT(__type): return PR_VISIBILITY_DEFAULT __type # macro
# PR_PUBLIC_API = PR_IMPLEMENT # alias
MSG_TRUNC = 32
MSG_TRUNC = MSG_TRUNC # alias
SEC_OID_PKCS7_SIGNED_ENVELOPED_DATA = 28
ssl_auth_kea = 3
CKA_NSS_PASSWORD_CHECK = 3461563222L # Variable c_uint '-833404074u'
CKA_NETSCAPE_PASSWORD_CHECK = CKA_NSS_PASSWORD_CHECK # alias
nssILockSession = 1
# def IP_MSFILTER_SIZE(numsrc): return (sizeof (struct ip_msfilter) - sizeof (struct in_addr) + (numsrc) * sizeof (struct in_addr)) # macro
__NFDBITS = 32 # Variable c_int '32'
NFDBITS = __NFDBITS # alias
def __ASMNAME(cname): return __ASMNAME2 (__USER_LABEL_PREFIX__, cname) # macro
SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST = 275
SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID = 163
SEC_OID_SECG_EC_SECT131R2 = 245
MSG_DONTROUTE = 4
MSG_DONTROUTE = MSG_DONTROUTE # alias
PR_BYTES_PER_DWORD = 8 # Variable c_int '8'
BYTES_PER_DWORD = PR_BYTES_PER_DWORD # alias
__codecvt_error = 2
certUsageProtectedObjectSigner = 9
SOCK_NONBLOCK = SOCK_NONBLOCK # alias
ssl_compression_null = 0
PF_INET = 2 # Variable c_int '2'
AF_INET = PF_INET # alias
PF_AX25 = 3 # Variable c_int '3'
AF_AX25 = PF_AX25 # alias
SEC_OID_X509_ANY_POLICY = 303
# def __FD_ZERO(fdsp): return do { int __d0, __d1; __asm__ __volatile__ ("cld; rep; " __FD_ZERO_STOS : "=c" (__d0), "=D" (__d1) : "a" (0), "0" (sizeof (fd_set) / sizeof (__fd_mask)), "1" (&__FDS_BITS (fdsp)[0]) : "memory"); } while (0) # macro
# def PORT_New(type): return (type*)PORT_Alloc(sizeof(type)) # macro
PR_SockOpt_Broadcast = 15
IPPROTO_ENCAP = 98
def PZ_Lock(k): return PR_Lock((k)) # macro
certRegisterID = 9
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC = 117
PR_BYTES_PER_DOUBLE = 8 # Variable c_int '8'
BYTES_PER_DOUBLE = PR_BYTES_PER_DOUBLE # alias
def SEC_ASN1_GET(x): return x # macro
MSG_ERRQUEUE = 8192
MSG_ERRQUEUE = MSG_ERRQUEUE # alias
# SSL_IMPORT = extern # alias
def __WIFEXITED(status): return (__WTERMSIG(status) == 0) # macro
IPPORT_SMTP = 25
PR_LOG_MAX = 4
SEC_OID_RC2_CBC = 5
CKO_NSS_DELSLOT = 3461563222L # Variable c_uint '-833404074u'
CKO_NETSCAPE_DELSLOT = CKO_NSS_DELSLOT # alias
IPPROTO_UDPLITE = 136
IPPROTO_UDPLITE = IPPROTO_UDPLITE # alias
SOCK_CLOEXEC = 524288
SOCK_CLOEXEC = SOCK_CLOEXEC # alias
SCM_CREDENTIALS = 2
SCM_CREDENTIALS = SCM_CREDENTIALS # alias
SEC_OID_NS_CERT_EXT_LOST_PASSWORD_URL = 76
PR_ACCESS_WRITE_OK = 2
SEC_OID_ANSIX962_EC_C2PNB176V1 = 225
SEC_OID_AVA_INITIALS = 269
CERT_N2A_READABLE = 0
# def PR_REMOVE_AND_INIT_LINK(_e): return PR_BEGIN_MACRO (_e)->prev->next = (_e)->next; (_e)->next->prev = (_e)->prev; (_e)->next = (_e); (_e)->prev = (_e); PR_END_MACRO # macro
SEC_OID_PKIX_OCSP_BASIC_RESPONSE = 131
IPPROTO_FRAGMENT = 44
# stdout = stdout # alias
# def CMSG_DATA(cmsg): return ((cmsg)->__cmsg_data) # macro
nssILockAttribute = 13
# def __tobody(c,f,a,args): return (__extension__ ({ int __res; if (sizeof (c) > 1) { if (__builtin_constant_p (c)) { int __c = (c); __res = __c < -128 || __c > 255 ? __c : (a)[__c]; } else __res = f args; } else __res = (a)[(int) (c)]; __res; })) # macro
SEC_OID_DES_MAC = 13
dsaKey = 2
# explicit = expl # alias
ssl_server_name_xtn = 0
SEC_OID_EXT_KEY_USAGE_CODE_SIGN = 148
SEC_OID_ANSIX962_EC_C2PNB163V3 = 224
__off_t = c_long
_G_off_t = __off_t # alias
SEC_OID_EXT_KEY_USAGE_SERVER_AUTH = 146
SEC_OID_AVA_DC = 48
__u_quad_t = c_ulonglong
__UQUAD_TYPE = __u_quad_t # alias
__FSBLKCNT64_T_TYPE = __UQUAD_TYPE # alias
# def __NTH(fct): return fct throw () # macro
CKA_NSS_PQG_H = 3461563238L # Variable c_uint '-833404058u'
CKA_NETSCAPE_PQG_H = CKA_NSS_PQG_H # alias
SEC_OID_CMS_RC2_KEY_WRAP = 181
# def LL_MOD(r,a,b): return ((r) = (a) % (b)) # macro
# PR_ArenaRelease = PL_ArenaRelease # alias
SEC_OID_NS_CERT_EXT_SCOPE_OF_USE = 178
__quad_t = c_longlong
__off64_t = __quad_t
_G_off64_t = __off64_t # alias
_IO_off64_t = _G_off64_t # alias
# def IN6_ARE_ADDR_EQUAL(a,b): return ((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0]) && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1]) && (((__const uint32_t *) (a))[2] == ((__const uint32_t *) (b))[2]) && (((__const uint32_t *) (a))[3] == ((__const uint32_t *) (b))[3])) # macro
SEC_OID_X500_RSA_ENCRYPTION = 97
PK11CertListRootUnique = 2
# __MODE_T_TYPE = __U32_TYPE # alias
SEC_OID_CAMELLIA_128_CBC = 288
SEC_OID_SECG_EC_SECP224K1 = 217
SEC_OID_PKCS9_SMIME_CAPABILITIES = 40
crlEntryReasonRemoveFromCRL = 8
# PR_InitArenaPool = PL_InitArenaPool # alias
ssl_calg_rc4 = 1
# def CMSG_FIRSTHDR(mhdr): return ((size_t) (mhdr)->msg_controllen >= sizeof (struct cmsghdr) ? (struct cmsghdr *) (mhdr)->msg_control : (struct cmsghdr *) 0) # macro
SEC_OID_AES_256_ECB = 187
def PR_APPEND_LINK(_e,_l): return PR_INSERT_BEFORE(_e,_l) # macro
SEC_OID_PKCS7_ENCRYPTED_DATA = 30
certUsageSSLServer = 1
certUsageVerifyCA = 8
SEC_OID_PKCS5_PBKDF2 = 291
PF_PHONET = 35 # Variable c_int '35'
AF_PHONET = PF_PHONET # alias
SEC_OID_ANSIX962_EC_PRIME239V1 = 205
def FD_SET(fd,fdsetp): return __FD_SET (fd, fdsetp) # macro
MSG_PROXY = 16
SEC_OID_ANSIX962_EC_PRIME192V1 = 202
# def LL_NEG(r,a): return ((r) = -(a)) # macro
SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_40_BIT_RC4 = 121
certUsageSSLCA = 3
# def __exctype(name): return extern int name (int) __THROW # macro
__U64_TYPE = __u_quad_t # alias
SEC_OID_PKCS1_MGF1 = 305
ssl_calg_seed = 9
MSG_CMSG_CLOEXEC = MSG_CMSG_CLOEXEC # alias
SEC_OID_MISSI_DSS = 57
IPPORT_RJE = 77
SEC_OID_SHA256 = 191
PR_ALIGN_OF_INT = 4 # Variable c_int '4'
ALIGN_OF_INT = PR_ALIGN_OF_INT # alias
# def LL_F2L(l,f): return ((l) = (PRInt64)(f)) # macro
PR_LOG_NOTICE = 4
SOCK_DCCP = 6
IPPORT_FTP = 21
SEC_OID_NETSCAPE_RECOVERY_REQUEST = 176
# def __WIFSIGNALED(status): return (((signed char) (((status) & 0x7f) + 1) >> 1) > 0) # macro
# def PR_CLIST_IS_EMPTY(_l): return ((_l)->next == (_l)) # macro
def IN_CLASSC(a): return ((((in_addr_t)(a)) & 0xe0000000) == 0xc0000000) # macro
MSG_RST = 4096
SEC_OID_SECG_EC_SECT113R2 = 243
PRUint32 = c_uint
PLHashNumber = PRUint32
PRHashNumber = PLHashNumber # alias
generalName = 1
SEC_OID_AES_256_CBC = 188
# def __REDIRECT_NTH(name,proto,alias): return name proto __THROW __asm__ (__ASMNAME (#alias)) # macro
# PORT_Strcat = strcat # alias
# def SEC_ASN1_CHOOSER_IMPLEMENT(x): return const SEC_ASN1Template * NSS_Get_ ##x(void * arg, PRBool enc) { return x; } # macro
SEC_OID_NS_KEY_USAGE_GOVT_APPROVED = 78
IPPORT_MTP = 57
# def PR_IMPLEMENT_DATA(__type): return PR_VISIBILITY_DEFAULT __type # macro
INADDR_LOOPBACK = 2130706433L # Variable c_uint '2130706433u'
PR_INADDR_LOOPBACK = INADDR_LOOPBACK # alias
PR_TRANSMITFILE_KEEP_OPEN = 0
# def PORT_ZNewArray(type,num): return (type*) PORT_ZAlloc (sizeof(type)*(num)) # macro
IPPROTO_ESP = 50
IPPROTO_ESP = IPPROTO_ESP # alias
SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT = 149
IPPROTO_IPIP = 4
IPPROTO_IPIP = IPPROTO_IPIP # alias
IPPORT_SYSTAT = 11
nssILockRWLock = 15
certValidityChooseA = 3
SO_TIMESTAMP = 29 # Variable c_int '29'
SCM_TIMESTAMP = SO_TIMESTAMP # alias
PR_BITS_PER_FLOAT = 32 # Variable c_int '32'
BITS_PER_FLOAT = PR_BITS_PER_FLOAT # alias
PF_KEY = 15 # Variable c_int '15'
AF_KEY = PF_KEY # alias
SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE = 15
PR_FILE_FILE = 1
SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE = 278
SEC_OID_SECG_EC_SECP160R2 = 215
SHUT_RD = 0
__pid_t = c_int
_G_pid_t = __pid_t # alias
def _IO_peekc(_fp): return _IO_peekc_unlocked (_fp) # macro
SEC_OID_X509_KEY_USAGE = 81
SEC_OID_PKCS12_KEY_USAGE = SEC_OID_X509_KEY_USAGE # alias
# def LL_SHR(r,a,b): return ((r) = (PRInt64)(a) >> (b)) # macro
trustSSL = 0
IPPROTO_TCP = 6
INVALID_CERT_EXTENSION = 0
SEC_OID_RFC1274_MAIL = 99
IPPROTO_FRAGMENT = IPPROTO_FRAGMENT # alias
# PR_ArenaCountRelease = PL_ArenaCountRelease # alias
# def IN6_IS_ADDR_MC_LINKLOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x2)) # macro
SEC_OID_PKIX_REGCTRL_REGTOKEN = 138
# PORT_Strcasecmp = PL_strcasecmp # alias
SEC_OID_ANSIX962_EC_C2TNB191V1 = 226
PF_LOCAL = 1 # Variable c_int '1'
AF_LOCAL = PF_LOCAL # alias
ssl_kea_ecdh = 4
kt_ecdh = ssl_kea_ecdh # alias
SEC_OID_SECG_EC_SECP128R2 = 212
# def PR_EXPORT_DATA(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
trustObjectSigning = 2
SEC_OID_CMS_3DES_KEY_WRAP = 180
cert_pi_certStores = 10
SEC_OID_X509_REASON_CODE = 95
SEC_OID_CAMELLIA_256_CBC = 290
SEC_OID_NETSCAPE_AOLSCREENNAME = 260
MSG_SYN = 1024
MSG_SYN = MSG_SYN # alias
def WIFSIGNALED(status): return __WIFSIGNALED (__WAIT_INT (status)) # macro
# _LIBUTIL_H_ = _LIBUTIL_H__Util # alias
# def PL_ARENA_DESTROY(pool,a,pnext): return PR_BEGIN_MACRO PL_COUNT_ARENA(pool,--); if ((pool)->current == (a)) (pool)->current = &(pool)->first; *(pnext) = (a)->next; PL_CLEAR_ARENA(a); free(a); (a) = 0; PR_END_MACRO # macro
PK11TokenNotRemovable = 0
PF_NETROM = 6 # Variable c_int '6'
AF_NETROM = PF_NETROM # alias
class _G_fpos_t(Structure):
    pass
class __mbstate_t(Structure):
    pass
class N11__mbstate_t4DOT_42E(Union):
    pass
N11__mbstate_t4DOT_42E._fields_ = [
    ('__wch', c_uint),
    ('__wchb', c_char * 4),
]
__mbstate_t._fields_ = [
    ('__count', c_int),
    ('__value', N11__mbstate_t4DOT_42E),
]
_G_fpos_t._fields_ = [
    ('__pos', __off_t),
    ('__state', __mbstate_t),
]
_IO_pos_t = _G_fpos_t # alias
SEC_OID_PKCS12_V1_CRL_BAG_ID = 165
SEC_OID_AES_192_ECB = 185
__codecvt_ok = 0
CKT_NSS_VALID = 3461563226L # Variable c_uint '-833404070u'
CKT_NETSCAPE_VALID = CKT_NSS_VALID # alias
PF_UNIX = PF_LOCAL # alias
AF_UNIX = PF_UNIX # alias
PR_AF_LOCAL = AF_UNIX # alias
SEC_OID_AVA_TITLE = 264
def __isgraph_l(c,l): return __isctype_l((c), _ISgraph, (l)) # macro
# __BLKCNT_T_TYPE = __SLONGWORD_TYPE # alias
def __GNUC_PREREQ(maj,min): return ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min)) # macro
nssILockObject = 2
SEC_OID_ANSIX9_DSA_SIGNATURE = 124
SEC_ASN1_Contents = 2
SEC_OID_PKCS12_SDSI_CERT_BAG = 114
MSG_DONTWAIT = 64
def PR_INT32(x): return x # macro
PR_SockOpt_RecvBufferSize = 4
SEC_OID_PKCS12_SIGNATURE_IDS = 107
siUTCTime = 11
def PZ_Unlock(k): return PR_Unlock((k)) # macro
PR_SockOpt_NoDelay = 13
PR_LibSpec_PathnameU = 3
SEC_OID_X509_POLICY_CONSTRAINTS = 90
__SQUAD_TYPE = __quad_t # alias
__OFF64_T_TYPE = __SQUAD_TYPE # alias
SEC_OID_NS_CERT_EXT_BASE_URL = 64
cert_pi_certList = 3
# PORT_Strncat = strncat # alias
CKO_NSS_CRL = 3461563217L # Variable c_uint '-833404079u'
CKO_NETSCAPE_CRL = CKO_NSS_CRL # alias
ssl_hmac_sha = 4
SOCK_DCCP = SOCK_DCCP # alias
SEC_OID_PKIX_CPS_POINTER_QUALIFIER = 128
PR_BITS_PER_BYTE_LOG2 = 3 # Variable c_int '3'
BITS_PER_BYTE_LOG2 = PR_BITS_PER_BYTE_LOG2 # alias
# PR_CompareValues = PL_CompareValues # alias
CKT_NSS_TRUSTED_DELEGATOR = 3461563218L # Variable c_uint '-833404078u'
CKT_NETSCAPE_TRUSTED_DELEGATOR = CKT_NSS_TRUSTED_DELEGATOR # alias
def PORT_Strlen(s): return strlen(s) # macro
PR_SockOpt_AddMember = 8
SEC_OID_EXT_KEY_USAGE_TIME_STAMP = 150
# _G_OPEN64 = __open64 # alias
siBuffer = 0
ssl_sign_null = 0
SEC_OID_NS_CERT_EXT_CERT_TYPE = 63
SEC_OID_SECG_EC_SECP224R1 = 218
SEC_OID_PKCS9_CHALLENGE_PASSWORD = 37
# def PL_ARENA_GROW(p,pool,size,incr): return PR_BEGIN_MACRO PLArena *_a = (pool)->current; PRUint32 _incr = PL_ARENA_ALIGN(pool, incr); PRUword _p = _a->avail; PRUword _q = _p + _incr; if (_p == (PRUword)(p) + PL_ARENA_ALIGN(pool, size) && _q <= _a->limit) { _a->avail = _q; PL_ArenaCountInplaceGrowth(pool, size, incr); } else { p = PL_ArenaGrow(pool, p, size, incr); } PL_ArenaCountGrowth(pool, size, incr); PR_END_MACRO # macro
# PR_ARENA_GROW = PL_ARENA_GROW # alias
cert_pi_policyFlags = 5
PK11CertListUnique = 0
SSL_sni_host_name = 0
SEC_OID_SECG_EC_SECT571K1 = 258
def htole64(x): return (x) # macro
nssILockSelfServ = 17
SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION = 17
def LL_GE_ZERO(a): return ((a) >= 0) # macro
# PR_HashTableRawLookup = PL_HashTableRawLookup # alias
CKT_NSS_TRUST_UNKNOWN = 3461563221L # Variable c_uint '-833404075u'
CKT_NETSCAPE_TRUST_UNKNOWN = CKT_NSS_TRUST_UNKNOWN # alias
# PR_ArenaGrow = PL_ArenaGrow # alias
def isdigit_l(c,l): return __isdigit_l ((c), (l)) # macro
def LL_NE(a,b): return ((a) != (b)) # macro
# def PR_MIN(x,y): return ((x)<(y)?(x):(y)) # macro
SEC_ASN1_EndOfContents = 3
# def __bswap_32(x): return (__extension__ ({ register unsigned int __v, __x = (x); if (__builtin_constant_p (__x)) __v = __bswap_constant_32 (__x); else __asm__ ("bswap %0" : "=r" (__v) : "0" (__x)); __v; })) # macro
siAsciiNameString = 7
PF_X25 = 9 # Variable c_int '9'
AF_X25 = PF_X25 # alias
IPPROTO_IPV6 = 41
def htobe64(x): return __bswap_64 (x) # macro
PK11_TypeGeneric = 0
def __WIFSTOPPED(status): return (((status) & 0xff) == 0x7f) # macro
IPPROTO_AH = 51
SEC_OID_PKCS12_V1_SECRET_BAG_ID = 166
def IN_CLASSA(a): return ((((in_addr_t)(a)) & 0x80000000) == 0) # macro
SEC_OID_AVA_STATE_OR_PROVINCE = 44
# def LL_UI2L(l,ui): return ((l) = (PRInt64)(ui)) # macro
# def PR_LIST_HEAD(_l): return (_l)->next # macro
# WORDS_PER_DWORD_LOG2 = PR_WORDS_PER_DWORD_LOG2 # alias
cert_pi_end = 0
__S64_TYPE = __quad_t # alias
PF_PACKET = 17 # Variable c_int '17'
AF_PACKET = PF_PACKET # alias
# PR_ARENA_DESTROY = PL_ARENA_DESTROY # alias
NO_DATA = 4 # Variable c_int '4'
NO_ADDRESS = NO_DATA # alias
SEC_OID_SEED_CBC = 302
SOCK_RAW = 3
IPPORT_TTYLINK = 87
MSG_OOB = 1
MSG_OOB = MSG_OOB # alias
_IO_off_t = _G_off_t # alias
SEC_OID_PKIX_REGINFO_UTF8_PAIRS = 144
crlEntryReasonKeyCompromise = 1
certUsageAnyCA = 11
certX400Address = 4
ssl_kea_size = 5
# PORT_Memcpy = memcpy # alias
def __attribute_format_strfmon__(a,b): return __attribute__ ((__format__ (__strfmon__, a, b))) # macro
PF_ATMSVC = 20 # Variable c_int '20'
AF_ATMSVC = PF_ATMSVC # alias
certEDIPartyName = 6
PR_DESC_LAYERED = 4
SEC_OID_PKCS12_PBE_IDS = 106
MSG_WAITALL = 256
IPPORT_ROUTESERVER = 520
# PRArenaStats = PLArenaStats # alias
PR_FILE_OTHER = 3
PK11_OriginGenerated = 2
SECWouldBlock = -2
SEC_OID_RC5_CBC_PAD = 8
# def IN6_IS_ADDR_MULTICAST(a): return (((__const uint8_t *) (a))[0] == 0xff) # macro
CKO_NSS_BUILTIN_ROOT_LIST = 3461563220L # Variable c_uint '-833404076u'
CKO_NETSCAPE_BUILTIN_ROOT_LIST = CKO_NSS_BUILTIN_ROOT_LIST # alias
# KEAprivilege = KEApriviledge # alias
def offsetof(TYPE,MEMBER): return __builtin_offsetof (TYPE, MEMBER) # macro
PR_SockOpt_Reuseaddr = 2
def isascii_l(c,l): return __isascii_l ((c), (l)) # macro
def PZ_DestroyMonitor(m): return PR_DestroyMonitor((m)) # macro
IPPROTO_ICMPV6 = 58
IPPROTO_ICMPV6 = IPPROTO_ICMPV6 # alias
SEC_OID_SHA1 = 4
SEC_OID_PKCS12_V1_CERT_BAG_ID = 164
ssl_mac_md5 = 1
SHUT_WR = 1
SHUT_WR = SHUT_WR # alias
def __GLIBC_PREREQ(maj,min): return ((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min)) # macro
SEC_OID_OCSP_RESPONDER = 151
# __FSFILCNT_T_TYPE = __ULONGWORD_TYPE # alias
# PR_ArenaCountAllocation = PL_ArenaCountAllocation # alias
PR_SockOpt_SendBufferSize = 5
def toascii_l(c,l): return __toascii_l ((c), (l)) # macro
SEC_OID_X509_PRIVATE_KEY_USAGE_PERIOD = 82
# SCM_SRCRT = IPV6_RXSRCRT # alias
PR_BITS_PER_LONG = 32 # Variable c_int '32'
BITS_PER_LONG = PR_BITS_PER_LONG # alias
SEC_OID_PKCS1_SHA224_WITH_RSA_ENCRYPTION = 308
SEC_OID_PKCS12_BAG_IDS = 103
def __isalnum_l(c,l): return __isctype_l((c), _ISalnum, (l)) # macro
trustTypeNone = 3
PR_BYTES_PER_WORD_LOG2 = 2 # Variable c_int '2'
BYTES_PER_WORD_LOG2 = PR_BYTES_PER_WORD_LOG2 # alias
nssILockLast = 19
certValidityUndetermined = 0
def htobe32(x): return __bswap_32 (x) # macro
SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION = 19
def major(dev): return gnu_dev_major (dev) # macro
# def SECKEY_HAS_ATTRIBUTE_SET(key,attribute): return (0 != (key->staticflags & SECKEY_Attributes_Cached)) ? (0 != (key->staticflags & SECKEY_ ##attribute)) : PK11_HasAttributeSet(key->pkcs11Slot,key->pkcs11ID,attribute) # macro
SEC_OID_PKIX_REGCTRL_PROTOCOL_ENC_KEY = 143
def makedev(maj,min): return gnu_dev_makedev (maj, min) # macro
PF_IEEE802154 = 36 # Variable c_int '36'
AF_IEEE802154 = PF_IEEE802154 # alias
# PORT_Memmove = memmove # alias
SEC_OID_X509_ISSUING_DISTRIBUTION_POINT = 283
SEC_OID_AVA_STREET_ADDRESS = 263
MSG_PROXY = MSG_PROXY # alias
# PR_CompactArenaPool = PL_CompactArenaPool # alias
SEC_OID_SECG_EC_SECT113R1 = 242
IP_ORIGDSTADDR = 20 # Variable c_int '20'
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR # alias
CKA_NSS_SMIME_TIMESTAMP = 3461563220L # Variable c_uint '-833404076u'
CKA_NETSCAPE_SMIME_TIMESTAMP = CKA_NSS_SMIME_TIMESTAMP # alias
SOCK_STREAM = SOCK_STREAM # alias
ssl_calg_idea = 5
PK11_DIS_USER_SELECTED = 1
_G_BUFSIZ = 8192 # Variable c_int '8192'
_IO_BUFSIZ = _G_BUFSIZ # alias
PR_BITS_PER_LONG_LOG2 = 5 # Variable c_int '5'
BITS_PER_LONG_LOG2 = PR_BITS_PER_LONG_LOG2 # alias
SEC_OID_PKCS12_V1_SAFE_CONTENTS_BAG_ID = 167
SEC_OID_PKIX_OCSP_SERVICE_LOCATOR = 137
cert_po_max = 9
IPPROTO_NONE = 59
SEC_OID_HMAC_SHA1 = 294
def __isdigit_l(c,l): return __isctype_l((c), _ISdigit, (l)) # macro
SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME = 46
# def LL_CMP(a,op,b): return ((PRInt64)(a) op (PRInt64)(b)) # macro
PR_SKIP_NONE = 0
siBMPString = 15
UNSUPPORTED_CERT_EXTENSION = 1
_ISupper = 256
SEC_OID_PKCS12_CERT_AND_CRL_BAG_ID = 111
SEC_OID_ANSIX962_EC_C2TNB239V1 = 232
# def SECKEY_ATTRIBUTE_VALUE(key,attribute): return (0 != (key->staticflags & SECKEY_ ##attribute)) # macro
def isalpha_l(c,l): return __isalpha_l ((c), (l)) # macro
PR_SKIP_DOT_DOT = 2
IPPROTO_IPV6 = IPPROTO_IPV6 # alias
# def PL_CLEAR_UNUSED_PATTERN(a,pattern): return (PR_ASSERT((a)->avail <= (a)->limit), memset((void*)(a)->avail, (pattern), (a)->limit - (a)->avail)) # macro
nssILockCertDB = 5
IPPROTO_TCP = IPPROTO_TCP # alias
SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE = 201
def be16toh(x): return __bswap_16 (x) # macro
def isblank_l(c,l): return __isblank_l ((c), (l)) # macro
SEC_OID_NS_CERT_EXT_CA_CRL_URL = 67
# def _IO_PENDING_OUTPUT_COUNT(_fp): return ((_fp)->_IO_write_ptr - (_fp)->_IO_write_base) # macro
IPV6_HOPOPTS = 54 # Variable c_int '54'
IPV6_RXHOPOPTS = IPV6_HOPOPTS # alias
CKT_NSS_TRUSTED = 3461563217L # Variable c_uint '-833404079u'
CKT_NETSCAPE_TRUSTED = CKT_NSS_TRUSTED # alias
SEC_OID_AES_192_KEY_WRAP = 198
SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST = 125
# PR_NewHashTable = PL_NewHashTable # alias
CKT_NSS_VALID_DELEGATOR = 3461563227L # Variable c_uint '-833404069u'
CKT_NETSCAPE_VALID_DELEGATOR = CKT_NSS_VALID_DELEGATOR # alias
def __isalpha_l(c,l): return __isctype_l((c), _ISalpha, (l)) # macro
SEC_OID_SECG_EC_SECT571R1 = 259
SEC_OID_NETSCAPE_SMIME_KEA = 152
def __WCOREDUMP(status): return ((status) & __WCOREFLAG) # macro
PF_SECURITY = 14 # Variable c_int '14'
AF_SECURITY = PF_SECURITY # alias
ssl_sign_ecdsa = 3
CKA_NSS_KRL = 3461563224L # Variable c_uint '-833404072u'
CKA_NETSCAPE_KRL = CKA_NSS_KRL # alias
SEC_OID_AES_128_CBC = 184
IPPORT_EFSSERVER = 520
PR_FAILURE = -1
siAsciiString = 8
SEC_OID_X509_ISSUER_ALT_NAME = 84
SEC_OID_X509_INHIBIT_ANY_POLICY = 286
SEC_OID_SHA512 = 193
SEC_OID_BOGUS_KEY_USAGE = 173
SEC_OID_SECG_EC_SECP384R1 = 220
PR_LOG_ERROR = 2
PR_ALIGN_OF_LONG = 4 # Variable c_int '4'
ALIGN_OF_LONG = PR_ALIGN_OF_LONG # alias
SEC_OID_SECG_EC_SECT283R1 = 255
ssl_session_ticket_xtn = 35
# def __exctype_l(name): return extern int name (int, __locale_t) __THROW # macro
def PZ_NotifyAll(m): return PR_Notify((m)) # macro
# SEC_OID_SHA = SEC_OID_MISS_DSS # alias
SEC_OID_MISSI_ALT_KEA = 59
# _G_wint_t = wint_t # alias
SEC_OID_PKCS12_PKCS8_SHROUDED_KEY_BAG_ID = 161
SEC_OID_PKCS9_X509_CRL = 170
SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC = 21
def __LONG_LONG_PAIR(HI,LO): return LO, HI # macro
SIGEV_THREAD_ID = 4
IPPROTO_COMP = 108
IPPROTO_COMP = IPPROTO_COMP # alias
# def PR_EXPORT(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
secCertTimeExpired = 1
PK11_OriginFortezzaHack = 3
def PR_LOG_DEFINE(_name): return NULL # macro
def ispunct_l(c,l): return __ispunct_l ((c), (l)) # macro
PF_APPLETALK = 5 # Variable c_int '5'
AF_APPLETALK = PF_APPLETALK # alias
SEC_OID_PKCS9_X509_CERT = 168
SEC_OID_SECG_EC_SECP128R1 = 211
def __FDELT(d): return ((d) / __NFDBITS) # macro
secCertTimeValid = 0
__RLIM64_T_TYPE = __UQUAD_TYPE # alias
PF_NETLINK = 16 # Variable c_int '16'
AF_NETLINK = PF_NETLINK # alias
class _G_fpos64_t(Structure):
    pass
_G_fpos64_t._pack_ = 4
_G_fpos64_t._fields_ = [
    ('__pos', __off64_t),
    ('__state', __mbstate_t),
]
_IO_fpos64_t = _G_fpos64_t # alias
SEC_OID_PKIX_TIMESTAMPING = 299
# def PORT_Atoi(buff): return (int)strtol(buff, NULL, 10) # macro
PRIntn = c_int
PLHashComparator = CFUNCTYPE(PRIntn, c_void_p, c_void_p)
PRHashComparator = PLHashComparator # alias
SEC_OID_HMAC_SHA256 = 296
def ntohs(x): return __bswap_16 (x) # macro
# def __isctype_l(c,type,locale): return ((locale)->__ctype_b[(int) (c)] & (unsigned short int) type) # macro
PR_ALIGN_OF_FLOAT = 4 # Variable c_int '4'
ALIGN_OF_FLOAT = PR_ALIGN_OF_FLOAT # alias
cert_po_nbioContext = 1
# def LL_L2D(d,l): return ((d) = (PRFloat64)(l)) # macro
# __SWBLK_T_TYPE = __SLONGWORD_TYPE # alias
SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE = 190
crlEntryReasonCaCompromise = 2
IPPROTO_AH = IPPROTO_AH # alias
IPPROTO_ROUTING = 43
IPPROTO_ROUTING = IPPROTO_ROUTING # alias
# def SEC_ASN1_CHOOSER_DECLARE(x): return extern const SEC_ASN1Template * NSS_Get_ ##x (void *arg, PRBool enc); # macro
# def PR_PREV_LINK(_e): return ((_e)->prev) # macro
SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION = 194
MSG_WAITALL = MSG_WAITALL # alias
__ssize_t = c_int
_G_ssize_t = __ssize_t # alias
_IO_ssize_t = _G_ssize_t # alias
# def LL_USHR(r,a,b): return ((r) = (PRUint64)(a) >> (b)) # macro
SEC_OID_ANSIX962_EC_C2ONB191V5 = 230
dhKey = 4
SEC_OID_NS_CERT_EXT_CERT_RENEWAL_URL = 69
# PR_HashTableDump = PL_HashTableDump # alias
siCipherDataBuffer = 2
SEC_OID_RC4 = 6
INADDR_BROADCAST = 4294967295L # Variable c_uint '-1u'
PR_INADDR_BROADCAST = INADDR_BROADCAST # alias
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC = 118
MSG_NOSIGNAL = 16384
# def PORT_NewArray(type,num): return (type*) PORT_Alloc (sizeof(type)*(num)) # macro
def isalnum_l(c,l): return __isalnum_l ((c), (l)) # macro
SEC_OID_FORTEZZA_SKIPJACK = 153
SEC_OID_DES_ECB = 9
SIGEV_NONE = 1
SIGEV_NONE = SIGEV_NONE # alias
__DEV_T_TYPE = __UQUAD_TYPE # alias
SEC_OID_AVA_GENERATION_QUALIFIER = 270
SEC_OID_UNKNOWN = 0
PK11CertListAll = 6
PR_BITS_PER_INT_LOG2 = 5 # Variable c_int '5'
BITS_PER_INT_LOG2 = PR_BITS_PER_INT_LOG2 # alias
# def __FDMASK(d): return ((__fd_mask) 1 << ((d) % __NFDBITS)) # macro
PR_SockOpt_McastTimeToLive = 11
# __FSBLKCNT_T_TYPE = __ULONGWORD_TYPE # alias
# def LL_I2L(l,i): return ((l) = (PRInt64)(i)) # macro
def PR_INSERT_LINK(_e,_l): return PR_INSERT_AFTER(_e,_l) # macro
def WIFCONTINUED(status): return __WIFCONTINUED (__WAIT_INT (status)) # macro
PR_SUCCESS = 0
# PORT_Memset = memset # alias
SEC_OID_PKCS9_SDSI_CERT = 169
SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC = 23
CKA_NSS_SMIME_INFO = 3461563219L # Variable c_uint '-833404077u'
CKA_NETSCAPE_SMIME_INFO = CKA_NSS_SMIME_INFO # alias
def PZ_Notify(m): return PR_Notify((m)) # macro
PK11CertListCAUnique = 4
IPPROTO_RSVP = 46
def __bswap_constant_32(x): return ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >> 8) | (((x) & 0x0000ff00) << 8) | (((x) & 0x000000ff) << 24)) # macro
SEC_OID_SECG_EC_SECT193R2 = 250
IPV6_JOIN_GROUP = 20 # Variable c_int '20'
IPV6_ADD_MEMBERSHIP = IPV6_JOIN_GROUP # alias
ssl_compression_deflate = 1
# def PR_ABS(x): return ((x)<0?-(x):(x)) # macro
# def CK_DECLARE_FUNCTION(rtype,func): return extern rtype func # macro
SEC_OID_SECG_EC_SECP112R2 = 210
def WEXITSTATUS(status): return __WEXITSTATUS (__WAIT_INT (status)) # macro
SEC_OID_SECG_EC_SECT233R1 = 252
# def __LDBL_REDIR1_NTH(name,proto,alias): return name proto __THROW # macro
PR_BYTES_PER_DWORD_LOG2 = 3 # Variable c_int '3'
BYTES_PER_DWORD_LOG2 = PR_BYTES_PER_DWORD_LOG2 # alias
SEC_OID_NS_TYPE_JPEG = 50
MSG_CONFIRM = 2048
MSG_CONFIRM = MSG_CONFIRM # alias
IPPROTO_MTP = 92
class PLHashEntry(Structure):
    pass
PRHashEntry = PLHashEntry # alias
def isgraph_l(c,l): return __isgraph_l ((c), (l)) # macro
SEC_OID_PKCS9_EXTENSION_REQUEST = 274
IPPORT_WHOIS = 43
SEC_OID_PKCS9_LOCAL_KEY_ID = 172
SOCK_RDM = 4
certIPAddress = 8
# PORT_Assert = PR_ASSERT # alias
IPV6_DSTOPTS = 59 # Variable c_int '59'
IPV6_RXDSTOPTS = IPV6_DSTOPTS # alias
PR_BYTES_PER_INT64 = 8 # Variable c_int '8'
BYTES_PER_INT64 = PR_BYTES_PER_INT64 # alias
def __WIFCONTINUED(status): return ((status) == __W_CONTINUED) # macro
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4 = 154
SEC_OID_NS_CERT_EXT_HOMEPAGE_URL = 71
__BIG_ENDIAN = 4321 # Variable c_int '4321'
BIG_ENDIAN = __BIG_ENDIAN # alias
PR_LOG_MIN = 4
def __FD_ISSET(d,set): return ((__FDS_BITS (set)[__FDELT (d)] & __FDMASK (d)) != 0) # macro
PR_SockOpt_McastLoopback = 12
PF_ROSE = 11 # Variable c_int '11'
AF_ROSE = PF_ROSE # alias
SEC_OID_MD4 = 2
# def PR_STATIC_CALLBACK(__x): return static __x # macro
# def LL_MUL(r,a,b): return ((r) = (a) * (b)) # macro
MSG_MORE = 32768
CKA_NSS_EXPIRES = 3461563223L # Variable c_uint '-833404073u'
CKA_NETSCAPE_EXPIRES = CKA_NSS_EXPIRES # alias
PR_SockOpt_McastInterface = 10
SEC_OID_PKIX_REGCTRL_PKI_ARCH_OPTIONS = 141
IPPROTO_IP = 0
# def LL_NOT(r,a): return ((r) = ~(a)) # macro
# def PR_DirName(dirEntry): return (dirEntry->name) # macro
def IN_EXPERIMENTAL(a): return ((((in_addr_t)(a)) & 0xe0000000) == 0xe0000000) # macro
SO_TIMESTAMPING = 37 # Variable c_int '37'
SCM_TIMESTAMPING = SO_TIMESTAMPING # alias
PR_SockOpt_MaxSegment = 14
# def strdupa(s): return (__extension__ ({ __const char *__old = (s); size_t __len = strlen (__old) + 1; char *__new = (char *) __builtin_alloca (__len); (char *) memcpy (__new, __old, __len); })) # macro
# CLEAR_BIT = PR_CLEAR_BIT # alias
# def LL_XOR(r,a,b): return ((r) = (a) ^ (b)) # macro
PK11TokenRemoved = 3
keaKey = 5
# __SWORD_TYPE = int # alias
# __SSIZE_T_TYPE = __SWORD_TYPE # alias
kt_kea_size = ssl_kea_size # alias
# PORT_Strncasecmp = PL_strncasecmp # alias
# __GID_T_TYPE = __U32_TYPE # alias
# def PR_INSERT_AFTER(_e,_l): return PR_BEGIN_MACRO (_e)->next = (_l)->next; (_e)->prev = (_l); (_l)->next->prev = (_e); (_l)->next = (_e); PR_END_MACRO # macro
siDERCertBuffer = 3
def PZ_ExitMonitor(m): return PR_ExitMonitor((m)) # macro
fortezzaKey = 3
# def PORT_ArenaNewArray(poolp,type,num): return (type*) PORT_ArenaAlloc (poolp, sizeof(type)*(num)) # macro
def __va_arg_pack_len(): return __builtin_va_arg_pack_len () # macro
def PZ_NotifyAllCondVar(v): return PR_NotifyAllCondVar((v)) # macro
SEC_OID_PKIX_REGCTRL_AUTHENTICATOR = 139
class PLArenaPool(Structure):
    pass
PLArenaPool._fields_ = [
    ('first', PLArena),
    ('current', POINTER(PLArena)),
    ('arenasize', PRUint32),
    ('mask', PRUword),
]
PRArenaPool = PLArenaPool # alias
def NSPR_DATA_API(__type): return PR_IMPORT_DATA(__type) # macro
PR_SEEK_END = 2
PK11TokenChanged = 2
MSG_RST = MSG_RST # alias
def putc(_ch,_fp): return _IO_putc (_ch, _fp) # macro
SECSuccess = 0
IPPORT_EXECSERVER = 512
IPPROTO_RAW = 255
SEC_OID_ANSIX962_EC_C2TNB191V3 = 228
# __KEY_T_TYPE = __S32_TYPE # alias
def minor(dev): return gnu_dev_minor (dev) # macro
PR_DESC_FILE = 1
PF_NETBEUI = 13 # Variable c_int '13'
AF_NETBEUI = PF_NETBEUI # alias
# _IO_file_flags = _flags # alias
IPPROTO_RAW = IPPROTO_RAW # alias
MSG_TRYHARD = MSG_DONTROUTE # alias
PF_WANPIPE = 25 # Variable c_int '25'
AF_WANPIPE = PF_WANPIPE # alias
PK11_OriginNULL = 0
CKA_NSS_PQG_COUNTER = 3461563236L # Variable c_uint '-833404060u'
CKA_NETSCAPE_PQG_COUNTER = CKA_NSS_PQG_COUNTER # alias
PR_PROT_READONLY = 0
SEC_OID_ANSIX962_EC_C2TNB239V3 = 234
SEC_OID_X509_HOLD_INSTRUCTION_CODE = 281
PK11_TypeCert = 3
def WSTOPSIG(status): return __WSTOPSIG (__WAIT_INT (status)) # macro
crlEntryReasonUnspecified = 0
SEC_OID_X509_AUTH_INFO_ACCESS = 93
certUsageEmailRecipient = 5
SEC_OID_X509_CERT_ISSUER = 284
SEC_OID_X509_DELTA_CRL_INDICATOR = 282
SEC_OID_PKIX_CA_REPOSITORY = 300
# PR_CompareStrings = PL_CompareStrings # alias
def __STRING(x): return #x # macro
SEC_OID_AVA_COUNTRY_NAME = 42
# PORT_Strtok = strtok # alias
# def LL_DIV(r,a,b): return ((r) = (a) / (b)) # macro
def PZ_NewMonitor(t): return PR_NewMonitor() # macro
# def LL_INIT(hi,lo): return ((hi ## LL << 32) + lo ## LL) # macro
PR_PROT_WRITECOPY = 2
PR_LOG_NONE = 0
class PRCondVar(Structure):
    pass
PRCondVar._fields_ = [
]
PZCondVar = PRCondVar # alias
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4 = 115
crlEntryReasonSuperseded = 4
PR_BYTES_PER_INT = 4 # Variable c_int '4'
BYTES_PER_INT = PR_BYTES_PER_INT # alias
SEC_OID_PKCS12_SAFE_CONTENTS_ID = 160
def be32toh(x): return __bswap_32 (x) # macro
certDirectoryName = 5
SOCK_RDM = SOCK_RDM # alias
crlEntryReasonAffiliationChanged = 3
IPPORT_TIMESERVER = 37
SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST = 276
ssl_calg_camellia = 8
siVisibleString = 13
SEC_OID_AES_128_KEY_WRAP = 197
PR_SockOpt_Keepalive = 3
PR_SKIP_BOTH = 3
SEC_OID_NS_CERT_EXT_USER_PICTURE = 73
siClearDataBuffer = 1
SIGEV_SIGNAL = 0
SIGEV_SIGNAL = SIGEV_SIGNAL # alias
# PR_HashString = PL_HashString # alias
# def _IO_ferror_unlocked(__fp): return (((__fp)->_flags & _IO_ERR_SEEN) != 0) # macro
PF_FILE = PF_LOCAL # alias
AF_FILE = PF_FILE # alias
SEC_OID_PKIX_USER_NOTICE_QUALIFIER = 129
cert_po_trustAnchor = 2
# _G_MMAP64 = __mmap64 # alias
certValidityEqual = 2
_ISblank = 1
def getc(_fp): return _IO_getc (_fp) # macro
# _G_VTABLE_LABEL_PREFIX_ID = __vt_ # alias
SEC_OID_AES_128_ECB = 183
PR_BITS_PER_INT64_LOG2 = 6 # Variable c_int '6'
BITS_PER_INT64_LOG2 = PR_BITS_PER_INT64_LOG2 # alias
SEC_OID_AVA_SERIAL_NUMBER = 262
def FD_ZERO(fdsetp): return __FD_ZERO (fdsetp) # macro
CKM_NSS_AES_KEY_WRAP_PAD = 3461563218L # Variable c_uint '-833404078u'
CKM_NETSCAPE_AES_KEY_WRAP_PAD = CKM_NSS_AES_KEY_WRAP_PAD # alias
SEC_OID_PKIX_OCSP_RESPONSE = 134
def __va_arg_pack(): return __builtin_va_arg_pack () # macro
SEC_OID_MISSI_KEA = 58
def iscntrl_l(c,l): return __iscntrl_l ((c), (l)) # macro
# def IN6_IS_ADDR_SITELOCAL(a): return ((((__const uint32_t *) (a))[0] & htonl (0xffc00000)) == htonl (0xfec00000)) # macro
SEC_OID_X509_FRESHEST_CRL = 285
def _IO_BE(expr,res): return __builtin_expect ((expr), res) # macro
CKT_NSS_UNTRUSTED = 3461563219L # Variable c_uint '-833404077u'
CKT_NETSCAPE_UNTRUSTED = CKT_NSS_UNTRUSTED # alias
IPPORT_NAMESERVER = 42
# PR_HashTableAdd = PL_HashTableAdd # alias
certOwnerUser = 0
# def PR_MAX(x,y): return ((x)>(y)?(x):(y)) # macro
__FLOAT_WORD_ORDER = __BYTE_ORDER # alias
IPPROTO_ICMP = 1
IPPROTO_ICMP = IPPROTO_ICMP # alias
SEC_OID_PKCS9_EXTENDED_CERTIFICATE_ATTRIBUTES = 39
def WTERMSIG(status): return __WTERMSIG (__WAIT_INT (status)) # macro
ssl_auth_null = 0
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4 = 116
# __NLINK_T_TYPE = __UWORD_TYPE # alias
# def PL_ARENA_ALIGN(pool,n): return (((PRUword)(n) + (pool)->mask) & ~(pool)->mask) # macro
PR_BITS_PER_WORD_LOG2 = 5 # Variable c_int '5'
BITS_PER_WORD_LOG2 = PR_BITS_PER_WORD_LOG2 # alias
SEC_OID_AVA_SURNAME = 261
SEC_OID_SECG_EC_SECT131R1 = 244
SEC_OID_PKCS12_OIDS = 105
SEC_OID_PKCS7_ENVELOPED_DATA = 27
IPPROTO_ENCAP = IPPROTO_ENCAP # alias
ssl_auth_dsa = 2
# def LL_L2UI(ui,l): return ((ui) = (PRUint32)(l)) # macro
def PZ_NewCondVar(l): return PR_NewCondVar((l)) # macro
# PORT_Strncpy = strncpy # alias
_ISxdigit = 4096
_ISalpha = 1024
SEC_OID_ANSIX962_EC_PRIME239V3 = 207
PK11TokenPresent = 1
# def LL_UDIVMOD(qp,rp,a,b): return (*(qp) = ((PRUint64)(a) / (b)), *(rp) = ((PRUint64)(a) % (b))) # macro
PK11_TypeSymKey = 4
CERT_N2A_INVERTIBLE = 20
# def __LDBL_REDIR1(name,proto,alias): return name proto # macro
# def __bswap_16(x): return (__extension__ ({ register unsigned short int __v, __x = (x); if (__builtin_constant_p (__x)) __v = __bswap_constant_16 (__x); else __asm__ ("rorw $8, %w0" : "=r" (__v) : "0" (__x) : "cc"); __v; })) # macro
# def LL_OR2(r,a): return ((r) = (r) | (a)) # macro
SEC_OID_PKIX_OCSP_NO_CHECK = 135
certOtherName = 1
IPPROTO_RSVP = IPPROTO_RSVP # alias
SEC_OID_ANSIX962_EC_PRIME192V3 = 204
__codecvt_partial = 1
# PORT_Strstr = strstr # alias
cert_pi_date = 8
PF_BLUETOOTH = 31 # Variable c_int '31'
AF_BLUETOOTH = PF_BLUETOOTH # alias
certDNSName = 3
IPPORT_USERRESERVED = 5000
PF_PPPOX = 24 # Variable c_int '24'
AF_PPPOX = PF_PPPOX # alias
IPPORT_ECHO = 7
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC = 156
certPackageNone = 0
cert_pi_keyusage = 6
# def PR_EXTERN_DATA(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
PR_BYTES_PER_WORD = 4 # Variable c_int '4'
BYTES_PER_WORD = PR_BYTES_PER_WORD # alias
PR_SockOpt_Last = 16
def __bos0(ptr): return __builtin_object_size (ptr, 0) # macro
PK11_OriginUnwrap = 4
SEC_OID_PKCS5_PBES2 = 292
certUsageSSLClient = 0
SEC_OID_X509_SUBJECT_INFO_ACCESS = 287
ssl_calg_rc2 = 2
# _EXTERN_INLINE = __extern_inline # alias
SEC_OID_NS_CERT_EXT_COMMENT = 75
PR_LibSpec_MacNamedFragment = 1
# def PORT_ZNew(type): return (type*)PORT_ZAlloc(sizeof(type)) # macro
PK11_DIS_COULD_NOT_INIT_TOKEN = 2
SEC_OID_DES_CFB = 12
SOCK_RAW = SOCK_RAW # alias
SUPPORTED_CERT_EXTENSION = 2
CKT_NSS_MUST_VERIFY = 3461563220L # Variable c_uint '-833404076u'
CKT_NETSCAPE_MUST_VERIFY = CKT_NSS_MUST_VERIFY # alias
ssl_mac_null = 0
nssILockDBM = 6
SEC_OID_SECG_EC_SECP192R1 = SEC_OID_ANSIX962_EC_PRIME192V1 # alias
# PR_HashTableRawAdd = PL_HashTableRawAdd # alias
SEC_OID_PKIX_OCSP_ARCHIVE_CUTOFF = 136
ssl_kea_fortezza = 3
kt_fortezza = ssl_kea_fortezza # alias
SEC_OID_MISSI_KEA_DSS_OLD = 54
def NSPR_API(__type): return PR_IMPORT(__type) # macro
# def LL_SUB(r,a,b): return ((r) = (a) - (b)) # macro
SEC_OID_PKCS9_SIGNING_TIME = 35
CKA_NSS_PQG_SEED = 3461563237L # Variable c_uint '-833404059u'
CKA_NETSCAPE_PQG_SEED = CKA_NSS_PQG_SEED # alias
def __WTERMSIG(status): return ((status) & 0x7f) # macro
SEC_OID_X509_EXT_KEY_USAGE = 92
# def _IO_putc_unlocked(_ch,_fp): return (_IO_BE ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end, 0) ? __overflow (_fp, (unsigned char) (_ch)) : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch))) # macro
SHUT_RDWR = 2
SHUT_RDWR = SHUT_RDWR # alias
SEC_OID_PKCS12_PKCS8_KEY_SHROUDING = 109
SEC_OID_X509_NAME_CONSTRAINTS = 86
secCertTimeNotValidYet = 2
# PORT_Strcmp = strcmp # alias
PR_BITS_PER_DOUBLE = 64 # Variable c_int '64'
BITS_PER_DOUBLE = PR_BITS_PER_DOUBLE # alias
SEC_OID_PKCS7_DIGESTED_DATA = 29
nssILockSSL = 8
def WIFEXITED(status): return __WIFEXITED (__WAIT_INT (status)) # macro
IPPROTO_EGP = 8
IPPROTO_EGP = IPPROTO_EGP # alias
SEC_OID_PKCS1_RSA_PSS_SIGNATURE = 307
PK11_TypePrivKey = 1
nssILockArena = 0
# def __nonnull(params): return __attribute__ ((__nonnull__ params)) # macro
# PORT_Strncmp = strncmp # alias
# def IN6_IS_ADDR_V4MAPPED(a): return ((((__const uint32_t *) (a))[0] == 0) && (((__const uint32_t *) (a))[1] == 0) && (((__const uint32_t *) (a))[2] == htonl (0xffff))) # macro
IPPROTO_NONE = IPPROTO_NONE # alias
MSG_DONTWAIT = MSG_DONTWAIT # alias
SEC_OID_PKCS9_CONTENT_TYPE = 33
# def PL_ARENA_MARK(pool): return ((void *) (pool)->current->avail) # macro
_ISdigit = 2048
SEC_OID_PKCS12_SECRET_BAG_ID = 112
MSG_CTRUNC = 8
# def PORT_ArenaZNew(poolp,type): return (type*) PORT_ArenaZAlloc(poolp, sizeof(type)) # macro
certURI = 7
SEC_OID_SECG_EC_SECT163R1 = 247
SEC_OID_SECG_EC_SECT233K1 = 251
# def _IO_feof_unlocked(__fp): return (((__fp)->_flags & _IO_EOF_SEEN) != 0) # macro
SEC_OID_PKCS1_RSA_OAEP_ENCRYPTION = 304
# __BLKSIZE_T_TYPE = __SLONGWORD_TYPE # alias
PR_BYTES_PER_SHORT = 2 # Variable c_int '2'
BYTES_PER_SHORT = PR_BYTES_PER_SHORT # alias
SEC_OID_MISSI_KEA_DSS = 56
# PR_CLEAR_UNUSED = PL_CLEAR_UNUSED # alias
SEC_OID_PKIX_OCSP_NONCE = 132
# def __SOCKADDR_COMMON(sa_prefix): return sa_family_t sa_prefix ##family # macro
PK11_OriginDerive = 1
PR_LOG_DEBUG = 4
SEC_OID_DES_EDE3_CBC = 7
PR_DESC_PIPE = 5
# def PR_REMOVE_LINK(_e): return PR_BEGIN_MACRO (_e)->prev->next = (_e)->next; (_e)->next->prev = (_e)->prev; PR_END_MACRO # macro
def PZ_NotifyCondVar(v): return PR_NotifyCondVar((v)) # macro
SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST = 126
def __REDIRECT_LDBL(name,proto,alias): return __REDIRECT (name, proto, alias) # macro
IPPROTO_MTP = IPPROTO_MTP # alias
# def __FD_CLR(d,set): return (__FDS_BITS (set)[__FDELT (d)] &= ~__FDMASK (d)) # macro
MSG_CTRUNC = MSG_CTRUNC # alias
SEC_OID_NS_CERT_EXT_CERT_RENEWAL_TIME = 77
certOwnerPeer = 1
SECFailure = -1
SEC_OID_SECG_EC_SECT239K1 = 253
# def __FDS_BITS(set): return ((set)->fds_bits) # macro
# PR_ARENA_MARK = PL_ARENA_MARK # alias
ssl_calg_fortezza = 6
# stdin = stdin # alias
nssILockPK11cxt = 14
SEC_OID_DES_EDE = 14
MSG_FIN = 512
MSG_FIN = MSG_FIN # alias
def islower_l(c,l): return __islower_l ((c), (l)) # macro
SIGEV_THREAD = 2
SIGEV_THREAD = SIGEV_THREAD # alias
# PR_ArenaCountInplaceGrowth = PL_ArenaCountInplaceGrowth # alias
def PR_ROUNDUP(x,y): return ((((x)+((y)-1))/(y))*(y)) # macro
PF_LLC = 26 # Variable c_int '26'
AF_LLC = PF_LLC # alias
nssILockKeyDB = 18
SEC_OID_RFC1274_UID = 98
PR_FILE_DIRECTORY = 2
SEC_OID_ANSIX962_EC_C2TNB239V2 = 233
# PR_CLEAR_ARENA = PL_CLEAR_ARENA # alias
__INO64_T_TYPE = __UQUAD_TYPE # alias
# def LL_UCMP(a,op,b): return ((PRUint64)(a) op (PRUint64)(b)) # macro
SEC_OID_PKCS12_ESPVK_IDS = 102
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC = 157
# def DER_ConvertBitString(item): return { (item)->len = ((item)->len + 7) >> 3; } # macro
__gnuc_va_list = STRING
_G_va_list = __gnuc_va_list # alias
# def CMSG_ALIGN(len): return (((len) + sizeof (size_t) - 1) & (size_t) ~(sizeof (size_t) - 1)) # macro
SEC_OID_X509_CRL_NUMBER = 94
BUFSIZ = _IO_BUFSIZ # alias
PF_MAX = 37 # Variable c_int '37'
AF_MAX = PF_MAX # alias
def FD_ISSET(fd,fdsetp): return __FD_ISSET (fd, fdsetp) # macro
SEC_OID_AVA_COMMON_NAME = 41
# PR_ArenaFinish = PL_ArenaFinish # alias
MSG_EOR = 128
MSG_EOR = MSG_EOR # alias
PK11_DIS_TOKEN_NOT_PRESENT = 4
# __RLIM_T_TYPE = __ULONGWORD_TYPE # alias
# def PR_STATIC_ASSERT(condition): return extern void pr_static_assert(int arg[(condition) ? 1 : -1]) # macro
SEC_OID_PKCS9_EMAIL_ADDRESS = 31
certUsageSSLServerWithStepUp = 2
def __ispunct_l(c,l): return __isctype_l((c), _ISpunct, (l)) # macro
PR_SHUTDOWN_RCV = 0
def PR_BITMASK(n): return (PR_BIT(n) - 1) # macro
class PLHashTable(Structure):
    pass
PLHashFunction = CFUNCTYPE(PLHashNumber, c_void_p)
class PLHashAllocOps(Structure):
    pass
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
PRHashTable = PLHashTable # alias
certUsageUserCertImport = 7
cert_pi_policyOID = 4
PR_SKIP_DOT = 1
PR_SHUTDOWN_BOTH = 2
def isxdigit_l(c,l): return __isxdigit_l ((c), (l)) # macro
def __toascii(c): return ((c) & 0x7f) # macro
def SEC_ASN1_SUB(x): return x # macro
SEC_OID_X509_SUBJECT_KEY_ID = 80
cert_pi_max = 13
siEncodedNameBuffer = 6
SEC_OID_SECG_EC_SECT193R1 = 249
def le32toh(x): return (x) # macro
SEC_OID_PKCS1_PSPECIFIED = 306
# def __FD_SET(d,set): return (__FDS_BITS (set)[__FDELT (d)] |= __FDMASK (d)) # macro
PRHashAllocOps = PLHashAllocOps # alias
def LL_IS_ZERO(a): return ((a) == 0) # macro
IPPROTO_UDP = IPPROTO_UDP # alias
PR_LibSpec_MacIndexedFragment = 2
def PZ_DestroyLock(k): return PR_DestroyLock((k)) # macro
def IN_CLASSB(a): return ((((in_addr_t)(a)) & 0xc0000000) == 0x80000000) # macro
SEC_OID_PKCS12_ENVELOPING_IDS = 108
PR_TRANSMITFILE_CLOSE_SOCKET = 1
certPackageNSCertWrap = 4
SEC_OID_X509_SUBJECT_DIRECTORY_ATTR = 79
ecKey = 6
ssl_kea_null = 0
CKR_NSS_KEYDB_FAILED = 3461563218L # Variable c_uint '-833404078u'
CKR_NETSCAPE_KEYDB_FAILED = CKR_NSS_KEYDB_FAILED # alias
# PR_ArenaCountGrowth = PL_ArenaCountGrowth # alias
SEC_OID_PKIX_OCSP_CRL = 133
# PR_ArenaAllocate = PL_ArenaAllocate # alias
SEC_OID_AVA_POSTAL_ADDRESS = 265
nssILockOther = 16
IPPROTO_HOPOPTS = 0
_ISalnum = 8
PF_INET6 = 10 # Variable c_int '10'
AF_INET6 = PF_INET6 # alias
def isprint_l(c,l): return __isprint_l ((c), (l)) # macro
# PR_HashTableLookup = PL_HashTableLookup # alias
def alloca(size): return __builtin_alloca (size) # macro
def ntohl(x): return __bswap_32 (x) # macro
SEC_OID_CMS_EPHEMERAL_STATIC_DIFFIE_HELLMAN = 179
SEC_OID_PKCS12 = 100
IPPROTO_HOPOPTS = IPPROTO_HOPOPTS # alias
SEC_OID_SECG_EC_SECP160R1 = 214
CKA_NSS_PQG_SEED_BITS = 3461563239L # Variable c_uint '-833404057u'
CKA_NETSCAPE_PQG_SEED_BITS = CKA_NSS_PQG_SEED_BITS # alias
SEC_OID_SDN702_DSA_SIGNATURE = 189
SHUT_RD = SHUT_RD # alias
SEC_OID_HMAC_SHA512 = 298
# def __LDBL_REDIR_NTH(name,proto): return name proto __THROW # macro
IP_RETOPTS = 7 # Variable c_int '7'
IP_RECVRETOPTS = IP_RETOPTS # alias
SEC_OID_ANSIX962_EC_C2PNB208W1 = 231
nullKey = 0
# __PID_T_TYPE = __S32_TYPE # alias
_ISspace = 8192
SEC_OID_SECG_EC_SECP192K1 = 216
SEC_OID_AVA_LOCALITY = 43
SEC_OID_PKIX_CA_ISSUERS = 273
def __isascii(c): return (((c) & ~0x7f) == 0) # macro
ssl_auth_ecdsa = 4
PF_ISDN = 34 # Variable c_int '34'
AF_ISDN = PF_ISDN # alias
# def PR_BIT(n): return ((PRUint32)1 << (n)) # macro
# def IN6_IS_ADDR_V4COMPAT(a): return ((((__const uint32_t *) (a))[0] == 0) && (((__const uint32_t *) (a))[1] == 0) && (((__const uint32_t *) (a))[2] == 0) && (ntohl (((__const uint32_t *) (a))[3]) > 1)) # macro
# def SEC_GET_TRUST_FLAGS(trust,type): return (((type)==trustSSL)?((trust)->sslFlags): (((type)==trustEmail)?((trust)->emailFlags): (((type)==trustObjectSigning)?((trust)->objectSigningFlags):0))) # macro
def __CONCAT(x,y): return x ## y # macro
IPPORT_WHOSERVER = 513
# _IO_wint_t = _G_wint_t # alias
SEC_OID_ANSIX962_EC_PRIME192V2 = 203
__codecvt_noconv = 3
cert_pi_trustAnchors = 11
PK11CertListUser = 1
class PRLock(Structure):
    pass
PRLock._fields_ = [
]
PZLock = PRLock # alias
siEncodedCertBuffer = 4
# def __intN_t(N,MODE): return typedef int int ##N ##_t __attribute__ ((__mode__ (MODE))) # macro
ssl_kea_dh = 2
PF_CAN = 29 # Variable c_int '29'
AF_CAN = PF_CAN # alias
# __USECONDS_T_TYPE = __U32_TYPE # alias
_IO_pid_t = _G_pid_t # alias
SEC_OID_ANSIX962_EC_PUBLIC_KEY = 200
SEC_OID_ANSIX962_EC_C2TNB359V1 = 239
SEC_OID_VERISIGN_USER_NOTICES = 127
SEC_OID_PKCS12_RSA_SIGNATURE_WITH_SHA1_DIGEST = 123
def PZ_DestroyCondVar(v): return PR_DestroyCondVar((v)) # macro
# def IN6_IS_ADDR_LOOPBACK(a): return (((__const uint32_t *) (a))[0] == 0 && ((__const uint32_t *) (a))[1] == 0 && ((__const uint32_t *) (a))[2] == 0 && ((__const uint32_t *) (a))[3] == htonl (1)) # macro
SEC_OID_PKCS12_MODE_IDS = 101
nssILockOID = 12
# PORT_Memcmp = memcmp # alias
# def __bswap_constant_64(x): return ((((x) & 0xff00000000000000ull) >> 56) | (((x) & 0x00ff000000000000ull) >> 40) | (((x) & 0x0000ff0000000000ull) >> 24) | (((x) & 0x000000ff00000000ull) >> 8) | (((x) & 0x00000000ff000000ull) << 8) | (((x) & 0x0000000000ff0000ull) << 24) | (((x) & 0x000000000000ff00ull) << 40) | (((x) & 0x00000000000000ffull) << 56)) # macro
SEC_OID_NS_CERT_EXT_NETSCAPE_OK = 60
SEC_OID_ANSIX962_EC_C2TNB191V2 = 227
PF_RXRPC = 33 # Variable c_int '33'
AF_RXRPC = PF_RXRPC # alias
CKA_NSS_EMAIL = 3461563218L # Variable c_uint '-833404078u'
CKA_NETSCAPE_EMAIL = CKA_NSS_EMAIL # alias
SIGEV_THREAD_ID = SIGEV_THREAD_ID # alias
SEC_OID_ANSIX962_EC_C2PNB272W1 = 237
PRHashFunction = PLHashFunction # alias
SEC_OID_AES_192_CBC = 186
cert_po_end = 0
def __isxdigit_l(c,l): return __isctype_l((c), _ISxdigit, (l)) # macro
SEC_OID_HMAC_SHA224 = 295
ssl_sign_dsa = 2
CKR_NSS_CERTDB_FAILED = 3461563217L # Variable c_uint '-833404079u'
CKR_NETSCAPE_CERTDB_FAILED = CKR_NSS_CERTDB_FAILED # alias
SEC_OID_PKIX_REGCTRL_PKIPUBINFO = 140
# def __REDIRECT(name,proto,alias): return name proto __asm__ (__ASMNAME (#alias)) # macro
PR_SockOpt_IpTimeToLive = 6
# TEST_BIT = PR_TEST_BIT # alias
# __CLOCK_T_TYPE = __SLONGWORD_TYPE # alias
PK11CertListUserUnique = 5
PR_BITS_PER_INT = 32 # Variable c_int '32'
BITS_PER_INT = PR_BITS_PER_INT # alias
PR_ALIGN_OF_DOUBLE = 4 # Variable c_int '4'
ALIGN_OF_DOUBLE = PR_ALIGN_OF_DOUBLE # alias
MSG_NOSIGNAL = MSG_NOSIGNAL # alias
def __W_EXITCODE(ret,sig): return ((ret) << 8 | (sig)) # macro
# PR_HashTableEnumerateEntries = PL_HashTableEnumerateEntries # alias
SSL_sni_type_total = 1
PR_SockOpt_Linger = 1
# def PR_INIT_STATIC_CLIST(_l): return {(_l), (_l)} # macro
SEC_OID_ANSIX962_ECDSA_SIGNATURE_WITH_SHA1_DIGEST = SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE # alias
# def LL_OR(r,a,b): return ((r) = (a) | (b)) # macro
SEC_OID_PKCS1_MD4_WITH_RSA_ENCRYPTION = 18
SEC_OID_AVA_DN_QUALIFIER = 47
SEC_OID_MD5 = 3
kt_null = ssl_kea_null # alias
# __ID_T_TYPE = __U32_TYPE # alias
SEC_OID_PKCS12_CERT_BAG_IDS = 104
class PRMonitor(Structure):
    pass
PRMonitor._fields_ = [
]
PZMonitor = PRMonitor # alias
SEC_OID_SECG_EC_SECP160K1 = 213
SEC_OID_X509_BASIC_CONSTRAINTS = 85
SEC_OID_ANSIX962_EC_C2PNB163V1 = 222
# stderr = stderr # alias
PK11CertListCA = 3
_ISprint = 16384
# PR_ARENA_ALIGN = PL_ARENA_ALIGN # alias
cert_revocation_method_count = 2
# def PR_IMPORT_DATA(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
def WIFSTOPPED(status): return __WIFSTOPPED (__WAIT_INT (status)) # macro
# PR_INIT_ARENA_POOL = PL_INIT_ARENA_POOL # alias
CKA_SUBPRIME_BITS = 308 # Variable c_int '308'
CKA_SUB_PRIME_BITS = CKA_SUBPRIME_BITS # alias
_IO_va_list = __gnuc_va_list # alias
SEC_OID_PKCS5_PBMAC1 = 293
_IScntrl = 2
# def PORT_ArenaZNewArray(poolp,type,num): return (type*) PORT_ArenaZAlloc (poolp, sizeof(type)*(num)) # macro
SEC_OID_AVA_ORGANIZATION_NAME = 45
LITTLE_ENDIAN = __LITTLE_ENDIAN # alias
PF_ROUTE = PF_NETLINK # alias
AF_ROUTE = PF_ROUTE # alias
# def IN6_IS_ADDR_LINKLOCAL(a): return ((((__const uint32_t *) (a))[0] & htonl (0xffc00000)) == htonl (0xfe800000)) # macro
def IN_MULTICAST(a): return IN_CLASSD(a) # macro
def CK_DECLARE_FUNCTION_POINTER(rtype,func): return rtype (PR_CALLBACK * func) # macro
def __bos(ptr): return __builtin_object_size (ptr, __USE_FORTIFY_LEVEL > 1) # macro
_ISgraph = 32768
SEC_OID_SECG_EC_SECT163R2 = 248
nssILockCert = 4
# def LL_L2F(f,l): return ((f) = (PRFloat64)(l)) # macro
# __wur = __attribute_warn_unused_result__ # alias
_G_HAVE_SYS_WAIT = 1 # Variable c_int '1'
_IO_HAVE_SYS_WAIT = _G_HAVE_SYS_WAIT # alias
def __REDIRECT_NTH_LDBL(name,proto,alias): return __REDIRECT_NTH (name, proto, alias) # macro
# PORT_Tolower = tolower # alias
SEC_OID_NS_CERT_EXT_CA_REVOCATION_URL = 66
SEC_OID_SECG_EC_SECT409K1 = 256
cert_pi_nbioContext = 1
PF_DECnet = 12 # Variable c_int '12'
AF_DECnet = PF_DECnet # alias
PR_DESC_SOCKET_TCP = 2
PF_IPX = 4 # Variable c_int '4'
AF_IPX = PF_IPX # alias
# def PR_EXTERN(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
def __bswap_constant_16(x): return ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)) # macro
# __WCHAR_MAX = __WCHAR_MAX__ # alias
def htonl(x): return __bswap_32 (x) # macro
__FSFILCNT64_T_TYPE = __UQUAD_TYPE # alias
PR_BYTES_PER_FLOAT = 4 # Variable c_int '4'
BYTES_PER_FLOAT = PR_BYTES_PER_FLOAT # alias
PR_ALIGN_OF_SHORT = 2 # Variable c_int '2'
ALIGN_OF_SHORT = PR_ALIGN_OF_SHORT # alias
def __isupper_l(c,l): return __isctype_l((c), _ISupper, (l)) # macro
PR_LOG_WARN = 3
SEC_OID_DES_CBC = 10
SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE = 277
PR_BYTES_PER_BYTE = 1 # Variable c_int '1'
BYTES_PER_BYTE = PR_BYTES_PER_BYTE # alias
SEC_OID_NS_CERT_EXT_SUBJECT_LOGO = 62
PR_BITS_PER_FLOAT_LOG2 = 5 # Variable c_int '5'
BITS_PER_FLOAT_LOG2 = PR_BITS_PER_FLOAT_LOG2 # alias
# __SUSECONDS_T_TYPE = __SLONGWORD_TYPE # alias
SEC_ASN1_Identifier = 0
SEC_OID_PKIX_OCSP = 130
certValidityChooseB = 1
def CMSG_NXTHDR(mhdr,cmsg): return __cmsg_nxthdr (mhdr, cmsg) # macro
IPPORT_NETSTAT = 15
nssILockSlot = 10
def CK_CALLBACK_FUNCTION(rtype,func): return rtype (PR_CALLBACK * func) # macro
SEC_OID_X509_SUBJECT_ALT_NAME = 83
PR_StandardOutput = 1
certUsageObjectSigner = 6
IPPROTO_DSTOPTS = 60
IPPROTO_DSTOPTS = IPPROTO_DSTOPTS # alias
# def PR_NEXT_LINK(_e): return ((_e)->next) # macro
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4 = 155
PR_LibSpec_Pathname = 0
def __isblank_l(c,l): return __isctype_l((c), _ISblank, (l)) # macro
IPPORT_SUPDUP = 95
_IO_fpos_t = _G_fpos_t # alias
SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION = 20
SEC_OID_AVA_PSEUDONYM = 272
def IN_CLASSD(a): return ((((in_addr_t)(a)) & 0xf0000000) == 0xe0000000) # macro
# PR_COUNT_ARENA = PL_COUNT_ARENA # alias
# _G_stat64 = stat64 # alias
SEC_OID_CAMELLIA_192_CBC = 289
IPPROTO_PUP = IPPROTO_PUP # alias
# def GROUP_FILTER_SIZE(numsrc): return (sizeof (struct group_filter) - sizeof (struct sockaddr_storage) + ((numsrc) * sizeof (struct sockaddr_storage))) # macro
# __OFF_T_TYPE = __SLONGWORD_TYPE # alias
SEC_OID_NS_CERT_EXT_CA_POLICY_URL = 70
# def PR_IMPORT(__type): return extern PR_VISIBILITY_DEFAULT __type # macro
IPPROTO_IP = IPPROTO_IP # alias
PK11TokenRemovedOrChangedEvent = 0
# def _IO_getc_unlocked(_fp): return (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) ? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++) # macro
def __WSTOPSIG(status): return __WEXITSTATUS(status) # macro
SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC = 119
def _PARAMS(protos): return __P(protos) # macro
CKK_NSS_PKCS8 = 3461563217L # Variable c_uint '-833404079u'
CKK_NETSCAPE_PKCS8 = CKK_NSS_PKCS8 # alias
# PR_ARENA_ALLOCATE = PL_ARENA_ALLOCATE # alias
certOwnerCA = 2
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC = 159
cert_revocation_method_crl = 0
rsaOaepKey = 8
__BLKCNT64_T_TYPE = __SQUAD_TYPE # alias
__PDP_ENDIAN = 3412 # Variable c_int '3412'
PDP_ENDIAN = __PDP_ENDIAN # alias
SEC_OID_ANSIX962_EC_C2PNB304W1 = 238
SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_128_BIT_RC4 = 120
PR_BITS_PER_DOUBLE_LOG2 = 6 # Variable c_int '6'
BITS_PER_DOUBLE_LOG2 = PR_BITS_PER_DOUBLE_LOG2 # alias
# def PR_LIST_TAIL(_l): return (_l)->prev # macro
IPPORT_TELNET = 23
PLHashEnumerator = CFUNCTYPE(PRIntn, POINTER(PLHashEntry), PRIntn, c_void_p)
PRHashEnumerator = PLHashEnumerator # alias
PF_BRIDGE = 7 # Variable c_int '7'
AF_BRIDGE = PF_BRIDGE # alias
# __TIME_T_TYPE = __SLONGWORD_TYPE # alias
_ISlower = 512
def isupper_l(c,l): return __isupper_l ((c), (l)) # macro
# def IN6_IS_ADDR_UNSPECIFIED(a): return (((__const uint32_t *) (a))[0] == 0 && ((__const uint32_t *) (a))[1] == 0 && ((__const uint32_t *) (a))[2] == 0 && ((__const uint32_t *) (a))[3] == 0) # macro
SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_TRIPLE_DES = 122
SEC_OID_NS_CERT_EXT_CA_CERT_URL = 68
SEC_OID_SECG_EC_SECT409R1 = 257
PF_SNA = 22 # Variable c_int '22'
AF_SNA = PF_SNA # alias
trustEmail = 1
ssl_calg_3des = 4
SEC_OID_ANSIX962_EC_C2PNB163V2 = 223
_IO_uid_t = _G_uid_t # alias
def PZ_EnterMonitor(m): return PR_EnterMonitor((m)) # macro
# def LL_ADD(r,a,b): return ((r) = (a) + (b)) # macro
SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC = 158
def IN_BADCLASS(a): return ((((in_addr_t)(a)) & 0xf0000000) == 0xf0000000) # macro
PR_DESC_SOCKET_UDP = 3
# PR_FreeArenaPool = PL_FreeArenaPool # alias
cert_po_extendedKeyusage = 8
PR_AF_INET = AF_INET # alias
SEC_OID_NS_CERT_EXT_REVOCATION_URL = 65
CKO_NSS_TRUST = 3461563219L # Variable c_uint '-833404077u'
CKO_NETSCAPE_TRUST = CKO_NSS_TRUST # alias
PR_BITS_PER_BYTE = 8 # Variable c_int '8'
BITS_PER_BYTE = PR_BITS_PER_BYTE # alias
MSG_WAITFORONE = 65536
MSG_WAITFORONE = MSG_WAITFORONE # alias
PK11_TypePubKey = 2
SEC_OID_SECG_EC_SECP521R1 = 221
# __CLOCKID_T_TYPE = __S32_TYPE # alias
SCM_RIGHTS = SCM_RIGHTS # alias
certPackagePKCS7 = 2
MSG_MORE = MSG_MORE # alias
# def __warndecl(name,msg): return extern void name (void) __attribute__((__warning__ (msg))) # macro
SO_TIMESTAMPNS = 35 # Variable c_int '35'
SCM_TIMESTAMPNS = SO_TIMESTAMPNS # alias
def LL_EQ(a,b): return ((a) == (b)) # macro
cert_po_keyUsage = 7
kt_dh = ssl_kea_dh # alias
relativeDistinguishedName = 2
# _G_wchar_t = wchar_t # alias
PR_SEEK_SET = 0
def FD_CLR(fd,fdsetp): return __FD_CLR (fd, fdsetp) # macro
ssl_renegotiation_info_xtn = 65281
# def _IO_peekc_unlocked(_fp): return (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) && __underflow (_fp) == EOF ? EOF : *(unsigned char *) (_fp)->_IO_read_ptr) # macro
# def CMSG_LEN(len): return (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len)) # macro
SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC = 22
PR_PROT_READWRITE = 1
INADDR_ANY = 0L # Variable c_uint '0u'
PR_INADDR_ANY = INADDR_ANY # alias
SEC_OID_PKCS12_V1_KEY_BAG_ID = 162
cert_po_usages = 6
def le64toh(x): return (x) # macro
def PZ_NewLock(t): return PR_NewLock() # macro
SEC_OID_NETSCAPE_NICKNAME = 175
# def LL_SHL(r,a,b): return ((r) = (PRInt64)(a) << (b)) # macro
nssILockFreelist = 11
def htole32(x): return (x) # macro
ssl_auth_rsa = 1
CKA_NSS_URL = 3461563217L # Variable c_uint '-833404079u'
CKA_NETSCAPE_URL = CKA_NSS_URL # alias
CERT_N2A_STRICT = 10
def __isprint_l(c,l): return __isctype_l((c), _ISprint, (l)) # macro
# def CERT_LIST_NEXT(n): return ((CERTCertListNode *)n->links.next) # macro
SEC_OID_PKCS1_RSA_ENCRYPTION = 16
def PZ_InMonitor(m): return PR_InMonitor((m)) # macro
def isspace_l(c,l): return __isspace_l ((c), (l)) # macro
_ISpunct = 4
SEC_OID_HMAC_SHA384 = 297
# _IO_iconv_t = _G_iconv_t # alias
# def __LDBL_REDIR(name,proto): return name proto # macro
IPPORT_RESERVED = 1024
SEC_OID_NS_TYPE_GIF = 49
SEC_OID_ANSIX962_EC_C2PNB368W1 = 240
# def IN6_IS_ADDR_MC_SITELOCAL(a): return (IN6_IS_ADDR_MULTICAST(a) && ((((__const uint8_t *) (a))[1] & 0xf) == 0x5)) # macro
# PORT_Strrchr = strrchr # alias
cert_po_errorLog = 5
SEC_OID_X509_CERTIFICATE_POLICIES = 88
siDEROID = 9
PF_ATMPVC = 8 # Variable c_int '8'
AF_ATMPVC = PF_ATMPVC # alias
certRFC822Name = 2
def PR_UPTRDIFF(p,q): return ((PRUword)(p) - (PRUword)(q)) # macro
SEC_OID_PKCS12_X509_CERT_CRL_BAG = 113
# def SECMOD_MAKE_NSS_FLAGS(fips,slot): return "Flags=internal,critical"fips" slotparams=("#slot"={"SECMOD_SLOT_FLAGS"})" # macro
def PZ_Wait(m,t): return PR_Wait(((m)),((t))) # macro
siDERNameBuffer = 5
SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE = 280
PF_RDS = 21 # Variable c_int '21'
AF_RDS = PF_RDS # alias
IPV6_LEAVE_GROUP = 21 # Variable c_int '21'
IPV6_DROP_MEMBERSHIP = IPV6_LEAVE_GROUP # alias
SEC_OID_AES_256_KEY_WRAP = 199
ssl_hmac_md5 = 3
SOCK_SEQPACKET = SOCK_SEQPACKET # alias
SEC_OID_SECG_EC_SECT163K1 = 246
PR_ALIGN_OF_INT64 = 4 # Variable c_int '4'
ALIGN_OF_INT64 = PR_ALIGN_OF_INT64 # alias
SEC_OID_NS_CERT_EXT_ISSUER_LOGO = 61
SEC_OID_AVA_POST_OFFICE_BOX = 267
cert_po_policyOID = 4
PR_BYTES_PER_LONG = 4 # Variable c_int '4'
BYTES_PER_LONG = PR_BYTES_PER_LONG # alias
SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION = 196
PR_ACCESS_EXISTS = 1
PR_SockOpt_DropMember = 9
CKO_NSS_SMIME = 3461563218L # Variable c_uint '-833404078u'
CKO_NETSCAPE_SMIME = CKO_NSS_SMIME # alias
crlEntryReasonAaCompromise = 10
ssl_mac_sha = 2
# def __bswap_64(x): return (__extension__ ({ union { __extension__ unsigned long long int __ll; unsigned int __l[2]; } __w, __r; if (__builtin_constant_p (x)) __r.__ll = __bswap_constant_64 (x); else { __w.__ll = (x); __r.__l[0] = __bswap_32 (__w.__l[1]); __r.__l[1] = __bswap_32 (__w.__l[0]); } __r.__ll; })) # macro
PF_UNSPEC = 0 # Variable c_int '0'
AF_UNSPEC = PF_UNSPEC # alias
PR_ALIGN_OF_WORD = 4 # Variable c_int '4'
ALIGN_OF_WORD = PR_ALIGN_OF_WORD # alias
nssILockCache = 7
def __isascii_l(c,l): return ((l), __isascii (c)) # macro
SEC_OID_AVA_HOUSE_IDENTIFIER = 271
def SSL_IS_SSL2_CIPHER(which): return (((which) & 0xfff0) == 0xff00) # macro
certUsageStatusResponder = 10
# PR_HashTableDestroy = PL_HashTableDestroy # alias
cert_po_certList = 3
# def strndupa(s,n): return (__extension__ ({ __const char *__old = (s); size_t __len = strnlen (__old, (n)); char *__new = (char *) __builtin_alloca (__len + 1); __new[__len] = '\0'; (char *) memcpy (__new, __old, __len); })) # macro
SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE = 182
IPPORT_DAYTIME = 13
CKO_DOMAIN_PARAMETERS = 6 # Variable c_int '6'
CKO_KG_PARAMETERS = CKO_DOMAIN_PARAMETERS # alias
IPPORT_BIFFUDP = 512
# PR_ArenaCountRetract = PL_ArenaCountRetract # alias
SECGreaterThan = 1
SEC_OID_X509_CRL_DIST_POINTS = 87
SEC_OID_PKCS9_FRIENDLY_NAME = 171
PRSize = size_t
PRUintn = c_uint
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
uintn = PRUintn
intn = PRIntn
PRUint64 = c_ulonglong
uint64 = PRUint64
uint32 = PRUint32
PRUint16 = c_ushort
uint16 = PRUint16
PRUint8 = c_ubyte
uint8 = PRUint8
PRInt64 = c_longlong
int64 = PRInt64
PRInt32 = c_int
int32 = PRInt32
PRInt16 = c_short
int16 = PRInt16
PRInt8 = c_byte
int8 = PRInt8
PRFloat64 = c_double
float64 = PRFloat64
PRUptrdiff = c_ulong
uptrdiff_t = PRUptrdiff
uprword_t = PRUword
PRWord = c_long
prword_t = PRWord
class PRCListStr(Structure):
    pass
PRCList = PRCListStr
PRCListStr._fields_ = [
    ('next', POINTER(PRCList)),
    ('prev', POINTER(PRCList)),
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
PRIntervalTime = PRUint32
class PRDir(Structure):
    pass
PRDir._fields_ = [
]
class PRDirEntry(Structure):
    pass
class PRFileDesc(Structure):
    pass
class PRFileInfo(Structure):
    pass
class PRFileInfo64(Structure):
    pass
class PRNetAddr(Union):
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
class PRIPv6Addr(Structure):
    pass
class N10PRIPv6Addr4DOT_25E(Union):
    pass
N10PRIPv6Addr4DOT_25E._pack_ = 4
N10PRIPv6Addr4DOT_25E._fields_ = [
    ('_S6_u8', PRUint8 * 16),
    ('_S6_u16', PRUint16 * 8),
    ('_S6_u32', PRUint32 * 4),
    ('_S6_u64', PRUint64 * 2),
]
PRIPv6Addr._fields_ = [
    ('_S6_un', N10PRIPv6Addr4DOT_25E),
]
class N9PRNetAddr4DOT_26E(Structure):
    pass
N9PRNetAddr4DOT_26E._fields_ = [
    ('family', PRUint16),
    ('data', c_char * 14),
]
class N9PRNetAddr4DOT_27E(Structure):
    pass
N9PRNetAddr4DOT_27E._fields_ = [
    ('family', PRUint16),
    ('port', PRUint16),
    ('ip', PRUint32),
    ('pad', c_char * 8),
]
class N9PRNetAddr4DOT_28E(Structure):
    pass
N9PRNetAddr4DOT_28E._fields_ = [
    ('family', PRUint16),
    ('port', PRUint16),
    ('flowinfo', PRUint32),
    ('ip', PRIPv6Addr),
    ('scope_id', PRUint32),
]
class N9PRNetAddr4DOT_29E(Structure):
    pass
N9PRNetAddr4DOT_29E._fields_ = [
    ('family', PRUint16),
    ('path', c_char * 104),
]
PRNetAddr._fields_ = [
    ('raw', N9PRNetAddr4DOT_26E),
    ('inet', N9PRNetAddr4DOT_27E),
    ('ipv6', N9PRNetAddr4DOT_28E),
    ('local', N9PRNetAddr4DOT_29E),
]

# values for enumeration 'PRSockOption'
PRSockOption = c_int # enum
class PRLinger(Structure):
    pass
PRBool = PRIntn
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
class N18PRSocketOptionData4DOT_30E(Union):
    pass
N18PRSocketOptionData4DOT_30E._fields_ = [
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
    ('value', N18PRSocketOptionData4DOT_30E),
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

# values for enumeration 'PRStatus'
PRStatus = c_int # enum
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
class N9PRLibSpec4DOT_31E(Union):
    pass
class N9PRLibSpec4DOT_314DOT_32E(Structure):
    pass
N9PRLibSpec4DOT_314DOT_32E._fields_ = [
    ('fsspec', POINTER(FSSpec)),
    ('name', STRING),
]
class N9PRLibSpec4DOT_314DOT_33E(Structure):
    pass
N9PRLibSpec4DOT_314DOT_33E._fields_ = [
    ('fsspec', POINTER(FSSpec)),
    ('index', PRUint32),
]
PRUnichar = PRUint16
N9PRLibSpec4DOT_31E._fields_ = [
    ('pathname', STRING),
    ('mac_named_fragment', N9PRLibSpec4DOT_314DOT_32E),
    ('mac_indexed_fragment', N9PRLibSpec4DOT_314DOT_33E),
    ('pathname_u', POINTER(PRUnichar)),
]
PRLibSpec._fields_ = [
    ('type', PRLibSpecType),
    ('value', N9PRLibSpec4DOT_31E),
]
PRFuncPtr = CFUNCTYPE(None)

# values for enumeration 'PRLogModuleLevel'
PRLogModuleLevel = c_int # enum
class PRLogModuleInfo(Structure):
    pass
PRLogModuleInfo._fields_ = [
    ('name', STRING),
    ('level', PRLogModuleLevel),
    ('next', POINTER(PRLogModuleInfo)),
]
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
ptrdiff_t = c_int
PRPtrdiff = ptrdiff_t
PRPackedBool = PRUint8

# values for enumeration '_SECStatus'
_SECStatus = c_int # enum
SECStatus = _SECStatus
class SECItemStr(Structure):
    pass
SECItem = SECItemStr
CERTImportCertificateFunc = CFUNCTYPE(SECStatus, c_void_p, POINTER(POINTER(SECItem)), c_int)
CERTPolicyStringCallback = CFUNCTYPE(STRING, STRING, c_ulong, c_void_p)
class CERTCertificateStr(Structure):
    pass
CERTCertificate = CERTCertificateStr
CERTSortCallback = CFUNCTYPE(PRBool, POINTER(CERTCertificate), POINTER(CERTCertificate), c_void_p)
class NSSCertificateStr(Structure):
    pass
NSSCertificateStr._fields_ = [
]
class NSSTrustDomainStr(Structure):
    pass
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
CERTCertDBHandle = NSSTrustDomainStr
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
class CERTCertificateListStr(Structure):
    pass
CERTCertificateList = CERTCertificateListStr
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
class CERTDistNamesStr(Structure):
    pass
CERTDistNames = CERTDistNamesStr
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

# values for enumeration 'SECItemType'
SECItemType = c_int # enum
SECItemStr._fields_ = [
    ('type', SECItemType),
    ('data', POINTER(c_ubyte)),
    ('len', c_uint),
]
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
class N18CERTCertificateStr4DOT_62E(Union):
    pass
class N18CERTCertificateStr4DOT_624DOT_63E(Structure):
    pass
N18CERTCertificateStr4DOT_624DOT_63E._fields_ = [
    ('hasUnsupportedCriticalExt', c_uint, 1),
]
N18CERTCertificateStr4DOT_62E._fields_ = [
    ('apointer', c_void_p),
    ('bits', N18CERTCertificateStr4DOT_624DOT_63E),
]
class PK11SlotInfoStr(Structure):
    pass
PK11SlotInfo = PK11SlotInfoStr
CK_ULONG = c_ulong
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
    ('options', N18CERTCertificateStr4DOT_62E),
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
class N18CERTGeneralNameStr4DOT_64E(Union):
    pass
N18CERTGeneralNameStr4DOT_64E._fields_ = [
    ('directoryName', CERTName),
    ('OthName', OtherName),
    ('other', SECItem),
]
CERTGeneralNameStr._fields_ = [
    ('type', CERTGeneralNameType),
    ('name', N18CERTGeneralNameStr4DOT_64E),
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
class N23CRLDistributionPointStr4DOT_65E(Union):
    pass
N23CRLDistributionPointStr4DOT_65E._fields_ = [
    ('fullName', POINTER(CERTGeneralName)),
    ('relativeName', CERTRDN),
]
CRLDistributionPointStr._fields_ = [
    ('distPointType', DistributionPointTypes),
    ('distPoint', N23CRLDistributionPointStr4DOT_65E),
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
class N22CERTValParamInValueStr4DOT_81E(Union):
    pass
N22CERTValParamInValueStr4DOT_81E._pack_ = 4
N22CERTValParamInValueStr4DOT_81E._fields_ = [
    ('b', PRBool),
    ('i', PRInt32),
    ('ui', PRUint32),
    ('l', PRInt64),
    ('ul', PRUint64),
    ('time', PRTime),
]
class N22CERTValParamInValueStr4DOT_82E(Union):
    pass
N22CERTValParamInValueStr4DOT_82E._fields_ = [
    ('p', c_void_p),
    ('s', STRING),
    ('cert', POINTER(CERTCertificate)),
    ('chain', POINTER(CERTCertList)),
    ('revocation', POINTER(CERTRevocationFlags)),
]
class N22CERTValParamInValueStr4DOT_83E(Union):
    pass
N22CERTValParamInValueStr4DOT_83E._fields_ = [
    ('pi', POINTER(PRInt32)),
    ('pui', POINTER(PRUint32)),
    ('pl', POINTER(PRInt64)),
    ('pul', POINTER(PRUint64)),
    ('oids', POINTER(SECOidTag)),
]
CERTValParamInValueStr._fields_ = [
    ('scalar', N22CERTValParamInValueStr4DOT_81E),
    ('pointer', N22CERTValParamInValueStr4DOT_82E),
    ('array', N22CERTValParamInValueStr4DOT_83E),
    ('arraySize', c_int),
]
CERTValParamInValue = CERTValParamInValueStr
class CERTValParamOutValueStr(Structure):
    pass
class N23CERTValParamOutValueStr4DOT_84E(Union):
    pass
N23CERTValParamOutValueStr4DOT_84E._pack_ = 4
N23CERTValParamOutValueStr4DOT_84E._fields_ = [
    ('b', PRBool),
    ('i', PRInt32),
    ('ui', PRUint32),
    ('l', PRInt64),
    ('ul', PRUint64),
    ('usages', SECCertificateUsage),
]
class N23CERTValParamOutValueStr4DOT_85E(Union):
    pass
N23CERTValParamOutValueStr4DOT_85E._fields_ = [
    ('p', c_void_p),
    ('s', STRING),
    ('log', POINTER(CERTVerifyLog)),
    ('cert', POINTER(CERTCertificate)),
    ('chain', POINTER(CERTCertList)),
]
class N23CERTValParamOutValueStr4DOT_86E(Union):
    pass
N23CERTValParamOutValueStr4DOT_86E._fields_ = [
    ('p', c_void_p),
    ('oids', POINTER(SECOidTag)),
]
CERTValParamOutValueStr._fields_ = [
    ('scalar', N23CERTValParamOutValueStr4DOT_84E),
    ('pointer', N23CERTValParamOutValueStr4DOT_85E),
    ('array', N23CERTValParamOutValueStr4DOT_86E),
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
class SECKEYPublicKeyStr(Structure):
    pass
class N18SECKEYPublicKeyStr4DOT_57E(Union):
    pass
N18SECKEYPublicKeyStr4DOT_57E._fields_ = [
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
    ('u', N18SECKEYPublicKeyStr4DOT_57E),
]
SECKEYPublicKey = SECKEYPublicKeyStr
class SECKEYPrivateKeyStr(Structure):
    pass
SECKEYPrivateKeyStr._fields_ = [
    ('arena', POINTER(PLArenaPool)),
    ('keyType', KeyType),
    ('pkcs11Slot', POINTER(PK11SlotInfo)),
    ('pkcs11ID', CK_OBJECT_HANDLE),
    ('pkcs11IsTemp', PRBool),
    ('wincx', c_void_p),
    ('staticflags', PRUint32),
]
SECKEYPrivateKey = SECKEYPrivateKeyStr
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
class SECMODModuleStr(Structure):
    pass
SECMODModule = SECMODModuleStr
class SECMODModuleListStr(Structure):
    pass
SECMODModuleList = SECMODModuleListStr
class nssRWLockStr(Structure):
    pass
NSSRWLock = nssRWLockStr
SECMODListLock = NSSRWLock
PK11SlotInfoStr._fields_ = [
]
class PK11PreSlotInfoStr(Structure):
    pass
PK11PreSlotInfoStr._fields_ = [
]
PK11PreSlotInfo = PK11PreSlotInfoStr
class PK11SymKeyStr(Structure):
    pass
PK11SymKeyStr._fields_ = [
]
PK11SymKey = PK11SymKeyStr
class PK11ContextStr(Structure):
    pass
PK11ContextStr._fields_ = [
]
PK11Context = PK11ContextStr
class PK11SlotListStr(Structure):
    pass
PK11SlotList = PK11SlotListStr
class PK11SlotListElementStr(Structure):
    pass
PK11SlotListElement = PK11SlotListElementStr
class PK11RSAGenParamsStr(Structure):
    pass
PK11RSAGenParams = PK11RSAGenParamsStr
SECMODModuleID = c_ulong
class PK11DefaultArrayEntryStr(Structure):
    pass
PK11DefaultArrayEntry = PK11DefaultArrayEntryStr
class PK11GenericObjectStr(Structure):
    pass
PK11GenericObject = PK11GenericObjectStr
PK11GenericObjectStr._fields_ = [
]
PK11FreeDataFunc = CFUNCTYPE(None, c_void_p)
class CK_VERSION(Structure):
    pass
CK_BYTE = c_ubyte
CK_VERSION._fields_ = [
    ('major', CK_BYTE),
    ('minor', CK_BYTE),
]
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
CK_RV = CK_ULONG
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
SSLAuthCertificate = CFUNCTYPE(SECStatus, c_void_p, POINTER(PRFileDesc), PRBool, PRBool)
SSLGetClientAuthData = CFUNCTYPE(SECStatus, c_void_p, POINTER(PRFileDesc), POINTER(CERTDistNames), POINTER(POINTER(CERTCertificate)), POINTER(POINTER(SECKEYPrivateKey)))
SSLSNISocketConfig = CFUNCTYPE(PRInt32, POINTER(PRFileDesc), POINTER(SECItem), PRUint32, c_void_p)
SSLBadCertHandler = CFUNCTYPE(SECStatus, c_void_p, POINTER(PRFileDesc))
SSLHandshakeCallback = CFUNCTYPE(None, POINTER(PRFileDesc), c_void_p)
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

# values for enumeration 'SSLKEAType'
SSLKEAType = c_int # enum

# values for enumeration 'SSLSignType'
SSLSignType = c_int # enum

# values for enumeration 'SSLAuthType'
SSLAuthType = c_int # enum

# values for enumeration 'SSLCipherAlgorithm'
SSLCipherAlgorithm = c_int # enum

# values for enumeration 'SSLMACAlgorithm'
SSLMACAlgorithm = c_int # enum

# values for enumeration 'SSLCompressionMethod'
SSLCompressionMethod = c_int # enum
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

# values for enumeration 'nssILockType'
nssILockType = c_int # enum
nssRWLockStr._fields_ = [
]
CK_TRUST = CK_ULONG
SECMODModuleDBFunc = CFUNCTYPE(POINTER(STRING), c_ulong, STRING, c_void_p)
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
CK_SLOT_ID = CK_ULONG
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
CK_MECHANISM_TYPE = CK_ULONG
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
SEC_ASN1DecoderContext = sec_DecoderContext_struct
sec_DecoderContext_struct._fields_ = [
]
class sec_EncoderContext_struct(Structure):
    pass
sec_EncoderContext_struct._fields_ = [
]
SEC_ASN1EncoderContext = sec_EncoderContext_struct

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
CKR_KEY_NOT_WRAPPABLE = 105 # Variable c_int '105'
SSL_RENEGOTIATE_NEVER = 0 # Variable c_int '0'
PR_IS_CONNECTED_ERROR = -5984 # Variable c_long '-0x000001760l'
CKT_NSS = 3461563216L # Variable c_uint '-833404080u'
CKF_EC_UNCOMPRESS = 16777216 # Variable c_int '16777216'
LL_MAXUINT = 18446744073709551615L # Variable c_ulonglong '0xffffffffffffffffull'
CKM_SHA224_HMAC = 598 # Variable c_int '598'
CKK_X9_42_DH = 4 # Variable c_int '4'
NI_IDN = 32 # Variable c_int '32'
CKK_DH = 2 # Variable c_int '2'
CKM_SHA_1_HMAC = 545 # Variable c_int '545'
CKA_PIXEL_Y = 1025 # Variable c_int '1025'
PR_POLL_ERR = 8 # Variable c_int '8'
SEC_CERT_CLASS_USER = 3 # Variable c_int '3'
CKR_DATA_INVALID = 32 # Variable c_int '32'
SECMOD_RC2_FLAG = 4 # Variable c_long '4l'
CKA_PRIVATE_EXPONENT = 291 # Variable c_int '291'
SSL_V2_COMPATIBLE_HELLO = 12 # Variable c_int '12'
_IO_SHOWBASE = 128 # Variable c_int '128'
CKA_RESOLUTION = 1026 # Variable c_int '1026'
DER_BOOLEAN = 1 # Variable c_int '1'
_KEYTHI_H_ = 1 # Variable c_int '1'
CKF_SERIAL_SESSION = 4 # Variable c_int '4'
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
PK11_ATTR_SESSION = 2 # Variable c_long '2l'
SEC_ASN1_CHOICE = 1048576 # Variable c_int '1048576'
SECKEY_Attributes_Cached = 1 # Variable c_int '1'
MCAST_JOIN_GROUP = 42 # Variable c_int '42'
CKO_HW_FEATURE = 5 # Variable c_int '5'
NI_IDN_ALLOW_UNASSIGNED = 64 # Variable c_int '64'
CKM_CDMF_MAC = 323 # Variable c_int '323'
IP_PKTINFO = 8 # Variable c_int '8'
CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC = 2147483653L # Variable c_ulong '-2147483643ul'
CKM_RIPEMD128_HMAC = 561 # Variable c_int '561'
CKA_VERIFY = 266 # Variable c_int '266'
PR_INT16_MAX = 32767 # Variable c_int '32767'
_IO_BOOLALPHA = 65536 # Variable c_int '65536'
PR_TPD_RANGE_ERROR = -5972 # Variable c_long '-0x000001754l'
PR_CONNECT_RESET_ERROR = -5961 # Variable c_long '-0x000001749l'
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
CKG_MGF1_SHA512 = 4 # Variable c_int '4'
CKF_GENERATE = 32768 # Variable c_int '32768'
IN_CLASSA_MAX = 128 # Variable c_int '128'
PR_MSEC_PER_SEC = 1000L # Variable c_ulong '1000ul'
CRL_IMPORT_DEFAULT_OPTIONS = 0 # Variable c_int '0'
__GLIBC__ = 2 # Variable c_int '2'
_XLOCALE_H = 1 # Variable c_int '1'
CKM_AES_CBC = 4226 # Variable c_int '4226'
KU_KEY_CERT_SIGN = 4 # Variable c_int '4'
CKH_MONOTONIC_COUNTER = 1 # Variable c_int '1'
CKM_SKIPJACK_OFB64 = 4099 # Variable c_int '4099'
PR_IWGRP = 16 # Variable c_int '16'
_IONBF = 2 # Variable c_int '2'
CKR_BUFFER_TOO_SMALL = 336 # Variable c_int '336'
_BITS_UIO_H = 1 # Variable c_int '1'
__USE_POSIX2 = 1 # Variable c_int '1'
CKA_ALWAYS_SENSITIVE = 357 # Variable c_int '357'
IPV6_RECVRTHDR = 56 # Variable c_int '56'
SSL_BYPASS_PKCS11 = 16 # Variable c_int '16'
NS_CERT_TYPE_SSL_SERVER = 64 # Variable c_int '64'
CKM_MD2_HMAC_GENERAL = 514 # Variable c_int '514'
PR_MAX_ERROR = -5924 # Variable c_long '-0x000001724l'
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
PR_END_OF_FILE_ERROR = -5938 # Variable c_long '-0x000001732l'
EAI_FAMILY = -6 # Variable c_int '-0x000000006'
CKA_EC_POINT = 385 # Variable c_int '385'
EXT_KEY_USAGE_TIME_STAMP = 32768 # Variable c_int '32768'
DER_ANY = 1024 # Variable c_int '1024'
HT_ENUMERATE_REMOVE = 2 # Variable c_int '2'
SEC_ASN1_OBJECT_DESCRIPTOR = 7 # Variable c_int '7'
IP_MULTICAST_LOOP = 34 # Variable c_int '34'
PR_INVALID_IO_LAYER = -1 # Variable c_int '-0x000000001'
CKA_ISSUER = 129 # Variable c_int '129'
CKD_NULL = 1 # Variable c_int '1'
SSL_NO_LOCKS = 17 # Variable c_int '17'
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
__USE_ANSI = 1 # Variable c_int '1'
CKM_PBE_MD5_CAST_CBC = 930 # Variable c_int '930'
CKM_SHA224 = 597 # Variable c_int '597'
_PATH_HOSTS = '/etc/hosts' # Variable STRING '(const char*)"/etc/hosts"'
CKM_SEED_CBC_PAD = 1621 # Variable c_int '1621'
CKA_FLAGS_ONLY = 0 # Variable c_int '0'
CKA_PIXEL_X = 1024 # Variable c_int '1024'
CKA_TRUST_DIGITAL_SIGNATURE = 3461571409L # Variable c_uint '-833395887u'
__STDC_ISO_10646__ = 200009 # Variable c_long '200009l'
CKM_GENERIC_SECRET_KEY_GEN = 848 # Variable c_int '848'
_IO_TIED_PUT_GET = 1024 # Variable c_int '1024'
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
CKK_RC4 = 18 # Variable c_int '18'
CKK_RC5 = 25 # Variable c_int '25'
INADDR_ALLHOSTS_GROUP = 3758096385L # Variable c_uint '-536870911u'
CKA_CHAR_COLUMNS = 1028 # Variable c_int '1028'
_IOS_ATEND = 4 # Variable c_int '4'
SECMOD_RC4_FLAG = 8 # Variable c_long '8l'
PK11_ATTR_SENSITIVE = 64 # Variable c_long '64l'
SECMOD_DH_FLAG = 32 # Variable c_long '32l'
DER_APPLICATION = 64 # Variable c_int '64'
PR_OPERATION_NOT_SUPPORTED_ERROR = -5965 # Variable c_long '-0x00000174dl'
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
IP_DROP_SOURCE_MEMBERSHIP = 40 # Variable c_int '40'
PR_NOT_SAME_DEVICE_ERROR = -5945 # Variable c_long '-0x000001739l'
SSL_RESTRICTED = 2 # Variable c_int '2'
CKA_TRUST_TIME_STAMPING = 3461571423L # Variable c_uint '-833395873u'
KU_CRL_SIGN = 2 # Variable c_int '2'
CKR_CANT_LOCK = 10 # Variable c_int '10'
SEC_ASN1_BMP_STRING = 30 # Variable c_int '30'
CKA_CHAR_SETS = 1152 # Variable c_int '1152'
IP_FREEBIND = 15 # Variable c_int '15'
IPV6_PKTINFO = 50 # Variable c_int '50'
SEC_CERTIFICATE_VERSION_2 = 1 # Variable c_int '1'
SEC_CERTIFICATE_VERSION_3 = 2 # Variable c_int '2'
SEC_CERTIFICATE_VERSION_1 = 0 # Variable c_int '0'
CKM_SHA512_HMAC = 625 # Variable c_int '625'
PR_ADDRESS_IN_USE_ERROR = -5982 # Variable c_long '-0x00000175el'
CKM_CAST_CBC_PAD = 773 # Variable c_int '773'
NI_NUMERICHOST = 1 # Variable c_int '1'
PR_FILE_SEEK_ERROR = -5937 # Variable c_long '-0x000001731l'
PL_HASH_BITS = 32 # Variable c_int '32'
DER_SET = 17 # Variable c_int '17'
SSL_SNI_CURRENT_CONFIG_IS_USED = -1 # Variable c_int '-0x000000001'
SSL_HANDSHAKE_AS_SERVER = 6 # Variable c_int '6'
SOL_DECNET = 261 # Variable c_int '261'
SSL_SECURITY_STATUS_FORTEZZA = 3 # Variable c_int '3'
CKF_TOKEN_INITIALIZED = 1024 # Variable c_int '1024'
_IO_HEX = 64 # Variable c_int '64'
CKA_MODIFIABLE = 368 # Variable c_int '368'
WNOHANG = 1 # Variable c_int '1'
CERT_ENABLE_LDAP_FETCH = 1 # Variable c_int '1'
SEC_ASN1_BIT_STRING = 3 # Variable c_int '3'
FILENAME_MAX = 4096 # Variable c_int '4096'
CKM_CAST128_ECB = 801 # Variable c_int '801'
EXIT_SUCCESS = 0 # Variable c_int '0'
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
SO_SECURITY_AUTHENTICATION = 22 # Variable c_int '22'
SO_SECURITY_ENCRYPTION_NETWORK = 24 # Variable c_int '24'
CKM_BATON_CBC128 = 4147 # Variable c_int '4147'
SEC_ASN1_SKIP = 32768 # Variable c_int '32768'
SSL_REQUIRE_ALWAYS = 1 # Variable c_int '1'
__SIZEOF_PTHREAD_ATTR_T = 36 # Variable c_int '36'
SO_PROTOCOL = 38 # Variable c_int '38'
certificateUsageEmailSigner = 16 # Variable c_int '16'
CKM_RC2_KEY_GEN = 256 # Variable c_int '256'
CKN_SURRENDER = 0 # Variable c_int '0'
CKK_RC2 = 17 # Variable c_int '17'
MCAST_UNBLOCK_SOURCE = 44 # Variable c_int '44'
PK11_DISABLE_FLAG = 1073741824 # Variable c_long '1073741824l'
CKM_PBE_MD5_DES_CBC = 929 # Variable c_int '929'
CKH_USER_INTERFACE = 3 # Variable c_int '3'
__USE_XOPEN2KXSI = 1 # Variable c_int '1'
AI_NUMERICHOST = 4 # Variable c_int '4'
PR_NOT_CONNECTED_ERROR = -5978 # Variable c_long '-0x00000175al'
CKM_FORTEZZA_TIMESTAMP = 4128 # Variable c_int '4128'
__USE_XOPEN2K8 = 1 # Variable c_int '1'
PR_WRONLY = 2 # Variable c_int '2'
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
SEC_ASN1_OBJECT_ID = 6 # Variable c_int '6'
CKA_DECRYPT = 261 # Variable c_int '261'
CKM_SHA512_RSA_PKCS = 66 # Variable c_int '66'
CKM_KEA_KEY_PAIR_GEN = 4112 # Variable c_int '4112'
NS_CERT_TYPE_EMAIL = 32 # Variable c_int '32'
CKA_MODULUS_BITS = 289 # Variable c_int '289'
PR_FILE_EXISTS_ERROR = -5943 # Variable c_long '-0x000001737l'
SO_RXQ_OVFL = 40 # Variable c_int '40'
CKS_RO_PUBLIC_SESSION = 0 # Variable c_int '0'
CKM_SHA384_HMAC = 609 # Variable c_int '609'
_BITS_SOCKADDR_H = 1 # Variable c_int '1'
SEC_ASN1_GENERAL_STRING = 27 # Variable c_int '27'
_IO_IN_BACKUP = 256 # Variable c_int '256'
CKA_AUTH_PIN_FLAGS = 513 # Variable c_int '513'
CERT_REV_M_ALLOW_NETWORK_FETCHING = 0 # Variable c_long '0l'
_SIGSET_H_types = 1 # Variable c_int '1'
CKM_PBA_SHA1_WITH_SHA1_HMAC = 960 # Variable c_int '960'
CERT_REV_M_FAIL_ON_MISSING_FRESH_INFO = 16 # Variable c_long '16l'
_G_HAVE_BOOL = 1 # Variable c_int '1'
PR_NOT_TCP_SOCKET_ERROR = -5968 # Variable c_long '-0x000001750l'
CKM_TWOFISH_CBC = 4243 # Variable c_int '4243'
CKA_CERT_SHA1_HASH = 3461571508L # Variable c_uint '-833395788u'
EAI_INTR = -104 # Variable c_int '-0x000000068'
CKF_OS_LOCKING_OK = 2 # Variable c_int '2'
CKM_CAST3_ECB = 785 # Variable c_int '785'
CKM_SEED_KEY_GEN = 1616 # Variable c_int '1616'
CKM_CAST128_CBC = 802 # Variable c_int '802'
PK11_ATTR_PUBLIC = 8 # Variable c_long '8l'
PR_NSEC_PER_SEC = 1000000000L # Variable c_ulong '1000000000ul'
CKF_USER_PIN_COUNT_LOW = 65536 # Variable c_int '65536'
PK11_PW_RETRY = 'RETRY' # Variable STRING '(const char*)"RETRY"'
_IO_UNIFIED_JUMPTABLES = 1 # Variable c_int '1'
CKA_SUPPORTED_CMS_ATTRIBUTES = 1283 # Variable c_int '1283'
CKO_PRIVATE_KEY = 3 # Variable c_int '3'
_IO_SHOWPOS = 1024 # Variable c_int '1024'
SEC_ASN1_HIGH_TAG_NUMBER = 31 # Variable c_int '31'
PR_LD_NOW = 2 # Variable c_int '2'
SEC_ASN1_TAG_MASK = 255 # Variable c_int '255'
SEC_ASN1_XTRN = 0 # Variable c_int '0'
PR_REMOTE_FILE_ERROR = -5963 # Variable c_long '-0x00000174bl'
PR_MSG_PEEK = 2 # Variable c_int '2'
SOL_X25 = 262 # Variable c_int '262'
CKK_SEED = 38 # Variable c_int '38'
SSL_REQUEST_CERTIFICATE = 3 # Variable c_int '3'
CKK_KEA = 5 # Variable c_int '5'
_LARGEFILE64_SOURCE = 1 # Variable c_int '1'
CKM_MD5 = 528 # Variable c_int '528'
CKM_MD2 = 512 # Variable c_int '512'
EAI_CANCELED = -101 # Variable c_int '-0x000000065'
CKK_BATON = 28 # Variable c_int '28'
SO_DOMAIN = 39 # Variable c_int '39'
DER_CLASS_MASK = 192 # Variable c_int '192'
CKM_RIPEMD128_HMAC_GENERAL = 562 # Variable c_int '562'
SO_PASSSEC = 34 # Variable c_int '34'
CKM_MD2_RSA_PKCS = 4 # Variable c_int '4'
SEC_ASN1_UNIVERSAL_STRING = 28 # Variable c_int '28'
SIOCSPGRP = 35074 # Variable c_int '35074'
CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN = 2147483659L # Variable c_ulong '-2147483637ul'
SO_PASSCRED = 16 # Variable c_int '16'
CKM_RSA_PKCS_OAEP = 9 # Variable c_int '9'
CERT_REV_MI_REQUIRE_SOME_FRESH_INFO_AVAILABLE = 2 # Variable c_long '2l'
KU_KEY_ENCIPHERMENT = 32 # Variable c_int '32'
SIOCGSTAMP = 35078 # Variable c_int '35078'
SSL_ENABLE_TLS = 13 # Variable c_int '13'
CKA_UNWRAP_TEMPLATE = 1073742354 # Variable c_int '1073742354'
CKA_MECHANISM_TYPE = 1280 # Variable c_int '1280'
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
_IO_FIXED = 4096 # Variable c_int '4096'
SEC_ASN1_REAL = 9 # Variable c_int '9'
CKM_RSA_9796 = 2 # Variable c_int '2'
IPV6_HOPLIMIT = 52 # Variable c_int '52'
CKM_DES3_MAC = 308 # Variable c_int '308'
CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = 980 # Variable c_int '980'
SO_BROADCAST = 6 # Variable c_int '6'
LL_MININT = -9223372036854775808L # Variable c_longlong '-0x8000000000000000ll'
CKM_MD5_HMAC_GENERAL = 530 # Variable c_int '530'
CKM_RC2_CBC_PAD = 261 # Variable c_int '261'
CKM_DH_PKCS_PARAMETER_GEN = 8193 # Variable c_int '8193'
_G_HAVE_MMAP = 1 # Variable c_int '1'
CKM_WTLS_MASTER_KEY_DERIVE = 977 # Variable c_int '977'
SSL_SNI_SEND_ALERT = -2 # Variable c_int '-0x000000002'
SO_NO_CHECK = 11 # Variable c_int '11'
SECMOD_MODULE_DB_FUNCTION_DEL = 2 # Variable c_int '2'
CKK_CAST5 = 24 # Variable c_int '24'
SECMOD_WAIT_PKCS11_EVENT = 4 # Variable c_int '4'
CKR_KEY_SIZE_RANGE = 98 # Variable c_int '98'
IPV6_RTHDR_LOOSE = 0 # Variable c_int '0'
IP_MTU = 14 # Variable c_int '14'
PR_NO_ACCESS_RIGHTS_ERROR = -5966 # Variable c_long '-0x00000174el'
SOMAXCONN = 128 # Variable c_int '128'
PK11_ATTR_INSENSITIVE = 128 # Variable c_long '128l'
CKA_START_DATE = 272 # Variable c_int '272'
CKR_KEY_UNEXTRACTABLE = 106 # Variable c_int '106'
CKA_EC_PARAMS = 384 # Variable c_int '384'
PR_LANGUAGE_EN = 1 # Variable c_int '1'
PR_LOAD_LIBRARY_ERROR = -5977 # Variable c_long '-0x000001759l'
_IOS_TRUNC = 16 # Variable c_int '16'
NI_NOFQDN = 4 # Variable c_int '4'
PR_APPEND = 16 # Variable c_int '16'
CKM_BATON_ECB96 = 4146 # Variable c_int '4146'
FIOGETOWN = 35075 # Variable c_int '35075'
SECMOD_SHA1_FLAG = 256 # Variable c_long '256l'
CKA_NETSCAPE_TRUST = 2147483649L # Variable c_ulong '-2147483647ul'
CKM_RC2_MAC_GENERAL = 260 # Variable c_int '260'
CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 138 # Variable c_int '138'
__WALL = 1073741824 # Variable c_int '1073741824'
_IO_UNITBUF = 8192 # Variable c_int '8192'
CKF_EC_NAMEDCURVE = 8388608 # Variable c_int '8388608'
CKO_DATA = 0 # Variable c_int '0'
SEC_ASN1_INTEGER = 2 # Variable c_int '2'
SOL_PACKET = 263 # Variable c_int '263'
PR_NETWORK_UNREACHABLE_ERROR = -5980 # Variable c_long '-0x00000175cl'
_IO_UNBUFFERED = 2 # Variable c_int '2'
CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4 = 2147483655L # Variable c_ulong '-2147483641ul'
CKK_RSA = 0 # Variable c_int '0'
CRL_DECODE_ADOPT_HEAP_DER = 8 # Variable c_int '8'
NSS_USE_ALG_IN_CMS_SIGNATURE = 2 # Variable c_int '2'
SO_KEEPALIVE = 9 # Variable c_int '9'
CK_INVALID_HANDLE = 0 # Variable c_int '0'
CKM_DES_MAC = 291 # Variable c_int '291'
IP_PMTUDISC_DO = 2 # Variable c_int '2'
CKM_SKIPJACK_CFB16 = 4102 # Variable c_int '4102'
CERT_POLICY_FLAG_NO_MAPPING = 1 # Variable c_int '1'
CERT_REV_M_DO_NOT_TEST_USING_THIS_METHOD = 0 # Variable c_long '0l'
CKM_SKIPJACK_CFB8 = 4103 # Variable c_int '4103'
CKR_CRYPTOKI_ALREADY_INITIALIZED = 401 # Variable c_int '401'
CKM_IDEA_MAC = 835 # Variable c_int '835'
PR_LOOP_ERROR = -5952 # Variable c_long '-0x000001740l'
_G_HAVE_IO_GETLINE_INFO = 1 # Variable c_int '1'
NETDB_SUCCESS = 0 # Variable c_int '0'
DER_DEFAULT_CHUNKSIZE = 2048 # Variable c_int '2048'
NI_IDN_USE_STD3_ASCII_RULES = 128 # Variable c_int '128'
IN_CLASSB_HOST = 65535L # Variable c_uint '65535u'
CKM_ECDSA_KEY_PAIR_GEN = 4160 # Variable c_int '4160'
DER_INTEGER = 2 # Variable c_int '2'
CKO_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
CKA_CHAR_ROWS = 1027 # Variable c_int '1027'
__WORDSIZE = 32 # Variable c_int '32'
SOL_IRDA = 266 # Variable c_int '266'
CKA_BASE = 306 # Variable c_int '306'
IN_CLASSB_MAX = 65536 # Variable c_int '65536'
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
CKA_REQUIRED_CMS_ATTRIBUTES = 1281 # Variable c_int '1281'
CKF_USER_PIN_LOCKED = 262144 # Variable c_int '262144'
PR_IROTH = 4 # Variable c_int '4'
SO_RCVLOWAT = 18 # Variable c_int '18'
PR_FILE_TOO_BIG_ERROR = -5957 # Variable c_long '-0x000001745l'
IN_CLASSB_NSHIFT = 16 # Variable c_int '16'
_SYS_TYPES_H = 1 # Variable c_int '1'
CKM_X9_42_DH_HYBRID_DERIVE = 50 # Variable c_int '50'
_IO_ERR_SEEN = 32 # Variable c_int '32'
CKA_MIME_TYPES = 1154 # Variable c_int '1154'
__USE_GNU = 1 # Variable c_int '1'
WUNTRACED = 2 # Variable c_int '2'
CKA_TRUST_CODE_SIGNING = 3461571418L # Variable c_uint '-833395878u'
CKA_WRAP_TEMPLATE = 1073742353 # Variable c_int '1073742353'
CKR_SESSION_READ_ONLY_EXISTS = 183 # Variable c_int '183'
CKA_BITS_PER_PIXEL = 1030 # Variable c_int '1030'
SOL_IPV6 = 41 # Variable c_int '41'
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
SOL_ATM = 264 # Variable c_int '264'
CKM_CAST_MAC_GENERAL = 772 # Variable c_int '772'
_IO_INTERNAL = 8 # Variable c_int '8'
SEC_ASN1_ANY = 1024 # Variable c_int '1024'
CKM_SSL3_SHA1_MAC = 897 # Variable c_int '897'
CKA_APPLICATION = 16 # Variable c_int '16'
CKM_SHA256_HMAC_GENERAL = 594 # Variable c_int '594'
PR_TOP_IO_LAYER = -2 # Variable c_int '-0x000000002'
IPV6_MTU_DISCOVER = 23 # Variable c_int '23'
CKR_PIN_EXPIRED = 163 # Variable c_int '163'
CKM_AES_MAC_GENERAL = 4228 # Variable c_int '4228'
CKM_DES3_CBC_PAD = 310 # Variable c_int '310'
IP_ROUTER_ALERT = 5 # Variable c_int '5'
PR_NOT_SOCKET_ERROR = -5969 # Variable c_long '-0x000001751l'
CKF_LOGIN_REQUIRED = 4 # Variable c_int '4'
PR_INVALID_METHOD_ERROR = -5996 # Variable c_long '-0x00000176cl'
CKA_CERTIFICATE_CATEGORY = 135 # Variable c_int '135'
CKR_DEVICE_ERROR = 48 # Variable c_int '48'
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
IPV6_2292DSTOPTS = 4 # Variable c_int '4'
NS_CERT_TYPE_OBJECT_SIGNING = 16 # Variable c_int '16'
SEC_CRL_VERSION_2 = 1 # Variable c_int '1'
SEC_CRL_VERSION_1 = 0 # Variable c_int '0'
SIOCGPGRP = 35076 # Variable c_int '35076'
CKM_AES_CBC_ENCRYPT_DATA = 4357 # Variable c_int '4357'
__FD_ZERO_STOS = 'stosl' # Variable STRING '(const char*)"stosl"'
CKM_TLS_MASTER_KEY_DERIVE_DH = 887 # Variable c_int '887'
CKR_DOMAIN_PARAMS_INVALID = 304 # Variable c_int '304'
_G_HAVE_SYS_CDEFS = 1 # Variable c_int '1'
SECMOD_DSA_FLAG = 2 # Variable c_long '2l'
IP_RECVTTL = 12 # Variable c_int '12'
CKR_ATTRIBUTE_TYPE_INVALID = 18 # Variable c_int '18'
PR_INTERVAL_MIN = 1000L # Variable c_ulong '1000ul'
SO_ERROR = 4 # Variable c_int '4'
MCAST_LEAVE_GROUP = 45 # Variable c_int '45'
_IO_LINE_BUF = 512 # Variable c_int '512'
IPV6_RECVHOPLIMIT = 51 # Variable c_int '51'
certificateUsageSSLClient = 1 # Variable c_int '1'
_G_config_h = 1 # Variable c_int '1'
CKK_BLOWFISH = 32 # Variable c_int '32'
_IO_FLAGS2_MMAP = 1 # Variable c_int '1'
__GLIBC_HAVE_LONG_LONG = 1 # Variable c_int '1'
CKA_EXPONENT_1 = 294 # Variable c_int '294'
CKA_EXPONENT_2 = 295 # Variable c_int '295'
CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = 978 # Variable c_int '978'
CKF_WRAP = 131072 # Variable c_int '131072'
CKM_SHA256_RSA_PKCS = 64 # Variable c_int '64'
PR_INT8_MAX = 127 # Variable c_int '127'
CK_TRUE = 1 # Variable c_int '1'
SO_REUSEADDR = 2 # Variable c_int '2'
CKM_CAST128_MAC_GENERAL = 804 # Variable c_int '804'
SO_BINDTODEVICE = 25 # Variable c_int '25'
_STDLIB_H = 1 # Variable c_int '1'
GAI_NOWAIT = 1 # Variable c_int '1'
IN_CLASSC_HOST = 255L # Variable c_uint '255u'
PR_RDWR = 4 # Variable c_int '4'
SSL_SECURITY_STATUS_OFF = 0 # Variable c_int '0'
CKM_DES_OFB8 = 337 # Variable c_int '337'
__USE_XOPEN2K = 1 # Variable c_int '1'
SO_SECURITY_ENCRYPTION_TRANSPORT = 23 # Variable c_int '23'
CKA_DIGEST = 2164260864L # Variable c_ulong '-2130706432ul'
IPV6_RTHDRDSTOPTS = 55 # Variable c_int '55'
IP_DROP_MEMBERSHIP = 36 # Variable c_int '36'
CKR_WRAPPING_KEY_SIZE_RANGE = 276 # Variable c_int '276'
EAI_MEMORY = -10 # Variable c_int '-0x00000000a'
CKF_DIGEST = 1024 # Variable c_int '1024'
PR_SOCKET_ADDRESS_IS_BOUND_ERROR = -5967 # Variable c_long '-0x00000174fl'
_IO_LINKED = 128 # Variable c_int '128'
SFTK_MIN_USER_SLOT_ID = 4 # Variable c_int '4'
NS_CERT_TYPE_OBJECT_SIGNING_CA = 1 # Variable c_int '1'
PR_AF_INET6 = 10 # Variable c_int '10'
CKM_IDEA_CBC = 834 # Variable c_int '834'
CKR_STATE_UNSAVEABLE = 384 # Variable c_int '384'
CKM_RC5_MAC_GENERAL = 820 # Variable c_int '820'
IPV6_MULTICAST_HOPS = 18 # Variable c_int '18'
SSL_RENEGOTIATE_UNRESTRICTED = 1 # Variable c_int '1'
CKM_AES_ECB = 4225 # Variable c_int '4225'
SSL_NO_STEP_DOWN = 15 # Variable c_int '15'
CKF_EC_ECPARAMETERS = 4194304 # Variable c_int '4194304'
CKK_CAST128 = 24 # Variable c_int '24'
_STDINT_H = 1 # Variable c_int '1'
CKM_RC5_CBC = 818 # Variable c_int '818'
CKR_MECHANISM_INVALID = 112 # Variable c_int '112'
CKF_PROTECTED_AUTHENTICATION_PATH = 256 # Variable c_int '256'
CKM_FASTHASH = 4208 # Variable c_int '4208'
CKF_SECONDARY_AUTHENTICATION = 2048 # Variable c_int '2048'
CKF_REMOVABLE_DEVICE = 2 # Variable c_int '2'
CKR_NSS = 3461563216L # Variable c_uint '-833404080u'
CKM_SEED_CBC = 1618 # Variable c_int '1618'
CKM_CAST5_CBC = 802 # Variable c_int '802'
PR_LD_GLOBAL = 4 # Variable c_int '4'
SECMOD_MD2_FLAG = 1024 # Variable c_long '1024l'
CKM_DES_KEY_GEN = 288 # Variable c_int '288'
SEC_ASN1_DYNAMIC = 16384 # Variable c_int '16384'
CKA_KEY_TYPE = 256 # Variable c_int '256'
SO_RCVBUFFORCE = 33 # Variable c_int '33'
CKA_TRUST_IPSEC_USER = 3461571422L # Variable c_uint '-833395874u'
CKS_RW_PUBLIC_SESSION = 2 # Variable c_int '2'
PR_ACCEPT_READ_BUF_OVERHEAD = 248L # Variable c_uint '248u'
CKA_NETSCAPE_DB = 3584088832L # Variable c_ulong '-710878464ul'
IPV6_PMTUDISC_DONT = 0 # Variable c_int '0'
IP_UNBLOCK_SOURCE = 37 # Variable c_int '37'
EAI_OVERFLOW = -12 # Variable c_int '-0x00000000c'
CKM_TWOFISH_KEY_GEN = 4242 # Variable c_int '4242'
_PATH_SERVICES = '/etc/services' # Variable STRING '(const char*)"/etc/services"'
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
CKS_RW_USER_FUNCTIONS = 3 # Variable c_int '3'
CKA_OBJECT_ID = 18 # Variable c_int '18'
PR_UINT32_MAX = 4294967295L # Variable c_uint '-1u'
CKM_DES3_CBC_ENCRYPT_DATA = 4355 # Variable c_int '4355'
PR_DIRECTORY_LOOKUP_ERROR = -5973 # Variable c_long '-0x000001755l'
IP_HDRINCL = 3 # Variable c_int '3'
CERT_REV_M_SKIP_TEST_ON_MISSING_SOURCE = 0 # Variable c_long '0l'
CKM_SHA_1_HMAC_GENERAL = 546 # Variable c_int '546'
__SIZEOF_PTHREAD_RWLOCKATTR_T = 8 # Variable c_int '8'
NSSCK_VENDOR_NSS = 1314079568 # Variable c_int '1314079568'
CKF_USER_PIN_FINAL_TRY = 131072 # Variable c_int '131072'
IP_IPSEC_POLICY = 16 # Variable c_int '16'
CKH_CLOCK = 2 # Variable c_int '2'
CKA_ENCODING_METHODS = 1153 # Variable c_int '1153'
_BITS_PTHREADTYPES_H = 1 # Variable c_int '1'
_IO_FLAGS2_NOTCANCEL = 2 # Variable c_int '2'
PR_OPERATION_ABORTED_ERROR = -5935 # Variable c_long '-0x00000172fl'
_PATH_PROTOCOLS = '/etc/protocols' # Variable STRING '(const char*)"/etc/protocols"'
IPV6_RTHDR_TYPE_0 = 0 # Variable c_int '0'
SECMOD_INTERNAL = 1 # Variable c_int '1'
CKA_PRIVATE = 2 # Variable c_int '2'
SECMOD_SLOT_FLAGS = 'slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]' # Variable STRING '(const char*)"slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]"'
SEC_ASN1_APPLICATION = 64 # Variable c_int '64'
CERT_REV_M_REQUIRE_INFO_ON_MISSING_SOURCE = 8 # Variable c_long '8l'
CKK_DES2 = 20 # Variable c_int '20'
CKK_DES3 = 21 # Variable c_int '21'
DER_OUTER = 262144 # Variable c_int '262144'
SEC_CERT_NICKNAMES_SERVER = 3 # Variable c_int '3'
CKM_CDMF_ECB = 321 # Variable c_int '321'
CKK_CAST = 22 # Variable c_int '22'
PK11_ATTR_MODIFIABLE = 16 # Variable c_long '16l'
MCAST_MSFILTER = 48 # Variable c_int '48'
CERT_MAX_CERT_CHAIN = 20 # Variable c_int '20'
_SVID_SOURCE = 1 # Variable c_int '1'
CKM_SSL3_KEY_AND_MAC_DERIVE = 882 # Variable c_int '882'
IP_DEFAULT_MULTICAST_TTL = 1 # Variable c_int '1'
IPV6_V6ONLY = 26 # Variable c_int '26'
CKR_SESSION_EXISTS = 182 # Variable c_int '182'
CKM_PBE_MD5_CAST5_CBC = 932 # Variable c_int '932'
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
IN_CLASSA_NSHIFT = 24 # Variable c_int '24'
certificateUsageSSLServerWithStepUp = 4 # Variable c_int '4'
PR_IO_LAYER_HEAD = -3 # Variable c_int '-0x000000003'
CKM_DES3_ECB = 306 # Variable c_int '306'
IPV6_RECVPKTINFO = 49 # Variable c_int '49'
RF_KEY_COMPROMISE = 64 # Variable c_int '64'
CKR_CRYPTOKI_NOT_INITIALIZED = 400 # Variable c_int '400'
EAI_NONAME = -2 # Variable c_int '-0x000000002'
CKR_ENCRYPTED_DATA_INVALID = 64 # Variable c_int '64'
INET6_ADDRSTRLEN = 46 # Variable c_int '46'
CKF_SO_PIN_FINAL_TRY = 2097152 # Variable c_int '2097152'
SECMOD_MODULE_DB_FUNCTION_ADD = 1 # Variable c_int '1'
__WCHAR_MIN = -2147483648 # Variable c_int '-0x080000000'
SSL_SECURITY_STATUS_ON_HIGH = 1 # Variable c_int '1'
CKM_DES3_ECB_ENCRYPT_DATA = 4354 # Variable c_int '4354'
EAI_SOCKTYPE = -7 # Variable c_int '-0x000000007'
IPV6_RTHDR_STRICT = 1 # Variable c_int '1'
CKR_FUNCTION_NOT_PARALLEL = 81 # Variable c_int '81'
SSL_NOT_ALLOWED = 0 # Variable c_int '0'
_BITS_BYTESWAP_H = 1 # Variable c_int '1'
CKM_SSL3_PRE_MASTER_KEY_GEN = 880 # Variable c_int '880'
SEC_ASN1_OPTIONAL = 256 # Variable c_int '256'
AI_IDN_ALLOW_UNASSIGNED = 256 # Variable c_int '256'
_SIGSET_NWORDS = 32L # Variable c_uint '32u'
GAI_WAIT = 0 # Variable c_int '0'
CKM_DSA_KEY_PAIR_GEN = 16 # Variable c_int '16'
PR_ADDRESS_NOT_SUPPORTED_ERROR = -5985 # Variable c_long '-0x000001761l'
IPV6_RECVTCLASS = 66 # Variable c_int '66'
CKA_TRUST_IPSEC_TUNNEL = 3461571421L # Variable c_uint '-833395875u'
PR_IRWXG = 56 # Variable c_int '56'
_G_HAVE_ATEXIT = 1 # Variable c_int '1'
CERT_ENABLE_HTTP_FETCH = 2 # Variable c_int '2'
PR_IRWXO = 7 # Variable c_int '7'
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
CKA_OWNER = 132 # Variable c_int '132'
CKM_BLOWFISH_CBC = 4241 # Variable c_int '4241'
PR_UINT8_MAX = 255L # Variable c_uint '255u'
CKA_EXTRACTABLE = 354 # Variable c_int '354'
DER_EXPLICIT = 512 # Variable c_int '512'
CKO_PUBLIC_KEY = 2 # Variable c_int '2'
SEC_ASN1_ENUMERATED = 10 # Variable c_int '10'
IP_RECVERR = 11 # Variable c_int '11'
CKM_SKIPJACK_KEY_GEN = 4096 # Variable c_int '4096'
CK_UNAVAILABLE_INFORMATION = 4294967295L # Variable c_ulong '-1ul'
PR_CONNECT_REFUSED_ERROR = -5981 # Variable c_long '-0x00000175dl'
__SIZEOF_PTHREAD_MUTEXATTR_T = 4 # Variable c_int '4'
_POSIX_SOURCE = 1 # Variable c_int '1'
SEC_ASN1_VISIBLE_STRING = 26 # Variable c_int '26'
EAI_NOTCANCELED = -102 # Variable c_int '-0x000000066'
CKR_KEY_INDIGESTIBLE = 103 # Variable c_int '103'
CKM_CDMF_CBC = 322 # Variable c_int '322'
SEC_CERTIFICATE_REQUEST_VERSION = 0 # Variable c_int '0'
PR_IRGRP = 32 # Variable c_int '32'
CKA_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
SSL_ENABLE_SESSION_TICKETS = 18 # Variable c_int '18'
PR_CONNECT_TIMEOUT_ERROR = -5979 # Variable c_long '-0x00000175bl'
SSL_ENABLE_FDX = 11 # Variable c_int '11'
CRL_DECODE_DONT_COPY_DER = 1 # Variable c_int '1'
CKR_SIGNATURE_INVALID = 192 # Variable c_int '192'
CERT_REV_M_ALLOW_IMPLICIT_DEFAULT_SOURCE = 0 # Variable c_long '0l'
CKM_SKIPJACK_ECB64 = 4097 # Variable c_int '4097'
PR_LANGUAGE_I_DEFAULT = 0 # Variable c_int '0'
CKM_CAMELLIA_CBC = 1362 # Variable c_int '1362'
CK_NULL_PTR = 0 # Variable c_int '0'
_IO_SKIPWS = 1 # Variable c_int '1'
CKM_EXTRACT_KEY_FROM_KEY = 869 # Variable c_int '869'
CKR_TOKEN_WRITE_PROTECTED = 226 # Variable c_int '226'
CKR_NEED_TO_CREATE_THREADS = 9 # Variable c_int '9'
_IO_SCIENTIFIC = 2048 # Variable c_int '2048'
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
PR_INSUFFICIENT_RESOURCES_ERROR = -5974 # Variable c_long '-0x000001756l'
_ENDIAN_H = 1 # Variable c_int '1'
SECMOD_FIPS = 2 # Variable c_int '2'
__USE_FORTIFY_LEVEL = 2 # Variable c_int '2'
CKA_SUBPRIME = 305 # Variable c_int '305'
SEC_ASN1_PRIVATE = 192 # Variable c_int '192'
EAI_SYSTEM = -11 # Variable c_int '-0x00000000b'
PR_DIRECTORY_CORRUPTED_ERROR = -5944 # Variable c_long '-0x000001738l'
CKM_SHA256_RSA_PKCS_PSS = 67 # Variable c_int '67'
RF_AFFILIATION_CHANGED = 16 # Variable c_int '16'
KU_NON_REPUDIATION = 64 # Variable c_int '64'
CKF_HW = 1 # Variable c_int '1'
CKM_CONCATENATE_BASE_AND_DATA = 866 # Variable c_int '866'
CKR_KEY_HANDLE_INVALID = 96 # Variable c_int '96'
SO_PEERCRED = 17 # Variable c_int '17'
CKM_ECDSA_SHA1 = 4162 # Variable c_int '4162'
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
__WCLONE = 2147483648L # Variable c_uint '-2147483648u'
CKM_IDEA_MAC_GENERAL = 836 # Variable c_int '836'
CKM_BATON_SHUFFLE = 4149 # Variable c_int '4149'
CKK_SKIPJACK = 27 # Variable c_int '27'
PR_POLL_READ = 1 # Variable c_int '1'
CKF_EC_COMPRESS = 33554432 # Variable c_int '33554432'
SEC_ASN1_INLINE = 2048 # Variable c_int '2048'
CKM_X9_42_MQV_DERIVE = 51 # Variable c_int '51'
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
CKR_KEY_NEEDED = 102 # Variable c_int '102'
PR_LD_LAZY = 1 # Variable c_int '1'
SO_PEERNAME = 28 # Variable c_int '28'
NI_NAMEREQD = 8 # Variable c_int '8'
IPV6_AUTHHDR = 10 # Variable c_int '10'
PR_SYNC = 64 # Variable c_int '64'
CKM_CAST5_KEY_GEN = 800 # Variable c_int '800'
IPV6_2292PKTOPTIONS = 6 # Variable c_int '6'
_G_NAMES_HAVE_UNDERSCORE = 0 # Variable c_int '0'
_IO_NO_READS = 4 # Variable c_int '4'
CKF_USER_PIN_TO_BE_CHANGED = 524288 # Variable c_int '524288'
SSL_SECURITY_STATUS_NOOPT = -1 # Variable c_int '-0x000000001'
CERT_REV_MI_TEST_EACH_METHOD_SEPARATELY = 0 # Variable c_long '0l'
PR_FILE_IS_LOCKED_ERROR = -5958 # Variable c_long '-0x000001746l'
AI_IDN = 64 # Variable c_int '64'
__GLIBC_MINOR__ = 12 # Variable c_int '12'
SO_ACCEPTCONN = 30 # Variable c_int '30'
CKM_CAST3_KEY_GEN = 784 # Variable c_int '784'
CKM_BLOWFISH_KEY_GEN = 4240 # Variable c_int '4240'
IP_OPTIONS = 4 # Variable c_int '4'
SEC_ASN1_NO_STREAM = 2097152 # Variable c_int '2097152'
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
CKM_CAMELLIA_CBC_PAD = 1365 # Variable c_int '1365'
NS_CERT_TYPE_SSL_CA = 4 # Variable c_int '4'
IP_TTL = 2 # Variable c_int '2'
SEC_ASN1_UTF8_STRING = 12 # Variable c_int '12'
_IOS_NOCREATE = 32 # Variable c_int '32'
DER_CONTEXT_SPECIFIC = 128 # Variable c_int '128'
AI_ADDRCONFIG = 32 # Variable c_int '32'
SSL_REQUIRE_CERTIFICATE = 10 # Variable c_int '10'
CKM_DES_CBC = 290 # Variable c_int '290'
DER_FORCE = 65536 # Variable c_int '65536'
__USE_LARGEFILE = 1 # Variable c_int '1'
_FEATURES_H = 1 # Variable c_int '1'
CK_FALSE = 0 # Variable c_int '0'
SEC_ASN1_GROUP = 8192 # Variable c_int '8192'
CERT_REV_M_TEST_USING_THIS_METHOD = 1 # Variable c_long '1l'
PR_INT16_MIN = -32768 # Variable c_int '-0x000008000'
PR_INT32_MAX = 2147483647 # Variable c_int '2147483647'
PR_NSPR_ERROR_BASE = -6000 # Variable c_int '-0x000001770'
SFTK_MAX_USER_SLOT_ID = 100 # Variable c_int '100'
CKA_ALWAYS_AUTHENTICATE = 514 # Variable c_int '514'
CKK_EC = 3 # Variable c_int '3'
SSL_ROLLBACK_DETECTION = 14 # Variable c_int '14'
CKK_IDEA = 26 # Variable c_int '26'
IP_MINTTL = 21 # Variable c_int '21'
SEC_CERT_NICKNAMES_USER = 2 # Variable c_int '2'
KU_KEY_AGREEMENT = 8 # Variable c_int '8'
UIO_MAXIOV = 1024 # Variable c_int '1024'
SSL_ALLOWED = 1 # Variable c_int '1'
CERT_MAX_SERIAL_NUMBER_BYTES = 20 # Variable c_int '20'
SSL_NO_CACHE = 9 # Variable c_int '9'
SO_DETACH_FILTER = 27 # Variable c_int '27'
CKM_CAST5_ECB = 801 # Variable c_int '801'
IP_MULTICAST_TTL = 33 # Variable c_int '33'
CKR_FUNCTION_FAILED = 6 # Variable c_int '6'
CERT_REV_M_IGNORE_IMPLICIT_DEFAULT_SOURCE = 4 # Variable c_long '4l'
CKA_TRUST_NON_REPUDIATION = 3461571410L # Variable c_uint '-833395886u'
CKM_AES_MAC = 4227 # Variable c_int '4227'
CKR_FUNCTION_REJECTED = 512 # Variable c_int '512'
CERT_REV_M_FORBID_NETWORK_FETCHING = 2 # Variable c_long '2l'
PR_INT8_MIN = -128 # Variable c_int '-0x000000080'
CKO_CERTIFICATE = 1 # Variable c_int '1'
CKM_RIPEMD160_HMAC = 577 # Variable c_int '577'
SSL_SECURITY_STATUS_ON_LOW = 2 # Variable c_int '2'
HT_ENUMERATE_STOP = 1 # Variable c_int '1'
CKR_SAVED_STATE_INVALID = 352 # Variable c_int '352'
SECMOD_MODULE_DB_FUNCTION_RELEASE = 3 # Variable c_int '3'
KU_NS_GOVT_APPROVED = 32768 # Variable c_int '32768'
CKK_NSS = 3461563216L # Variable c_uint '-833404080u'
SO_TYPE = 3 # Variable c_int '3'
IPV6_LEAVE_ANYCAST = 28 # Variable c_int '28'
CERT_REV_MI_TEST_ALL_LOCAL_INFORMATION_FIRST = 1 # Variable c_long '1l'
_G_USING_THUNKS = 1 # Variable c_int '1'
SEC_CRL_TYPE = 1 # Variable c_int '1'
CERT_REV_MI_NO_OVERALL_INFO_REQUIREMENT = 0 # Variable c_long '0l'
FOPEN_MAX = 16 # Variable c_int '16'
IP_ADD_SOURCE_MEMBERSHIP = 39 # Variable c_int '39'
CKM_TLS_MASTER_KEY_DERIVE = 885 # Variable c_int '885'
CKM_AES_KEY_GEN = 4224 # Variable c_int '4224'
DER_UTC_TIME = 23 # Variable c_int '23'
CKR_ATTRIBUTE_VALUE_INVALID = 19 # Variable c_int '19'
CKA_KEY_GEN_MECHANISM = 358 # Variable c_int '358'
_PATH_HEQUIV = '/etc/hosts.equiv' # Variable STRING '(const char*)"/etc/hosts.equiv"'
CKR_USER_ALREADY_LOGGED_IN = 256 # Variable c_int '256'
CKM_DH_PKCS_DERIVE = 33 # Variable c_int '33'
CKA_SUBJECT = 257 # Variable c_int '257'
CKA_PRIME = 304 # Variable c_int '304'
DER_HIGH_TAG_NUMBER = 31 # Variable c_int '31'
CKM_CAMELLIA_CBC_ENCRYPT_DATA = 1367 # Variable c_int '1367'
CKF_RW_SESSION = 2 # Variable c_int '2'
SIOCATMARK = 35077 # Variable c_int '35077'
CKM_RIPEMD128_RSA_PKCS = 7 # Variable c_int '7'
CKM_PBE_SHA1_DES2_EDE_CBC = 937 # Variable c_int '937'
__timespec_defined = 1 # Variable c_int '1'
_STRUCT_TIMEVAL = 1 # Variable c_int '1'
CKC_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 242 # Variable c_int '242'
CKR_USER_TYPE_INVALID = 259 # Variable c_int '259'
CKR_GENERAL_ERROR = 5 # Variable c_int '5'
_SYS_UIO_H = 1 # Variable c_int '1'
__SIZEOF_PTHREAD_BARRIERATTR_T = 4 # Variable c_int '4'
SEC_ASN1_NUMERIC_STRING = 18 # Variable c_int '18'
_IOS_BIN = 128 # Variable c_int '128'
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
CKM_BATON_WRAP = 4150 # Variable c_int '4150'
CKM_SKIPJACK_CFB64 = 4100 # Variable c_int '4100'
CRL_DECODE_DEFAULT_OPTIONS = 0 # Variable c_int '0'
CKM_JUNIPER_KEY_GEN = 4192 # Variable c_int '4192'
CKM_SHA384_RSA_PKCS_PSS = 68 # Variable c_int '68'
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
SEEK_SET = 0 # Variable c_int '0'
CKR_RANDOM_NO_RNG = 289 # Variable c_int '289'
_IOS_OUTPUT = 2 # Variable c_int '2'
SO_ATTACH_FILTER = 26 # Variable c_int '26'
PK11_PW_AUTHENTICATED = 'AUTH' # Variable STRING '(const char*)"AUTH"'
CKU_SO = 0 # Variable c_int '0'
CKM_CDMF_CBC_PAD = 325 # Variable c_int '325'
PR_UNKNOWN_ERROR = -5994 # Variable c_long '-0x00000176al'
_LARGEFILE_SOURCE = 1 # Variable c_int '1'
CKM_ECMQV_DERIVE = 4178 # Variable c_int '4178'
SO_RCVTIMEO = 20 # Variable c_int '20'
_IO_LEFT = 2 # Variable c_int '2'
_STRING_H = 1 # Variable c_int '1'
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
_ARPA_INET_H = 1 # Variable c_int '1'
DER_SEQUENCE = 16 # Variable c_int '16'
CKK_ECDSA = 3 # Variable c_int '3'
CKM_SHA256_KEY_DERIVATION = 915 # Variable c_int '915'
MCAST_INCLUDE = 1 # Variable c_int '1'
SECMOD_FIPS_NAME = 'NSS Internal FIPS PKCS #11 Module' # Variable STRING '(const char*)"NSS Internal FIPS PKCS #11 Module"'
TRY_AGAIN = 2 # Variable c_int '2'
EAI_INPROGRESS = -100 # Variable c_int '-0x000000064'
CKM_SHA1_RSA_PKCS_PSS = 14 # Variable c_int '14'
CKM_SHA224_HMAC_GENERAL = 599 # Variable c_int '599'
DER_NULL = 5 # Variable c_int '5'
CKR_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
CKA_TRUST_STEP_UP_APPROVED = 3461571424L # Variable c_uint '-833395872u'
_NETDB_H = 1 # Variable c_int '1'
CKM_ECDH1_DERIVE = 4176 # Variable c_int '4176'
CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 260 # Variable c_int '260'
SECMOD_RESERVED_FLAG = 134217728 # Variable c_long '134217728l'
DER_INDEFINITE = 8192 # Variable c_int '8192'
CKM_JUNIPER_SHUFFLE = 4196 # Variable c_int '4196'
SEC_ASN1_TAGNUM_MASK = 31 # Variable c_int '31'
CKT_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
IPV6_RECVDSTOPTS = 58 # Variable c_int '58'
IPV6_MTU = 24 # Variable c_int '24'
__USE_BSD = 1 # Variable c_int '1'
CKR_RANDOM_SEED_NOT_SUPPORTED = 288 # Variable c_int '288'
CKA_WRAP_WITH_TRUSTED = 528 # Variable c_int '528'
__have_sigval_t = 1 # Variable c_int '1'
_IOS_NOREPLACE = 64 # Variable c_int '64'
INADDR_UNSPEC_GROUP = 3758096384L # Variable c_uint '-536870912u'
CKM_SKIPJACK_WRAP = 4104 # Variable c_int '4104'
CKF_GENERATE_KEY_PAIR = 65536 # Variable c_int '65536'
PR_POLL_HUP = 32 # Variable c_int '32'
SEEK_CUR = 1 # Variable c_int '1'
CKM_SHA1_RSA_X9_31 = 12 # Variable c_int '12'
CRL_DECODE_KEEP_BAD_CRL = 4 # Variable c_int '4'
CKF_EXTENSION = 2147483648L # Variable c_uint '-2147483648u'
PR_LD_LOCAL = 8 # Variable c_int '8'
IPV6_2292HOPLIMIT = 8 # Variable c_int '8'
CKM_PBE_SHA1_DES3_EDE_CBC = 936 # Variable c_int '936'
CK_INVALID_SESSION = 0 # Variable c_int '0'
SECMOD_INT_NAME = 'NSS Internal PKCS #11 Module' # Variable STRING '(const char*)"NSS Internal PKCS #11 Module"'
CKF_LIBRARY_CANT_CREATE_OS_THREADS = 1 # Variable c_int '1'
IPV6_NEXTHOP = 9 # Variable c_int '9'
CKA_NSS_OVERRIDE_EXTENSIONS = 3461563241L # Variable c_uint '-833404055u'
__STDC_IEC_559_COMPLEX__ = 1 # Variable c_int '1'
DER_VISIBLE_STRING = 26 # Variable c_int '26'
CKK_CAMELLIA = 37 # Variable c_int '37'
CKM_PBE_MD5_CAST128_CBC = 932 # Variable c_int '932'
SEC_CERT_NICKNAMES_CA = 4 # Variable c_int '4'
CKM_DES3_KEY_GEN = 305 # Variable c_int '305'
CRL_IMPORT_BYPASS_CHECKS = 1 # Variable c_int '1'
__SIGEV_PAD_SIZE = 13L # Variable c_uint '13u'
PR_DIRECTORY_OPEN_ERROR = -5988 # Variable c_long '-0x000001764l'
IPV6_CHECKSUM = 7 # Variable c_int '7'
SEC_ASN1_SAVE = 131072 # Variable c_int '131072'
CKA_SIGN = 264 # Variable c_int '264'
CKM_RSA_X9_31_KEY_PAIR_GEN = 10 # Variable c_int '10'
DER_PRIVATE = 192 # Variable c_int '192'
CKF_SO_PIN_TO_BE_CHANGED = 8388608 # Variable c_int '8388608'
CKZ_SALT_SPECIFIED = 1 # Variable c_int '1'
CKM_SKIPJACK_CFB32 = 4101 # Variable c_int '4101'
SSL_MAX_EXTENSIONS = 5 # Variable c_int '5'
DER_PRIMITIVE = 0 # Variable c_int '0'
_G_NEED_STDARG_H = 1 # Variable c_int '1'
CKA_COLOR = 1029 # Variable c_int '1029'
CKD_SHA1_KDF = 2 # Variable c_int '2'
NS_CERT_TYPE_SSL_CLIENT = 128 # Variable c_int '128'
SECMOD_FIPS_FLAGS = 'Flags=internal,critical,fips slotparams=(3={slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]})' # Variable STRING '(const char*)"Flags=internal,critical,fips slotparams=(3={slotFlags=[RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512]})"'
certificateUsageUserCertImport = 128 # Variable c_int '128'
CKM_MD5_RSA_PKCS = 5 # Variable c_int '5'
CKR_DATA_LEN_RANGE = 33 # Variable c_int '33'
CKM_DSA = 17 # Variable c_int '17'
_ATFILE_SOURCE = 1 # Variable c_int '1'
SEC_ASN1_SET_OF = 8209 # Variable c_int '8209'
PR_IO_PENDING_ERROR = -5989 # Variable c_long '-0x000001765l'
SSL_ENABLE_DEFLATE = 19 # Variable c_int '19'
CKM_CAST3_MAC = 787 # Variable c_int '787'
CKF_SO_PIN_LOCKED = 4194304 # Variable c_int '4194304'
CERT_POLICY_FLAG_EXPLICIT = 2 # Variable c_int '2'
PR_MAX_IOVECTOR_SIZE = 16 # Variable c_int '16'
CKA_TRUST = 3461571408L # Variable c_uint '-833395888u'
PR_CONNECT_ABORTED_ERROR = -5928 # Variable c_long '-0x000001728l'
DER_OCTET_STRING = 4 # Variable c_int '4'
CKR_INFORMATION_SENSITIVE = 368 # Variable c_int '368'
IP_PASSSEC = 18 # Variable c_int '18'
CKM_SKIPJACK_PRIVATE_WRAP = 4105 # Variable c_int '4105'
__SIZEOF_PTHREAD_CONDATTR_T = 4 # Variable c_int '4'
SSL_CBP_SSL3 = 1 # Variable c_int '1'
NSS_USE_ALG_IN_CERT_SIGNATURE = 1 # Variable c_int '1'
PR_NSPR_IO_LAYER = 0 # Variable c_int '0'
CERT_REV_M_STOP_TESTING_ON_FRESH_INFO = 0 # Variable c_long '0l'
_PATH_NSSWITCH_CONF = '/etc/nsswitch.conf' # Variable STRING '(const char*)"/etc/nsswitch.conf"'
CKR_SESSION_HANDLE_INVALID = 179 # Variable c_int '179'
SEC_ASN1_PRIMITIVE = 0 # Variable c_int '0'
PR_ALREADY_INITIATED_ERROR = -5933 # Variable c_long '-0x00000172dl'
PR_NO_DEVICE_SPACE_ERROR = -5956 # Variable c_long '-0x000001744l'
CERT_POLICY_FLAG_NO_ANY = 4 # Variable c_int '4'
_ALLOCA_H = 1 # Variable c_int '1'
SO_MARK = 36 # Variable c_int '36'
SSL_CBP_TLS1_0 = 2 # Variable c_int '2'
__USE_POSIX199309 = 1 # Variable c_int '1'
DER_BIT_STRING = 3 # Variable c_int '3'
SEC_ASN1_UNIVERSAL = 0 # Variable c_int '0'
PR_POLL_NVAL = 16 # Variable c_int '16'
CKK_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
__lldiv_t_defined = 1 # Variable c_int '1'
PR_NSEC_PER_MSEC = 1000000L # Variable c_ulong '1000000ul'
__SIZEOF_PTHREAD_BARRIER_T = 20 # Variable c_int '20'
_IO_DONT_CLOSE = 32768 # Variable c_int '32768'
CKM_WTLS_PRF = 979 # Variable c_int '979'
_CTYPE_H = 1 # Variable c_int '1'
MCAST_JOIN_SOURCE_GROUP = 46 # Variable c_int '46'
CKK_AES = 31 # Variable c_int '31'
CKA_SENSITIVE = 259 # Variable c_int '259'
NSS_USE_ALG_RESERVED = 4294967292L # Variable c_uint '-4u'
_PATH_NETWORKS = '/etc/networks' # Variable STRING '(const char*)"/etc/networks"'
CKZ_DATA_SPECIFIED = 1 # Variable c_int '1'
CKR_OBJECT_HANDLE_INVALID = 130 # Variable c_int '130'
SSL_HANDSHAKE_AS_CLIENT = 5 # Variable c_int '5'
__WNOTHREAD = 536870912 # Variable c_int '536870912'
CKM_DES_CBC_ENCRYPT_DATA = 4353 # Variable c_int '4353'
CKM_SHA1_RSA_PKCS = 6 # Variable c_int '6'
SEC_ASN1_SEQUENCE_OF = 8208 # Variable c_int '8208'
CKA_PUBLIC_EXPONENT = 290 # Variable c_int '290'
CKM_NSS = 3461563216L # Variable c_uint '-833404080u'
CKM_CAST_MAC = 771 # Variable c_int '771'
RF_CA_COMPROMISE = 32 # Variable c_int '32'
CKR_KEY_FUNCTION_NOT_PERMITTED = 104 # Variable c_int '104'
CKM_RC4_KEY_GEN = 272 # Variable c_int '272'
CKM_IDEA_ECB = 833 # Variable c_int '833'
CKR_MUTEX_NOT_LOCKED = 417 # Variable c_int '417'
CKK_JUNIPER = 29 # Variable c_int '29'
CKM_CAMELLIA_MAC_GENERAL = 1364 # Variable c_int '1364'
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
CKU_CONTEXT_SPECIFIC = 2 # Variable c_int '2'
CKM_RSA_PKCS_PSS = 13 # Variable c_int '13'
CKM_RSA_PKCS_KEY_PAIR_GEN = 0 # Variable c_int '0'
SFTK_MAX_FIPS_USER_SLOT_ID = 127 # Variable c_int '127'
CKM_IDEA_CBC_PAD = 837 # Variable c_int '837'
WEXITED = 4 # Variable c_int '4'
certificateUsageCheckAllUsages = 0 # Variable c_int '0'
CKM_RIPEMD160_HMAC_GENERAL = 578 # Variable c_int '578'
CKM_RC2_MAC = 259 # Variable c_int '259'
__USE_ISOC95 = 1 # Variable c_int '1'
CKR_PIN_LEN_RANGE = 162 # Variable c_int '162'
PR_ACCESS_FAULT_ERROR = -5997 # Variable c_long '-0x00000176dl'
CKM_CONCATENATE_BASE_AND_KEY = 864 # Variable c_int '864'
__USE_ISOC99 = 1 # Variable c_int '1'
CKM_DES_CFB64 = 338 # Variable c_int '338'
IPV6_MULTICAST_LOOP = 19 # Variable c_int '19'
NS_CERT_TYPE_EMAIL_CA = 2 # Variable c_int '2'
CKM_CAST_CBC = 770 # Variable c_int '770'
SECMOD_AES_FLAG = 8192 # Variable c_long '8192l'
PR_IS_DIRECTORY_ERROR = -5953 # Variable c_long '-0x000001741l'
SEC_ASN1_CLASS_MASK = 192 # Variable c_int '192'
IPPORT_RESERVED = 1024 # Variable c_int '1024'
CKM_RIPEMD160 = 576 # Variable c_int '576'
PR_EXCL = 128 # Variable c_int '128'
EAI_SERVICE = -8 # Variable c_int '-0x000000008'
__USE_XOPEN = 1 # Variable c_int '1'
CKR_SIGNATURE_LEN_RANGE = 193 # Variable c_int '193'
CKM_SHA512_KEY_DERIVATION = 917 # Variable c_int '917'
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
CKM_DES3_MAC_GENERAL = 309 # Variable c_int '309'
SEC_ASN1_ANY_CONTENTS = 66560 # Variable c_int '66560'
_IO_CURRENTLY_PUTTING = 2048 # Variable c_int '2048'
IPV6_IPSEC_POLICY = 34 # Variable c_int '34'
__SOCKADDR_COMMON_SIZE = 2L # Variable c_uint '2u'
CKR_TEMPLATE_INCONSISTENT = 209 # Variable c_int '209'
CKK_TWOFISH = 33 # Variable c_int '33'
SO_BSDCOMPAT = 14 # Variable c_int '14'
SO_SNDLOWAT = 19 # Variable c_int '19'
CKA_WRAP = 262 # Variable c_int '262'
IP_TOS = 1 # Variable c_int '1'
CKG_MGF1_SHA256 = 2 # Variable c_int '2'
CKF_SO_PIN_COUNT_LOW = 1048576 # Variable c_int '1048576'
PR_NO_SEEK_DEVICE_ERROR = -5954 # Variable c_long '-0x000001742l'
SEC_ASN1_VIDEOTEX_STRING = 21 # Variable c_int '21'
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
IP_MSFILTER = 41 # Variable c_int '41'
SSL_ENABLE_SSL2 = 7 # Variable c_int '7'
SSL_ENABLE_SSL3 = 8 # Variable c_int '8'
CKM_TLS_PRE_MASTER_KEY_GEN = 884 # Variable c_int '884'
CKA_MODULUS = 288 # Variable c_int '288'
IP_PMTUDISC_DONT = 0 # Variable c_int '0'
PR_INTERVAL_NO_TIMEOUT = 4294967295L # Variable c_ulong '-1ul'
_XOPEN_SOURCE_EXTENDED = 1 # Variable c_int '1'
SEC_ASN1_MAY_STREAM = 262144 # Variable c_int '262144'
CKM_DES_CFB8 = 339 # Variable c_int '339'
SOL_SOCKET = 1 # Variable c_int '1'
CKA_CERT_MD5_HASH = 3461571509L # Variable c_uint '-833395787u'
CKG_MGF1_SHA1 = 1 # Variable c_int '1'
PR_USEC_PER_SEC = 1000000L # Variable c_ulong '1000000ul'
CKM_SSL3_MASTER_KEY_DERIVE_DH = 883 # Variable c_int '883'
_BSD_SOURCE = 1 # Variable c_int '1'
IP_ADD_MEMBERSHIP = 35 # Variable c_int '35'
CKU_USER = 1 # Variable c_int '1'
AI_NUMERICSERV = 1024 # Variable c_int '1024'
CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC = 2147483651L # Variable c_ulong '-2147483645ul'
_IO_USER_BUF = 1 # Variable c_int '1'
__USE_LARGEFILE64 = 1 # Variable c_int '1'
SECMOD_DES_FLAG = 16 # Variable c_long '16l'
CKA_VERIFY_RECOVER = 267 # Variable c_int '267'
certificateUsageStatusResponder = 1024 # Variable c_int '1024'
PR_IXOTH = 1 # Variable c_int '1'
CKM_DES_CBC_PAD = 293 # Variable c_int '293'
CKR_PIN_LOCKED = 164 # Variable c_int '164'
IN_CLASSA_NET = 4278190080L # Variable c_uint '-16777216u'
CKM_INVALID_MECHANISM = 4294967295L # Variable c_ulong '-1ul'
CKR_ATTRIBUTE_SENSITIVE = 17 # Variable c_int '17'
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
SO_SNDBUF = 7 # Variable c_int '7'
IPV6_UNICAST_HOPS = 16 # Variable c_int '16'
CKA_SECONDARY_AUTH = 512 # Variable c_int '512'
CKA_VALUE_BITS = 352 # Variable c_int '352'
PR_FILE_NOT_FOUND_ERROR = -5950 # Variable c_long '-0x00000173el'
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
_IOFBF = 0 # Variable c_int '0'
CKA_NEVER_EXTRACTABLE = 356 # Variable c_int '356'
CKA_UNWRAP = 263 # Variable c_int '263'
PR_DEVICE_IS_LOCKED_ERROR = -5940 # Variable c_long '-0x000001734l'
certificateUsageEmailRecipient = 32 # Variable c_int '32'
__SIGEV_MAX_SIZE = 64 # Variable c_int '64'
__USE_POSIX199506 = 1 # Variable c_int '1'
CKR_SESSION_CLOSED = 176 # Variable c_int '176'
CKK_INVALID_KEY_TYPE = 4294967295L # Variable c_uint '-1u'
CKH_VENDOR_DEFINED = 2147483648L # Variable c_uint '-2147483648u'
DER_OBJECT_ID = 6 # Variable c_int '6'
SEC_ASN1_GENERALIZED_TIME = 24 # Variable c_int '24'
PR_RANGE_ERROR = -5960 # Variable c_long '-0x000001748l'
DER_TAGNUM_MASK = 31 # Variable c_int '31'
_G_HAVE_PRINTF_FP = 1 # Variable c_int '1'
_SECMODT_H_ = 1 # Variable c_int '1'
DER_INLINE = 2048 # Variable c_int '2048'
WCONTINUED = 8 # Variable c_int '8'
CKM_SHA384_HMAC_GENERAL = 610 # Variable c_int '610'
CKM_CAST128_CBC_PAD = 805 # Variable c_int '805'
CKM_SHA1_KEY_DERIVATION = 914 # Variable c_int '914'
CKA_NSS = 3461563216L # Variable c_uint '-833404080u'
CKR_SESSION_READ_ONLY = 181 # Variable c_int '181'
WSTOPPED = 2 # Variable c_int '2'
PR_BAD_DESCRIPTOR_ERROR = -5999 # Variable c_long '-0x00000176fl'
CKM_PBE_SHA1_RC2_128_CBC = 938 # Variable c_int '938'
CKR_PIN_INVALID = 161 # Variable c_int '161'
CKP_PKCS5_PBKD2_HMAC_SHA1 = 1 # Variable c_int '1'
CKR_FUNCTION_CANCELED = 80 # Variable c_int '80'
IS_LITTLE_ENDIAN = 1 # Variable c_int '1'
INADDR_ALLRTRS_GROUP = 3758096386L # Variable c_uint '-536870910u'
PR_INTERVAL_MAX = 100000L # Variable c_ulong '100000ul'
IP_PMTUDISC_PROBE = 3 # Variable c_int '3'
_PKCS11T_H_ = 1 # Variable c_int '1'
_SS_PADSIZE = 120L # Variable c_uint '120u'
CKA_TOKEN = 1 # Variable c_int '1'
CKM_XOR_BASE_AND_DATA = 868 # Variable c_int '868'
PR_NETWORK_DOWN_ERROR = -5930 # Variable c_long '-0x00000172al'
PR_TRUNCATE = 32 # Variable c_int '32'
CKF_RESTORE_KEY_NOT_NEEDED = 32 # Variable c_int '32'
CKR_WRAPPING_KEY_HANDLE_INVALID = 275 # Variable c_int '275'
SECMOD_CAMELLIA_FLAG = 65536 # Variable c_long '65536l'
PR_IWUSR = 128 # Variable c_int '128'
_G_VTABLE_LABEL_PREFIX = '__vt_' # Variable STRING '(const char*)"__vt_"'
CKM_BATON_ECB128 = 4145 # Variable c_int '4145'
_SYS_SELECT_H = 1 # Variable c_int '1'
CKM_JUNIPER_WRAP = 4197 # Variable c_int '4197'
SO_SNDBUFFORCE = 32 # Variable c_int '32'
_ISOC95_SOURCE = 1 # Variable c_int '1'
CKF_ARRAY_ATTRIBUTE = 1073741824 # Variable c_int '1073741824'
CKF_DECRYPT = 512 # Variable c_int '512'
CKO_SECRET_KEY = 4 # Variable c_int '4'
HT_FREE_ENTRY = 1 # Variable c_int '1'
CKF_UNWRAP = 262144 # Variable c_int '262144'
AI_CANONNAME = 2 # Variable c_int '2'
CKA_VALUE_LEN = 353 # Variable c_int '353'
__clock_t_defined = 1 # Variable c_int '1'
_STDIO_H = 1 # Variable c_int '1'
AI_PASSIVE = 1 # Variable c_int '1'
CKM_SHA224_KEY_DERIVATION = 918 # Variable c_int '918'
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
CKM_MD2_HMAC = 513 # Variable c_int '513'
PR_IN_PROGRESS_ERROR = -5934 # Variable c_long '-0x00000172el'
SEEK_END = 2 # Variable c_int '2'
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
CKO_NSS = 3461563216L # Variable c_uint '-833404080u'
KU_KEY_AGREEMENT_OR_ENCIPHERMENT = 16384 # Variable c_int '16384'
_IO_OCT = 32 # Variable c_int '32'
CKR_WRAPPED_KEY_INVALID = 272 # Variable c_int '272'
CKM_SHA224_RSA_PKCS = 70 # Variable c_int '70'
CKM_CAMELLIA_MAC = 1363 # Variable c_int '1363'
CKR_USER_TOO_MANY_TYPES = 261 # Variable c_int '261'
AI_IDN_USE_STD3_ASCII_RULES = 512 # Variable c_int '512'
CKD_SHA1_KDF_ASN1 = 3 # Variable c_int '3'
PR_FALSE = 0 # Variable c_int '0'
NI_MAXSERV = 32 # Variable c_int '32'
CKR_PIN_INCORRECT = 160 # Variable c_int '160'
PR_RDONLY = 1 # Variable c_int '1'
EAI_IDN_ENCODE = -105 # Variable c_int '-0x000000069'
CKR_WRAPPED_KEY_LEN_RANGE = 274 # Variable c_int '274'
IPV6_JOIN_ANYCAST = 27 # Variable c_int '27'
_IO_FLAGS2_USER_WBUF = 8 # Variable c_int '8'
CKM_DES_OFB64 = 336 # Variable c_int '336'
CKA_CERTIFICATE_TYPE = 128 # Variable c_int '128'
_IO_MAGIC_MASK = 4294901760L # Variable c_uint '-65536u'
PR_IXGRP = 8 # Variable c_int '8'
PR_IWOTH = 2 # Variable c_int '2'
CKM_EC_KEY_PAIR_GEN = 4160 # Variable c_int '4160'
CERT_REV_M_CONTINUE_TESTING_ON_FRESH_INFO = 32 # Variable c_long '32l'
IPV6_XFRM_POLICY = 35 # Variable c_int '35'
CKA_ID = 258 # Variable c_int '258'
LL_ZERO = 0L # Variable c_longlong '0ll'
HOST_NOT_FOUND = 1 # Variable c_int '1'
IP_MULTICAST_IF = 32 # Variable c_int '32'
EAI_BADFLAGS = -1 # Variable c_int '-0x000000001'
SEC_CERT_CLASS_SERVER = 2 # Variable c_int '2'
EXIT_FAILURE = 1 # Variable c_int '1'
CKR_HOST_MEMORY = 2 # Variable c_int '2'
_IOLBF = 1 # Variable c_int '1'
_G_int16_t = c_short
_G_int32_t = c_int
_G_uint16_t = c_ushort
_G_uint32_t = c_uint
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
class N8sigevent4DOT_22E(Union):
    pass
class N8sigevent4DOT_224DOT_23E(Structure):
    pass
N8sigevent4DOT_224DOT_23E._fields_ = [
    ('_function', CFUNCTYPE(None, sigval_t)),
    ('_attribute', c_void_p),
]
N8sigevent4DOT_22E._fields_ = [
    ('_pad', c_int * 13),
    ('_tid', __pid_t),
    ('_sigev_thread', N8sigevent4DOT_224DOT_23E),
]
sigevent._fields_ = [
    ('sigev_value', sigval_t),
    ('sigev_signo', c_int),
    ('sigev_notify', c_int),
    ('_sigev_un', N8sigevent4DOT_22E),
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
class N4wait4DOT_35E(Structure):
    pass
N4wait4DOT_35E._fields_ = [
    ('__w_termsig', c_uint, 7),
    ('__w_coredump', c_uint, 1),
    ('__w_retcode', c_uint, 8),
    ('', c_uint, 16),
]
class N4wait4DOT_36E(Structure):
    pass
N4wait4DOT_36E._fields_ = [
    ('__w_stopval', c_uint, 8),
    ('__w_stopsig', c_uint, 8),
    ('', c_uint, 16),
]
wait._fields_ = [
    ('w_status', c_int),
    ('__wait_terminated', N4wait4DOT_35E),
    ('__wait_stopped', N4wait4DOT_36E),
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
class N8in6_addr4DOT_21E(Union):
    pass
uint8_t = c_uint8
N8in6_addr4DOT_21E._fields_ = [
    ('__u6_addr8', uint8_t * 16),
    ('__u6_addr16', uint16_t * 8),
    ('__u6_addr32', uint32_t * 4),
]
in6_addr._fields_ = [
    ('__in6_u', N8in6_addr4DOT_21E),
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
__all__ = ['certRFC822Name', 'SECMOD_SHA256_FLAG',
           'SEC_OID_PKCS9_MESSAGE_DIGEST', 'PK11SlotInfo',
           'AI_CANONIDN', 'SSL_ENABLE_RENEGOTIATION', 'CKO_NSS',
           'SEC_OID_X509_HOLD_INSTRUCTION_CODE', '__OFF64_T_TYPE',
           'SO_RCVBUF', 'CKA_NSS_PASSWORD_CHECK', 'siVisibleString',
           '__off64_t', 'PR_FILESYSTEM_MOUNTED_ERROR',
           'SEC_OID_PKCS12_V1_KEY_BAG_ID',
           'CKM_CONCATENATE_DATA_AND_BASE', 'SECMOD_SSL_FLAG',
           'CKR_TOKEN_NOT_PRESENT', 'SEC_ASN1_CONSTRUCTED',
           'PR_PROTOCOL_NOT_SUPPORTED_ERROR', 'CKM_DSA_PARAMETER_GEN',
           'PK11SlotListStr', '__USE_SVID', 'CERTCertificateStr',
           '__BYTE_ORDER', '_IO_BUFSIZ', 'CKR_DATA_INVALID',
           'CKM_JUNIPER_CBC128', '__FILE', '_IO_off64_t',
           'CERTSubjectPublicKeyInfo', 'MSG_CTRUNC',
           'CKM_PBE_MD5_CAST3_CBC', 'BITS_PER_WORD_LOG2',
           'CKR_KEY_NOT_WRAPPABLE', 'CKR_USER_ALREADY_LOGGED_IN',
           '__NFDBITS', 'SEC_OID_PKCS12_OIDS', 'in_port_t',
           '_IO_cookie_io_functions_t', 'IPPORT_TTYLINK',
           'SECKEYDHPublicKey', 'trustObjectSigning',
           'PR_IS_CONNECTED_ERROR', 'CKT_NSS', 'nssILockKeyDB',
           'in_pktinfo', 'LL_MAXUINT', 'CERTCrlHeadNode',
           'CKM_BATON_WRAP', 'SEC_OID_SECG_EC_SECP112R2',
           'SEC_OID_SECG_EC_SECP112R1', 'SEC_OID_PKIX_OCSP_NO_CHECK',
           'CK_WTLS_PRF_PARAMS', 'CKK_X9_42_DH',
           'IPV6_DROP_MEMBERSHIP', 'PR_READ_ONLY_FILESYSTEM_ERROR',
           'NI_IDN', 'cert_pi_useAIACertFetch', 'SIGEV_NONE',
           'CKK_DH', 'CKM_SHA_1_HMAC', 'CKA_PIXEL_Y', 'PR_AF_INET',
           'SEC_CERT_CLASS_USER', 'PRTime', 'CKF_USER_PIN_LOCKED',
           'siUTF8String', 'CERTDERCertsStr', 'CKA_NETSCAPE_EMAIL',
           'SECMOD_RC2_FLAG', 'CKA_PRIVATE_EXPONENT',
           'SSL_V2_COMPATIBLE_HELLO', 'PR_INADDR_ANY',
           'CERTCrlDistributionPointsStr', '_IO_SHOWBASE',
           'SEC_OID_ISO_SHA1_WITH_RSA_SIGNATURE', 'CKA_RESOLUTION',
           'CK_ATTRIBUTE_PTR', 'fortezzaKey', 'AF_KEY', 'in_addr',
           'be64toh', 'SOCK_CLOEXEC', 'PR_FILE_TOO_BIG_ERROR',
           'IPPROTO_ENCAP', 'IPPROTO_ESP', 'SEC_OID_AES_128_KEY_WRAP',
           'CKF_SERIAL_SESSION', 'PRErrorCallbackPrivate',
           '__locale_data', 'SEC_OID_PKCS5_PBKDF2', '__isgraph_l',
           'CKM_SEED_CBC_ENCRYPT_DATA', 'CK_VOID_PTR',
           'ip_mreq_source', 'SEC_ASN1_EXPLICIT', 'siDERNameBuffer',
           'SEC_OID_SECG_EC_SECP128R1', 'SEC_OID_SECG_EC_SECP128R2',
           'CKM_SHA256', 'IPV6_RTHDR', 'PK11CertListRootUnique',
           'CKA_TRUST_EMAIL_PROTECTION', 'CKM_X9_42_DH_HYBRID_DERIVE',
           'CK_MECHANISM_INFO', 'CERT_MAX_DN_BYTES', '__P',
           'SSL_REQUIRE_FIRST_HANDSHAKE', 'CKM_KEA_KEY_DERIVE',
           'PR_HOST_UNREACHABLE_ERROR', 'PRHashFunction',
           'CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC', 'SSLSniNameType',
           'siEncodedNameBuffer', '_IO_DEC',
           'CKM_TLS_PRE_MASTER_KEY_GEN', 'SECKEYPQGDualParamsStr',
           'NSSCK_VENDOR_NSS', 'AF_NETBEUI',
           'certificateUsageVerifyCA',
           'SEC_OID_PKCS12_X509_CERT_CRL_BAG', '_IO_ERR_SEEN',
           'SEC_OID_NS_CERT_EXT_USER_PICTURE', 'PR_DESC_LAYERED',
           'BITS_PER_SHORT_LOG2', 'PK11_ATTR_SESSION',
           'SEC_OID_X509_CERTIFICATE_POLICIES',
           'CERTCertificateInhibitAny', 'CKA_MIME_TYPES', 'isblank_l',
           'sockaddr_in', 'SEC_ASN1TemplateChooser',
           'SECKEY_Attributes_Cached', 'MCAST_JOIN_GROUP',
           '_G_va_list', 'SEC_OID_PKIX_USER_NOTICE_QUALIFIER',
           'RF_CA_COMPROMISE', 'CK_INFO', 'BITS_PER_DOUBLE_LOG2',
           'SO_TIMESTAMPING', '__iscntrl_l', 'PRFileInfoFN',
           'CKA_EXTRACTABLE', 'NI_IDN_ALLOW_UNASSIGNED', '_IO_uid_t',
           'PR_LOG_TEST', 'CKA_TRUST_TIME_STAMPING', 'PK11TokenEvent',
           'CERTCRLEntryReasonCode', 'SEC_ASN1TemplateChooserPtr',
           'CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC',
           'CKM_RIPEMD128_HMAC', 'CKA_VERIFY', 'SECKEYECPublicKeyStr',
           'PR_INT16_MAX', 'PR_AF_LOCAL', '_IO_FILE',
           'SEC_OID_X509_ISSUER_ALT_NAME',
           'CK_X9_42_MQV_DERIVE_PARAMS', 'PK11CertListCAUnique',
           '__FD_ISSET', '_IO_BOOLALPHA', 'rsaPssKey', 'PF_APPLETALK',
           'CERTAttributeStr', 'SEC_OID_AES_128_ECB',
           'SEC_OID_NS_KEY_USAGE_GOVT_APPROVED', 'PR_TRUE',
           'CKF_VERIFY', 'off_t', 'SEC_ASN1_DEBUG_BREAK',
           'siAsciiNameString', 'CKA_WRAP_TEMPLATE',
           'CKM_PBE_SHA1_CAST128_CBC', '__fsblkcnt_t',
           'PR_FILE_OTHER', 'PRAvailable64FN',
           'EXT_KEY_USAGE_STATUS_RESPONDER', 'CK_WTLS_KEY_MAT_OUT',
           'CERTValInParam', 'ssl_hmac_md5', 'CK_CMS_SIG_PARAMS',
           'SEC_OID_SECG_EC_SECT163R2', 'SEC_OID_SECG_EC_SECT163R1',
           'ssl_auth_rsa', 'AF_LLC', 'CK_RC2_CBC_PARAMS_PTR',
           'CKR_KEY_PARAMS_INVALID', 'PRReservedFN', 'CERTAttribute',
           'CKT_NSS_TRUSTED_DELEGATOR', 'PLHashFunction',
           'CKM_SHA224_RSA_PKCS_PSS', 'CERT_StringFromCertFcn',
           '_XOPEN_SOURCE', 'u_short', 'CKG_MGF1_SHA512',
           'SEC_OID_ANSIX962_EC_C2ONB191V4',
           'SEC_OID_ANSIX962_EC_C2ONB191V5', 'CKF_GENERATE',
           'IN_CLASSA_MAX', 'PR_MSEC_PER_SEC', 'IPPORT_CMDSERVER',
           'PR_LIBRARY_NOT_LOADED_ERROR',
           'SO_SECURITY_ENCRYPTION_NETWORK', '__GLIBC__',
           'pthread_rwlockattr_t', 'PR_BYTES_PER_INT64',
           'SO_PROTOCOL', 'SO_OOBINLINE',
           'N15pthread_mutex_t17__pthread_mutex_s3DOT_6E',
           'SECCertUsage', 'CK_SKIPJACK_RELAYX_PARAMS',
           'CKA_BITS_PER_PIXEL', 'SEC_ASN1_SKIP', '_XLOCALE_H',
           'CERTGeneralNameListStr', 'CKM_AES_CBC',
           'PK11CertListUnique', 'SECKEYAttributeStr',
           '_IO_FILE_plus', 'CERTCertificateListStr',
           'SEC_OID_PKCS12_V1_CRL_BAG_ID',
           'SEC_OID_X509_SUBJECT_DIRECTORY_ATTR',
           'CKH_MONOTONIC_COUNTER', 'CKM_SKIPJACK_OFB64', 'PR_IWGRP',
           '_IONBF', 'CKR_BUFFER_TOO_SMALL', 'pthread_mutexattr_t',
           'PR_SYS_DESC_TABLE_FULL_ERROR',
           'UNSUPPORTED_CERT_EXTENSION', 'PF_ROSE', '_BITS_UIO_H',
           'SEC_OID_PKCS9_FRIENDLY_NAME', 'CK_CALLBACK_FUNCTION',
           '__USE_POSIX2', 'CKA_ALWAYS_SENSITIVE', '_IO_marker',
           'PRSendtoFN', 'IPV6_RECVRTHDR',
           'SEC_OID_PKIX_OCSP_ARCHIVE_CUTOFF', 'CERTRDN',
           'PR_BYTES_PER_WORD', 'SSL_RENEGOTIATE_NEVER',
           'SSL_BYPASS_PKCS11', 'NS_CERT_TYPE_SSL_SERVER',
           'CKM_MD2_HMAC_GENERAL', 'SEC_OID_PKIX_OCSP', 'AF_PHONET',
           'u_char', 'SEC_OID_AVA_HOUSE_IDENTIFIER',
           'CKR_MECHANISM_PARAM_INVALID', 'PZ_NewCondVar',
           'u_int16_t', 'SECAlgorithmIDStr', 'SECStatus',
           'CKM_SEED_ECB_ENCRYPT_DATA', 'CERTValParamOutValueStr',
           'CERTCrlStr', 'AF_FILE', 'SECTrustTypeEnum', 'CKF_RNG',
           'SEC_ASN1_NULL', 'CKA_HAS_RESET', 'EAI_FAIL',
           'IP_RECVOPTS', 'CERTCertDBHandle',
           'SEC_OID_ANSIX962_EC_C2PNB368W1', 'PR_UINT16_MAX',
           'IPPROTO_IP', 'SEC_OID_EXT_KEY_USAGE_CLIENT_AUTH',
           'PK11_ATTR_PRIVATE', 'htole32', 'IP_PMTUDISC_WANT',
           'SEC_OID_PKCS9_EMAIL_ADDRESS', 'CKA_NETSCAPE_TRUST',
           'EAI_FAMILY', 'N18SECKEYPublicKeyStr4DOT_57E', 'sigevent',
           'IPV6_RECVPKTINFO', 'PR_BYTES_PER_FLOAT',
           'EXT_KEY_USAGE_TIME_STAMP', 'WIFSIGNALED', 'uint_fast16_t',
           'DER_ANY', 'uint_fast32_t', 'crlEntryReasonRemoveFromCRL',
           'HT_ENUMERATE_REMOVE', '__INO64_T_TYPE', 'CK_DATE',
           'CERT_N2A_INVERTIBLE', 'AF_IPX',
           'SEC_ASN1_OBJECT_DESCRIPTOR', 'IP_MULTICAST_LOOP',
           'IPPORT_DISCARD', 'PK11TokenPresent',
           'SEC_OID_SECG_EC_SECT131R2', 'CKA_ISSUER',
           'SEC_OID_SECG_EC_SECT131R1', 'IN_CLASSA',
           'PR_BITS_PER_DOUBLE_LOG2', 'IN_CLASSC', 'IN_CLASSB',
           'IN_CLASSD', 'CK_PKCS5_PBKD2_PARAMS', 'CKM_RSA_X_509',
           'SO_DEBUG', 'PR_SockOpt_McastLoopback',
           'cert_pi_revocationFlags', 'PR_NO_MORE_FILES_ERROR',
           'CKA_SIGN_RECOVER', 'PRSetsocketoptionFN',
           'certRegisterID', 'CKK_NETSCAPE_PKCS8',
           'SEC_OID_SECG_EC_SECP224R1', 'CKM_RC5_MAC',
           'certPackagePKCS7', 'CKA_KEY_GEN_MECHANISM',
           'CERTCompareValidityStatus', 'CKO_NSS_CRL', 'AF_INET',
           '_ISlower', 'kt_ecdh', 'PRHashNumber', 'PRConnectFN',
           'SEC_OID_PKCS7_DATA', 'CKR_SESSION_READ_ONLY',
           'SECKEYPQGParamsStr', 'CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN',
           'cert_po_trustAnchor', '__rlim64_t', 'ino_t',
           'ssl_sign_ecdsa', 'DER_OBJECT_ID', 'PZ_EnterMonitor',
           'SEC_OID_SECG_EC_SECT193R2', 'CKA_NSS_KRL',
           'PR_BITS_PER_INT64_LOG2', 'SEC_OID_SECG_EC_SECT193R1',
           'PRIntervalTime', 'PRFileMapProtect', 'CKT_NETSCAPE_VALID',
           'SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC', '__blksize_t',
           'cert_pi_nbioContext', 'CKR_KEY_TYPE_INCONSISTENT',
           '__pthread_slist_t', 'siUnsignedInteger',
           'CERTCertNicknames', 'CK_ATTRIBUTE_TYPE',
           'BYTES_PER_FLOAT', 'CKM_PBE_MD5_CAST_CBC',
           'CK_MAC_GENERAL_PARAMS',
           'SEC_OID_PKCS1_SHA224_WITH_RSA_ENCRYPTION', 'CKM_SHA224',
           'ino64_t', '_PATH_HOSTS',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC',
           'IN_CLASSA_NSHIFT', 'ssl_renegotiation_info_xtn',
           'CKM_SEED_CBC_PAD', 'SEC_OID_ANSIX962_EC_PRIME256V1',
           'KU_ALL', 'SEC_OID_PKIX_REGINFO_CERT_REQUEST',
           'CKA_PIXEL_X', 'CKN_SURRENDER',
           'CKA_TRUST_DIGITAL_SIGNATURE', 'PR_BITS_PER_FLOAT_LOG2',
           'AF_BLUETOOTH', '__STDC_ISO_10646__', 'CKM_RC5_CBC',
           'CKM_GENERIC_SECRET_KEY_GEN', 'CK_MECHANISM_TYPE_PTR',
           'ssl_kea_rsa', 'CERTCertKeyStr', 'EAI_AGAIN', 'CKC_NSS',
           'SEC_OID_DES_CFB', '_IO_BE', 'SSLHandshakeCallback',
           'CKM_RIPEMD128', 'uint64_t', 'CKM_MD2_KEY_DERIVATION',
           'CERTNameConstraint', 'CKM_CDMF_CBC_PAD',
           'SEC_OID_MISSI_DSS', 'crlEntryReasonAffiliationChanged',
           'group_source_req', '_BITS_TYPES_H',
           'IP_DEFAULT_MULTICAST_LOOP', '__have_sigevent_t',
           'PDP_ENDIAN', 'CKK_DES', 'CERTAuthInfoAccess', '__rlim_t',
           '__FLOAT_WORD_ORDER', 'CKF_ENCRYPT', 'CKO_NSS_TRUST',
           'CKO_DATA', 'PR_DIRECTORY_NOT_EMPTY_ERROR',
           'cert_po_policyOID', 'MCAST_UNBLOCK_SOURCE', 'CK_ULONG',
           '__isspace_l', 'PZMonitor', 'PRLibrary',
           '__SIZEOF_PTHREAD_RWLOCK_T', 'ssl_hmac_sha',
           'PZ_DestroyLock', 'INADDR_ALLHOSTS_GROUP',
           'PR_BYTES_PER_BYTE', '_IOS_ATEND', 'PRUptrdiff',
           'CERTSignedCrl', 'SECMOD_RC4_FLAG', 'PK11_ATTR_SENSITIVE',
           'SEC_OID_HMAC_SHA512',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR',
           'CK_X9_42_DH1_DERIVE_PARAMS', 'SECMOD_DH_FLAG',
           'SEC_OID_PKCS12_V1_CERT_BAG_ID', 'DER_APPLICATION',
           'CK_DESTROYMUTEX', 'IPPORT_ECHO', 'CKA_APPLICATION',
           '__key_t', 'dev_t', 'PR_OPERATION_NOT_SUPPORTED_ERROR',
           'CKM_PKCS5_PBKD2', 'PF_NETROM', 'CKC_X_509_ATTR_CERT',
           'PR_SHUTDOWN_RCV', 'AF_IRDA', 'DER_OPTIONAL',
           '__GNU_LIBRARY__', 'PRSocketOptionData',
           'SSL_REQUIRE_NO_ERROR', 'PF_FILE',
           'PK11SlotListElementStr', 'PZ_DestroyCondVar',
           'SEC_ASN1_DEFAULT_ARENA_SIZE', 'SEC_OID_SECG_EC_SECT239K1',
           'CKM_ECDSA_KEY_PAIR_GEN', 'certURI',
           'SEC_OID_PKCS1_SHA512_WITH_RSA_ENCRYPTION',
           'BITS_PER_WORD', 'ssl_server_name_xtn',
           'PR_INVALID_DEVICE_STATE_ERROR',
           'CKA_NETSCAPE_MODULE_SPEC', 'SSLChannelInfo',
           'CERTOidSequence', 'IP_ORIGDSTADDR', 'PR_DEADLOCK_ERROR',
           'CERT_REV_M_ALLOW_IMPLICIT_DEFAULT_SOURCE',
           'CKR_DEVICE_REMOVED', 'SEC_OID_CERT_RENEWAL_LOCATOR',
           'PR_FILE_IS_BUSY_ERROR', 'PF_NETBEUI', 'PK11CertListAll',
           'NS_CERT_TYPE_APP', 'PR_ACCESS_EXISTS', 'nssILockOther',
           'CKR_KEY_CHANGED', 'certPackageNone',
           'SECMOD_MODULE_DB_FUNCTION_FIND', 'CERTAuthKeyID',
           'SEC_OID_NS_CERT_EXT_BASE_URL', 'pthread_condattr_t',
           'SEC_OID_PKCS1_SHA1_WITH_RSA_ENCRYPTION',
           '__codecvt_partial', 'IPPROTO_MAX',
           'CK_RC5_MAC_GENERAL_PARAMS', 'PR_ACCESS_WRITE_OK',
           'PR_NOT_SAME_DEVICE_ERROR', '__timer_t',
           'SEC_OID_PKIX_OCSP_RESPONSE', 'CKM_BLOWFISH_KEY_GEN',
           'CKM_SKIPJACK_ECB64', 'SECMODModuleListStr',
           'IPPORT_WHOIS', 'ssl_calg_aes', 'CK_TRUST',
           'SSL_RESTRICTED', 'PR_LOG_NONE', 'ALIGN_OF_POINTER',
           'SEC_OID_PKCS12_CERT_BAG_IDS', 'SSLAuthType',
           'SECComparison', 'ssl_calg_des', 'PR_BITS_PER_DOUBLE',
           'CKR_CANT_LOCK', 'MSG_ERRQUEUE', 'PK11_TypePubKey',
           'CKA_CHAR_SETS', 'IPPROTO_IGMP', 'IP_FREEBIND',
           'PR_LANGUAGE_I_DEFAULT', 'PR_SockOpt_Nonblocking',
           '__uint32_t', '__FD_SETSIZE', 'IPV6_PKTINFO',
           'SEC_CERTIFICATE_VERSION_2', 'SEC_CERTIFICATE_VERSION_3',
           'SEC_CERTIFICATE_VERSION_1', 'PF_CAN', 'PRStatus',
           'hostent', 'SEC_OID_VERISIGN_USER_NOTICES', 'PRArenaPool',
           'CKM_CAMELLIA_CBC', 'CERTRevocationFlags',
           'CKM_SHA512_HMAC', 'fsid_t', '_IO_va_list',
           'SEC_OID_BOGUS_DSA_SIGNATURE_WITH_SHA1_DIGEST',
           'CKO_NETSCAPE_NEWSLOT', 'CK_DECLARE_FUNCTION_POINTER',
           'certUsageStatusResponder', 'PK11DefaultArrayEntryStr',
           'PR_ADDRESS_IN_USE_ERROR', 'CKM_CAST_CBC_PAD',
           'IPPROTO_DCCP', 'msghdr', 'SO_TIMESTAMP',
           'SEC_OID_NETSCAPE_RECOVERY_REQUEST', 'SCM_TIMESTAMPING',
           'NI_NUMERICHOST', 'nssILockRefLock',
           'CKR_NETSCAPE_KEYDB_FAILED', 'int32_t', 'off64_t',
           'PR_FILE_SEEK_ERROR', 'PL_HASH_BITS',
           'CK_ECMQV_DERIVE_PARAMS', 'SEC_OID_NETSCAPE_AOLSCREENNAME',
           'ssl_auth_dsa', 'PRIOVec', 'PF_IPX', 'htole64',
           'SSL_SNI_CURRENT_CONFIG_IS_USED', 'PR_BYTES_PER_SHORT',
           'SSL_HANDSHAKE_AS_SERVER', 'SOL_DECNET', 'ssl_auth_null',
           'putc', 'PR_INT32', '_IO_HEX', 'PK11_TypeSymKey',
           'PR_SKIP_DOT', 'CKA_MODIFIABLE', 'PR_BITS_PER_SHORT_LOG2',
           'PRGetpeernameFN', 'PK11CertListCA', 'WNOHANG',
           '_IO_SKIPWS', 'N8sigevent4DOT_224DOT_23E',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC',
           'CKM_EXTRACT_KEY_FROM_KEY', 'FILENAME_MAX', 'PRCListStr',
           'CKM_CAST128_ECB', 'EXIT_SUCCESS', '__suseconds_t',
           'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR',
           'LL_GE_ZERO', 'CKM_TLS_KEY_AND_MAC_DERIVE',
           'DER_METHOD_MASK', 'CKT_NETSCAPE_VALID_DELEGATOR',
           'AF_ROSE', 'PR_FIND_SYMBOL_ERROR', 'CKM_CAMELLIA_MAC',
           'HT_ENUMERATE_UNHASH', 'AF_UNSPEC', 'CKR_DEVICE_MEMORY',
           'CKM_RSA_PKCS', 'PR_UNLOAD_LIBRARY_ERROR',
           'CK_SESSION_INFO', 'CKA_COEFFICIENT', 'CKM_TLS_PRF',
           'PR_IO_TIMEOUT_ERROR', 'SECKEYDSAPublicKey',
           'CK_WTLS_KEY_MAT_PARAMS', 'IPV6_RECVHOPLIMIT',
           'SO_SECURITY_AUTHENTICATION', 'pthread_t',
           'CRL_IMPORT_DEFAULT_OPTIONS', 'blksize_t',
           'CKM_BATON_CBC128', 'PR_BITS_PER_FLOAT', 'AF_DECnet',
           'PZ_Wait', 'CERTDistNames', 'SUPPORTED_CERT_EXTENSION',
           'PR_ADDRESS_NOT_SUPPORTED_ERROR', 'CKA_CLASS',
           'PORTCharConversionWSwapFunc', '__SIZEOF_PTHREAD_ATTR_T',
           'CK_RSA_PKCS_MGF_TYPE_PTR', 'siCipherDataBuffer',
           'PK11_OriginGenerated', 'CKA_NSS_PQG_H', 'ucred',
           'CERT_N2A_STRICT', 'ALIGN_OF_INT64', '_IO_lock_t',
           'PR_IRUSR', 'PR_SockOpt_IpTimeToLive', 'ALIGN_OF_INT',
           'DistributionPointTypesEnum', 'CERTCertTrustStr',
           'PRSpecialFD', 'uint_fast64_t',
           'SEC_OID_NS_CERT_EXT_COMMENT',
           'SEC_OID_PKCS7_ENVELOPED_DATA', 'SEC_OID_PKCS12_BAG_IDS',
           'SEC_OID_PKCS7', 'CKK_RC2', 'AF_RXRPC', 'CKK_RC4',
           'CKK_RC5', 'SEC_OID_ANSIX962_EC_C2PNB208W1',
           'CK_CREATEMUTEX', 'IPV6_PMTUDISC_DO', 'CKH_USER_INTERFACE',
           '_XOPEN_SOURCE_EXTENDED', 'CERTNameConstraintsStr',
           '__USE_XOPEN2KXSI', 'AI_NUMERICHOST',
           'PR_NOT_CONNECTED_ERROR', 'PK11RSAGenParamsStr',
           'CKA_NSS_PQG_SEED_BITS', 'CKM_FORTEZZA_TIMESTAMP',
           'CKM_CAMELLIA_CBC_PAD', 'pthread_once_t', 'CKM_CAST_MAC',
           '__fsid_t', 'CK_EC_KDF_TYPE', 'cert_po_nbioContext',
           'ispunct_l', 'CKM_SHA224_HMAC_GENERAL', 'PRRecvFN',
           '__USE_XOPEN2K8', 'BYTES_PER_WORD_LOG2', 'PR_WRONLY',
           'crlEntryReasonKeyCompromise',
           'N23CERTValParamOutValueStr4DOT_84E', 'WNOWAIT',
           'CK_VERSION', 'RAND_MAX', 'uint16', 'PRHashEnumerator',
           'SEC_OID_AVA_COUNTRY_NAME',
           'CKR_WRAPPING_KEY_HANDLE_INVALID', 'CKA_DERIVE',
           'SECMOD_TLS_FLAG', 'CKM_SSL3_MASTER_KEY_DERIVE',
           'PRPtrdiff', 'SSL_RENEGOTIATE_REQUIRES_XTN',
           'SECMOD_RC5_FLAG', 'int_least32_t', '__STDC_IEC_559__',
           'CKA_ECDSA_PARAMS', 'SECMOD_RANDOM_FLAG',
           'CKM_X9_42_DH_PARAMETER_GEN', 'PRAcceptFN',
           'PR_POLL_WRITE', 'keaKey', 'SO_PEERSEC',
           'MCAST_BLOCK_SOURCE', 'PR_NOT_IMPLEMENTED_ERROR',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4',
           'CKM_CAMELLIA_KEY_GEN', 'CKF_SIGN_RECOVER',
           '_ISOC99_SOURCE', 'CKK_ECDSA', 'CKM_CMS_SIG',
           '_SIGSET_H_types', 'KU_DATA_ENCIPHERMENT',
           'INADDR_LOOPBACK', 'PK11MergeLogStr', 'PF_ATMPVC',
           'DER_UNIVERSAL', 'PR_WOULD_BLOCK_ERROR',
           'IPV6_ADD_MEMBERSHIP',
           'SEC_OID_ANSIX962_ECDSA_SHA384_SIGNATURE',
           'SEC_OID_PKIX_REGCTRL_PROTOCOL_ENC_KEY', 'CKM_AES_CBC_PAD',
           '_IO_MAGIC', 'PLHashNumber',
           'SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_TRIPLE_DES',
           'IP_PKTOPTIONS', 'EAI_ADDRFAMILY', 'CK_CHAR',
           'SEC_OID_DES_EDE', 'MSG_CMSG_CLOEXEC', 'rsaKey',
           'SEC_OID_PKCS9_X509_CRL', 'WSTOPPED', '__timer_t_defined',
           'SEC_OID_CAMELLIA_128_CBC', 'CKA_NSS_MODULE_SPEC',
           'SEC_ASN1_OBJECT_ID', 'SEC_OID_PKCS1_MGF1', 'CKA_DECRYPT',
           'CKM_SHA512_RSA_PKCS', 'CKM_KEA_KEY_PAIR_GEN',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC',
           'DER_FORCE', 'FD_ISSET', 'PRErrorCode', 'CKT_NSS_VALID',
           'NS_CERT_TYPE_EMAIL', '__codecvt_result',
           'SCM_CREDENTIALS', 'CKA_MODULUS_BITS',
           'PR_FILE_EXISTS_ERROR', 'SO_RXQ_OVFL',
           'PK11_DIS_COULD_NOT_INIT_TOKEN', 'CKS_RO_PUBLIC_SESSION',
           'IP_HDRINCL', 'IPPORT_FINGER', 'CKM_SHA384_HMAC',
           '_SECComparison', 'CERTNoticeReference',
           '_BITS_SOCKADDR_H', 'PR_FAILURE', 'CK_SESSION_INFO_PTR',
           'SECKEYDHPublicKeyStr', 'PK11DefaultArrayEntry',
           'PRUnichar', 'certEDIPartyName', 'PZ_NewMonitor',
           '_IO_IN_BACKUP', 'CKA_AUTH_PIN_FLAGS', 'SECKEYECPublicKey',
           'SEC_OID_DES_EDE3_CBC', 'CKM_PBA_SHA1_WITH_SHA1_HMAC',
           'SECKEYECParams', 'CERT_REV_M_FAIL_ON_MISSING_FRESH_INFO',
           'PRSeekFN', 'OtherNameStr', 'SEC_OID_HMAC_SHA1',
           'AF_ECONET', 'SEC_OID_PKCS5_PBMAC1', '_G_HAVE_BOOL',
           'SEC_OID_X509_PRIVATE_KEY_USAGE_PERIOD',
           'PR_NOT_TCP_SOCKET_ERROR', 'CKM_TWOFISH_CBC',
           'PK11GenericObject', 'SEC_OID_X509_AUTH_INFO_ACCESS',
           'AF_WANPIPE', 'SEC_OID_AES_192_ECB', 'EAI_INTR',
           'siDERCertBuffer', 'PR_LOG_MAX', 'CKF_OS_LOCKING_OK',
           'CKM_CAST3_ECB', 'PR_ALIGN_OF_INT', 'CERTStatusConfig',
           'CKM_SEED_KEY_GEN', 'CKM_CAST128_CBC', 'PF_BRIDGE',
           'certUsageAnyCA', 'htobe32', 'SSLSignType',
           'PK11_ATTR_PUBLIC', 'BUFSIZ', 'IPPORT_TELNET',
           'PR_NSEC_PER_SEC', 'CKF_USER_PIN_COUNT_LOW',
           'PK11_PW_RETRY', 'CKR_NSS_KEYDB_FAILED',
           '_IO_UNIFIED_JUMPTABLES', 'CKA_SUPPORTED_CMS_ATTRIBUTES',
           'CRL_DECODE_DEFAULT_OPTIONS', 'PR_MAX_IOVECTOR_SIZE',
           'SSL_REQUIRE_NEVER', 'CKM_SKIPJACK_KEY_GEN',
           'CKO_PRIVATE_KEY', 'CKM_SHA1_RSA_PKCS_PSS',
           'PR_USEC_PER_SEC', 'SEC_ASN1_HIGH_TAG_NUMBER', 'PF_KEY',
           'SEC_OID_X509_BASIC_CONSTRAINTS', 'PR_ALIGN_OF_SHORT',
           'IP_RETOPTS', 'IPV6_JOIN_GROUP', 'SEC_ASN1_TAG_MASK',
           'SEC_OID_SECG_EC_SECP384R1', 'SEC_OID_AVA_SERIAL_NUMBER',
           'PR_REMOTE_FILE_ERROR', 'PR_MSG_PEEK', 'WEXITSTATUS',
           'BYTE_ORDER', 'DER_NULL', 'isupper_l',
           'CK_CMS_SIG_PARAMS_PTR', 'cert_pi_end', 'CKK_SEED',
           'ip6_mtuinfo', 'SSL_REQUEST_CERTIFICATE', '__u_quad_t',
           '__u_short', 'AF_BRIDGE', '_BSD_SOURCE', 'CKK_KEA',
           '_LARGEFILE64_SOURCE', 'CKM_PBE_SHA1_RC2_40_CBC',
           'PR_ALIGN_OF_LONG', '_IScntrl', 'PR_BITS_PER_INT_LOG2',
           'CKA_SUBPRIME', 'SECFailure', 'PF_WANPIPE', 'CKM_MD2',
           'EAI_CANCELED', 'PR_BITMASK', 'CK_X9_42_DH_KDF_TYPE',
           'SO_DOMAIN', 'DER_CLASS_MASK',
           'SECKEYFortezzaPublicKeyStr', 'CKM_RIPEMD128_HMAC_GENERAL',
           'IPPROTO_NONE', '_ISpunct', '__toascii',
           'SECKEYDHParamsStr', 'SO_PASSSEC',
           'SEC_OID_BOGUS_KEY_USAGE', 'SEC_ASN1_UNIVERSAL_STRING',
           'SIOCSPGRP', 'offsetof', 'SECEqual', 'SEC_OID_RC4',
           'CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN', 'SO_PASSCRED',
           'iscntrl_l', 'CERTCrlKeyStr', 'AF_ISDN', 'PR_LOG_ALWAYS',
           'nssILockOID', 'KU_KEY_ENCIPHERMENT', 'AF_PACKET',
           'CKM_TLS_MASTER_KEY_DERIVE_DH', '_G_ssize_t',
           'AI_NUMERICSERV', 'CKF_EC_F_P',
           'crlEntryReasoncertificatedHold',
           'CKR_DOMAIN_PARAMS_INVALID', '_G_HAVE_SYS_CDEFS',
           'CKA_ENCRYPT', 'CKM_SHA256_HMAC', 'KU_NON_REPUDIATION',
           'CKM_ECDSA', 'CERTCertificateRequest',
           'CKR_UNWRAPPING_KEY_SIZE_RANGE', 'SOL_AAL',
           'PR_LD_ALT_SEARCH_PATH', 'rsaOaepKey', 'SECMOD_MD5_FLAG',
           'SSLKEAType', 'SECKEYPrivateKeyStr', 'FSSpec',
           'nssRWLockStr', 'CKT_NSS_TRUSTED', '_IO_fpos64_t',
           '__mbstate_t_defined', 'PR_StandardError',
           'KU_ENCIPHER_ONLY', 'SEC_OID_SECG_EC_SECT233K1',
           '__time_t_defined', '__time_t', '__GLIBC_PREREQ',
           'CKA_NETSCAPE_SMIME_TIMESTAMP', 'MSG_RST',
           'PK11TokenPresentEvent', 'PRLibSpecType', 'pid_t',
           'SEC_OID_PKIX_REGINFO_UTF8_PAIRS', '_IO_FIXED',
           '_G_HAVE_PRINTF_FP', 'PF_ISDN', 'pthread_rwlock_t',
           'IP_PKTINFO', 'certUsageObjectSigner', 'cert_pi_policyOID',
           'SEC_OID_ANSIX9_DSA_SIGNATURE',
           'SEC_OID_EXT_KEY_USAGE_SERVER_AUTH',
           'CK_RC2_MAC_GENERAL_PARAMS', 'CKM_RSA_9796', 'timespec',
           'DistributionPointTypes', 'CKF_EC_UNCOMPRESS', 'SOL_IRDA',
           'CK_SLOT_INFO', 'pthread_mutex_t', 'NSSCertificateStr',
           'PRUint8', 'SEC_OID_HMAC_SHA224', '_IO_USER_BUF',
           'CKM_DES3_MAC', 'CERTSignedDataStr', 'ssl_calg_idea',
           'CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE', 'PRAccessHow',
           'IPPROTO_TP', 'SO_BROADCAST', 'CKM_MD5_HMAC_GENERAL',
           'LL_MININT', '_G_ARGS', 'CERTSortCallback',
           'CKM_RC2_CBC_PAD', 'SEC_ASN1_Identifier', '_G_HAVE_MMAP',
           '__u_char', '_G_uint16_t', '__attribute_format_strfmon__',
           'PRUintn', 'certIPAddress', 'CKM_WTLS_MASTER_KEY_DERIVE',
           'protoent', 'CK_RC2_MAC_GENERAL_PARAMS_PTR',
           'CRLDistributionPointStr', 'SSL_SNI_SEND_ALERT',
           'SO_NO_CHECK', 'SECMOD_MODULE_DB_FUNCTION_DEL',
           'PRShutdownHow', '__u_long', 'wait', 'CERTStatusChecker',
           'SCM_TIMESTAMP', 'secCertTimeValid',
           'SEC_OID_NETSCAPE_NICKNAME', 'SSL3StatisticsStr',
           'AF_IEEE802154', 'CKA_NETSCAPE_KRL',
           'SECCertTimeValidityEnum',
           'SEC_OID_PKIX_OCSP_BASIC_RESPONSE',
           'SECMOD_WAIT_PKCS11_EVENT', '_G_FSTAT64',
           'CKR_KEY_SIZE_RANGE', 'IPV6_RTHDR_LOOSE',
           '_G_HAVE_SYS_WAIT', 'IP_MTU', 'PR_TPD_RANGE_ERROR',
           'PR_NO_ACCESS_RIGHTS_ERROR', 'SEC_ASN1_TAGNUM_MASK',
           'u_int64_t', 'CERTCertificateRequestStr', '__off_t',
           'PR_CONNECT_RESET_ERROR', 'uptrdiff_t',
           'PK11_ATTR_INSENSITIVE', 'CKA_START_DATE',
           'CKR_KEY_UNEXTRACTABLE', 'CKA_EC_PARAMS', 'PR_LANGUAGE_EN',
           'CKA_VERIFY_RECOVER', 'INADDR_BROADCAST', '_IO_LINE_BUF',
           'PR_LOAD_LIBRARY_ERROR', 'CK_SKIPJACK_RELAYX_PARAMS_PTR',
           'SEC_OID_SECG_EC_SECP256K1', '_IOS_TRUNC',
           'CERTSubjectPublicKeyInfoStr', 'uint_least32_t',
           'SEC_OID_ANSIX962_EC_C2PNB176V1',
           '__pthread_internal_slist', 'NI_NOFQDN', 'PR_APPEND',
           'CKM_BATON_ECB96', 'PRFloat64', 'SECMOD_SHA1_FLAG',
           'SEC_OID_AES_256_KEY_WRAP', 'CKA_CERT_MD5_HASH',
           '__int8_t', 'SEC_OID_PKCS9_EXTENSION_REQUEST',
           'SEC_OID_AES_256_CBC', 'SEC_OID_FORTEZZA_SKIPJACK',
           'MSG_SYN', 'nssILockSession', 'CKO_NSS_NEWSLOT',
           'CK_CERTIFICATE_TYPE', 'CKM_RC2_MAC_GENERAL', 'PRFsyncFN',
           '_IO_pid_t', 'PF_IRDA', 'ulong', 'IPV6_RXDSTOPTS',
           'pthread_key_t', 'PK11SymKey',
           'CKA_HASH_OF_SUBJECT_PUBLIC_KEY', 'CKR_HOST_MEMORY',
           '__locale_struct', 'u_int8_t', 'CK_OBJECT_CLASS', '__WALL',
           'PK11_ATTR_EXTRACTABLE', 'PR_LibSpec_PathnameU',
           'BITS_PER_LONG', '__USE_BSD', 'CKF_EC_NAMEDCURVE',
           'IPPORT_NETSTAT', 'SEC_OID_AVA_SURNAME',
           'SEC_ASN1_INTEGER', '__locale_t', 'PRSendFileData',
           'SOL_PACKET', 'certUsageSSLServerWithStepUp',
           'PR_NETWORK_UNREACHABLE_ERROR', 'PZCondVar', 'sa_family_t',
           'CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4', '__isprint_l',
           'SEC_OID_OCSP_RESPONDER', 'CERTCrlHeadNodeStr',
           'cert_po_certList', 'DERTemplate', 'CKA_NETSCAPE_EXPIRES',
           'SEC_OID_ANSIX962_EC_PUBLIC_KEY',
           'NSS_USE_ALG_IN_CMS_SIGNATURE', 'socklen_t',
           'SO_KEEPALIVE', 'CK_INVALID_HANDLE',
           'SEC_ASN1_GENERAL_STRING', 'CKM_BATON_KEY_GEN',
           'PR_AF_UNSPEC', 'uint', 'AF_TIPC', '_G_off64_t',
           'nssILockRWLock', 'CKM_SKIPJACK_CFB16', 'SIGEV_THREAD',
           'CERT_POLICY_FLAG_NO_MAPPING',
           'CERT_REV_M_DO_NOT_TEST_USING_THIS_METHOD',
           'CERTGeneralNameType', 'CKM_SKIPJACK_CFB8',
           'PK11_TypePrivKey', 'CKR_CRYPTOKI_ALREADY_INITIALIZED',
           'CKM_IDEA_MAC', 'IPV6_HOPOPTS', 'CERTName',
           'SEC_OID_NS_CERT_EXT_SCOPE_OF_USE', 'PR_LOOP_ERROR',
           'SECOidDataStr', 'NETDB_SUCCESS',
           'CERT_REV_M_ALLOW_NETWORK_FETCHING',
           'NI_IDN_USE_STD3_ASCII_RULES', '_SVID_SOURCE',
           'SEC_OID_RFC1274_MAIL', 'IN_CLASSB_HOST', 'FILE', 'size_t',
           'PK11_OriginUnwrap', 'IN_CLASSA_HOST', 'SOCK_SEQPACKET',
           'PR_TRANSMITFILE_CLOSE_SOCKET',
           'N18CERTCertificateStr4DOT_624DOT_63E',
           'CKO_VENDOR_DEFINED', 'CKA_CHAR_ROWS', 'CK_KEY_TYPE',
           'SECKEYRSAPublicKey', 'PK11MergeLogNodeStr',
           'SEC_OID_PKCS12_MODE_IDS', 'SEC_OID_AVA_COMMON_NAME',
           'N10PRIPv6Addr4DOT_25E', '__qaddr_t', 'CKF_EC_F_2M',
           'CERTCertListStr', 'PR_POLL_HUP', 'PZ_NotifyCondVar',
           'siBMPString', '__isblank_l', 'cert_po_usages',
           'SEC_OID_X509_SUBJECT_INFO_ACCESS', 'IN_CLASSB_MAX',
           'cookie_write_function_t', 'isxdigit_l', 'u_long',
           'SSLChannelInfoStr', 'CKA_EXPONENT_1', 'CKM_DES2_KEY_GEN',
           'MSG_OOB', 'CK_CHAR_PTR', 'sigset_t',
           'SEC_OID_X509_INVALID_DATE', 'SEC_OID_NS_TYPE_JPEG',
           'CKM_SHA_1', 'PR_SOCKET_SHUTDOWN_ERROR',
           'NSSTrustDomainStr', 'CKR_FUNCTION_NOT_SUPPORTED',
           'pthread_barrierattr_t', '__USE_POSIX',
           'SEC_OID_PKCS9_UNSTRUCTURED_NAME', 'PROffset32',
           'CKF_VERIFY_RECOVER', 'BITS_PER_INT64_LOG2',
           'PK11SymKeyStr', 'IPPORT_USERRESERVED',
           'MCAST_LEAVE_SOURCE_GROUP', 'CK_WTLS_RANDOM_DATA_PTR',
           'SSL_ENABLE_FALSE_START', 'CKM_KEY_WRAP_SET_OAEP',
           'N23CRLDistributionPointStr4DOT_65E',
           'CKM_TLS_PRF_GENERAL', 'kt_kea_size',
           'CK_RSA_PKCS_PSS_PARAMS_PTR', 'CK_RC2_CBC_PARAMS',
           'NI_NUMERICSERV', 'CERTCrlNodeStr', 'PRDescType',
           'CERT_UNLIMITED_PATH_CONSTRAINT', 'IPV6_RECVHOPOPTS',
           'secCertTimeNotValidYet', 'CKD_SHA1_KDF_CONCATENATE',
           '_BITS_WCHAR_H', 'CK_RC5_CBC_PARAMS_PTR',
           '__clockid_t_defined', 'CKM_RSA_X9_31',
           'N23CERTValParamOutValueStr4DOT_86E', 'CKR_NO_EVENT',
           '__SQUAD_TYPE', 'SECKEYKEAParams', 'uint32',
           'uint_least8_t', 'CERTCertificatePolicyConstraints',
           'PR_PROC_DESC_TABLE_FULL_ERROR', 'IPV6_2292HOPLIMIT',
           'nssILockCertDB', 'ecKey',
           'SEC_OID_PKCS12_V1_PKCS8_SHROUDED_KEY_BAG_ID', 'PR_IROTH',
           'SO_RCVLOWAT', 'SHUT_RDWR', 'SECKEYPrivateKey',
           'trustTypeNone', 'IN_CLASSB_NSHIFT',
           'PR_SockOpt_McastTimeToLive', 'PRErrorMessage',
           'CK_C_INITIALIZE_ARGS_PTR', 'nssILockAttribute',
           'siBuffer', 'SEC_OID_SECG_EC_SECT571R1',
           'SEC_OID_PKCS9_CONTENT_TYPE',
           'SEC_OID_AVA_GENERATION_QUALIFIER', 'SEC_ASN1_CHOICE',
           'AF_ATMSVC', 'PR_DIRECTORY_CORRUPTED_ERROR',
           'PR_DESC_PIPE', 'PRSeek64FN', 'NS_CERT_TYPE_RESERVED',
           '__USE_GNU', 'N14pthread_cond_t3DOT_9E', 'WUNTRACED',
           'certUsageEmailSigner', 'CKA_TRUST_CODE_SIGNING',
           'CKS_RO_USER_FUNCTIONS', 'pthread_attr_t',
           '__attribute_format_arg__', 'SSL_REQUIRE_SAFE_NEGOTIATION',
           'CKR_SESSION_READ_ONLY_EXISTS', 'CERTDBNameFunc',
           'SOL_IPV6', 'AF_CAN', 'CK_WTLS_KEY_MAT_OUT_PTR',
           'CERTVerifyLogStr', 'PR_BYTES_PER_INT', 'IPPROTO_ICMP',
           'N11__mbstate_t4DOT_42E', 'CKA_VALUE',
           'BITS_PER_LONG_LOG2', 'IPPROTO_HOPOPTS', '__W_STOPCODE',
           'CKF_TOKEN_PRESENT', 'CKM_SEED_ECB',
           'PR_BUFFER_OVERFLOW_ERROR', 'ssl_calg_3des',
           '__ldiv_t_defined', 'ssl_calg_fortezza', 'PRAvailableFN',
           'CKR_TEMPLATE_INCOMPLETE',
           'certificateUsageProtectedObjectSigner', 'SOCK_DGRAM',
           'CKR_CANCEL', 'SO_TIMESTAMPNS', '__W_CONTINUED',
           'CKA_SUBPRIME_BITS', '__isalpha_l', 'comparison_fn_t',
           'le16toh', 'NI_DGRAM', 'IP_BLOCK_SOURCE',
           'CKG_MGF1_SHA224', '__mbstate_t', 'CKM_CAST_MAC_GENERAL',
           'CKM_AES_ECB_ENCRYPT_DATA', '_IO_INTERNAL', 'SEC_ASN1_ANY',
           'SSL_ENV_VAR_NAME', 'SECMOD_INT_NAME', 'PLHashTable',
           'CKM_SHA256_HMAC_GENERAL', 'PRDirFlags',
           'CK_X9_42_DH2_DERIVE_PARAMS', 'PR_TOP_IO_LAYER',
           '_G_uid_t', 'BYTES_PER_DWORD', 'SEC_OID_SEED_CBC',
           'CERTCertOwnerEnum', 'quad_t', 'SECMODModuleStr',
           'N9PRNetAddr4DOT_27E', 'IPV6_MTU_DISCOVER', 'dsaKey',
           'CKR_PIN_EXPIRED', 'CERTAVA', 'CKM_AES_MAC_GENERAL',
           'CKM_DSA_KEY_PAIR_GEN', 'CKM_DES3_CBC_PAD',
           'IP_ROUTER_ALERT', 'BITS_PER_BYTE', 'pthread_cond_t',
           'PR_NOT_SOCKET_ERROR', 'PRStaticLinkTable',
           'crlEntryReasonCaCompromise', 'CKF_LOGIN_REQUIRED',
           'group_filter', 'CERTCertificate', 'SSLAuthCertificate',
           '__u_int', 'SEC_OID_ANSIX962_ECDSA_SHA1_SIGNATURE',
           'SEC_OID_X500_RSA_ENCRYPTION', 'PK11ObjectType', 'nlink_t',
           'PR_INVALID_METHOD_ERROR', 'CKA_CERTIFICATE_CATEGORY',
           '__UQUAD_TYPE', 'CKR_DEVICE_ERROR',
           'SEC_OID_X509_ISSUING_DISTRIBUTION_POINT',
           'CertStrictnessLevel', 'CKM_JUNIPER_COUNTER',
           'BYTES_PER_INT', 'SECKEY_CKA_PRIVATE',
           'SEC_OID_PKCS12_SIGNATURE_IDS', 'CKK_CDMF', 'PF_LOCAL',
           'CKR_TOKEN_NOT_RECOGNIZED', 'SECMOD_SEED_FLAG',
           'CK_ULONG_PTR', 'CKA_ALLOWED_MECHANISMS', 'cert_po_end',
           'CKR_FUNCTION_REJECTED', 'PR_IO_ERROR',
           'CERTGeneralNameStr', 'CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4',
           'PK11PreSlotInfoStr', 'CK_STATE', 'IPV6_TCLASS',
           'CKA_CHECK_VALUE', 'CKM_DES3_CBC', 'int8_t',
           'PK11CertListUser', '_RPC_NETDB_H', 'SO_SNDBUF',
           'PK11_PW_TRY', 'CERTGeneralNameTypeEnum',
           'CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE',
           'CKM_NSS_AES_KEY_WRAP', 'IP_MAX_MEMBERSHIPS',
           'generalName', 'IPV6_2292DSTOPTS', '__fsfilcnt_t',
           'NS_CERT_TYPE_OBJECT_SIGNING', 'IPPORT_RJE',
           'SEC_CRL_VERSION_1', 'SIOCGPGRP',
           'SSL_SECURITY_STATUS_OFF', '__FD_ZERO_STOS', 'PRBindFN',
           'WTERMSIG', 'htobe16', 'PR_SEEK_SET', 'isprint_l',
           'CKA_MECHANISM_TYPE', 'SECMOD_DSA_FLAG', 'fsfilcnt_t',
           '__swblk_t', 'IP_RECVTTL', 'CKR_ATTRIBUTE_TYPE_INVALID',
           'nssILockCache', 'PR_INTERVAL_MIN', 'SO_ERROR', 'PF_ROUTE',
           'MCAST_LEAVE_GROUP', '__STDC_IEC_559_COMPLEX__',
           'CERTCertificatePolicies', 'IPPROTO_ICMPV6',
           'SEC_OID_X509_CERT_ISSUER', 'PZLock', 'CKM_DES_OFB8',
           'uintptr_t', 'CMSG_NXTHDR', 'SOCK_DCCP', 'PRListenFN',
           'intptr_t', 'CK_FUNCTION_LIST_PTR', 'ssl_sign_dsa',
           'sigval', 'SEC_OID_PKCS1_SHA384_WITH_RSA_ENCRYPTION',
           'CERTGeneralNameList', 'CKK_BLOWFISH',
           'CKF_CLOCK_ON_TOKEN', '_IO_FLAGS2_MMAP', 'PZ_Lock',
           'DER_SET', '__GLIBC_HAVE_LONG_LONG', 'CKT_NSS_UNTRUSTED',
           '__WCLONE',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC',
           'PR_LibSpec_MacNamedFragment', 'CKA_EXPONENT_2',
           'N9PRLibSpec4DOT_314DOT_32E', 'PK11_ATTR_UNEXTRACTABLE',
           'CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC', 'PK11Context',
           'ip_mreqn', 'CKF_WRAP', 'CKM_SHA256_RSA_PKCS',
           'SO_SECURITY_ENCRYPTION_TRANSPORT', 'PR_INT8_MAX',
           'CK_TRUE', 'SO_REUSEADDR', 'CERTCertExtensionStr',
           'CKM_CAST128_MAC_GENERAL', 'be32toh', 'SECAlgorithmID',
           'PF_PPPOX', 'GAI_NOWAIT',
           'SEC_OID_PKIX_OCSP_SERVICE_LOCATOR', 'IN_CLASSC_HOST',
           'PF_RXRPC', 'SEC_OID_AVA_STREET_ADDRESS', 'PR_RDWR',
           'SEC_OID_ANSIX962_ECDSA_SIGNATURE_WITH_SHA1_DIGEST',
           'BITS_PER_SHORT', 'PK11_DIS_TOKEN_VERIFY_FAILED',
           'CKM_AES_CBC_ENCRYPT_DATA', 'CK_SSL3_KEY_MAT_PARAMS',
           'CKO_NETSCAPE_BUILTIN_ROOT_LIST',
           'certificateUsageSSLClient', 'PRSendFN', 'certDNSName',
           'ldiv_t', 'IP_DROP_MEMBERSHIP',
           'PR_LibSpec_MacIndexedFragment',
           'SEC_OID_AVA_POST_OFFICE_BOX', 'CK_SSL3_RANDOM_DATA',
           'IPV6_RTHDRDSTOPTS', 'CK_WTLS_RANDOM_DATA',
           '__USE_XOPEN2K', 'cookie_read_function_t',
           'CKR_WRAPPING_KEY_SIZE_RANGE',
           'SEC_OID_PKCS1_RSA_PSS_SIGNATURE', 'PK11TokenNotRemovable',
           'PR_SEEK_END', 'EAI_MEMORY', 'kt_null', 'CKF_DIGEST',
           'PR_SOCKET_ADDRESS_IS_BOUND_ERROR', '_IO_LINKED',
           'SEC_OID_ANSIX962_EC_C2PNB163V1',
           'SEC_OID_ANSIX962_EC_C2PNB163V2',
           'SEC_OID_ANSIX962_EC_C2PNB163V3',
           'NS_CERT_TYPE_OBJECT_SIGNING_CA', 'dhKey', '__blkcnt_t',
           'PR_AF_INET6', '_G_config_h', 'SEC_OID_SECG_EC_SECT283R1',
           'PZ_NotifyAllCondVar', 'blkcnt64_t',
           'PR_BYTES_PER_DWORD_LOG2', 'CKM_IDEA_CBC',
           'CKR_STATE_UNSAVEABLE', 'SEC_OID_NS_CERT_EXT_CERT_TYPE',
           'CKM_RC5_MAC_GENERAL', 'CK_SLOT_INFO_PTR', 'htonl',
           'PR_SockOpt_Keepalive',
           'N22CERTValParamInValueStr4DOT_83E', '_ISgraph',
           'CK_X9_42_DH1_DERIVE_PARAMS_PTR', 'uint_least16_t',
           'SEC_ASN1_SUB', 'SSL_RENEGOTIATE_UNRESTRICTED',
           'CERTCertOwner', 'CKM_AES_ECB', 'HT_ENUMERATE_NEXT',
           'SECSuccess', 'SSL_NO_STEP_DOWN', 'CKF_EC_FP', 'PRWord',
           'N9PRNetAddr4DOT_26E', 'SEC_ASN1_METHOD_MASK', '_ISalpha',
           'CKF_EC_ECPARAMETERS', 'CKK_CAST128', '_STDINT_H',
           'SEC_OID_X509_CRL_NUMBER', 'ssl_mac_null',
           'certUsageVerifyCA', 'CKF_PROTECTED_AUTHENTICATION_PATH',
           'certValidityEqual', 'ip_msfilter', 'CKM_FASTHASH',
           'CKF_SECONDARY_AUTHENTICATION',
           'CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR', 'PF_IEEE802154',
           'CERTPolicyInfo', 'CKR_NSS', 'PR_SHUTDOWN_SEND',
           'SEC_OID_MISSI_KEA_DSS_OLD', 'prword_t', 'CKM_SEED_CBC',
           'CKA_UNWRAP_TEMPLATE', 'PK11GenericObjectStr', 'gaicb',
           'CK_KEA_DERIVE_PARAMS', 'CKT_NSS_VALID_DELEGATOR',
           'PRLibSpec', 'SECMOD_MD2_FLAG', 'SEC_OID_NS_TYPE_HTML',
           'PF_NETLINK', 'CKM_DES_KEY_GEN', 'SEC_ASN1_DYNAMIC',
           'PR_LOG_DEBUG', 'CKA_KEY_TYPE', 'CERTValParamInValue',
           'SO_RCVBUFFORCE', 'CK_MECHANISM_TYPE', 'SEC_ASN1_SAVE',
           'CKA_TRUST_IPSEC_USER', 'time_t',
           'SEC_OID_SECG_EC_SECT163K1', 'htons', 'PR_ROUNDUP',
           'CKA_NETSCAPE_DB', 'PR_BITS_PER_INT64',
           'CERT_MAX_SERIAL_NUMBER_BYTES', 'IPV6_PMTUDISC_DONT',
           'IP_UNBLOCK_SOURCE', 'EAI_OVERFLOW', 'SEC_OID_UNKNOWN',
           'CKM_TWOFISH_KEY_GEN', '_IO_RIGHT', '_PATH_SERVICES',
           'BITS_PER_INT', 'PR_BITS_PER_INT', 'PR_MAX_ERROR',
           'DER_PRINTABLE_STRING', '_OLD_STDIO_MAGIC', '_STDLIB_H',
           '_G_pid_t', 'CKM_KEY_WRAP_LYNKS', 'CK_ATTRIBUTE',
           'PR_LD_NOW', 'IPV6_ROUTER_ALERT', 'toascii_l',
           'SEC_ASN1_UTC_TIME', 'SEC_ASN1EncodingPart',
           'SECMOD_FRIENDLY_FLAG', 'SFTK_MIN_FIPS_USER_SLOT_ID',
           'CK_MECHANISM', '__toascii_l', 'SEC_OID_PKIX_OCSP_CRL',
           'PR_SockOpt_SendBufferSize', 'CKS_RW_USER_FUNCTIONS',
           'SEC_OID_PKCS12_PKCS8_SHROUDED_KEY_BAG_ID', 'in_addr_t',
           'SOL_X25', 'in6_pktinfo', 'PF_LLC', '__int64_t',
           'CKA_OBJECT_ID', 'SEC_OID_SHA1', 'CERTSubjectNode',
           'CKK_CAST5', 'SO_LINGER', 'uid_t',
           'SEC_OID_AVA_ORGANIZATION_NAME', '__LITTLE_ENDIAN',
           'PR_BITS_PER_LONG_LOG2', 'MSG_PEEK',
           'SEC_OID_PKCS12_PBE_IDS', 'ssl_kea_size', 'CKM_SEED_MAC',
           'CERTStatusConfigStr', 'IP_RECVORIGDSTADDR',
           'CKM_DES3_CBC_ENCRYPT_DATA', 'N9PRLibSpec4DOT_314DOT_33E',
           'SEC_OID_NS_CERT_EXT_SSL_SERVER_NAME',
           'SEC_ASN1_TELETEX_STRING',
           'CERT_REV_M_SKIP_TEST_ON_MISSING_SOURCE',
           'CK_TLS_PRF_PARAMS_PTR',
           'SEC_OID_AVA_ORGANIZATIONAL_UNIT_NAME',
           'SEC_OID_ANSIX962_EC_PRIME192V1',
           'SEC_OID_ANSIX962_EC_PRIME192V2',
           'SEC_OID_ANSIX962_EC_PRIME192V3', 'AF_RDS',
           'CERTPublicKeyAndChallengeStr', 'CKF_USER_PIN_FINAL_TRY',
           'certPackageNSCertWrap', 'IP_IPSEC_POLICY', 'CKH_CLOCK',
           'DER_PRIVATE', 'PRFileInfo', '_BITS_PTHREADTYPES_H',
           '_IO_FLAGS2_NOTCANCEL', '_POSIX_SOURCE',
           'PR_OPERATION_ABORTED_ERROR', 'PRMcastRequest',
           '_G_uint32_t', 'IPV6_RTHDR_TYPE_0', 'PR_BITS_PER_SHORT',
           'SECMOD_INTERNAL', 'CKA_PRIVATE', 'SECMOD_SLOT_FLAGS',
           'SEC_ASN1_APPLICATION',
           'CERT_REV_M_IGNORE_MISSING_FRESH_INFO',
           'SEC_OID_PKCS12_CERT_AND_CRL_BAG_ID',
           '_IO_CURRENTLY_PUTTING', 'RF_UNUSED', 'DER_TAG_MASK',
           'CK_BYTE', 'CK_SSL3_KEY_MAT_OUT', '__nlink_t', 'AF_IUCV',
           'certificateUsageObjectSigner',
           'CERT_REV_M_REQUIRE_INFO_ON_MISSING_SOURCE', 'PF_PACKET',
           'CKK_DES2', 'CKK_DES3', 'CKZ_SALT_SPECIFIED',
           'PRErrorCallbackLookupFn', 'PRFileType',
           'SEC_OID_SECG_EC_SECT409R1', 'DER_OUTER', 'CERTUserNotice',
           '__U64_TYPE', 'PR_UPTRDIFF', 'cookie_io_functions_t',
           'CKM_CDMF_ECB', 'CK_KEA_DERIVE_PARAMS_PTR',
           'SEC_OID_PKCS5_PBES2', 'CKK_CAST',
           'CKA_NETSCAPE_PQG_SEED_BITS', 'siEncodedCertBuffer',
           'PK11_ATTR_MODIFIABLE', 'CK_BYTE_PTR',
           'CERTPrivKeyUsagePeriodStr', 'int_least16_t',
           'CK_SSL3_KEY_MAT_PARAMS_PTR', 'MCAST_MSFILTER',
           'CERTPackageType', 'CERT_MAX_CERT_CHAIN',
           'SEC_OID_PKCS1_MD4_WITH_RSA_ENCRYPTION', 'CERTCrlEntryStr',
           'CKM_SSL3_KEY_AND_MAC_DERIVE', 'nssILockArena',
           'SEC_OID_PKCS9_CHALLENGE_PASSWORD',
           'IP_DEFAULT_MULTICAST_TTL', 'IPV6_V6ONLY', 'AF_ASH',
           'SEC_OID_AVA_POSTAL_ADDRESS', 'CERTValOutParam',
           'certOtherName', 'CKM_PBE_MD5_CAST5_CBC',
           'CERTAuthInfoAccessStr', 'CKM_SHA384', 'certOwnerPeer',
           'CKM_MD5', 'SECMOD_RSA_FLAG', 'NETDB_INTERNAL',
           'CK_VOID_PTR_PTR', 'CKA_COLOR', '__islower_l',
           'PK11_ATTR_TOKEN', 'IP_MTU_DISCOVER',
           'SEC_OID_PKCS9_COUNTER_SIGNATURE', 'CKM_CAMELLIA_ECB',
           '__socket_type', 'NI_MAXHOST', 'PR_UINT32',
           'SEC_OID_X509_NAME_CONSTRAINTS',
           'SEC_OID_PKCS7_SIGNED_DATA', 'SOL_RAW',
           'CKM_CDMF_MAC_GENERAL', 'SSL_REQUIRE_ALWAYS',
           'HT_FREE_VALUE', 'N18CERTGeneralNameStr4DOT_64E',
           'CKA_TRUST_KEY_CERT_SIGN', 'CKR_WRAPPED_KEY_INVALID',
           'IPV6_2292HOPOPTS', 'useconds_t', 'MSG_CONFIRM', '__bos0',
           '__SIZEOF_PTHREAD_MUTEX_T', '_IO_STDIO', 'PRInt32',
           'PR_MAX_DIRECTORY_ENTRIES_ERROR', 'IPPORT_BIFFUDP',
           'CK_RC5_MAC_GENERAL_PARAMS_PTR', 'CKM_SKIPJACK_CBC64',
           'CERTIssuerAndSNStr', 'CKA_LOCAL',
           'INADDR_MAX_LOCAL_GROUP', 'SEC_OID_AES_256_ECB',
           '__sig_atomic_t', 'CERTPolicyStringCallback', 'PRIntn',
           'SOCK_PACKET', 'PR_ALIGN_OF_DOUBLE', 'SEC_OID_RC5_CBC_PAD',
           'CKT_NETSCAPE_TRUSTED', 'cert_pi_certStores',
           'CKM_PBE_MD5_CAST128_CBC', 'PRHashComparator',
           'SEC_CERT_NICKNAMES_CA', 'PR_IO_LAYER_HEAD',
           'CKM_DES3_ECB', 'CKO_NSS_DELSLOT', 'PR_SockOpt_MaxSegment',
           'RF_KEY_COMPROMISE', 'CKR_CRYPTOKI_NOT_INITIALIZED',
           'NSSRWLock', 'PRInt8', 'IPV6_AUTHHDR', 'MSG_FIN',
           'PZ_Unlock', 'EAI_NONAME', '__useconds_t', 'CERTNameStr',
           'PF_PHONET', 'IN_CLASSB_NET', 'SEC_OID_SECG_EC_SECP160R1',
           'SEC_OID_SECG_EC_SECP160R2', 'CKR_ENCRYPTED_DATA_INVALID',
           'INET6_ADDRSTRLEN', 'CKM_CAST5_KEY_GEN',
           'cert_po_errorLog', 'CKF_SO_PIN_FINAL_TRY',
           'SECMOD_MODULE_DB_FUNCTION_ADD', '__STRING',
           'SEC_OID_ANSIX962_EC_C2PNB272W1', '__WCHAR_MIN',
           'SSL_SECURITY_STATUS_ON_HIGH', 'CKM_DES3_ECB_ENCRYPT_DATA',
           '__GNUC_PREREQ', 'EAI_SOCKTYPE', '__BLKCNT64_T_TYPE',
           'CKR_FUNCTION_NOT_PARALLEL', 'PRHashAllocOps',
           'SSL_NOT_ALLOWED', 'SECMODModuleDBFunc', '__PDP_ENDIAN',
           'ssl_mac_sha', 'CKM_MD2_RSA_PKCS', 'SECCertificateUsage',
           'CKM_MD5_RSA_PKCS', 'loff_t', 'certUsageEmailRecipient',
           '__pid_t', '__va_arg_pack', 'CERTDERCerts',
           'CKM_SSL3_PRE_MASTER_KEY_GEN',
           'SEC_OID_ANSIX962_EC_C2TNB191V3',
           'SEC_OID_ANSIX962_EC_C2TNB191V2',
           'SEC_OID_SECG_EC_SECT233R1', 'AI_IDN_ALLOW_UNASSIGNED',
           '_SIGSET_NWORDS', 'GAI_WAIT', 'iovec', 'uint32_t',
           'SECMODModule', 'SEC_OID_HMAC_SHA256',
           'CKR_MECHANISM_INVALID', 'IPV6_RECVTCLASS',
           'CKA_TRUST_IPSEC_TUNNEL',
           'N22CERTValParamInValueStr4DOT_82E',
           'CKO_NSS_BUILTIN_ROOT_LIST', 'PR_IRWXG', '_G_HAVE_ATEXIT',
           'CERT_ENABLE_HTTP_FETCH', 'CKT_NETSCAPE_TRUSTED_DELEGATOR',
           'SEC_OID_AES_192_KEY_WRAP', 'SSLExtensionType',
           'CKR_WRAPPING_KEY_TYPE_INCONSISTENT', 'PR_IRWXU',
           '_NETINET_IN_H', 'NFDBITS', 'nssILockType',
           'CKM_CAST5_MAC_GENERAL', '_IO_USER_LOCK', 'cmsghdr',
           'siClearDataBuffer', 'int_fast32_t', 'lldiv_t',
           'CK_ECDH1_DERIVE_PARAMS', 'PR_StandardInput',
           'SECMOD_INT_FLAGS', 'EOF', 'SEC_OID_MD2', 'SEC_OID_MD5',
           'SEC_OID_MD4', 'uint8_t', '_G_HAVE_MREMAP',
           'SEC_ASN1_SET_OF', 'CERTRevocationTests', 'L_cuserid',
           'CKA_OWNER', 'CK_RC2_PARAMS_PTR', 'CK_WTLS_PRF_PARAMS_PTR',
           'IPPORT_ROUTESERVER', 'PR_UINT8_MAX', 'CKO_HW_FEATURE',
           'CKF_REMOVABLE_DEVICE', 'makedev', 'CKO_PUBLIC_KEY',
           'CKM_RSA_PKCS_OAEP', 'SEC_ASN1_ENUMERATED', 'trustEmail',
           'CERTSignedCrlStr', 'IPPROTO_RSVP', 'PF_X25',
           'CERT_REV_MI_REQUIRE_SOME_FRESH_INFO_AVAILABLE',
           'IP_RECVERR', 'CKA_NEVER_EXTRACTABLE',
           'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE', 'SOCK_RDM',
           'IPPROTO_AH', 'SECKEYPrivateKeyList',
           'PR_TRANSMITFILE_KEEP_OPEN', '__WSTOPSIG',
           'CK_UNAVAILABLE_INFORMATION',
           'SEC_OID_NS_CERT_EXT_HOMEPAGE_URL',
           'PR_CONNECT_REFUSED_ERROR', 'IPPORT_MTP',
           'PR_INVALID_IO_LAYER', 'PRCList',
           '__SIZEOF_PTHREAD_MUTEXATTR_T', 'PR_PROT_WRITECOPY',
           'CKA_EC_POINT', '_IO_jump_t', '_ISdigit',
           'SEC_OID_X509_KEY_USAGE', 'SEC_ASN1_VISIBLE_STRING',
           'SEC_OID_MISSI_KEA', 'EAI_NOTCANCELED',
           'SEC_OID_ANSIX962_EC_C2TNB239V2',
           'SEC_OID_ANSIX962_EC_C2TNB239V3', 'CKR_KEY_INDIGESTIBLE',
           'SEC_OID_ANSIX962_EC_C2TNB239V1', 'CKM_CDMF_CBC',
           'PK11_OriginDerive', 'ALIGN_OF_DOUBLE',
           'SEC_CERTIFICATE_REQUEST_VERSION', 'CKD_NULL',
           'certificateUsageEmailRecipient', 'PR_IRGRP',
           'ssl_compression_null', 'CKA_VENDOR_DEFINED',
           'SSL_ENABLE_SESSION_TICKETS', 'SSL_NO_LOCKS', '_IO_off_t',
           'PR_CONNECT_TIMEOUT_ERROR', 'CKA_NSS_PQG_SEED',
           '__clockid_t', 'PRCloseFN', 'SSL_ENABLE_FDX', 'osockaddr',
           'IPPROTO_RAW', 'CKM_CAST5_CBC', 'CKA_TRUST',
           'CRL_DECODE_DONT_COPY_DER', 'PR_CONNECT_ABORTED_ERROR',
           'SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE',
           'CK_RC5_PARAMS_PTR', '__WEXITSTATUS', 'PR_LD_GLOBAL',
           'SEC_OID_PKCS12_PKCS8_KEY_SHROUDING', '_IO_pos_t',
           'OtherName', 'nssILockSlot', 'SOL_ICMPV6',
           'PR_SockOpt_AddMember', '_ISxdigit', 'DER_OCTET_STRING',
           'SHUT_RD', 'CK_NULL_PTR', 'PK11_OriginFortezzaHack',
           'CERT_ENABLE_LDAP_FETCH', 'SEC_ASN1_BIT_STRING',
           '__WIFEXITED', 'SCM_RIGHTS', 'CKR_NEED_TO_CREATE_THREADS',
           'PR_SKIP_NONE', 'LL_NE', 'SSL_SECURITY',
           'CKA_SUB_PRIME_BITS', 'isspace_l', 'CKM_BLOWFISH_CBC',
           'CKA_PRIME_BITS', 'CKF_DUAL_CRYPTO_OPERATIONS', 'CK_LONG',
           'IPPROTO_TCP', 'PORTCharConversionFunc',
           'PR_ALIGN_OF_WORD', '__mode_t',
           'SEC_OID_NS_CERT_EXT_CA_CRL_URL', 'CKM_DES_ECB',
           'SEC_ASN1_EMBEDDED_PDV', 'secCertTimeUndetermined',
           'uintn', 'CKM_MD5_HMAC', 'SECMOD_WAIT_SIMULATED_EVENT',
           'INET_ADDRSTRLEN', 'PR_PIPE_ERROR',
           'CKA_NSS_SMIME_TIMESTAMP', 'IN_EXPERIMENTAL',
           'CERTCertList', 'PR_INSUFFICIENT_RESOURCES_ERROR',
           'CK_OBJECT_HANDLE_PTR', 'ssl_session_ticket_xtn',
           '__BIG_ENDIAN', 'minor', 'SECMOD_FIPS',
           'SEC_OID_NS_CERT_EXT_CERT_RENEWAL_URL',
           '__USE_FORTIFY_LEVEL', 'uint8', 'PRErrorTable',
           'SEC_ASN1_PRIVATE', 'EAI_SYSTEM', 'CKM_SHA1_RSA_PKCS',
           'CKM_RC2_KEY_GEN', 'SIOCGSTAMP', 'CKM_SHA256_RSA_PKCS_PSS',
           'RF_AFFILIATION_CHANGED',
           'SEC_OID_PKCS7_SIGNED_ENVELOPED_DATA', 'CERTAuthKeyIDStr',
           'uint64', 'CKM_CONCATENATE_BASE_AND_DATA',
           '__FSBLKCNT64_T_TYPE', 'CKR_KEY_HANDLE_INVALID',
           'certUsageSSLServer', 'SEC_ASN1_T61_STRING',
           'PRErrorCallbackTablePrivate', 'AF_X25',
           'SEC_ASN1_CONTEXT_SPECIFIC', '__fsfilcnt64_t',
           'CKM_ECDSA_SHA1', 'cert_pi_nbioAbort',
           'CKA_TRUST_KEY_ENCIPHERMENT', 'CKA_HW_FEATURE_TYPE',
           'PF_IUCV', 'CKK_CAST3', 'IPPORT_TFTP',
           'SECMOD_SHA512_FLAG', 'PRShutdownFN',
           'SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_40_BIT_RC4',
           'CK_TLS_PRF_PARAMS',
           'SEC_OID_PKIX_REGCTRL_PKI_ARCH_OPTIONS', 'SSL_CBP_SSL3',
           'N22CERTValParamInValueStr4DOT_81E', 'CKM_SKIPJACK_RELAYX',
           'SEC_CERT_CLASS_EMAIL',
           'SEC_OID_PKCS1_MD5_WITH_RSA_ENCRYPTION', 'PZ_NewLock',
           'SEC_ASN1D_MAX_DEPTH', 'siDEROID',
           'sec_DecoderContext_struct', 'cert_revocation_method_ocsp',
           'CKA_NETSCAPE_PASSWORD_CHECK',
           'SEC_OID_ISO_SHA_WITH_RSA_SIGNATURE',
           'PR_SockOpt_Broadcast', 'AF_SNA',
           'SEC_OID_ANSIX962_EC_PRIME239V2',
           'SEC_OID_ANSIX962_EC_PRIME239V3',
           'SEC_OID_ANSIX962_EC_PRIME239V1', 'PR_BITS_PER_WORD',
           'PRExplodedTime', 'CKR_KEY_NOT_NEEDED', 'CK_SLOT_ID',
           'PR_IXUSR', 'ipv6_mreq', 'PR_LOG_ERROR', 'SEC_ASN1_SET',
           'PR_INVALID_STATE_ERROR', 'CKR_ENCRYPTED_DATA_LEN_RANGE',
           'SSLBadCertHandler', 'SIOCGSTAMPNS', 'SECMODModuleList',
           'CERTCRLEntryReasonCodeEnum', 'CERTCertificateList',
           'PR_LibSpec_Pathname', 'CKA_URL', 'CKS_RW_PUBLIC_SESSION',
           'certValidityUndetermined', 'CKM_CAST128_KEY_GEN',
           'IN_CLASSC_NSHIFT', 'PRArena', 'cert_pi_certList',
           'PRInt64', 'SEC_OID_SHA256', 'PR_ACCEPT_READ_BUF_OVERHEAD',
           'CKA_PRIME_1', 'CKR_UNWRAPPING_KEY_HANDLE_INVALID',
           'CKA_PRIME_2', 'SECKEYPQGParams', '_ISspace', '__clock_t',
           'IPV6_ADDRFORM', 'CKM_CAST_ECB', 'PZ_InMonitor',
           'IPV6_RECVERR', '__STDLIB_MB_LEN_MAX',
           'SECKEYDiffPQGParamsStr',
           'SEC_OID_NS_CERT_EXT_ENTITY_LOGO', 'PRWriteFN',
           'CKM_DES_ECB_ENCRYPT_DATA', '__LONG_LONG_PAIR',
           '__WCOREDUMP', 'CKM_IDEA_MAC_GENERAL', 'CERTCrlNumber',
           'IP_MINTTL', 'CKM_BATON_SHUFFLE', 'CKK_SKIPJACK',
           'PR_POLL_READ', 'CKF_EC_COMPRESS',
           'SEC_OID_X509_SUBJECT_ALT_NAME', 'SEC_ASN1_INLINE',
           'PR_ALIGN_OF_FLOAT', 'SEC_ASN1_XTRN', 'PRUint32',
           'CKM_X9_42_MQV_DERIVE', 'CERTNameConstraintStr',
           'CK_OBJECT_HANDLE', 'fsblkcnt64_t',
           'SECKEYPrivateKeyListNode', 'PK11_TypeGeneric',
           'SECKEYPrivateKeyInfoStr', '_G_HAVE_LONG_DOUBLE_IO',
           'IPV6_2292PKTINFO', 'SECItemStr', '_IOS_APPEND',
           'CKR_NSS_CERTDB_FAILED', 'PR_CREATE_FILE',
           'SEC_OID_NS_CERT_EXT_SUBJECT_LOGO', 'fpos64_t',
           'CK_INFO_PTR', 'CERTCertExtension', '_G_BUFSIZ',
           'CKA_AC_ISSUER', 'KU_DIGITAL_SIGNATURE',
           'cert_pi_keyusage', 'SEC_OID_NS_CERT_EXT_CA_POLICY_URL',
           'PR_NOT_DIRECTORY_ERROR', 'PRAcceptreadFN',
           'SEC_OID_PKCS12_KEY_BAG_ID', 'AI_ALL', 'CKR_KEY_NEEDED',
           'SEC_OID_DES_ECB', 'PR_LD_LAZY',
           'SEC_OID_PKIX_TIMESTAMPING',
           'SEC_OID_AVA_STATE_OR_PROVINCE', 'SO_PEERNAME',
           'NI_NAMEREQD', 'SOCK_STREAM', 'CKR_MUTEX_BAD', 'isalnum_l',
           'CK_SKIPJACK_PRIVATE_WRAP_PARAMS', 'PR_SYNC',
           'SEC_ASN1DecoderContext', '__USE_ANSI',
           'PK11DisableReasons', 'SEC_OID_X509_EXT_KEY_USAGE',
           '_IO_NO_READS', 'SSL_SECURITY_STATUS_NOOPT',
           'CERT_REV_MI_TEST_EACH_METHOD_SEPARATELY', 'uprword_t',
           'AI_IDN', '__GLIBC_MINOR__', 'CK_LOCKMUTEX',
           'certX400Address', 'SEC_ASN1_SKIP_REST', 'SO_ACCEPTCONN',
           'IPPORT_SUPDUP', 'cert_pi_policyFlags',
           'CKM_CAST3_KEY_GEN',
           'SEC_OID_PKCS12_V1_SAFE_CONTENTS_BAG_ID',
           'SECKEYAttribute', 'SEC_OID_PKCS12_KEY_USAGE',
           'pthread_barrier_t', 'IP_OPTIONS', 'CKF_SIGN',
           'SEC_ASN1_NO_STREAM', 'PK11_DISABLE_FLAG',
           'CKR_NETSCAPE_CERTDB_FAILED', 'SEC_OID_SECG_EC_SECP192R1',
           'CKR_USER_PIN_NOT_INITIALIZED', 'PRGetsocknameFN',
           'CKM_MD5_KEY_DERIVATION', 'CK_MECHANISM_INFO_PTR',
           '_G_VTABLE_LABEL_HAS_LENGTH', 'CKM_NETSCAPE_AES_KEY_WRAP',
           'DER_POINTER', 'CKA_DEFAULT_CMS_ATTRIBUTES',
           'PLHashAllocOps', 'MSG_WAITALL',
           'CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN', 'EAI_NODATA',
           'servent', 'PRSeekWhence', 'certUsageUserCertImport',
           'PK11CertListUserUnique', 'sockaddr_in6',
           'nssILockFreelist', 'AF_MAX', 'major', 'SEC_ASN1_REAL',
           'nssILockDBM', 'SEC_OID_SECG_EC_SECP224K1',
           'SSL_RENEGOTIATE_TRANSITIONAL', 'IPPORT_DAYTIME',
           'CKF_WRITE_PROTECTED', 'N18PRSocketOptionData4DOT_30E',
           'pthread_spinlock_t', 'PRFileInfo64FN',
           'CKA_HASH_OF_ISSUER_PUBLIC_KEY', 'IN_LOOPBACKNET',
           'IPPROTO_IDP', 'AF_UNIX', 'CKA_NETSCAPE_PQG_H',
           'PR_CALL_ONCE_ERROR', '__io_read_fn', 'CKM_RC5_ECB',
           'CKM_SHA384_KEY_DERIVATION', 'CERTVerifyLogNodeStr',
           'CK_SESSION_HANDLE', 'SSL_ENABLE_SSL2',
           'PRGetsocketoptionFN', 'PK11SlotListElement',
           'CKA_TRUST_KEY_AGREEMENT', 'SIGEV_THREAD_ID',
           'CKM_PBE_SHA1_RC4_40', 'NS_CERT_TYPE_SSL_CA', 'IP_TTL',
           'PF_TIPC', 'SEC_ASN1_UTF8_STRING', 'SECKEYDSAPublicKeyStr',
           '_IOS_NOCREATE', 'DER_CONTEXT_SPECIFIC', 'group_req',
           'div_t', 'AI_ADDRCONFIG', 'SSL_REQUIRE_CERTIFICATE',
           'CKM_DES_CBC', 'isalpha_l', 'certificateUsageHighest',
           '__USE_LARGEFILE', 'CKA_NETSCAPE_PQG_SEED',
           'SEC_OID_NS_CERT_EXT_LOST_PASSWORD_URL', '_FEATURES_H',
           'CK_FALSE', 'SEC_ASN1_GROUP',
           'CERT_REV_M_TEST_USING_THIS_METHOD',
           'CK_RSA_PKCS_OAEP_PARAMS_PTR', 'WCONTINUED',
           'IPV6_HOPLIMIT', 'PRInt16', 'SEC_CRL_VERSION_2',
           'SEC_ASN1_OPTIONAL', 'SFTK_MAX_USER_SLOT_ID',
           'CKA_ALWAYS_AUTHENTICATE', 'CKA_FLAGS_ONLY',
           'SSL_ROLLBACK_DETECTION', 'ssl_calg_camellia', 'CKK_IDEA',
           'SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC',
           'CK_SESSION_HANDLE_PTR', 'SEC_OID_PKIX_CA_ISSUERS',
           'ssl_auth_kea', 'SEC_OID_X509_POLICY_MAPPINGS',
           'KU_KEY_AGREEMENT', 'AF_APPLETALK', 'UIO_MAXIOV',
           'SEC_OID_SHA512', 'PRFileDesc', 'PZ_Notify', 'SSL_ALLOWED',
           '_IO_UNBUFFERED', '__id_t', 'SSL_NO_CACHE', 'IPPROTO_MTP',
           'PR_SockOpt_Reuseaddr', 'SO_DETACH_FILTER',
           'CKM_CAST5_ECB', '__WIFSTOPPED', 'SEC_OID_AVA_POSTAL_CODE',
           'PRDescIdentity', 'SEC_OID_DES_OFB', 'DER_BOOLEAN',
           'siAsciiString', 'SEC_OID_PKCS1_MD2_WITH_RSA_ENCRYPTION',
           'siUTCTime', 'IP_MULTICAST_TTL', 'CKK_BATON',
           '__blkcnt64_t',
           'CERT_REV_M_IGNORE_IMPLICIT_DEFAULT_SOURCE',
           'CKA_TRUST_NON_REPUDIATION', 'CKM_AES_MAC',
           'CK_WTLS_KEY_MAT_PARAMS_PTR', 'ssl_kea_ecdh', 'be16toh',
           'certOwnerUser', 'CERT_REV_M_FORBID_NETWORK_FETCHING',
           'SEC_OID_SECG_EC_SECT283K1', 'CERTValidity', 'PR_INT8_MIN',
           'CKO_CERTIFICATE', 'CKM_RIPEMD160_HMAC', 'mode_t',
           'CK_RC5_PARAMS', 'SEC_OID_NS_TYPE_CERT_SEQUENCE',
           'sec_ASN1Template_struct', 'sec_EncoderContext_struct',
           'isascii_l', 'certificateUsageAnyCA',
           'PR_BITS_PER_WORD_LOG2', 'CKA_TRUST_SERVER_AUTH',
           'PZ_DestroyMonitor', 'CKR_SAVED_STATE_INVALID',
           'SECMOD_MODULE_DB_FUNCTION_RELEASE',
           'SEC_OID_PKCS9_SMIME_CAPABILITIES', '_LARGEFILE_SOURCE',
           'CERTCrlDistributionPoints', 'KU_NS_GOVT_APPROVED',
           'CKK_NSS', '_IO_TIED_PUT_GET', 'SECKEYPrivateKeyInfo',
           'PZ_ExitMonitor', '__loff_t', 'SO_TYPE',
           'IPV6_LEAVE_ANYCAST', 'FD_CLR', 'cookie_seek_function_t',
           'CKF_USER_PIN_INITIALIZED', 'PLHashComparator',
           '_G_USING_THUNKS', 'CK_PKCS5_PBKD2_PARAMS_PTR',
           'SEC_OID_CMS_RC2_KEY_WRAP', 'CERTBasicConstraints',
           'SEC_CRL_TYPE', 'IPPROTO_UDPLITE',
           'CKM_DH_PKCS_PARAMETER_GEN', 'N8sigevent4DOT_22E',
           'FOPEN_MAX', 'SEC_OID_NS_CERT_EXT_ISSUER_LOGO',
           'nssILockSSL', 'va_list', 'PR_SKIP_BOTH',
           'SEC_OID_MISSI_KEA_DSS', 'fd_mask',
           'IP_ADD_SOURCE_MEMBERSHIP', 'CKM_TLS_MASTER_KEY_DERIVE',
           '__int16_t', 'SEC_OID_EXT_KEY_USAGE_EMAIL_PROTECT',
           'CKM_AES_KEY_GEN', 'BITS_PER_INT64', 'IPPORT_NAMESERVER',
           'nullKey', 'certPackageCert', '__FDELT', '__io_write_fn',
           'BITS_PER_FLOAT', 'CK_ECDH2_DERIVE_PARAMS_PTR',
           'random_data', 'PRPollFN', '_PATH_HEQUIV',
           'SEC_OID_NETSCAPE_SMIME_KEA', 'PR_UINT32_MAX',
           'SEC_OID_SECG_EC_SECP160K1', 'CERTRevocationMethodIndex',
           'N4wait4DOT_36E', 'WIFCONTINUED', 'PLArenaPool',
           '__va_arg_pack_len', 'CKM_INVALID_MECHANISM',
           'CKM_DH_PKCS_DERIVE', 'CKA_SUBJECT', 'CKA_PRIME',
           'CK_DES_CBC_ENCRYPT_DATA_PARAMS',
           'PR_SockOpt_IpTypeOfService',
           'CKM_CAMELLIA_CBC_ENCRYPT_DATA', 'N9PRNetAddr4DOT_29E',
           'CKF_RW_SESSION', 'SEC_OID_RC2_CBC', 'SEC_OID_PKCS12',
           'htole16', 'CKM_RIPEMD128_RSA_PKCS', '__USE_ISOC99',
           '__intptr_t', 'trustSSL', 'PR_DIRECTORY_LOOKUP_ERROR',
           'PF_SNA', '__timespec_defined',
           'SEC_ASN1_PRINTABLE_STRING', 'CKC_VENDOR_DEFINED',
           'CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT',
           'CERTVerifyLogNode', 'PR_INT16_MIN', 'SECLessThan',
           'CKR_USER_TYPE_INVALID', 'CKR_GENERAL_ERROR', '_SYS_UIO_H',
           '__SIZEOF_PTHREAD_BARRIERATTR_T', '_IOS_INPUT',
           'SECSupportExtenTag', 'CKM_SHA_1_HMAC_GENERAL',
           'SEC_ASN1_NUMERIC_STRING', '_IOS_BIN', 'alloca',
           'BYTES_PER_DOUBLE', 'CERTValParamOutType',
           'SEC_OID_X509_CRL_DIST_POINTS', 'CERTGeneralName',
           '_IO_BAD_SEEN',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC',
           'PR_NSPR_ERROR_BASE', '__BIT_TYPES_DEFINED__',
           'PR_NAME_TOO_LONG_ERROR', 'PK11_OriginNULL',
           'SEC_OID_PKIX_REGCTRL_AUTHENTICATOR', 'SO_PEERCRED',
           'in6_addr', 'CK_EFFECTIVELY_INFINITE', 'SCOPE_DELIMITER',
           'SEC_OID_SECG_EC_SECP256R1', 'CKR_OK', 'CKF_DONT_BLOCK',
           'SEC_OID_ANSIX962_ECDSA_SHA512_SIGNATURE',
           'sockaddr_storage', 'certificateUsageSSLServer',
           'CKM_X9_42_DH_DERIVE', 'P_tmpdir', 'CKM_VENDOR_DEFINED',
           'CertStrictnessLevels', 'PK11IsLoggedInFunc',
           'CKM_IDEA_KEY_GEN', 'CK_VERSION_PTR', 'SEC_OID_AVA_TITLE',
           'CRL_DECODE_SKIP_ENTRIES', 'CKM_SEED_MAC_GENERAL',
           'SEC_OID_PKIX_CA_REPOSITORY', 'CERTPolicyMap',
           'CKM_SHA224_HMAC', 'CKM_SKIPJACK_CFB64', 'PR_POLL_ERR',
           'CKM_JUNIPER_KEY_GEN', 'relativeDistinguishedName',
           'CKM_SHA384_RSA_PKCS_PSS', 'PR_SockOpt_RecvBufferSize',
           'SEC_OID_PKCS12_RSA_SIGNATURE_WITH_SHA1_DIGEST',
           'CKA_TOKEN', 'int_fast16_t', 'PZ_NotifyAll',
           'CKM_PBE_SHA1_RC4_128', 'PR_LOG_DEFINE', 'IPV6_RXHOPOPTS',
           'SECCertTimeValidity', '__DEV_T_TYPE', '__WTERMSIG',
           'PF_MAX', 'AF_NETROM', 'CERTCrlNode',
           'CKA_TRUST_IPSEC_END_SYSTEM', 'PK11RSAGenParams',
           'CERT_N2A_READABLE', 'CKM_XOR_BASE_AND_DATA',
           'PR_ILLEGAL_ACCESS_ERROR', 'ssl_kea_dh', 'drand48_data',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4',
           'CKM_SHA512', 'PROffset64', 'CKM_CAST3_MAC_GENERAL',
           'FIOSETOWN', 'CKM_CAST128_MAC', '__USE_XOPEN2K8XSI',
           'CKA_RESET_ON_INIT', 'PRLanguageCode', '_G_size_t',
           '_SYS_CDEFS_H', 'INADDR_UNSPEC_GROUP', 'CKK_DSA',
           '__pthread_mutex_s', '_IO_IS_FILEBUF', 'SEEK_SET',
           'INVALID_CERT_EXTENSION', 'CKM_DSA_SHA1',
           'CKR_RANDOM_NO_RNG', '_IOS_OUTPUT',
           'SEC_CERT_NICKNAMES_USER', 'IPPORT_LOGINSERVER',
           'PK11_DIS_TOKEN_NOT_PRESENT', 'CERTCrl',
           'SEC_OID_PKCS9_SDSI_CERT', 'SO_ATTACH_FILTER',
           'certDirectoryName', 'PRMonitor', 'PK11_PW_AUTHENTICATED',
           'SECMOD_CAMELLIA_FLAG', 'SEC_ASN1EncoderContext',
           'CKM_PBE_MD5_DES_CBC', 'PR_UNKNOWN_ERROR',
           'SEC_OID_PKCS9_UNSTRUCTURED_ADDRESS',
           'SEC_ASN1_EndOfContents', 'uint_fast8_t', 'PRSendfileFN',
           'CK_C_INITIALIZE_ARGS', 'suseconds_t',
           'CKT_NSS_MUST_VERIFY', 'CK_AES_CBC_ENCRYPT_DATA_PARAMS',
           'CKM_ECMQV_DERIVE', 'CKR_SESSION_READ_WRITE_SO_EXISTS',
           'SO_RCVTIMEO', '_IO_LEFT', '_STRING_H', '__isdigit_l',
           'CKO_NETSCAPE_TRUST', '_G_off_t', 'DER_IA5_STRING',
           'CKM_PBE_MD2_DES_CBC', 'CKM_SHA512_HMAC_GENERAL',
           'certUsageProtectedObjectSigner',
           'CK_KEY_DERIVATION_STRING_DATA_PTR', 'SECKEYDHParams',
           'PK11_OWN_PW_DEFAULTS', 'CKT_NETSCAPE_TRUST_UNKNOWN',
           'mmsghdr', '_PATH_PROTOCOLS', 'PRCondVar',
           'SECMODModuleID', 'fd_set', 'SFTK_MIN_USER_SLOT_ID',
           'CERTValParamOutValue', 'CKM_SSL3_MD5_MAC',
           'ERROR_TABLE_BASE_nspr', 'IPPROTO_COMP',
           'PR_PENDING_INTERRUPT_ERROR', 'SEC_OID_X509_REASON_CODE',
           'SEC_ASN1_POINTER', 'CKA_END_DATE', '_IO_SHOWPOINT',
           'SEC_ASN1_IA5_STRING',
           'CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR', 'PLHashEntry',
           'SSLCipherAlgorithm', 'CK_SLOT_ID_PTR',
           'PK11TokenRemovedOrChangedEvent', 'nssILockSelfServ',
           'register_t', 'ALIGN_OF_SHORT', '_ARPA_INET_H',
           'SEC_OID_X509_AUTH_KEY_ID', 'DER_SEQUENCE', 'AF_SECURITY',
           'IPPORT_SMTP', 'SO_SNDBUFFORCE',
           'SEC_OID_CAMELLIA_256_CBC', 'SSLGetClientAuthData',
           'PR_BYTES_PER_LONG', 'MCAST_INCLUDE',
           'CERTImportCertificateFunc', 'SOCK_RAW',
           'crlEntryReasonAaCompromise', 'SECMOD_FIPS_NAME',
           'IPPORT_EFSSERVER', 'SEC_OID_SECG_EC_SECT571K1',
           'CKA_NSS_PKCS8_SALT', 'TRY_AGAIN', 'intmax_t',
           'EAI_INPROGRESS', '_IO_SHOWPOS', 'CK_RV', 'CK_NOTIFY',
           'CKR_VENDOR_DEFINED', 'N9PRNetAddr4DOT_28E',
           'CKF_ARRAY_ATTRIBUTE', 'CK_SKIPJACK_PRIVATE_WRAP_PTR',
           'CKA_TRUST_STEP_UP_APPROVED', 'int_least8_t', 'PRPollDesc',
           '__bswap_constant_16', 'PRUint16', 'IN_MULTICAST',
           'IPV6_LEAVE_GROUP', 'CKM_CAMELLIA_ECB_ENCRYPT_DATA',
           '_CTYPE_H', '_NETDB_H', 'SEC_OID_X509_POLICY_CONSTRAINTS',
           'CKM_ECDH1_DERIVE', 'CK_X9_42_MQV_DERIVE_PARAMS_PTR',
           'CKR_USER_ANOTHER_ALREADY_LOGGED_IN', 'CKA_NSS_EXPIRES',
           'SECMOD_RESERVED_FLAG', 'DER_INDEFINITE',
           'CKM_JUNIPER_SHUFFLE', 'SOMAXCONN', 'u_quad_t',
           'CKT_VENDOR_DEFINED', 'IPV6_RECVDSTOPTS',
           'SECKEYPQGDualParams', 'CK_X9_42_DH_KDF_TYPE_PTR',
           'IPV6_MTU', '_IO_peekc', 'certificateUsageCheckAllUsages',
           'CKA_DIGEST', 'CKR_RANDOM_SEED_NOT_SUPPORTED',
           'CKF_DECRYPT', '__CONCAT', 'CKA_WRAP_WITH_TRUSTED',
           'ptrdiff_t', '_IOS_NOREPLACE', 'crlEntryReasonSuperseded',
           'AF_INET6', 'N8in6_addr4DOT_21E', '__ispunct_l',
           'CKA_BASE', 'intn', 'SEEK_CUR', 'CKM_SHA1_RSA_X9_31',
           'CRL_DECODE_KEEP_BAD_CRL', 'CKF_EXTENSION', 'PR_LD_LOCAL',
           'PR_INT32_MAX', 'CKM_PBE_SHA1_DES3_EDE_CBC',
           'CK_INVALID_SESSION', 'N18CERTCertificateStr4DOT_62E',
           'ssl_kea_null', 'IP_DROP_SOURCE_MEMBERSHIP', 'CERTCertKey',
           'SECKEYPublicKeyStr', '_IO_cookie_file',
           'CKM_SSL3_SHA1_MAC', 'IPPORT_TIMESERVER',
           'CKF_LIBRARY_CANT_CREATE_OS_THREADS', 'IPV6_NEXTHOP',
           'PK11Origin', 'SIGEV_SIGNAL', '__uint16_t', 'CK_BBOOL',
           'u_int', 'CKM_NSS', 'CRLDistributionPoint', 'gid_t',
           'int8', 'SEC_OID_AVA_DN_QUALIFIER', 'DER_VISIBLE_STRING',
           'CKA_VALUE_LEN', 'PR_DESC_FILE', 'SEC_ASN1Template',
           'SEC_OID_PKCS12_ESPVK_IDS', 'SEC_CERT_NICKNAMES_SERVER',
           'SEC_OID_EXT_KEY_USAGE_CODE_SIGN', 'CKM_DES3_KEY_GEN',
           'LL_EQ', 'PRFuncPtr', 'CRL_IMPORT_BYPASS_CHECKS',
           '_STDIO_H', 'CKR_KEY_FUNCTION_NOT_PERMITTED',
           'cookie_close_function_t', 'PR_DIRECTORY_OPEN_ERROR',
           'IPV6_CHECKSUM', 'FIOGETOWN', 'CKR_FUNCTION_FAILED',
           'PRPackedBool', 'BITS_PER_DOUBLE', '_PARAMS', 'CKA_SIGN',
           'certPackageNSCertSeq', 'PR_SEEK_CUR',
           'cert_pi_trustAnchors', 'CKM_RSA_X9_31_KEY_PAIR_GEN',
           'CK_ECDH2_DERIVE_PARAMS', 'PF_ATMSVC',
           'CKA_ENCODING_METHODS', 'PR_SockOpt_DropMember',
           'RF_CERTIFICATE_HOLD', 'AF_PPPOX', 'CERTValParamInType',
           'PR_BITS_PER_LONG', 'CKM_SKIPJACK_CFB32',
           'SSL_MAX_EXTENSIONS', '__fsblkcnt64_t', 'DER_PRIMITIVE',
           '_G_NEED_STDARG_H', 'SEC_ASN1_OCTET_STRING',
           '__io_close_fn', '__FSFILCNT64_T_TYPE', 'CKD_SHA1_KDF',
           'CKO_NSS_SMIME', 'NS_CERT_TYPE_SSL_CLIENT',
           '_G_VTABLE_LABEL_PREFIX', 'SECMOD_FIPS_FLAGS',
           '_G_int16_t', '__socklen_t', 'NSPR_API',
           'certificateUsageUserCertImport', 'CKK_JUNIPER',
           'CK_OBJECT_CLASS_PTR', '__codecvt_noconv',
           'CKR_DATA_LEN_RANGE', 'CKM_DSA', 'CK_RC2_PARAMS',
           'SEC_OID_AVA_LOCALITY', 'SECCertUsageEnum',
           '_IO_UPPERCASE', '_ATFILE_SOURCE', '_KEYTHI_H_',
           'PR_IO_PENDING_ERROR', 'CKR_SESSION_EXISTS',
           'SEC_OID_NS_CERT_EXT_NETSCAPE_OK', 'SSL_ENABLE_DEFLATE',
           'CKM_CAST3_MAC', 'SEC_OID_NS_CERT_EXT_REVOCATION_URL',
           'CKF_SO_PIN_LOCKED', 'CERT_POLICY_FLAG_EXPLICIT',
           'MSG_DONTROUTE', 'PRBool', 'PR_SHUTDOWN_BOTH',
           'PRWritevFN', 'CKR_SIGNATURE_INVALID', 'PF_SECURITY',
           'CKO_NETSCAPE_DELSLOT', 'sigval_t', 'fpos_t',
           'CKR_INFORMATION_SENSITIVE', '_IO_EOF_SEEN', 'IP_PASSSEC',
           'CKM_SKIPJACK_PRIVATE_WRAP', 'IPV6_DSTOPTS',
           '__SIZEOF_PTHREAD_CONDATTR_T', 'PLArena', 'CKA_ATTR_TYPES',
           'CERTSignedData', 'NSS_USE_ALG_IN_CERT_SIGNATURE',
           '_STRUCT_TIMEVAL', 'PR_NSPR_IO_LAYER',
           'CKT_NSS_TRUST_UNKNOWN', 'PORT_Strlen',
           'CERT_REV_M_STOP_TESTING_ON_FRESH_INFO',
           'SEC_OID_PKIX_REGCTRL_REGTOKEN', 'BITS_PER_BYTE_LOG2',
           'CKR_SESSION_HANDLE_INVALID', 'SEC_ASN1_PRIMITIVE',
           '__ASMNAME', 'CK_TOKEN_INFO', 'CK_RSA_PKCS_OAEP_PARAMS',
           'SEC_OID_TOTAL', 'SECOidData', '_BITS_TYPESIZES_H',
           'PR_ALREADY_INITIATED_ERROR', 'PR_NO_DEVICE_SPACE_ERROR',
           'CERT_POLICY_FLAG_NO_ANY', '_ALLOCA_H',
           'SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC', 'DER_EXPLICIT',
           'AF_ATMPVC', 'SO_MARK', 'SEC_OID_MISSI_DSS_OLD',
           '__have_sigval_t', 'SSL_CBP_TLS1_0',
           'SSL_SECURITY_STATUS_ON_LOW', 'MSG_NOSIGNAL',
           'SEC_OID_HMAC_SHA384', 'certificateUsageEmailSigner',
           'SEC_OID_PKCS12_V1_SECRET_BAG_ID', 'DER_BIT_STRING',
           'SO_BINDTODEVICE', 'SEC_ASN1_UNIVERSAL', 'PR_POLL_NVAL',
           'PK11TokenChanged', 'CKM_SKIPJACK_WRAP',
           'CKK_GENERIC_SECRET', 'id_t',
           'SEC_OID_X509_SUBJECT_KEY_ID', 'PR_StandardOutput',
           'MSG_TRYHARD', '_G_fpos_t', 'CKK_VENDOR_DEFINED',
           'BYTES_PER_SHORT', 'PK11ContextStr',
           'ssl_compression_deflate', 'IP_RECVRETOPTS',
           '__lldiv_t_defined', 'PR_NSEC_PER_MSEC',
           '__SIZEOF_PTHREAD_BARRIER_T', 'blkcnt_t',
           'SEC_OID_CAMELLIA_192_CBC', 'CK_HW_FEATURE_TYPE',
           'ALIGN_OF_FLOAT', 'CKM_WTLS_PRF', '_SYS_TYPES_H',
           '_ISblank', '_ISupper', 'PR_INADDR_BROADCAST',
           'PR_SKIP_HIDDEN', 'MCAST_JOIN_SOURCE_GROUP',
           'SEC_OID_MISSI_ALT_KEA', 'PRUint64', 'HT_ENUMERATE_STOP',
           'CKK_AES', 'SSLCompressionMethod',
           'SEC_OID_SECG_EC_SECT113R2', 'IPPROTO_DSTOPTS',
           'SEC_OID_SECG_EC_SECT113R1', 'PRUword', 'SSL3Statistics',
           'CKA_SENSITIVE', '__PMT', 'NSS_USE_ALG_RESERVED',
           'CERTSubjectNodeStr', 'ALIGN_OF_WORD',
           'CKZ_DATA_SPECIFIED', 'SEC_OID_PKCS12_SDSI_CERT_BAG',
           'CKR_OBJECT_HANDLE_INVALID', 'CERTPolicyQualifier',
           'SSL_HANDSHAKE_AS_CLIENT', 'SECKEYKEAPublicKeyStr',
           'PRDir', '_IO_DONT_CLOSE', 'CK_EXTRACT_PARAMS_PTR',
           'IPV6_MULTICAST_HOPS', '__WNOTHREAD',
           'BITS_PER_FLOAT_LOG2', 'CKM_DES_CBC_ENCRYPT_DATA',
           '__SIZEOF_PTHREAD_RWLOCKATTR_T', 'fsfilcnt64_t',
           'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR',
           'SEC_OID_SECG_EC_SECP192K1', '_IO_UNITBUF',
           'CKA_PUBLIC_EXPONENT', 'CKA_NSS_OVERRIDE_EXTENSIONS',
           'PR_LOG_MIN', 'CERTStatusDestroy', 'CERTCertListNode',
           '__SIGEV_PAD_SIZE', 'islower_l', 'ssize_t', 'CKM_MD2_HMAC',
           'CKM_IDEA_ECB', 'CERTRDNStr', 'isgraph_l',
           'CKR_MUTEX_NOT_LOCKED', 'PR_ACCESS_READ_OK', 'MSG_EOR',
           'PR_FILE_FILE', 'CK_FLAGS', 'CKM_CAMELLIA_MAC_GENERAL',
           'BIG_ENDIAN', 'SECMOD_EXTERNAL', '__USE_XOPEN_EXTENDED',
           'CKM_RIPEMD160_RSA_PKCS', 'CKR_SLOT_ID_INVALID',
           'CKA_NSS_EMAIL', 'siGeneralizedTime', 'timer_t',
           'PF_BLUETOOTH', 'SO_DONTROUTE', 'FD_ZERO',
           'IPV6_2292RTHDR', 'CKM_DES_MAC_GENERAL', 'CKF_DERIVE',
           'N16pthread_rwlock_t4DOT_12E', 'SEC_CERT_CLASS_CA',
           'CKM_RC2_CBC', 'PR_INT32_MIN', 'SEC_OID_AVA_INITIALS',
           '_PATH_NETWORKS', 'IPV6_PMTUDISC_PROBE', 'NO_RECOVERY',
           'CERT_REV_MI_TEST_ALL_LOCAL_INFORMATION_FIRST',
           'PR_DESC_SOCKET_TCP', 'CKU_CONTEXT_SPECIFIC',
           'certOwnerCA', 'CKM_RSA_PKCS_PSS', '__WIFCONTINUED',
           'SFTK_MAX_FIPS_USER_SLOT_ID', 'CERTIssuerAndSN',
           'SEC_OID_DES_MAC', 'int16',
           'CERTCompareValidityStatusEnum',
           'SEC_OID_X942_DIFFIE_HELMAN_KEY',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC',
           'CKM_RIPEMD160_HMAC_GENERAL', 'CKM_RC2_MAC', 'fsblkcnt_t',
           'key_t', '__USE_ISOC95', 'CKM_RSA_PKCS_KEY_PAIR_GEN',
           'PR_ACCESS_FAULT_ERROR', 'CKM_CONCATENATE_BASE_AND_KEY',
           'SECKEYEncryptedPrivateKeyInfoStr',
           'SEC_OID_ANSIX962_EC_C2ONB239V5',
           'SEC_OID_ANSIX962_EC_C2ONB239V4', 'SECOidTag',
           'PRFilePrivate', '_IO_fpos_t', 'PF_AX25', 'CKM_DES_CFB64',
           'SEC_OID_ANSIX962_EC_C2PNB304W1', 'IPV6_MULTICAST_LOOP',
           'CERTCertTrust', 'SEC_OID_SECG_EC_SECP521R1',
           'NS_CERT_TYPE_EMAIL_CA', 'CKA_SERIAL_NUMBER', 'ip_mreq',
           'PRLogModuleInfo', 'CK_RSA_PKCS_OAEP_SOURCE_TYPE',
           'PR_BYTES_PER_WORD_LOG2', 'CK_UNLOCKMUTEX', '__fd_mask',
           'SEC_OID_NS_TYPE_GIF', '_BITS_BYTESWAP_H',
           'SECMOD_AES_FLAG', 'PR_IS_DIRECTORY_ERROR',
           'SEC_OID_X509_ANY_POLICY', 'CKM_SHA384_RSA_PKCS',
           'SEC_ASN1_CLASS_MASK', 'IPPORT_RESERVED',
           'IPV6_MULTICAST_IF', 'SEC_ASN1_Contents', 'PR_EXCL',
           'CERTNameConstraints', 'EAI_SERVICE', '__USE_XOPEN',
           'CKR_SIGNATURE_LEN_RANGE', 'CKM_SHA512_KEY_DERIVATION',
           'CK_RC5_CBC_PARAMS', 'SEC_OID_PKCS12_SAFE_CONTENTS_ID',
           'CERTVerifyLog', 'CERTDistNamesStr', 'PRFileMap',
           'CKM_IDEA_CBC_PAD',
           'CERT_REV_MI_NO_OVERALL_INFO_REQUIREMENT',
           '__USE_POSIX199309', '____FILE_defined',
           'PR_INADDR_LOOPBACK', 'SEC_OID_EXT_KEY_USAGE_TIME_STAMP',
           'CK_FUNCTION_LIST', 'IP_PMTUDISC', 'uint_least64_t',
           'PR_SockOpt_Last', 'PR_ALIGN_OF_INT64', '__W_EXITCODE',
           'CKM_RC5_CBC_PAD', 'PK11MergeLogNode',
           'SEC_OID_PKCS9_EXTENDED_CERTIFICATE_ATTRIBUTES',
           'SO_PRIORITY', 'LITTLE_ENDIAN', 'MSG_TRUNC',
           'PR_END_OF_FILE_ERROR', '__USE_ATFILE', '_ISalnum',
           'TMP_MAX', 'certificateUsageSSLCA', 'CK_PBE_PARAMS',
           'CKM_CAST_KEY_GEN', 'kt_fortezza', 'N9PRLibSpec4DOT_31E',
           'CKF_GENERATE_KEY_PAIR', '_IO_NO_WRITES',
           'SEC_OID_NS_CERT_EXT_CERT_RENEWAL_TIME',
           'SSL_sni_type_total', 'CK_ECDH1_DERIVE_PARAMS_PTR',
           'CERT_LIST_EMPTY', '_G_HAVE_IO_FILE_OPEN',
           'PR_PROT_READONLY', 'SEC_OID_PKCS12_ENVELOPING_IDS',
           '__FILE_defined', 'PRDirEntry', 'IPV6_PMTUDISC_WANT',
           'PK11TokenStatus', 'clock_t',
           'N23CERTValParamOutValueStr4DOT_85E',
           'CKM_DES3_MAC_GENERAL', 'IPPROTO_PUP',
           'SECKEYPublicKeyListNode', 'timeval', 'isdigit_l',
           'SEC_ASN1_ANY_CONTENTS',
           'SEC_OID_PKCS12_RSA_ENCRYPTION_WITH_128_BIT_RC4',
           'CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR',
           'PR_DESC_SOCKET_UDP', '__SOCKADDR_COMMON_SIZE',
           'SECKEYDiffPQGParams', 'ssl_mac_md5', 'ssl_sign_rsa',
           'CERTCertListNodeStr', 'DERTemplateStr',
           'CKR_TEMPLATE_INCONSISTENT', '_G_NAMES_HAVE_UNDERSCORE',
           'CRL_DECODE_ADOPT_HEAP_DER', 'uint16_t', 'CKK_TWOFISH',
           'SO_BSDCOMPAT', 'CKM_DES_MAC',
           'SEC_OID_PKCS7_ENCRYPTED_DATA', '__gnuc_va_list',
           'CKA_WRAP', 'IP_TOS', 'CKM_RC2_ECB',
           'CERTValParamInValueStr', '__uint64_t', '_SECStatus',
           'ssl_calg_null', 'CKM_NETSCAPE_AES_KEY_WRAP_PAD',
           'cert_revocation_method_count', 'CKG_MGF1_SHA256',
           'CKF_SO_PIN_COUNT_LOW', 'PR_NO_SEEK_DEVICE_ERROR',
           'SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE',
           'CKR_PIN_LEN_RANGE', 'SEC_ASN1_VIDEOTEX_STRING',
           'IN_BADCLASS', '_G_IO_IO_FILE_VERSION', '_POSIX_C_SOURCE',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS', 'CKS_RW_SO_FUNCTIONS',
           'CK_UTF8CHAR_PTR', 'addrinfo', 'PRErrorCallbackNewTableFn',
           'SECKEYPublicKeyList', '_IO_ssize_t', 'SSL_sni_host_name',
           'CKM_CAST5_MAC', 'SEC_ASN1_GRAPHIC_STRING',
           'PK11_DIS_NONE', 'CKM_CDMF_KEY_GEN', 'AF_ROUTE',
           'BYTES_PER_INT64', '_IO_IS_APPENDING',
           'PR_BAD_ADDRESS_ERROR', 'DER_UTC_TIME',
           'SEC_ASN1_SEQUENCE', 'DER_CONSTRUCTED', 'PF_UNSPEC',
           'ntohl', '__bswap_constant_32',
           'CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR', 'ntohs',
           'SECKEYKEAParamsStr', 'IPPORT_WHOSERVER', 'SOL_IP',
           'L_ctermid', 'CKM_ECDH1_COFACTOR_DERIVE',
           'IPV6_RTHDR_STRICT', '__uint8_t', 'SEC_ASN1NotifyProc',
           'SEC_OID_SHA384', 'CKR_USER_NOT_LOGGED_IN', 'PRHashEntry',
           '__caddr_t', '_SYS_SOCKET_H', 'NS_CERT_TYPE_CA',
           'BITS_PER_INT_LOG2', 'CK_ECMQV_DERIVE_PARAMS_PTR',
           'nssILockObject', 'SEC_CERT_NICKNAMES_ALL',
           'CKR_OPERATION_NOT_INITIALIZED', 'SO_SNDTIMEO',
           'IP_XFRM_POLICY', '__WCOREFLAG', 'nssILockPK11cxt',
           'CERTOKDomainName', 'CKM_X9_42_DH_KEY_PAIR_GEN',
           'CKO_DOMAIN_PARAMETERS', 'SEC_OID_PKCS9_LOCAL_KEY_ID',
           '__USE_EXTERN_INLINES', '__SIZEOF_PTHREAD_COND_T',
           'SEC_ASN1_Length', 'AI_V4MAPPED',
           'SEC_OID_PKIX_REGCTRL_PKIPUBINFO',
           'SEC_OID_X509_INHIBIT_ANY_POLICY', 'CKO_MECHANISM',
           '__REDIRECT_NTH_LDBL', 'SEC_KRL_TYPE',
           'RF_CESSATION_OF_OPERATION', 'nssILockLast',
           'N4wait4DOT_35E', 'AF_AX25',
           'SEC_OID_ANSIX962_EC_C2TNB431R1', 'PR_SUCCESS',
           'IP_MSFILTER', 'PF_DECnet', 'CKR_ARGUMENTS_BAD',
           'SSL_ENABLE_SSL3', 'SEC_OID_AES_192_CBC',
           'CKR_SESSION_PARALLEL_NOT_SUPPORTED',
           'CKM_SHA224_RSA_PKCS', 'MSG_DONTWAIT', 'AF_NETLINK',
           'CKA_MODULUS', 'BYTES_PER_BYTE', 'IP_PMTUDISC_DONT',
           'PR_INTERVAL_NO_TIMEOUT',
           'certificateUsageSSLServerWithStepUp', 'NO_DATA',
           '__io_seek_fn', 'PK11_DIS_USER_SELECTED', 'PRSockOption',
           'CK_SSL3_KEY_MAT_OUT_PTR', 'int64', 'IPPROTO_SCTP',
           'certUsageSSLCA', 'CKM_RC5_KEY_GEN', 'SSLCipherSuiteInfo',
           'CERTCertificatePolicyMappings', 'CERTCrlKey',
           'CKM_DES_CFB8', 'sigevent_t',
           'SEC_OID_ANSIX962_ECDSA_SIGNATURE_RECOMMENDED_DIGEST',
           'CK_KEY_WRAP_SET_OAEP_PARAMS', 'CKR_PIN_INCORRECT',
           'SOL_SOCKET', 'CKA_CERT_SHA1_HASH',
           'CKA_NETSCAPE_PQG_COUNTER', 'PR_FILE_DIRECTORY',
           'CKG_MGF1_SHA1', 'CKM_CAST_CBC', 'KU_CRL_SIGN',
           'IPPROTO_UDP', 'AI_IDN_USE_STD3_ASCII_RULES',
           'CKM_SSL3_MASTER_KEY_DERIVE_DH',
           'SEC_OID_SDN702_DSA_SIGNATURE', '__quad_t',
           'PR_SockOpt_NoDelay', '__uid_t', 'IP_ADD_MEMBERSHIP',
           'CERTOKDomainNameStr', 'CKU_USER', 'SSL_ENABLE_TLS',
           'SECItemType', '__WORDSIZE',
           'CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC',
           '_G_HAVE_IO_GETLINE_INFO', 'CKA_REQUIRED_CMS_ATTRIBUTES',
           'le32toh', '__USE_LARGEFILE64', 'PK11PreSlotInfo',
           'NI_MAXSERV', 'CKM_NSS_AES_KEY_WRAP_PAD', 'htobe64',
           'SEC_OID_PKCS1_PSPECIFIED',
           'SEC_OID_ANSIX9_DSA_SIGNATURE_WITH_SHA1_DIGEST',
           'DER_DEFAULT_CHUNKSIZE', 'PRLogModuleLevel',
           'SECGreaterThan', 'PR_LOG_WARNING', 'CKM_RIPEMD160',
           'certificateUsageStatusResponder', 'PR_IXOTH', 'daddr_t',
           'int_fast8_t', '__RLIM64_T_TYPE', 'CKM_DES_CBC_PAD',
           'CKR_PIN_LOCKED', 'IN_CLASSA_NET',
           'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE',
           'CKR_ATTRIBUTE_SENSITIVE', 'CERTCrlEntry', 'cert_pi_max',
           'CK_RSA_PKCS_MGF_TYPE', 'CKM_FAKE_RANDOM',
           'SSLMACAlgorithm', 'CK_EXTRACT_PARAMS', 'PRHashTable',
           '_IO_DELETE_DONT_CLOSE', 'CKM_DH_PKCS_KEY_PAIR_GEN',
           'SEC_ASN1_BMP_STRING', 'IP_RECVTOS', 'PR_BYTES_PER_DOUBLE',
           'PRTransmitFileFlags', 'PK11_ATTR_UNMODIFIABLE',
           'CKM_NETSCAPE_PBE_SHA1_DES_CBC', 'certUsageSSLClient',
           'SECMOD_FORTEZZA_FLAG', 'PR_ALIGN_OF_POINTER',
           'CKM_CAST3_CBC_PAD', 'CERTAVAStr',
           'SEC_OID_CMS_3DES_KEY_WRAP', '__bos', 'CKM_RC4',
           'MSG_PROXY', '__ssize_t', 'kt_rsa', 'CKA_CHAR_COLUMNS',
           'RF_SUPERSEDED', 'EAI_ALLDONE', 'PRTransmitfileFN',
           'int16_t', '__warnattr', 'cert_pi_extendedKeyusage',
           '__sigset_t', 'SEC_OID_AVA_GIVEN_NAME',
           'SEC_OID_AES_128_CBC', '__isalnum_l', 'SOCK_NONBLOCK',
           'WEXITED', 'CKA_NETSCAPE_SMIME_INFO', 'PK11SlotList',
           'PLHashEnumerator', 'SEC_OID_PKCS1_RSA_OAEP_ENCRYPTION',
           'IPV6_UNICAST_HOPS', 'BYTES_PER_LONG',
           'CKA_SECONDARY_AUTH', 'CKA_VALUE_BITS',
           'DER_HIGH_TAG_NUMBER', 'CK_MAC_GENERAL_PARAMS_PTR',
           '_ENDIAN_H', 'PR_FILE_NOT_FOUND_ERROR',
           'SEC_OID_X509_DELTA_CRL_INDICATOR', 'IPPROTO_IPV6',
           'CERTValidityStr', 'CKK_EC', 'DER_T61_STRING', 'SOL_ATM',
           'SEC_OID_CMS_EPHEMERAL_STATIC_DIFFIE_HELLMAN',
           'PR_LOG_NOTICE', 'float64', 'ushort',
           'SEC_OID_PKCS7_DIGESTED_DATA', 'SEC_OID_RFC1274_UID',
           'clockid_t', '_IO_size_t', 'cert_pi_date',
           'CKF_TOKEN_INITIALIZED', 'DER_INTEGER', 'caddr_t',
           'SIOCATMARK', 'CK_KEY_DERIVATION_STRING_DATA',
           'CK_MECHANISM_PTR', 'CKF_HW_SLOT', 'DER_DERPTR',
           'CKA_NETSCAPE_PKCS8_SALT', 'L_tmpnam',
           'IPV6_2292PKTOPTIONS', '_IO_SCIENTIFIC',
           'CKA_TRUST_DATA_ENCIPHERMENT', 'SECTrustType', 'CKA_LABEL',
           'PF_INET',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4',
           '__USE_MISC', 'CKA_NSS_SMIME_INFO', 'CKA_TRUST_CRL_SIGN',
           'PZ_WaitCondVar', 'CKM_PBE_SHA1_CAST5_CBC',
           '__USE_EXTERN_INLINES_IN_LIBC', 'PF_INET6',
           'CK_RSA_PKCS_PSS_PARAMS', '__compar_d_fn_t', 'obstack',
           'PR_PROT_READWRITE', 'WIFEXITED', 'CKR_SESSION_COUNT',
           'SECItem', 'FD_SET', 'CKM_PBE_SHA1_DES2_EDE_CBC',
           'CKM_JUNIPER_ECB128', 'ALIGN_OF_LONG', 'SEC_ASN1_GET',
           'PRIOMethods', 'CKA_TRUSTED',
           'CKA_JAVA_MIDP_SECURITY_DOMAIN', 'CKM_CAST3_CBC',
           'CERTSubjectList', 'IP_TRANSPARENT', 'PF_UNIX',
           'CK_KEY_WRAP_SET_OAEP_PARAMS_PTR', 'WSTOPSIG',
           'PR_INTERVAL_NO_WAIT', 'PR_ADDRESS_NOT_AVAILABLE_ERROR',
           'SECMOD_END_WAIT', 'PR_SockOpt_McastInterface', '__dev_t',
           'DER_SKIP', 'CKK_RSA', '_IO_HAVE_SYS_WAIT',
           'CKR_ATTRIBUTE_READ_ONLY', '_SYS_SYSMACROS_H', 'CKC_X_509',
           '_IOFBF', 'PR_POLL_EXCEPT', 'cert_po_extendedKeyusage',
           'CKA_UNWRAP', 'PR_DEVICE_IS_LOCKED_ERROR',
           'CKT_NETSCAPE_UNTRUSTED', 'PK11FreeDataFunc',
           'SEC_OID_NS_CERT_EXT_CA_CERT_URL', 'netent', 'rpcent',
           '__SIGEV_MAX_SIZE', '_IO_FLAGS2_USER_WBUF',
           'SEC_OID_PKCS9_X509_CERT', 'PRLinger', 'kt_dh',
           '__USE_POSIX199506', 'crlEntryReasonUnspecified',
           'CKR_SESSION_CLOSED', 'PK11_TypeCert', '__S64_TYPE',
           'PRRecvfromFN', 'CK_WTLS_MASTER_KEY_DERIVE_PARAMS',
           'uintmax_t', 'SEC_OID_NS_TYPE_URL',
           'CERTBasicConstraintsStr', 'CKK_NSS_PKCS8',
           'IS_LITTLE_ENDIAN', 'SEC_OID_PKCS1_RSA_ENCRYPTION',
           'PRTimeParamFn', 'CKK_INVALID_KEY_TYPE',
           'SEC_OID_PKCS9_SIGNING_TIME',
           'SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC', 'getc',
           'CKA_NETSCAPE_URL', 'CKH_VENDOR_DEFINED', 'MSG_WAITFORONE',
           'SO_SNDLOWAT', 'KeyType', 'ip_opts', 'nssILockList',
           'PR_SockOpt_Linger',
           'CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC',
           'CKF_USER_PIN_TO_BE_CHANGED', 'IPPROTO_ROUTING',
           'SEC_ASN1_GENERALIZED_TIME', 'PR_RANGE_ERROR', 'AF_LOCAL',
           'DER_TAGNUM_MASK',
           'SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4',
           '__ino_t', '_SECMODT_H_', 'CK_PBE_PARAMS_PTR',
           '__REDIRECT_LDBL', '_PATH_NSSWITCH_CONF',
           'SEC_OID_ANSIX962_ECDSA_SHA224_SIGNATURE', 'DER_INLINE',
           'CERTPackageTypeEnum', 'CKM_SHA384_HMAC_GENERAL',
           'PR_SKIP_DOT_DOT', 'CKM_CAST128_CBC_PAD',
           'CKM_SHA1_KEY_DERIVATION', 'MSG_MORE', 'PK11TokenRemoved',
           'CKA_NSS', 'PF_ECONET', 'CKA_NSS_PQG_COUNTER',
           'NSPR_DATA_API', 'CKC_WTLS', 'EXIT_FAILURE',
           'PR_BAD_DESCRIPTOR_ERROR', 'CKM_PBE_SHA1_RC2_128_CBC',
           'CKR_PIN_INVALID', 'CKP_PKCS5_PBKD2_HMAC_SHA1', 'PF_RDS',
           'CKR_FUNCTION_CANCELED', 'SSLCipherSuiteInfoStr',
           'SHUT_WR', 'INADDR_ALLRTRS_GROUP', 'IPPROTO_IPIP',
           'PR_INTERVAL_MAX', 'IP_PMTUDISC_PROBE',
           'IPPORT_EXECSERVER', 'SEC_OID_AVA_PSEUDONYM',
           'SEC_OID_PKIX_OCSP_NONCE',
           'SEC_OID_PKIX_CPS_POINTER_QUALIFIER', '__ino64_t',
           'PK11SlotInfoStr', '_SS_PADSIZE', 'CERTCertNicknamesStr',
           'int32', 'IPPROTO_FRAGMENT', 'PR_LOG_WARN',
           'PR_NETWORK_DOWN_ERROR', 'PR_TRUNCATE',
           'CKR_ATTRIBUTE_VALUE_INVALID', 'PR_IXGRP',
           'CKF_RESTORE_KEY_NOT_NEEDED', 'BYTES_PER_DWORD_LOG2',
           'SECWouldBlock', 'CK_X9_42_DH2_DERIVE_PARAMS_PTR',
           'WIFSTOPPED', 'u_int32_t', 'PK11VerifyPasswordFunc',
           'PRFileInfo64', 'PR_IWUSR', 'CK_TOKEN_INFO_PTR',
           'SEC_OID_AVA_DC', 'CKM_BATON_ECB128',
           'CK_FUNCTION_LIST_PTR_PTR', '_SYS_SELECT_H',
           '__isxdigit_l', 'CKM_JUNIPER_WRAP',
           'CKM_SHA256_KEY_DERIVATION', '_G_fpos64_t', 'NO_ADDRESS',
           'IN_CLASSC_NET', '_ISOC95_SOURCE', 'MCAST_EXCLUDE',
           '__compar_fn_t', 'ssl_kea_fortezza', 'SSLSNISocketConfig',
           'PR_IWOTH', 'CKO_SECRET_KEY',
           'SEC_OID_ANSIX962_ECDSA_SIGNATURE_SPECIFIED_DIGEST',
           'CKM_EC_KEY_PAIR_GEN', 'CKF_UNWRAP', 'CK_UTF8CHAR',
           'AI_CANONNAME', 'CKK_CAMELLIA', '__clock_t_defined',
           '__codecvt_ok', 'PK11AttrFlags', 'AI_PASSIVE',
           'PR_BITS_PER_BYTE_LOG2', 'CKM_SHA224_KEY_DERIVATION',
           'SEC_ASN1WriteProc', 'FD_SETSIZE',
           'SECKEYEncryptedPrivateKeyInfo', 'certValidityChooseB',
           'certValidityChooseA', 'SEC_ASN1_BOOLEAN', '__int32_t',
           'CKF_HW', 'CKR_OPERATION_ACTIVE', 'CKM_BATON_COUNTER',
           'PR_BYTES_PER_DWORD', 'CERTPrivKeyUsagePeriod',
           'SEC_OID_SECG_EC_SECT409K1', 'int_least64_t',
           'CKM_SHA512_RSA_PKCS_PSS', 'CKA_TRUST_CLIENT_AUTH',
           'PRIPv6Addr', 'CK_NOTIFICATION',
           'SEC_OID_PKCS1_SHA256_WITH_RSA_ENCRYPTION',
           'SEC_ASN1_INNER', 'IPV6_XFRM_POLICY', 'PK11PasswordFunc',
           'INADDR_NONE', 'SEC_OID_ANSIX962_EC_C2TNB191V1',
           'PR_BITS_PER_BYTE', 'LL_MAXINT', 'PRLock',
           'PR_INSERT_LINK', 'CKM_RC4_KEY_GEN',
           'PR_IN_PROGRESS_ERROR', 'SEEK_END', 'linger',
           'PR_OUT_OF_MEMORY_ERROR', 'CKM_CAST5_CBC_PAD', 'PRSize',
           '_SS_SIZE', 'cert_revocation_method_crl',
           'SECKEYFortezzaPublicKey', 'PR_INVALID_ARGUMENT_ERROR',
           'SEC_OID_DES_CBC', 'IPPROTO_GRE',
           'SEC_OID_NS_CERT_EXT_CA_REVOCATION_URL',
           'SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE',
           'PRConnectcontinueFN', 'CERTSubjectListStr',
           'SECMOD_DES_FLAG', 'SEC_ASN1_MAY_STREAM',
           'crlEntryReasonPrivilegeWithdrawn', 'SSL_SOCKS',
           'SECMODListLock', '__USE_UNIX98', 'CKG_MGF1_SHA384',
           'PF_ASH', '__gid_t', 'CKU_SO', 'PK11MergeLog',
           'PR_USEC_PER_MSEC', 'IPPROTO_EGP',
           'CKM_WTLS_PRE_MASTER_KEY_GEN',
           'KU_KEY_AGREEMENT_OR_ENCIPHERMENT', '_IO_OCT',
           'CKO_NETSCAPE_CRL', '__daddr_t', 'PR_FILE_IS_LOCKED_ERROR',
           'SEC_OID_ANSIX962_EC_C2TNB359V1', 'IPPORT_FTP',
           'CKO_KG_PARAMETERS', 'crlEntryReasonCessationOfOperation',
           'SSL_SECURITY_STATUS_FORTEZZA', 'CKR_USER_TOO_MANY_TYPES',
           '__isupper_l', '__isascii_l', 'CKF_SO_PIN_TO_BE_CHANGED',
           'SCM_TIMESTAMPNS', '__isascii', 'CKD_SHA1_KDF_ASN1',
           'SECKEYKEAPublicKey', 'PR_FALSE', 'ssl_sign_null',
           'IPPORT_SYSTAT', 'cert_po_max', 'INADDR_ANY', '_ISprint',
           'BYTES_PER_WORD', 'secCertTimeExpired', 'PR_RDONLY',
           'CERTPublicKeyAndChallenge', 'CK_USER_TYPE', '_PKCS11T_H_',
           'EAI_IDN_ENCODE', 'CKR_WRAPPED_KEY_LEN_RANGE', 'PRReadFN',
           'ssl_auth_ecdsa', 'sockaddr', 'IPV6_JOIN_ANYCAST',
           'nssILockCert', 'CKA_NSS_URL', 'PR_IRWXO',
           'SECKEYRSAPublicKeyStr', 'PR_GROUP_EMPTY_ERROR', 'int64_t',
           'SEC_OID_X509_FRESHEST_CRL', 'CKM_DES_OFB64', 'le64toh',
           'SSL_IS_SSL2_CIPHER', 'CKA_CERTIFICATE_TYPE',
           'PK11CertListType', '_IO_MAGIC_MASK', 'cert_po_keyUsage',
           'int_fast64_t', 'CKR_TOKEN_WRITE_PROTECTED',
           'ssl_calg_rc4', 'HT_FREE_ENTRY', 'IP_PMTUDISC_DO',
           'CERT_REV_M_CONTINUE_TESTING_ON_FRESH_INFO',
           'ssl_calg_rc2', '__codecvt_error',
           'CKT_NETSCAPE_MUST_VERIFY', 'ssl_calg_seed',
           'SEC_ASN1_SEQUENCE_OF', 'SECKEYPublicKey', 'CKA_ID',
           'SEC_OID_PKCS12_SECRET_BAG_ID', 'LL_ZERO',
           'HOST_NOT_FOUND', 'IP_MULTICAST_IF', 'locale_t',
           'IPPROTO_PIM', 'EAI_BADFLAGS', 'PRNetAddr',
           'SEC_CERT_CLASS_SERVER', 'KU_KEY_CERT_SIGN',
           'IPV6_IPSEC_POLICY', 'CKM_CDMF_MAC',
           'SEC_OID_PKIX_REGCTRL_OLD_CERT_ID', 'CKO_NETSCAPE_SMIME',
           '_IOLBF', '_G_int32_t', 'PR_APPEND_LINK',
           'PRTimeParameters', 'LL_IS_ZERO']
