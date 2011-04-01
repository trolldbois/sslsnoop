from ctypes import *

STRING = c_char_p


class asn1_string_st(Structure):
    pass
ASN1_INTEGER = asn1_string_st
ASN1_ENUMERATED = asn1_string_st
ASN1_BIT_STRING = asn1_string_st
ASN1_OCTET_STRING = asn1_string_st
ASN1_PRINTABLESTRING = asn1_string_st
ASN1_T61STRING = asn1_string_st
ASN1_IA5STRING = asn1_string_st
ASN1_GENERALSTRING = asn1_string_st
ASN1_UNIVERSALSTRING = asn1_string_st
ASN1_BMPSTRING = asn1_string_st
ASN1_UTCTIME = asn1_string_st
ASN1_TIME = asn1_string_st
ASN1_GENERALIZEDTIME = asn1_string_st
ASN1_VISIBLESTRING = asn1_string_st
ASN1_UTF8STRING = asn1_string_st
ASN1_BOOLEAN = c_int
ASN1_NULL = c_int
class bignum_st(Structure):
    pass
BIGNUM = bignum_st
class bignum_ctx(Structure):
    pass
BN_CTX = bignum_ctx
class bn_blinding_st(Structure):
    pass
BN_BLINDING = bn_blinding_st
class bn_mont_ctx_st(Structure):
    pass
BN_MONT_CTX = bn_mont_ctx_st
class bn_recp_ctx_st(Structure):
    pass
BN_RECP_CTX = bn_recp_ctx_st
class bn_gencb_st(Structure):
    pass
BN_GENCB = bn_gencb_st
class buf_mem_st(Structure):
    pass
BUF_MEM = buf_mem_st
class evp_cipher_st(Structure):
    pass
EVP_CIPHER = evp_cipher_st
class evp_cipher_ctx_st(Structure):
    pass
EVP_CIPHER_CTX = evp_cipher_ctx_st
class env_md_st(Structure):
    pass
EVP_MD = env_md_st
class env_md_ctx_st(Structure):
    pass
EVP_MD_CTX = env_md_ctx_st
class evp_pkey_st(Structure):
    pass
EVP_PKEY = evp_pkey_st
class dh_st(Structure):
    pass
DH = dh_st
class dh_method(Structure):
    pass
DH_METHOD = dh_method
class dsa_st(Structure):
    pass
DSA = dsa_st
class dsa_method(Structure):
    pass
DSA_METHOD = dsa_method
class rsa_st(Structure):
    pass
RSA = rsa_st
class rsa_meth_st(Structure):
    pass
RSA_METHOD = rsa_meth_st
class rand_meth_st(Structure):
    pass
RAND_METHOD = rand_meth_st
class ecdh_method(Structure):
    pass
ECDH_METHOD = ecdh_method
class ecdsa_method(Structure):
    pass
ECDSA_METHOD = ecdsa_method
class x509_st(Structure):
    pass
X509 = x509_st
class X509_algor_st(Structure):
    pass
X509_ALGOR = X509_algor_st
class X509_crl_st(Structure):
    pass
X509_CRL = X509_crl_st
class X509_name_st(Structure):
    pass
X509_NAME = X509_name_st
class x509_store_st(Structure):
    pass
X509_STORE = x509_store_st
class x509_store_ctx_st(Structure):
    pass
X509_STORE_CTX = x509_store_ctx_st
class ssl_st(Structure):
    pass
SSL = ssl_st
class ssl_ctx_st(Structure):
    pass
SSL_CTX = ssl_ctx_st
class v3_ext_ctx(Structure):
    pass
X509V3_CTX = v3_ext_ctx
class conf_st(Structure):
    pass
CONF = conf_st
class store_st(Structure):
    pass
STORE = store_st
class store_method_st(Structure):
    pass
STORE_METHOD = store_method_st
class ui_st(Structure):
    pass
UI = ui_st
class ui_method_st(Structure):
    pass
UI_METHOD = ui_method_st
class st_ERR_FNS(Structure):
    pass
ERR_FNS = st_ERR_FNS
class engine_st(Structure):
    pass
ENGINE = engine_st
class X509_POLICY_NODE_st(Structure):
    pass
X509_POLICY_NODE = X509_POLICY_NODE_st
class X509_POLICY_LEVEL_st(Structure):
    pass
X509_POLICY_LEVEL = X509_POLICY_LEVEL_st
class X509_POLICY_TREE_st(Structure):
    pass
X509_POLICY_TREE = X509_POLICY_TREE_st
class X509_POLICY_CACHE_st(Structure):
    pass
X509_POLICY_CACHE = X509_POLICY_CACHE_st
class crypto_ex_data_st(Structure):
    pass
CRYPTO_EX_DATA = crypto_ex_data_st
CRYPTO_EX_new = CFUNCTYPE(c_int, c_void_p, c_void_p, POINTER(CRYPTO_EX_DATA), c_int, c_long, c_void_p)
CRYPTO_EX_free = CFUNCTYPE(None, c_void_p, c_void_p, POINTER(CRYPTO_EX_DATA), c_int, c_long, c_void_p)
CRYPTO_EX_dup = CFUNCTYPE(c_int, POINTER(CRYPTO_EX_DATA), POINTER(CRYPTO_EX_DATA), c_void_p, c_int, c_long, c_void_p)
class ocsp_req_ctx_st(Structure):
    pass
OCSP_REQ_CTX = ocsp_req_ctx_st
class ocsp_response_st(Structure):
    pass
OCSP_RESPONSE = ocsp_response_st
class ocsp_responder_id_st(Structure):
    pass
OCSP_RESPID = ocsp_responder_id_st
size_t = c_uint
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
__quad_t = c_longlong
__u_quad_t = c_ulonglong
__dev_t = __u_quad_t
__uid_t = c_uint
__gid_t = c_uint
__ino_t = c_ulong
__ino64_t = __u_quad_t
__mode_t = c_uint
__nlink_t = c_uint
__off_t = c_long
__off64_t = __quad_t
__pid_t = c_int
__clock_t = c_long
__rlim_t = c_ulong
__rlim64_t = __u_quad_t
__id_t = c_uint
__time_t = c_long
__useconds_t = c_uint
__suseconds_t = c_long
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
__ssize_t = c_int
__loff_t = __off64_t
__qaddr_t = POINTER(__quad_t)
__caddr_t = STRING
__intptr_t = c_int
__socklen_t = c_uint
class _IO_FILE(Structure):
    pass
FILE = _IO_FILE
__FILE = _IO_FILE
_G_int16_t = c_short
_G_int32_t = c_int
_G_uint16_t = c_ushort
_G_uint32_t = c_uint
__gnuc_va_list = STRING
_IO_lock_t = None
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
cookie_io_functions_t = _IO_cookie_io_functions_t
va_list = __gnuc_va_list
off_t = __off_t
off64_t = __off64_t
ssize_t = __ssize_t
class _G_fpos_t(Structure):
    pass
fpos_t = _G_fpos_t
class _G_fpos64_t(Structure):
    pass
fpos64_t = _G_fpos64_t
class __locale_struct(Structure):
    pass
__locale_t = POINTER(__locale_struct)
locale_t = __locale_t
u_char = __u_char
u_short = __u_short
u_int = __u_int
u_long = __u_long
quad_t = __quad_t
u_quad_t = __u_quad_t
class __fsid_t(Structure):
    pass
fsid_t = __fsid_t
loff_t = __loff_t
ino_t = __ino_t
ino64_t = __ino64_t
dev_t = __dev_t
gid_t = __gid_t
mode_t = __mode_t
nlink_t = __nlink_t
uid_t = __uid_t
pid_t = __pid_t
id_t = __id_t
daddr_t = __daddr_t
caddr_t = __caddr_t
key_t = __key_t
clock_t = __clock_t
time_t = __time_t
clockid_t = __clockid_t
timer_t = __timer_t
useconds_t = __useconds_t
suseconds_t = __suseconds_t
ulong = c_ulong
ushort = c_ushort
uint = c_uint
int8_t = c_int8
int16_t = c_int16
int32_t = c_int32
int64_t = c_int64
u_int8_t = c_ubyte
u_int16_t = c_ushort
u_int32_t = c_uint
u_int64_t = c_ulonglong
register_t = c_int
__sig_atomic_t = c_int
class __sigset_t(Structure):
    pass
sigset_t = __sigset_t
__fd_mask = c_long
fd_mask = __fd_mask
blksize_t = __blksize_t
blkcnt_t = __blkcnt_t
fsblkcnt_t = __fsblkcnt_t
fsfilcnt_t = __fsfilcnt_t
blkcnt64_t = __blkcnt64_t
fsblkcnt64_t = __fsblkcnt64_t
fsfilcnt64_t = __fsfilcnt64_t
pthread_t = c_ulong
class __pthread_internal_slist(Structure):
    pass
__pthread_slist_t = __pthread_internal_slist
pthread_key_t = c_uint
pthread_once_t = c_int
pthread_spinlock_t = c_int
__compar_fn_t = CFUNCTYPE(c_int, c_void_p, c_void_p)
comparison_fn_t = __compar_fn_t
__compar_d_fn_t = CFUNCTYPE(c_int, c_void_p, c_void_p, c_void_p)
class stack_st(Structure):
    pass
STACK = stack_st
class openssl_item_st(Structure):
    pass
OPENSSL_ITEM = openssl_item_st
class bio_st(Structure):
    pass
BIO_dummy = bio_st
class crypto_ex_data_func_st(Structure):
    pass
CRYPTO_EX_DATA_FUNCS = crypto_ex_data_func_st
class st_CRYPTO_EX_DATA_IMPL(Structure):
    pass
CRYPTO_EX_DATA_IMPL = st_CRYPTO_EX_DATA_IMPL
CRYPTO_MEM_LEAK_CB = CFUNCTYPE(c_void_p, c_ulong, STRING, c_int, c_int, c_void_p)
BIO = bio_st
bio_info_cb = CFUNCTYPE(None, POINTER(bio_st), c_int, STRING, c_int, c_long, c_long)
class bio_method_st(Structure):
    pass
BIO_METHOD = bio_method_st
class bio_f_buffer_ctx_struct(Structure):
    pass
BIO_F_BUFFER_CTX = bio_f_buffer_ctx_struct
class asn1_ctx_st(Structure):
    pass
ASN1_CTX = asn1_ctx_st
class asn1_const_ctx_st(Structure):
    pass
ASN1_const_CTX = asn1_const_ctx_st
class asn1_object_st(Structure):
    pass
ASN1_OBJECT = asn1_object_st
ASN1_STRING = asn1_string_st
class ASN1_ENCODING_st(Structure):
    pass
ASN1_ENCODING = ASN1_ENCODING_st
class asn1_string_table_st(Structure):
    pass
ASN1_STRING_TABLE = asn1_string_table_st
class ASN1_TEMPLATE_st(Structure):
    pass
ASN1_TEMPLATE = ASN1_TEMPLATE_st
class ASN1_ITEM_st(Structure):
    pass
ASN1_ITEM = ASN1_ITEM_st
class ASN1_TLC_st(Structure):
    pass
ASN1_TLC = ASN1_TLC_st
class ASN1_VALUE_st(Structure):
    pass
ASN1_VALUE = ASN1_VALUE_st
i2d_of_void = CFUNCTYPE(c_int, c_void_p, POINTER(POINTER(c_ubyte)))
d2i_of_void = CFUNCTYPE(c_void_p, POINTER(c_void_p), POINTER(POINTER(c_ubyte)), c_long)
ASN1_ITEM_EXP = ASN1_ITEM
class asn1_type_st(Structure):
    pass
ASN1_TYPE = asn1_type_st
class asn1_method_st(Structure):
    pass
ASN1_METHOD = asn1_method_st
class asn1_header_st(Structure):
    pass
ASN1_HEADER = asn1_header_st
class BIT_STRING_BITNAME_st(Structure):
    pass
BIT_STRING_BITNAME = BIT_STRING_BITNAME_st
asn1_output_data_fn = CFUNCTYPE(c_int, POINTER(BIO), POINTER(BIO), POINTER(ASN1_VALUE), c_int, POINTER(ASN1_ITEM))
class obj_name_st(Structure):
    pass
OBJ_NAME = obj_name_st
evp_sign_method = CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint), c_void_p)
evp_verify_method = CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint, c_void_p)
class evp_cipher_info_st(Structure):
    pass
EVP_CIPHER_INFO = evp_cipher_info_st
class evp_Encode_Ctx_st(Structure):
    pass
EVP_ENCODE_CTX = evp_Encode_Ctx_st
EVP_PBE_KEYGEN = CFUNCTYPE(c_int, POINTER(EVP_CIPHER_CTX), STRING, c_int, POINTER(ASN1_TYPE), POINTER(EVP_CIPHER), POINTER(EVP_MD), c_int)
class aes_key_st(Structure):
    pass
AES_KEY = aes_key_st
class rc4_key_st(Structure):
    pass
RC4_KEY = rc4_key_st
class bf_key_st(Structure):
    pass
BF_KEY = bf_key_st
DES_cblock = c_ubyte * 8
const_DES_cblock = c_ubyte * 8
class DES_ks(Structure):
    pass
DES_key_schedule = DES_ks
_ossl_old_des_cblock = c_ubyte * 8
class _ossl_old_des_ks_struct(Structure):
    pass
class N23_ossl_old_des_ks_struct4DOT_31E(Union):
    pass
N23_ossl_old_des_ks_struct4DOT_31E._fields_ = [
    ('_', _ossl_old_des_cblock),
    ('pad', c_ulong * 2),
]
_ossl_old_des_ks_struct._fields_ = [
    ('ks', N23_ossl_old_des_ks_struct4DOT_31E),
]
_ossl_old_des_key_schedule = _ossl_old_des_ks_struct * 16
class ui_string_st(Structure):
    pass
UI_STRING = ui_string_st
class cast_key_st(Structure):
    pass
CAST_KEY = cast_key_st
class hmac_ctx_st(Structure):
    pass
HMAC_CTX = hmac_ctx_st
class DSA_SIG_st(Structure):
    pass
DSA_SIG = DSA_SIG_st
class ec_method_st(Structure):
    pass
EC_METHOD = ec_method_st
class ec_group_st(Structure):
    pass
EC_GROUP = ec_group_st
class ec_point_st(Structure):
    pass
EC_POINT = ec_point_st
class ecpk_parameters_st(Structure):
    pass
ECPKPARAMETERS = ecpk_parameters_st
class ec_key_st(Structure):
    pass
EC_KEY = ec_key_st
class ECDSA_SIG_st(Structure):
    pass
ECDSA_SIG = ECDSA_SIG_st
ptrdiff_t = c_int
class SHAstate_st(Structure):
    pass
SHA_CTX = SHAstate_st
class SHA256state_st(Structure):
    pass
SHA256_CTX = SHA256state_st
class SHA512state_st(Structure):
    pass
SHA512_CTX = SHA512state_st
class X509_objects_st(Structure):
    pass
X509_OBJECTS = X509_objects_st
X509_ALGORS = STACK
class X509_val_st(Structure):
    pass
X509_VAL = X509_val_st
class X509_pubkey_st(Structure):
    pass
X509_PUBKEY = X509_pubkey_st
class X509_sig_st(Structure):
    pass
X509_SIG = X509_sig_st
class X509_name_entry_st(Structure):
    pass
X509_NAME_ENTRY = X509_name_entry_st
class X509_extension_st(Structure):
    pass
X509_EXTENSION = X509_extension_st
X509_EXTENSIONS = STACK
class x509_attributes_st(Structure):
    pass
X509_ATTRIBUTE = x509_attributes_st
class X509_req_info_st(Structure):
    pass
X509_REQ_INFO = X509_req_info_st
class X509_req_st(Structure):
    pass
X509_REQ = X509_req_st
class x509_cinf_st(Structure):
    pass
X509_CINF = x509_cinf_st
class x509_cert_aux_st(Structure):
    pass
X509_CERT_AUX = x509_cert_aux_st
class x509_trust_st(Structure):
    pass
X509_TRUST = x509_trust_st
class x509_cert_pair_st(Structure):
    pass
X509_CERT_PAIR = x509_cert_pair_st
class X509_revoked_st(Structure):
    pass
X509_REVOKED = X509_revoked_st
class X509_crl_info_st(Structure):
    pass
X509_CRL_INFO = X509_crl_info_st
class private_key_st(Structure):
    pass
X509_PKEY = private_key_st
class X509_info_st(Structure):
    pass
X509_INFO = X509_info_st
class Netscape_spkac_st(Structure):
    pass
NETSCAPE_SPKAC = Netscape_spkac_st
class Netscape_spki_st(Structure):
    pass
NETSCAPE_SPKI = Netscape_spki_st
class Netscape_certificate_sequence(Structure):
    pass
NETSCAPE_CERT_SEQUENCE = Netscape_certificate_sequence
class PBEPARAM_st(Structure):
    pass
PBEPARAM = PBEPARAM_st
class PBE2PARAM_st(Structure):
    pass
PBE2PARAM = PBE2PARAM_st
class PBKDF2PARAM_st(Structure):
    pass
PBKDF2PARAM = PBKDF2PARAM_st
class pkcs8_priv_key_info_st(Structure):
    pass
PKCS8_PRIV_KEY_INFO = pkcs8_priv_key_info_st
class lhash_node_st(Structure):
    pass
LHASH_NODE = lhash_node_st
LHASH_COMP_FN_TYPE = CFUNCTYPE(c_int, c_void_p, c_void_p)
LHASH_HASH_FN_TYPE = CFUNCTYPE(c_ulong, c_void_p)
LHASH_DOALL_FN_TYPE = CFUNCTYPE(None, c_void_p)
LHASH_DOALL_ARG_FN_TYPE = CFUNCTYPE(None, c_void_p, c_void_p)
class lhash_st(Structure):
    pass
LHASH = lhash_st
class x509_hash_dir_st(Structure):
    pass
X509_HASH_DIR_CTX = x509_hash_dir_st
class x509_file_st(Structure):
    pass
X509_CERT_FILE_CTX = x509_file_st
class x509_object_st(Structure):
    pass
X509_OBJECT = x509_object_st
class x509_lookup_st(Structure):
    pass
X509_LOOKUP = x509_lookup_st
class x509_lookup_method_st(Structure):
    pass
X509_LOOKUP_METHOD = x509_lookup_method_st
class X509_VERIFY_PARAM_st(Structure):
    pass
X509_VERIFY_PARAM = X509_VERIFY_PARAM_st
class pkcs7_issuer_and_serial_st(Structure):
    pass
PKCS7_ISSUER_AND_SERIAL = pkcs7_issuer_and_serial_st
class pkcs7_signer_info_st(Structure):
    pass
PKCS7_SIGNER_INFO = pkcs7_signer_info_st
class pkcs7_recip_info_st(Structure):
    pass
PKCS7_RECIP_INFO = pkcs7_recip_info_st
class pkcs7_signed_st(Structure):
    pass
PKCS7_SIGNED = pkcs7_signed_st
class pkcs7_enc_content_st(Structure):
    pass
PKCS7_ENC_CONTENT = pkcs7_enc_content_st
class pkcs7_enveloped_st(Structure):
    pass
PKCS7_ENVELOPE = pkcs7_enveloped_st
class pkcs7_signedandenveloped_st(Structure):
    pass
PKCS7_SIGN_ENVELOPE = pkcs7_signedandenveloped_st
class pkcs7_digest_st(Structure):
    pass
PKCS7_DIGEST = pkcs7_digest_st
class pkcs7_encrypted_st(Structure):
    pass
PKCS7_ENCRYPT = pkcs7_encrypted_st
class pkcs7_st(Structure):
    pass
PKCS7 = pkcs7_st

# values for enumeration 'STORE_object_types'
STORE_OBJECT_TYPE_X509_CERTIFICATE = 1
STORE_OBJECT_TYPE_X509_CRL = 2
STORE_OBJECT_TYPE_PRIVATE_KEY = 3
STORE_OBJECT_TYPE_PUBLIC_KEY = 4
STORE_OBJECT_TYPE_NUMBER = 5
STORE_OBJECT_TYPE_ARBITRARY = 6
STORE_OBJECT_TYPE_NUM = 6
STORE_object_types = c_int # enum
STORE_OBJECT_TYPES = STORE_object_types

# values for enumeration 'STORE_params'
STORE_PARAM_EVP_TYPE = 1
STORE_PARAM_BITS = 2
STORE_PARAM_KEY_PARAMETERS = 3
STORE_PARAM_KEY_NO_PARAMETERS = 4
STORE_PARAM_AUTH_PASSPHRASE = 5
STORE_PARAM_AUTH_KRB5_TICKET = 6
STORE_PARAM_TYPE_NUM = 6
STORE_params = c_int # enum
STORE_PARAM_TYPES = STORE_params

# values for enumeration 'STORE_attribs'
STORE_ATTR_END = 0
STORE_ATTR_FRIENDLYNAME = 1
STORE_ATTR_KEYID = 2
STORE_ATTR_ISSUERKEYID = 3
STORE_ATTR_SUBJECTKEYID = 4
STORE_ATTR_ISSUERSERIALHASH = 5
STORE_ATTR_ISSUER = 6
STORE_ATTR_SERIAL = 7
STORE_ATTR_SUBJECT = 8
STORE_ATTR_CERTHASH = 9
STORE_ATTR_EMAIL = 10
STORE_ATTR_FILENAME = 11
STORE_ATTR_TYPE_NUM = 11
STORE_ATTR_OR = 255
STORE_attribs = c_int # enum
STORE_ATTR_TYPES = STORE_attribs

# values for enumeration 'STORE_certificate_status'
STORE_X509_VALID = 0
STORE_X509_EXPIRED = 1
STORE_X509_SUSPENDED = 2
STORE_X509_REVOKED = 3
STORE_certificate_status = c_int # enum
STORE_CERTIFICATE_STATUS = STORE_certificate_status
class STORE_OBJECT_st(Structure):
    pass
STORE_OBJECT = STORE_OBJECT_st
STORE_INITIALISE_FUNC_PTR = CFUNCTYPE(c_int, POINTER(STORE))
STORE_CLEANUP_FUNC_PTR = CFUNCTYPE(None, POINTER(STORE))
STORE_GENERATE_OBJECT_FUNC_PTR = CFUNCTYPE(POINTER(STORE_OBJECT), POINTER(STORE), STORE_OBJECT_TYPES, POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM))
STORE_GET_OBJECT_FUNC_PTR = CFUNCTYPE(POINTER(STORE_OBJECT), POINTER(STORE), STORE_OBJECT_TYPES, POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM))
STORE_START_OBJECT_FUNC_PTR = CFUNCTYPE(c_void_p, POINTER(STORE), STORE_OBJECT_TYPES, POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM))
STORE_NEXT_OBJECT_FUNC_PTR = CFUNCTYPE(POINTER(STORE_OBJECT), POINTER(STORE), c_void_p)
STORE_END_OBJECT_FUNC_PTR = CFUNCTYPE(c_int, POINTER(STORE), c_void_p)
STORE_HANDLE_OBJECT_FUNC_PTR = CFUNCTYPE(c_int, POINTER(STORE), STORE_OBJECT_TYPES, POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM))
STORE_STORE_OBJECT_FUNC_PTR = CFUNCTYPE(c_int, POINTER(STORE), STORE_OBJECT_TYPES, POINTER(STORE_OBJECT), POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM))
STORE_MODIFY_OBJECT_FUNC_PTR = CFUNCTYPE(c_int, POINTER(STORE), STORE_OBJECT_TYPES, POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM))
STORE_GENERIC_FUNC_PTR = CFUNCTYPE(c_int, POINTER(STORE), POINTER(OPENSSL_ITEM), POINTER(OPENSSL_ITEM))
STORE_CTRL_FUNC_PTR = CFUNCTYPE(c_int, POINTER(STORE), c_int, c_long, c_void_p, CFUNCTYPE(None))
class STORE_attr_info_st(Structure):
    pass
STORE_ATTR_INFO = STORE_attr_info_st
error_t = c_int
class err_state_st(Structure):
    pass
ERR_STATE = err_state_st
class ERR_string_data_st(Structure):
    pass
ERR_STRING_DATA = ERR_string_data_st
class ENGINE_CMD_DEFN_st(Structure):
    pass
ENGINE_CMD_DEFN = ENGINE_CMD_DEFN_st
ENGINE_GEN_FUNC_PTR = CFUNCTYPE(c_int)
ENGINE_GEN_INT_FUNC_PTR = CFUNCTYPE(c_int, POINTER(ENGINE))
ENGINE_CTRL_FUNC_PTR = CFUNCTYPE(c_int, POINTER(ENGINE), c_int, c_long, c_void_p, CFUNCTYPE(None))
ENGINE_LOAD_KEY_PTR = CFUNCTYPE(POINTER(EVP_PKEY), POINTER(ENGINE), STRING, POINTER(UI_METHOD), c_void_p)
ENGINE_SSL_CLIENT_CERT_PTR = CFUNCTYPE(c_int, POINTER(ENGINE), POINTER(SSL), POINTER(STACK), POINTER(POINTER(X509)), POINTER(POINTER(EVP_PKEY)), POINTER(POINTER(STACK)), POINTER(UI_METHOD), c_void_p)
ENGINE_CIPHERS_PTR = CFUNCTYPE(c_int, POINTER(ENGINE), POINTER(POINTER(EVP_CIPHER)), POINTER(POINTER(c_int)), c_int)
ENGINE_DIGESTS_PTR = CFUNCTYPE(c_int, POINTER(ENGINE), POINTER(POINTER(EVP_MD)), POINTER(POINTER(c_int)), c_int)
dyn_MEM_malloc_cb = CFUNCTYPE(c_void_p, size_t)
dyn_MEM_realloc_cb = CFUNCTYPE(c_void_p, c_void_p, size_t)
dyn_MEM_free_cb = CFUNCTYPE(None, c_void_p)
class st_dynamic_MEM_fns(Structure):
    pass
dynamic_MEM_fns = st_dynamic_MEM_fns
dyn_lock_locking_cb = CFUNCTYPE(None, c_int, c_int, STRING, c_int)
dyn_lock_add_lock_cb = CFUNCTYPE(c_int, POINTER(c_int), c_int, c_int, STRING, c_int)
class CRYPTO_dynlock_value(Structure):
    pass
dyn_dynlock_create_cb = CFUNCTYPE(POINTER(CRYPTO_dynlock_value), STRING, c_int)
dyn_dynlock_lock_cb = CFUNCTYPE(None, c_int, POINTER(CRYPTO_dynlock_value), STRING, c_int)
dyn_dynlock_destroy_cb = CFUNCTYPE(None, POINTER(CRYPTO_dynlock_value), STRING, c_int)
class st_dynamic_LOCK_fns(Structure):
    pass
dynamic_LOCK_fns = st_dynamic_LOCK_fns
class st_dynamic_fns(Structure):
    pass
dynamic_fns = st_dynamic_fns
dynamic_v_check_fn = CFUNCTYPE(c_ulong, c_ulong)
dynamic_bind_engine = CFUNCTYPE(c_int, POINTER(ENGINE), STRING, POINTER(dynamic_fns))
bignum_ctx._fields_ = [
]
bn_blinding_st._fields_ = [
]
ecdh_method._fields_ = [
]
ecdsa_method._fields_ = [
]
ssl_st._fields_ = [
]
ssl_ctx_st._fields_ = [
]
v3_ext_ctx._fields_ = [
]
conf_st._fields_ = [
]
store_st._fields_ = [
]
store_method_st._fields_ = [
]
ui_st._fields_ = [
]
ui_method_st._fields_ = [
]
st_ERR_FNS._fields_ = [
]
engine_st._fields_ = [
]
X509_POLICY_NODE_st._fields_ = [
]
X509_POLICY_LEVEL_st._fields_ = [
]
X509_POLICY_TREE_st._fields_ = [
]
X509_POLICY_CACHE_st._fields_ = [
]
ocsp_req_ctx_st._fields_ = [
]
ocsp_response_st._fields_ = [
]
ocsp_responder_id_st._fields_ = [
]
__fsid_t._fields_ = [
    ('__val', c_int * 2),
]
class __mbstate_t(Structure):
    pass
class N11__mbstate_t3DOT_2E(Union):
    pass
N11__mbstate_t3DOT_2E._fields_ = [
    ('__wch', c_uint),
    ('__wchb', c_char * 4),
]
__mbstate_t._fields_ = [
    ('__count', c_int),
    ('__value', N11__mbstate_t3DOT_2E),
]
_G_fpos_t._fields_ = [
    ('__pos', __off_t),
    ('__state', __mbstate_t),
]
_G_fpos64_t._pack_ = 4
_G_fpos64_t._fields_ = [
    ('__pos', __off64_t),
    ('__state', __mbstate_t),
]
class _IO_marker(Structure):
    pass
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
_IO_cookie_io_functions_t._fields_ = [
    ('read', POINTER(__io_read_fn)),
    ('write', POINTER(__io_write_fn)),
    ('seek', POINTER(__io_seek_fn)),
    ('close', POINTER(__io_close_fn)),
]
class __locale_data(Structure):
    pass
__locale_struct._fields_ = [
    ('__locales', POINTER(__locale_data) * 13),
    ('__ctype_b', POINTER(c_ushort)),
    ('__ctype_tolower', POINTER(c_int)),
    ('__ctype_toupper', POINTER(c_int)),
    ('__names', STRING * 13),
]
__sigset_t._fields_ = [
    ('__val', c_ulong * 32),
]
__pthread_internal_slist._fields_ = [
    ('__next', POINTER(__pthread_internal_slist)),
]
stack_st._fields_ = [
    ('num', c_int),
    ('data', POINTER(STRING)),
    ('sorted', c_int),
    ('num_alloc', c_int),
    ('comp', CFUNCTYPE(c_int, POINTER(STRING), POINTER(STRING))),
]
openssl_item_st._fields_ = [
    ('code', c_int),
    ('value', c_void_p),
    ('value_size', size_t),
    ('value_length', POINTER(size_t)),
]
CRYPTO_dynlock_value._fields_ = [
]
crypto_ex_data_st._fields_ = [
    ('sk', POINTER(STACK)),
    ('dummy', c_int),
]
crypto_ex_data_func_st._fields_ = [
    ('argl', c_long),
    ('argp', c_void_p),
    ('new_func', POINTER(CRYPTO_EX_new)),
    ('free_func', POINTER(CRYPTO_EX_free)),
    ('dup_func', POINTER(CRYPTO_EX_dup)),
]
st_CRYPTO_EX_DATA_IMPL._fields_ = [
]
bio_method_st._fields_ = [
    ('type', c_int),
    ('name', STRING),
    ('bwrite', CFUNCTYPE(c_int, POINTER(BIO), STRING, c_int)),
    ('bread', CFUNCTYPE(c_int, POINTER(BIO), STRING, c_int)),
    ('bputs', CFUNCTYPE(c_int, POINTER(BIO), STRING)),
    ('bgets', CFUNCTYPE(c_int, POINTER(BIO), STRING, c_int)),
    ('ctrl', CFUNCTYPE(c_long, POINTER(BIO), c_int, c_long, c_void_p)),
    ('create', CFUNCTYPE(c_int, POINTER(BIO))),
    ('destroy', CFUNCTYPE(c_int, POINTER(BIO))),
    ('callback_ctrl', CFUNCTYPE(c_long, POINTER(BIO), c_int, POINTER(bio_info_cb))),
]
bio_st._fields_ = [
    ('method', POINTER(BIO_METHOD)),
    ('callback', CFUNCTYPE(c_long, POINTER(bio_st), c_int, STRING, c_int, c_long, c_long)),
    ('cb_arg', STRING),
    ('init', c_int),
    ('shutdown', c_int),
    ('flags', c_int),
    ('retry_reason', c_int),
    ('num', c_int),
    ('ptr', c_void_p),
    ('next_bio', POINTER(bio_st)),
    ('prev_bio', POINTER(bio_st)),
    ('references', c_int),
    ('num_read', c_ulong),
    ('num_write', c_ulong),
    ('ex_data', CRYPTO_EX_DATA),
]
bio_f_buffer_ctx_struct._fields_ = [
    ('ibuf_size', c_int),
    ('obuf_size', c_int),
    ('ibuf', STRING),
    ('ibuf_len', c_int),
    ('ibuf_off', c_int),
    ('obuf', STRING),
    ('obuf_len', c_int),
    ('obuf_off', c_int),
]
bignum_st._fields_ = [
    ('d', POINTER(c_ulong)),
    ('top', c_int),
    ('dmax', c_int),
    ('neg', c_int),
    ('flags', c_int),
]
bn_mont_ctx_st._fields_ = [
    ('ri', c_int),
    ('RR', BIGNUM),
    ('N', BIGNUM),
    ('Ni', BIGNUM),
    ('n0', c_ulong),
    ('flags', c_int),
]
bn_recp_ctx_st._fields_ = [
    ('N', BIGNUM),
    ('Nr', BIGNUM),
    ('num_bits', c_int),
    ('shift', c_int),
    ('flags', c_int),
]
class N11bn_gencb_st4DOT_26E(Union):
    pass
N11bn_gencb_st4DOT_26E._fields_ = [
    ('cb_1', CFUNCTYPE(None, c_int, c_int, c_void_p)),
    ('cb_2', CFUNCTYPE(c_int, c_int, c_int, POINTER(BN_GENCB))),
]
bn_gencb_st._fields_ = [
    ('ver', c_uint),
    ('arg', c_void_p),
    ('cb', N11bn_gencb_st4DOT_26E),
]
asn1_ctx_st._fields_ = [
    ('p', POINTER(c_ubyte)),
    ('eos', c_int),
    ('error', c_int),
    ('inf', c_int),
    ('tag', c_int),
    ('xclass', c_int),
    ('slen', c_long),
    ('max', POINTER(c_ubyte)),
    ('q', POINTER(c_ubyte)),
    ('pp', POINTER(POINTER(c_ubyte))),
    ('line', c_int),
]
asn1_const_ctx_st._fields_ = [
    ('p', POINTER(c_ubyte)),
    ('eos', c_int),
    ('error', c_int),
    ('inf', c_int),
    ('tag', c_int),
    ('xclass', c_int),
    ('slen', c_long),
    ('max', POINTER(c_ubyte)),
    ('q', POINTER(c_ubyte)),
    ('pp', POINTER(POINTER(c_ubyte))),
    ('line', c_int),
]
asn1_object_st._fields_ = [
    ('sn', STRING),
    ('ln', STRING),
    ('nid', c_int),
    ('length', c_int),
    ('data', POINTER(c_ubyte)),
    ('flags', c_int),
]
asn1_string_st._fields_ = [
    ('length', c_int),
    ('type', c_int),
    ('data', POINTER(c_ubyte)),
    ('flags', c_long),
]
ASN1_ENCODING_st._fields_ = [
    ('enc', POINTER(c_ubyte)),
    ('len', c_long),
    ('modified', c_int),
]
asn1_string_table_st._fields_ = [
    ('nid', c_int),
    ('minsize', c_long),
    ('maxsize', c_long),
    ('mask', c_ulong),
    ('flags', c_ulong),
]
ASN1_TEMPLATE_st._fields_ = [
]
ASN1_ITEM_st._fields_ = [
]
ASN1_TLC_st._fields_ = [
]
ASN1_VALUE_st._fields_ = [
]
class N12asn1_type_st4DOT_27E(Union):
    pass
N12asn1_type_st4DOT_27E._fields_ = [
    ('ptr', STRING),
    ('boolean', ASN1_BOOLEAN),
    ('asn1_string', POINTER(ASN1_STRING)),
    ('object', POINTER(ASN1_OBJECT)),
    ('integer', POINTER(ASN1_INTEGER)),
    ('enumerated', POINTER(ASN1_ENUMERATED)),
    ('bit_string', POINTER(ASN1_BIT_STRING)),
    ('octet_string', POINTER(ASN1_OCTET_STRING)),
    ('printablestring', POINTER(ASN1_PRINTABLESTRING)),
    ('t61string', POINTER(ASN1_T61STRING)),
    ('ia5string', POINTER(ASN1_IA5STRING)),
    ('generalstring', POINTER(ASN1_GENERALSTRING)),
    ('bmpstring', POINTER(ASN1_BMPSTRING)),
    ('universalstring', POINTER(ASN1_UNIVERSALSTRING)),
    ('utctime', POINTER(ASN1_UTCTIME)),
    ('generalizedtime', POINTER(ASN1_GENERALIZEDTIME)),
    ('visiblestring', POINTER(ASN1_VISIBLESTRING)),
    ('utf8string', POINTER(ASN1_UTF8STRING)),
    ('set', POINTER(ASN1_STRING)),
    ('sequence', POINTER(ASN1_STRING)),
    ('asn1_value', POINTER(ASN1_VALUE)),
]
asn1_type_st._fields_ = [
    ('type', c_int),
    ('value', N12asn1_type_st4DOT_27E),
]
asn1_method_st._fields_ = [
    ('i2d', POINTER(i2d_of_void)),
    ('d2i', POINTER(d2i_of_void)),
    ('create', CFUNCTYPE(c_void_p)),
    ('destroy', CFUNCTYPE(None, c_void_p)),
]
asn1_header_st._fields_ = [
    ('header', POINTER(ASN1_OCTET_STRING)),
    ('data', c_void_p),
    ('meth', POINTER(ASN1_METHOD)),
]
BIT_STRING_BITNAME_st._fields_ = [
    ('bitnum', c_int),
    ('lname', STRING),
    ('sname', STRING),
]
obj_name_st._fields_ = [
    ('type', c_int),
    ('alias', c_int),
    ('name', STRING),
    ('data', STRING),
]
class N11evp_pkey_st4DOT_28E(Union):
    pass
N11evp_pkey_st4DOT_28E._fields_ = [
    ('ptr', STRING),
    ('rsa', POINTER(rsa_st)),
    ('dsa', POINTER(dsa_st)),
    ('dh', POINTER(dh_st)),
    ('ec', POINTER(ec_key_st)),
]
evp_pkey_st._fields_ = [
    ('type', c_int),
    ('save_type', c_int),
    ('references', c_int),
    ('pkey', N11evp_pkey_st4DOT_28E),
    ('save_parameters', c_int),
    ('attributes', POINTER(STACK)),
]
ec_key_st._fields_ = [
]
env_md_st._fields_ = [
    ('type', c_int),
    ('pkey_type', c_int),
    ('md_size', c_int),
    ('flags', c_ulong),
    ('init', CFUNCTYPE(c_int, POINTER(EVP_MD_CTX))),
    ('update', CFUNCTYPE(c_int, POINTER(EVP_MD_CTX), c_void_p, size_t)),
    ('final', CFUNCTYPE(c_int, POINTER(EVP_MD_CTX), POINTER(c_ubyte))),
    ('copy', CFUNCTYPE(c_int, POINTER(EVP_MD_CTX), POINTER(EVP_MD_CTX))),
    ('cleanup', CFUNCTYPE(c_int, POINTER(EVP_MD_CTX))),
    ('sign', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint), c_void_p)),
    ('verify', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint, c_void_p)),
    ('required_pkey_type', c_int * 5),
    ('block_size', c_int),
    ('ctx_size', c_int),
]
env_md_ctx_st._fields_ = [
    ('digest', POINTER(EVP_MD)),
    ('engine', POINTER(ENGINE)),
    ('flags', c_ulong),
    ('md_data', c_void_p),
]
evp_cipher_st._fields_ = [
    ('nid', c_int),
    ('block_size', c_int),
    ('key_len', c_int),
    ('iv_len', c_int),
    ('flags', c_ulong),
    ('init', CFUNCTYPE(c_int, POINTER(EVP_CIPHER_CTX), POINTER(c_ubyte), POINTER(c_ubyte), c_int)),
    ('do_cipher', CFUNCTYPE(c_int, POINTER(EVP_CIPHER_CTX), POINTER(c_ubyte), POINTER(c_ubyte), c_uint)),
    ('cleanup', CFUNCTYPE(c_int, POINTER(EVP_CIPHER_CTX))),
    ('ctx_size', c_int),
    ('set_asn1_parameters', CFUNCTYPE(c_int, POINTER(EVP_CIPHER_CTX), POINTER(ASN1_TYPE))),
    ('get_asn1_parameters', CFUNCTYPE(c_int, POINTER(EVP_CIPHER_CTX), POINTER(ASN1_TYPE))),
    ('ctrl', CFUNCTYPE(c_int, POINTER(EVP_CIPHER_CTX), c_int, c_int, c_void_p)),
    ('app_data', c_void_p),
]
evp_cipher_info_st._fields_ = [
    ('cipher', POINTER(EVP_CIPHER)),
    ('iv', c_ubyte * 16),
]
evp_cipher_ctx_st._fields_ = [
    ('cipher', POINTER(EVP_CIPHER)),
    ('engine', POINTER(ENGINE)),
    ('encrypt', c_int),
    ('buf_len', c_int),
    ('oiv', c_ubyte * 16),
    ('iv', c_ubyte * 16),
    ('buf', c_ubyte * 32),
    ('num', c_int),
    ('app_data', c_void_p),
    ('key_len', c_int),
    ('flags', c_ulong),
    ('cipher_data', c_void_p),
    ('final_used', c_int),
    ('block_mask', c_int),
    ('final', c_ubyte * 32),
]
evp_Encode_Ctx_st._fields_ = [
    ('num', c_int),
    ('length', c_int),
    ('enc_data', c_ubyte * 80),
    ('line_num', c_int),
    ('expect_nl', c_int),
]
aes_key_st._fields_ = [
    ('rd_key', c_uint * 60),
    ('rounds', c_int),
]
rc4_key_st._fields_ = [
    ('x', c_uint),
    ('y', c_uint),
    ('data', c_uint * 256),
]
bf_key_st._fields_ = [
    ('P', c_uint * 18),
    ('S', c_uint * 1024),
]
class N6DES_ks4DOT_30E(Union):
    pass
N6DES_ks4DOT_30E._fields_ = [
    ('cblock', DES_cblock),
    ('deslong', c_ulong * 2),
]
DES_ks._fields_ = [
    ('ks', N6DES_ks4DOT_30E * 16),
]
ui_string_st._fields_ = [
]
cast_key_st._fields_ = [
    ('data', c_ulong * 32),
    ('short_key', c_int),
]
hmac_ctx_st._fields_ = [
    ('md', POINTER(EVP_MD)),
    ('md_ctx', EVP_MD_CTX),
    ('i_ctx', EVP_MD_CTX),
    ('o_ctx', EVP_MD_CTX),
    ('key_length', c_uint),
    ('key', c_ubyte * 128),
]
dh_method._fields_ = [
    ('name', STRING),
    ('generate_key', CFUNCTYPE(c_int, POINTER(DH))),
    ('compute_key', CFUNCTYPE(c_int, POINTER(c_ubyte), POINTER(BIGNUM), POINTER(DH))),
    ('bn_mod_exp', CFUNCTYPE(c_int, POINTER(DH), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BN_CTX), POINTER(BN_MONT_CTX))),
    ('init', CFUNCTYPE(c_int, POINTER(DH))),
    ('finish', CFUNCTYPE(c_int, POINTER(DH))),
    ('flags', c_int),
    ('app_data', STRING),
    ('generate_params', CFUNCTYPE(c_int, POINTER(DH), c_int, c_int, POINTER(BN_GENCB))),
]
dh_st._fields_ = [
    ('pad', c_int),
    ('version', c_int),
    ('p', POINTER(BIGNUM)),
    ('g', POINTER(BIGNUM)),
    ('length', c_long),
    ('pub_key', POINTER(BIGNUM)),
    ('priv_key', POINTER(BIGNUM)),
    ('flags', c_int),
    ('method_mont_p', POINTER(BN_MONT_CTX)),
    ('q', POINTER(BIGNUM)),
    ('j', POINTER(BIGNUM)),
    ('seed', POINTER(c_ubyte)),
    ('seedlen', c_int),
    ('counter', POINTER(BIGNUM)),
    ('references', c_int),
    ('ex_data', CRYPTO_EX_DATA),
    ('meth', POINTER(DH_METHOD)),
    ('engine', POINTER(ENGINE)),
]
DSA_SIG_st._fields_ = [
    ('r', POINTER(BIGNUM)),
    ('s', POINTER(BIGNUM)),
]
dsa_method._fields_ = [
    ('name', STRING),
    ('dsa_do_sign', CFUNCTYPE(POINTER(DSA_SIG), POINTER(c_ubyte), c_int, POINTER(DSA))),
    ('dsa_sign_setup', CFUNCTYPE(c_int, POINTER(DSA), POINTER(BN_CTX), POINTER(POINTER(BIGNUM)), POINTER(POINTER(BIGNUM)))),
    ('dsa_do_verify', CFUNCTYPE(c_int, POINTER(c_ubyte), c_int, POINTER(DSA_SIG), POINTER(DSA))),
    ('dsa_mod_exp', CFUNCTYPE(c_int, POINTER(DSA), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BN_CTX), POINTER(BN_MONT_CTX))),
    ('bn_mod_exp', CFUNCTYPE(c_int, POINTER(DSA), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BN_CTX), POINTER(BN_MONT_CTX))),
    ('init', CFUNCTYPE(c_int, POINTER(DSA))),
    ('finish', CFUNCTYPE(c_int, POINTER(DSA))),
    ('flags', c_int),
    ('app_data', STRING),
    ('dsa_paramgen', CFUNCTYPE(c_int, POINTER(DSA), c_int, POINTER(c_ubyte), c_int, POINTER(c_int), POINTER(c_ulong), POINTER(BN_GENCB))),
    ('dsa_keygen', CFUNCTYPE(c_int, POINTER(DSA))),
]
dsa_st._fields_ = [
    ('pad', c_int),
    ('version', c_long),
    ('write_params', c_int),
    ('p', POINTER(BIGNUM)),
    ('q', POINTER(BIGNUM)),
    ('g', POINTER(BIGNUM)),
    ('pub_key', POINTER(BIGNUM)),
    ('priv_key', POINTER(BIGNUM)),
    ('kinv', POINTER(BIGNUM)),
    ('r', POINTER(BIGNUM)),
    ('flags', c_int),
    ('method_mont_p', POINTER(BN_MONT_CTX)),
    ('references', c_int),
    ('ex_data', CRYPTO_EX_DATA),
    ('meth', POINTER(DSA_METHOD)),
    ('engine', POINTER(ENGINE)),
]
rsa_meth_st._fields_ = [
    ('name', STRING),
    ('rsa_pub_enc', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), POINTER(c_ubyte), POINTER(RSA), c_int)),
    ('rsa_pub_dec', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), POINTER(c_ubyte), POINTER(RSA), c_int)),
    ('rsa_priv_enc', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), POINTER(c_ubyte), POINTER(RSA), c_int)),
    ('rsa_priv_dec', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), POINTER(c_ubyte), POINTER(RSA), c_int)),
    ('rsa_mod_exp', CFUNCTYPE(c_int, POINTER(BIGNUM), POINTER(BIGNUM), POINTER(RSA), POINTER(BN_CTX))),
    ('bn_mod_exp', CFUNCTYPE(c_int, POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BIGNUM), POINTER(BN_CTX), POINTER(BN_MONT_CTX))),
    ('init', CFUNCTYPE(c_int, POINTER(RSA))),
    ('finish', CFUNCTYPE(c_int, POINTER(RSA))),
    ('flags', c_int),
    ('app_data', STRING),
    ('rsa_sign', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), POINTER(c_uint), POINTER(RSA))),
    ('rsa_verify', CFUNCTYPE(c_int, c_int, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint, POINTER(RSA))),
    ('rsa_keygen', CFUNCTYPE(c_int, POINTER(RSA), c_int, POINTER(BIGNUM), POINTER(BN_GENCB))),
]
rsa_st._fields_ = [
    ('pad', c_int),
    ('version', c_long),
    ('meth', POINTER(RSA_METHOD)),
    ('engine', POINTER(ENGINE)),
    ('n', POINTER(BIGNUM)),
    ('e', POINTER(BIGNUM)),
    ('d', POINTER(BIGNUM)),
    ('p', POINTER(BIGNUM)),
    ('q', POINTER(BIGNUM)),
    ('dmp1', POINTER(BIGNUM)),
    ('dmq1', POINTER(BIGNUM)),
    ('iqmp', POINTER(BIGNUM)),
    ('ex_data', CRYPTO_EX_DATA),
    ('references', c_int),
    ('flags', c_int),
    ('_method_mod_n', POINTER(BN_MONT_CTX)),
    ('_method_mod_p', POINTER(BN_MONT_CTX)),
    ('_method_mod_q', POINTER(BN_MONT_CTX)),
    ('bignum_data', STRING),
    ('blinding', POINTER(BN_BLINDING)),
    ('mt_blinding', POINTER(BN_BLINDING)),
]
ec_method_st._fields_ = [
]
ec_group_st._fields_ = [
]
ec_point_st._fields_ = [
]
ecpk_parameters_st._fields_ = [
]
ECDSA_SIG_st._fields_ = [
    ('r', POINTER(BIGNUM)),
    ('s', POINTER(BIGNUM)),
]
rand_meth_st._fields_ = [
    ('seed', CFUNCTYPE(None, c_void_p, c_int)),
    ('bytes', CFUNCTYPE(c_int, POINTER(c_ubyte), c_int)),
    ('cleanup', CFUNCTYPE(None)),
    ('add', CFUNCTYPE(None, c_void_p, c_int, c_double)),
    ('pseudorand', CFUNCTYPE(c_int, POINTER(c_ubyte), c_int)),
    ('status', CFUNCTYPE(c_int)),
]
buf_mem_st._fields_ = [
    ('length', c_int),
    ('data', STRING),
    ('max', c_int),
]
SHAstate_st._fields_ = [
    ('h0', c_uint),
    ('h1', c_uint),
    ('h2', c_uint),
    ('h3', c_uint),
    ('h4', c_uint),
    ('Nl', c_uint),
    ('Nh', c_uint),
    ('data', c_uint * 16),
    ('num', c_uint),
]
SHA256state_st._fields_ = [
    ('h', c_uint * 8),
    ('Nl', c_uint),
    ('Nh', c_uint),
    ('data', c_uint * 16),
    ('num', c_uint),
    ('md_len', c_uint),
]
class N14SHA512state_st4DOT_34E(Union):
    pass
N14SHA512state_st4DOT_34E._pack_ = 4
N14SHA512state_st4DOT_34E._fields_ = [
    ('d', c_ulonglong * 16),
    ('p', c_ubyte * 128),
]
SHA512state_st._pack_ = 4
SHA512state_st._fields_ = [
    ('h', c_ulonglong * 8),
    ('Nl', c_ulonglong),
    ('Nh', c_ulonglong),
    ('u', N14SHA512state_st4DOT_34E),
    ('num', c_uint),
    ('md_len', c_uint),
]
X509_objects_st._fields_ = [
    ('nid', c_int),
    ('a2i', CFUNCTYPE(c_int)),
    ('i2a', CFUNCTYPE(c_int)),
]
X509_algor_st._fields_ = [
    ('algorithm', POINTER(ASN1_OBJECT)),
    ('parameter', POINTER(ASN1_TYPE)),
]
X509_val_st._fields_ = [
    ('notBefore', POINTER(ASN1_TIME)),
    ('notAfter', POINTER(ASN1_TIME)),
]
X509_pubkey_st._fields_ = [
    ('algor', POINTER(X509_ALGOR)),
    ('public_key', POINTER(ASN1_BIT_STRING)),
    ('pkey', POINTER(EVP_PKEY)),
]
X509_sig_st._fields_ = [
    ('algor', POINTER(X509_ALGOR)),
    ('digest', POINTER(ASN1_OCTET_STRING)),
]
X509_name_entry_st._fields_ = [
    ('object', POINTER(ASN1_OBJECT)),
    ('value', POINTER(ASN1_STRING)),
    ('set', c_int),
    ('size', c_int),
]
X509_name_st._fields_ = [
    ('entries', POINTER(STACK)),
    ('modified', c_int),
    ('bytes', POINTER(BUF_MEM)),
    ('hash', c_ulong),
]
X509_extension_st._fields_ = [
    ('object', POINTER(ASN1_OBJECT)),
    ('critical', ASN1_BOOLEAN),
    ('value', POINTER(ASN1_OCTET_STRING)),
]
class N18x509_attributes_st4DOT_35E(Union):
    pass
N18x509_attributes_st4DOT_35E._fields_ = [
    ('ptr', STRING),
    ('set', POINTER(STACK)),
    ('single', POINTER(ASN1_TYPE)),
]
x509_attributes_st._fields_ = [
    ('object', POINTER(ASN1_OBJECT)),
    ('single', c_int),
    ('value', N18x509_attributes_st4DOT_35E),
]
X509_req_info_st._fields_ = [
    ('enc', ASN1_ENCODING),
    ('version', POINTER(ASN1_INTEGER)),
    ('subject', POINTER(X509_NAME)),
    ('pubkey', POINTER(X509_PUBKEY)),
    ('attributes', POINTER(STACK)),
]
X509_req_st._fields_ = [
    ('req_info', POINTER(X509_REQ_INFO)),
    ('sig_alg', POINTER(X509_ALGOR)),
    ('signature', POINTER(ASN1_BIT_STRING)),
    ('references', c_int),
]
x509_cinf_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('serialNumber', POINTER(ASN1_INTEGER)),
    ('signature', POINTER(X509_ALGOR)),
    ('issuer', POINTER(X509_NAME)),
    ('validity', POINTER(X509_VAL)),
    ('subject', POINTER(X509_NAME)),
    ('key', POINTER(X509_PUBKEY)),
    ('issuerUID', POINTER(ASN1_BIT_STRING)),
    ('subjectUID', POINTER(ASN1_BIT_STRING)),
    ('extensions', POINTER(STACK)),
]
x509_cert_aux_st._fields_ = [
    ('trust', POINTER(STACK)),
    ('reject', POINTER(STACK)),
    ('alias', POINTER(ASN1_UTF8STRING)),
    ('keyid', POINTER(ASN1_OCTET_STRING)),
    ('other', POINTER(STACK)),
]
class AUTHORITY_KEYID_st(Structure):
    pass
x509_st._fields_ = [
    ('cert_info', POINTER(X509_CINF)),
    ('sig_alg', POINTER(X509_ALGOR)),
    ('signature', POINTER(ASN1_BIT_STRING)),
    ('valid', c_int),
    ('references', c_int),
    ('name', STRING),
    ('ex_data', CRYPTO_EX_DATA),
    ('ex_pathlen', c_long),
    ('ex_pcpathlen', c_long),
    ('ex_flags', c_ulong),
    ('ex_kusage', c_ulong),
    ('ex_xkusage', c_ulong),
    ('ex_nscert', c_ulong),
    ('skid', POINTER(ASN1_OCTET_STRING)),
    ('akid', POINTER(AUTHORITY_KEYID_st)),
    ('policy_cache', POINTER(X509_POLICY_CACHE)),
    ('sha1_hash', c_ubyte * 20),
    ('aux', POINTER(X509_CERT_AUX)),
]
x509_trust_st._fields_ = [
    ('trust', c_int),
    ('flags', c_int),
    ('check_trust', CFUNCTYPE(c_int, POINTER(x509_trust_st), POINTER(X509), c_int)),
    ('name', STRING),
    ('arg1', c_int),
    ('arg2', c_void_p),
]
x509_cert_pair_st._fields_ = [
    ('forward', POINTER(X509)),
    ('reverse', POINTER(X509)),
]
X509_revoked_st._fields_ = [
    ('serialNumber', POINTER(ASN1_INTEGER)),
    ('revocationDate', POINTER(ASN1_TIME)),
    ('extensions', POINTER(STACK)),
    ('sequence', c_int),
]
X509_crl_info_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('sig_alg', POINTER(X509_ALGOR)),
    ('issuer', POINTER(X509_NAME)),
    ('lastUpdate', POINTER(ASN1_TIME)),
    ('nextUpdate', POINTER(ASN1_TIME)),
    ('revoked', POINTER(STACK)),
    ('extensions', POINTER(STACK)),
    ('enc', ASN1_ENCODING),
]
X509_crl_st._fields_ = [
    ('crl', POINTER(X509_CRL_INFO)),
    ('sig_alg', POINTER(X509_ALGOR)),
    ('signature', POINTER(ASN1_BIT_STRING)),
    ('references', c_int),
]
private_key_st._fields_ = [
    ('version', c_int),
    ('enc_algor', POINTER(X509_ALGOR)),
    ('enc_pkey', POINTER(ASN1_OCTET_STRING)),
    ('dec_pkey', POINTER(EVP_PKEY)),
    ('key_length', c_int),
    ('key_data', STRING),
    ('key_free', c_int),
    ('cipher', EVP_CIPHER_INFO),
    ('references', c_int),
]
X509_info_st._fields_ = [
    ('x509', POINTER(X509)),
    ('crl', POINTER(X509_CRL)),
    ('x_pkey', POINTER(X509_PKEY)),
    ('enc_cipher', EVP_CIPHER_INFO),
    ('enc_len', c_int),
    ('enc_data', STRING),
    ('references', c_int),
]
Netscape_spkac_st._fields_ = [
    ('pubkey', POINTER(X509_PUBKEY)),
    ('challenge', POINTER(ASN1_IA5STRING)),
]
Netscape_spki_st._fields_ = [
    ('spkac', POINTER(NETSCAPE_SPKAC)),
    ('sig_algor', POINTER(X509_ALGOR)),
    ('signature', POINTER(ASN1_BIT_STRING)),
]
Netscape_certificate_sequence._fields_ = [
    ('type', POINTER(ASN1_OBJECT)),
    ('certs', POINTER(STACK)),
]
PBEPARAM_st._fields_ = [
    ('salt', POINTER(ASN1_OCTET_STRING)),
    ('iter', POINTER(ASN1_INTEGER)),
]
PBE2PARAM_st._fields_ = [
    ('keyfunc', POINTER(X509_ALGOR)),
    ('encryption', POINTER(X509_ALGOR)),
]
PBKDF2PARAM_st._fields_ = [
    ('salt', POINTER(ASN1_TYPE)),
    ('iter', POINTER(ASN1_INTEGER)),
    ('keylength', POINTER(ASN1_INTEGER)),
    ('prf', POINTER(X509_ALGOR)),
]
pkcs8_priv_key_info_st._fields_ = [
    ('broken', c_int),
    ('version', POINTER(ASN1_INTEGER)),
    ('pkeyalg', POINTER(X509_ALGOR)),
    ('pkey', POINTER(ASN1_TYPE)),
    ('attributes', POINTER(STACK)),
]
lhash_node_st._fields_ = [
    ('data', c_void_p),
    ('next', POINTER(lhash_node_st)),
    ('hash', c_ulong),
]
lhash_st._fields_ = [
    ('b', POINTER(POINTER(LHASH_NODE))),
    ('comp', LHASH_COMP_FN_TYPE),
    ('hash', LHASH_HASH_FN_TYPE),
    ('num_nodes', c_uint),
    ('num_alloc_nodes', c_uint),
    ('p', c_uint),
    ('pmax', c_uint),
    ('up_load', c_ulong),
    ('down_load', c_ulong),
    ('num_items', c_ulong),
    ('num_expands', c_ulong),
    ('num_expand_reallocs', c_ulong),
    ('num_contracts', c_ulong),
    ('num_contract_reallocs', c_ulong),
    ('num_hash_calls', c_ulong),
    ('num_comp_calls', c_ulong),
    ('num_insert', c_ulong),
    ('num_replace', c_ulong),
    ('num_delete', c_ulong),
    ('num_no_delete', c_ulong),
    ('num_retrieve', c_ulong),
    ('num_retrieve_miss', c_ulong),
    ('num_hash_comps', c_ulong),
    ('error', c_int),
]
x509_hash_dir_st._fields_ = [
    ('num_dirs', c_int),
    ('dirs', POINTER(STRING)),
    ('dirs_type', POINTER(c_int)),
    ('num_dirs_alloced', c_int),
]
x509_file_st._fields_ = [
    ('num_paths', c_int),
    ('num_alloced', c_int),
    ('paths', POINTER(STRING)),
    ('path_type', POINTER(c_int)),
]
class N14x509_object_st4DOT_36E(Union):
    pass
N14x509_object_st4DOT_36E._fields_ = [
    ('ptr', STRING),
    ('x509', POINTER(X509)),
    ('crl', POINTER(X509_CRL)),
    ('pkey', POINTER(EVP_PKEY)),
]
x509_object_st._fields_ = [
    ('type', c_int),
    ('data', N14x509_object_st4DOT_36E),
]
x509_lookup_method_st._fields_ = [
    ('name', STRING),
    ('new_item', CFUNCTYPE(c_int, POINTER(X509_LOOKUP))),
    ('free', CFUNCTYPE(None, POINTER(X509_LOOKUP))),
    ('init', CFUNCTYPE(c_int, POINTER(X509_LOOKUP))),
    ('shutdown', CFUNCTYPE(c_int, POINTER(X509_LOOKUP))),
    ('ctrl', CFUNCTYPE(c_int, POINTER(X509_LOOKUP), c_int, STRING, c_long, POINTER(STRING))),
    ('get_by_subject', CFUNCTYPE(c_int, POINTER(X509_LOOKUP), c_int, POINTER(X509_NAME), POINTER(X509_OBJECT))),
    ('get_by_issuer_serial', CFUNCTYPE(c_int, POINTER(X509_LOOKUP), c_int, POINTER(X509_NAME), POINTER(ASN1_INTEGER), POINTER(X509_OBJECT))),
    ('get_by_fingerprint', CFUNCTYPE(c_int, POINTER(X509_LOOKUP), c_int, POINTER(c_ubyte), c_int, POINTER(X509_OBJECT))),
    ('get_by_alias', CFUNCTYPE(c_int, POINTER(X509_LOOKUP), c_int, STRING, c_int, POINTER(X509_OBJECT))),
]
X509_VERIFY_PARAM_st._fields_ = [
    ('name', STRING),
    ('check_time', time_t),
    ('inh_flags', c_ulong),
    ('flags', c_ulong),
    ('purpose', c_int),
    ('trust', c_int),
    ('depth', c_int),
    ('policies', POINTER(STACK)),
]
x509_store_st._fields_ = [
    ('cache', c_int),
    ('objs', POINTER(STACK)),
    ('get_cert_methods', POINTER(STACK)),
    ('param', POINTER(X509_VERIFY_PARAM)),
    ('verify', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX))),
    ('verify_cb', CFUNCTYPE(c_int, c_int, POINTER(X509_STORE_CTX))),
    ('get_issuer', CFUNCTYPE(c_int, POINTER(POINTER(X509)), POINTER(X509_STORE_CTX), POINTER(X509))),
    ('check_issued', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(X509), POINTER(X509))),
    ('check_revocation', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX))),
    ('get_crl', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(POINTER(X509_CRL)), POINTER(X509))),
    ('check_crl', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(X509_CRL))),
    ('cert_crl', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(X509_CRL), POINTER(X509))),
    ('cleanup', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX))),
    ('ex_data', CRYPTO_EX_DATA),
    ('references', c_int),
]
x509_lookup_st._fields_ = [
    ('init', c_int),
    ('skip', c_int),
    ('method', POINTER(X509_LOOKUP_METHOD)),
    ('method_data', STRING),
    ('store_ctx', POINTER(X509_STORE)),
]
x509_store_ctx_st._fields_ = [
    ('ctx', POINTER(X509_STORE)),
    ('current_method', c_int),
    ('cert', POINTER(X509)),
    ('untrusted', POINTER(STACK)),
    ('crls', POINTER(STACK)),
    ('param', POINTER(X509_VERIFY_PARAM)),
    ('other_ctx', c_void_p),
    ('verify', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX))),
    ('verify_cb', CFUNCTYPE(c_int, c_int, POINTER(X509_STORE_CTX))),
    ('get_issuer', CFUNCTYPE(c_int, POINTER(POINTER(X509)), POINTER(X509_STORE_CTX), POINTER(X509))),
    ('check_issued', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(X509), POINTER(X509))),
    ('check_revocation', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX))),
    ('get_crl', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(POINTER(X509_CRL)), POINTER(X509))),
    ('check_crl', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(X509_CRL))),
    ('cert_crl', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX), POINTER(X509_CRL), POINTER(X509))),
    ('check_policy', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX))),
    ('cleanup', CFUNCTYPE(c_int, POINTER(X509_STORE_CTX))),
    ('valid', c_int),
    ('last_untrusted', c_int),
    ('chain', POINTER(STACK)),
    ('tree', POINTER(X509_POLICY_TREE)),
    ('explicit_policy', c_int),
    ('error_depth', c_int),
    ('error', c_int),
    ('current_cert', POINTER(X509)),
    ('current_issuer', POINTER(X509)),
    ('current_crl', POINTER(X509_CRL)),
    ('ex_data', CRYPTO_EX_DATA),
]
pkcs7_issuer_and_serial_st._fields_ = [
    ('issuer', POINTER(X509_NAME)),
    ('serial', POINTER(ASN1_INTEGER)),
]
pkcs7_signer_info_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('issuer_and_serial', POINTER(PKCS7_ISSUER_AND_SERIAL)),
    ('digest_alg', POINTER(X509_ALGOR)),
    ('auth_attr', POINTER(STACK)),
    ('digest_enc_alg', POINTER(X509_ALGOR)),
    ('enc_digest', POINTER(ASN1_OCTET_STRING)),
    ('unauth_attr', POINTER(STACK)),
    ('pkey', POINTER(EVP_PKEY)),
]
pkcs7_recip_info_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('issuer_and_serial', POINTER(PKCS7_ISSUER_AND_SERIAL)),
    ('key_enc_algor', POINTER(X509_ALGOR)),
    ('enc_key', POINTER(ASN1_OCTET_STRING)),
    ('cert', POINTER(X509)),
]
pkcs7_signed_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('md_algs', POINTER(STACK)),
    ('cert', POINTER(STACK)),
    ('crl', POINTER(STACK)),
    ('signer_info', POINTER(STACK)),
    ('contents', POINTER(pkcs7_st)),
]
pkcs7_enc_content_st._fields_ = [
    ('content_type', POINTER(ASN1_OBJECT)),
    ('algorithm', POINTER(X509_ALGOR)),
    ('enc_data', POINTER(ASN1_OCTET_STRING)),
    ('cipher', POINTER(EVP_CIPHER)),
]
pkcs7_enveloped_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('recipientinfo', POINTER(STACK)),
    ('enc_data', POINTER(PKCS7_ENC_CONTENT)),
]
pkcs7_signedandenveloped_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('md_algs', POINTER(STACK)),
    ('cert', POINTER(STACK)),
    ('crl', POINTER(STACK)),
    ('signer_info', POINTER(STACK)),
    ('enc_data', POINTER(PKCS7_ENC_CONTENT)),
    ('recipientinfo', POINTER(STACK)),
]
pkcs7_digest_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('md', POINTER(X509_ALGOR)),
    ('contents', POINTER(pkcs7_st)),
    ('digest', POINTER(ASN1_OCTET_STRING)),
]
pkcs7_encrypted_st._fields_ = [
    ('version', POINTER(ASN1_INTEGER)),
    ('enc_data', POINTER(PKCS7_ENC_CONTENT)),
]
class N8pkcs7_st4DOT_37E(Union):
    pass
N8pkcs7_st4DOT_37E._fields_ = [
    ('ptr', STRING),
    ('data', POINTER(ASN1_OCTET_STRING)),
    ('sign', POINTER(PKCS7_SIGNED)),
    ('enveloped', POINTER(PKCS7_ENVELOPE)),
    ('signed_and_enveloped', POINTER(PKCS7_SIGN_ENVELOPE)),
    ('digest', POINTER(PKCS7_DIGEST)),
    ('encrypted', POINTER(PKCS7_ENCRYPT)),
    ('other', POINTER(ASN1_TYPE)),
]
pkcs7_st._fields_ = [
    ('asn1', POINTER(c_ubyte)),
    ('length', c_long),
    ('state', c_int),
    ('detached', c_int),
    ('type', POINTER(ASN1_OBJECT)),
    ('d', N8pkcs7_st4DOT_37E),
]
class N15STORE_OBJECT_st4DOT_38E(Union):
    pass
class N15STORE_OBJECT_st4DOT_384DOT_39E(Structure):
    pass
N15STORE_OBJECT_st4DOT_384DOT_39E._fields_ = [
    ('status', STORE_CERTIFICATE_STATUS),
    ('certificate', POINTER(X509)),
]
N15STORE_OBJECT_st4DOT_38E._fields_ = [
    ('x509', N15STORE_OBJECT_st4DOT_384DOT_39E),
    ('crl', POINTER(X509_CRL)),
    ('key', POINTER(EVP_PKEY)),
    ('number', POINTER(BIGNUM)),
    ('arbitrary', POINTER(BUF_MEM)),
]
STORE_OBJECT_st._fields_ = [
    ('type', STORE_OBJECT_TYPES),
    ('data', N15STORE_OBJECT_st4DOT_38E),
]
STORE_attr_info_st._fields_ = [
]
err_state_st._fields_ = [
    ('pid', c_ulong),
    ('err_flags', c_int * 16),
    ('err_buffer', c_ulong * 16),
    ('err_data', STRING * 16),
    ('err_data_flags', c_int * 16),
    ('err_file', STRING * 16),
    ('err_line', c_int * 16),
    ('top', c_int),
    ('bottom', c_int),
]
ERR_string_data_st._fields_ = [
    ('error', c_ulong),
    ('string', STRING),
]
ENGINE_CMD_DEFN_st._fields_ = [
    ('cmd_num', c_uint),
    ('cmd_name', STRING),
    ('cmd_desc', STRING),
    ('cmd_flags', c_uint),
]
st_dynamic_MEM_fns._fields_ = [
    ('malloc_cb', dyn_MEM_malloc_cb),
    ('realloc_cb', dyn_MEM_realloc_cb),
    ('free_cb', dyn_MEM_free_cb),
]
st_dynamic_LOCK_fns._fields_ = [
    ('lock_locking_cb', dyn_lock_locking_cb),
    ('lock_add_lock_cb', dyn_lock_add_lock_cb),
    ('dynlock_create_cb', dyn_dynlock_create_cb),
    ('dynlock_lock_cb', dyn_dynlock_lock_cb),
    ('dynlock_destroy_cb', dyn_dynlock_destroy_cb),
]
st_dynamic_fns._fields_ = [
    ('static_state', c_void_p),
    ('err_fns', POINTER(ERR_FNS)),
    ('ex_data_fns', POINTER(CRYPTO_EX_DATA_IMPL)),
    ('mem_fns', dynamic_MEM_fns),
    ('lock_fns', dynamic_LOCK_fns),
]
_IO_marker._fields_ = [
    ('_next', POINTER(_IO_marker)),
    ('_sbuf', POINTER(_IO_FILE)),
    ('_pos', c_int),
]
__locale_data._fields_ = [
]
AUTHORITY_KEYID_st._fields_ = [
]
__all__ = ['__uint16_t', 'pkcs7_enc_content_st', '__int16_t',
           'X509_REVOKED', 'STORE_START_OBJECT_FUNC_PTR',
           'st_dynamic_LOCK_fns', 'SSL_CTX', 'openssl_item_st',
           '__off64_t', 'STORE_END_OBJECT_FUNC_PTR', 'fpos_t', 'X509',
           'STORE_GENERIC_FUNC_PTR', 'dyn_dynlock_create_cb',
           '_G_int16_t', 'STORE_X509_EXPIRED', '__FILE',
           'ASN1_TEMPLATE', 'BIO_METHOD', '__time_t', 'dh_method',
           'bio_f_buffer_ctx_struct', 'X509_SIG', 'X509_algor_st',
           'STORE_GET_OBJECT_FUNC_PTR', 'X509_POLICY_NODE_st',
           'pid_t', 'ec_group_st', 'ASN1_IA5STRING',
           'dynamic_v_check_fn', '__uint64_t', 'x509_cinf_st',
           'buf_mem_st', 'STORE_ATTR_SUBJECTKEYID',
           'ecpk_parameters_st', 'BIGNUM', 'PBEPARAM',
           'X509_NAME_ENTRY', '__clockid_t', 'lhash_st', 'id_t',
           'dyn_MEM_malloc_cb', 'ASN1_BIT_STRING', '_G_fpos_t',
           'STORE_METHOD', 'STORE_X509_REVOKED', 'STORE_ATTR_END',
           'env_md_ctx_st', 'pkcs7_signer_info_st', 'ASN1_METHOD',
           '__locale_data', '__u_long', 'DSA_SIG', 'DSA',
           'STORE_CERTIFICATE_STATUS', 'NETSCAPE_CERT_SEQUENCE',
           'pthread_t', 'UI_STRING', '__io_read_fn',
           'ENGINE_GEN_FUNC_PTR', 'DES_cblock', '__mode_t',
           'STORE_MODIFY_OBJECT_FUNC_PTR', '__off_t',
           'STORE_PARAM_KEY_PARAMETERS', '_ossl_old_des_ks_struct',
           'SHAstate_st', 'u_quad_t', 'STORE_OBJECT_TYPE_NUM',
           'fsfilcnt64_t', 'daddr_t', 'ui_string_st', 'x509_file_st',
           'X509_req_info_st', 'evp_Encode_Ctx_st', 'engine_st',
           'CRYPTO_EX_DATA', '__int8_t', 'HMAC_CTX', '__fsblkcnt64_t',
           'ec_point_st', 'X509_POLICY_LEVEL', 'EC_KEY',
           'EVP_CIPHER_CTX', 'bn_gencb_st', 'EC_POINT', 'RSA_METHOD',
           'timer_t', '__fsfilcnt64_t', 'dyn_MEM_free_cb', '_IO_FILE',
           'pthread_key_t', 'STORE_ATTR_ISSUERKEYID', 'ui_st',
           'X509_PUBKEY', '__locale_struct', 'u_int8_t',
           'ASN1_ITEM_st', 'pkcs7_recip_info_st', 'off_t',
           'ui_method_st', 'crypto_ex_data_st', '__fsblkcnt_t',
           '__locale_t', 'ENGINE_LOAD_KEY_PTR', 'ECDH_METHOD',
           'CRYPTO_EX_dup', 'OCSP_RESPID', 'BN_MONT_CTX',
           'STORE_ATTR_FRIENDLYNAME', 'STORE_PARAM_EVP_TYPE',
           'ASN1_NULL', 'ASN1_INTEGER', 'CRYPTO_EX_new',
           'SHA256state_st', 'asn1_type_st', 'CRYPTO_EX_DATA_FUNCS',
           'key_t', 'uint', 'ASN1_VALUE_st', 'DH_METHOD',
           'STORE_OBJECT_TYPE_NUMBER', '__pthread_internal_slist',
           'RSA', '__u_int', 'asn1_output_data_fn', 'ssize_t',
           '__clock_t', 'fsblkcnt_t', 'X509_PKEY',
           'evp_verify_method', 'FILE', 'X509_POLICY_CACHE_st',
           'X509_sig_st', 'SHA512_CTX', 'pkcs7_issuer_and_serial_st',
           'CRYPTO_MEM_LEAK_CB', 'X509_NAME', 'blkcnt_t',
           'evp_cipher_info_st', 'BN_BLINDING', '__qaddr_t',
           'err_state_st', 'st_dynamic_MEM_fns', 'DES_key_schedule',
           'N11__mbstate_t3DOT_2E', 'u_char', 'fpos64_t', 'uid_t',
           'cookie_write_function_t', 'u_int64_t', 'ASN1_STRING',
           'N11evp_pkey_st4DOT_28E', 'STORE_OBJECT_TYPE_X509_CRL',
           'sigset_t', 'conf_st', 'ASN1_CTX',
           'N12asn1_type_st4DOT_27E', 'PKCS7', '__int32_t',
           'UI_METHOD', 'NETSCAPE_SPKI', 'st_CRYPTO_EX_DATA_IMPL',
           'cast_key_st', 'X509_HASH_DIR_CTX', 'ERR_string_data_st',
           'st_dynamic_fns', '__fd_mask', 'dynamic_MEM_fns',
           'STORE_PARAM_TYPE_NUM', 'clock_t', 'aes_key_st',
           'asn1_string_table_st', '__useconds_t',
           'X509_POLICY_TREE_st', 'ASN1_VISIBLESTRING',
           'dynamic_LOCK_fns', 'x509_cert_pair_st', 'DSA_SIG_st',
           'obj_name_st', 'X509_LOOKUP_METHOD', 'u_int32_t',
           '_IO_cookie_io_functions_t', 'EVP_CIPHER_INFO',
           '__gnuc_va_list', 'AES_KEY', 'PKCS7_ISSUER_AND_SERIAL',
           'BN_CTX', 'ERR_FNS', 'SHA_CTX', 'pkcs7_signed_st', 'SSL',
           'EVP_MD', 'ASN1_BOOLEAN', '__rlim64_t', 'ino_t',
           'ecdsa_method', 'dyn_dynlock_lock_cb', 'ASN1_OCTET_STRING',
           'STORE_PARAM_AUTH_KRB5_TICKET', '__blksize_t',
           'ENGINE_CMD_DEFN', 'pthread_spinlock_t', 'asn1_ctx_st',
           '__pthread_slist_t', 'ecdh_method', 'BIO_F_BUFFER_CTX',
           'ECDSA_SIG_st', 'bn_mont_ctx_st', 'X509_REQ_INFO',
           'OCSP_REQ_CTX', 'ERR_STATE', 'STORE_certificate_status',
           'STORE_CTRL_FUNC_PTR', 'STORE_ATTR_SERIAL', 'ino64_t',
           'x509_attributes_st', 'ec_method_st', '__mbstate_t',
           'asn1_object_st', 'ASN1_ENCODING', '__uint8_t',
           'LHASH_NODE', '__u_char', '__caddr_t', '__blkcnt64_t',
           'PKCS7_SIGNER_INFO', 'asn1_method_st',
           'STORE_GENERATE_OBJECT_FUNC_PTR', 'stack_st',
           'bio_info_cb', 'STORE_ATTR_SUBJECT',
           'N18x509_attributes_st4DOT_35E', 'ASN1_PRINTABLESTRING',
           'PBEPARAM_st', 'quad_t', 'STORE_attr_info_st', 'rsa_st',
           'ASN1_UNIVERSALSTRING', 'X509_OBJECT', 'DH',
           'bn_blinding_st', 'ASN1_ENCODING_st', 'ASN1_TLC_st',
           '__rlim_t', 'BIO', 'nlink_t', 'BUF_MEM', 'bio_method_st',
           'BIO_dummy', 'ssl_ctx_st', 'RC4_KEY',
           'BIT_STRING_BITNAME_st', 'ulong', 'STORE_ATTR_TYPES',
           'EVP_ENCODE_CTX', 'STORE_ATTR_ISSUER', 'STORE_params',
           'int8_t', 'OBJ_NAME', 'STORE_PARAM_BITS',
           'ENGINE_CIPHERS_PTR', 'STORE', 'X509_POLICY_CACHE',
           'PKCS8_PRIV_KEY_INFO', 'X509_CRL', '__fsfilcnt_t',
           '__quad_t', '__key_t', 'X509_VAL', 'dev_t',
           'ASN1_TEMPLATE_st', 'ENGINE', 'LHASH_DOALL_ARG_FN_TYPE',
           'ocsp_req_ctx_st', 'ASN1_ITEM_EXP', 'fsfilcnt_t',
           '__swblk_t', 'mode_t', 'ASN1_VALUE', 'X509_POLICY_NODE',
           'EVP_PKEY', 'CRYPTO_EX_free', 'ENGINE_SSL_CLIENT_CERT_PTR',
           '_ossl_old_des_cblock', 'X509_INFO', 'asn1_string_st',
           '__loff_t', 'RAND_METHOD', 'STORE_ATTR_FILENAME',
           'ASN1_const_CTX', 'env_md_st', 'cookie_seek_function_t',
           'STORE_NEXT_OBJECT_FUNC_PTR', 'LHASH',
           'PKCS7_SIGN_ENVELOPE', 'X509_extension_st', 'va_list',
           'PKCS7_DIGEST', 'N6DES_ks4DOT_30E', 'fd_mask', 'ASN1_TYPE',
           'PKCS7_SIGNED', '__fsid_t', 'cookie_close_function_t',
           'EC_METHOD', '__ssize_t', 'comparison_fn_t', 'BF_KEY',
           'hmac_ctx_st', 'SHA512state_st', 'OPENSSL_ITEM', 'size_t',
           'int16_t', 'BN_GENCB', 'STORE_OBJECT_TYPE_PRIVATE_KEY',
           '__sigset_t', 'X509_TRUST', 'X509_STORE',
           'STORE_PARAM_AUTH_PASSPHRASE', 'X509_STORE_CTX',
           'ASN1_TIME', 'STORE_ATTR_KEYID', 'X509_LOOKUP',
           'Netscape_spki_st', 'STORE_X509_VALID',
           'ENGINE_CTRL_FUNC_PTR', '__intptr_t', 'SHA256_CTX',
           'STORE_CLEANUP_FUNC_PTR', 'x509_cert_aux_st', 'ushort',
           'STORE_STORE_OBJECT_FUNC_PTR', '__blkcnt_t', 'clockid_t',
           'N8pkcs7_st4DOT_37E', 'BN_RECP_CTX', 'x509_lookup_st',
           'ASN1_BMPSTRING', 'asn1_header_st', 'x509_trust_st',
           'STORE_OBJECT_TYPES', 'int32_t', 'off64_t',
           'X509_CRL_INFO', 'st_ERR_FNS', 'dynamic_fns',
           'ASN1_HEADER', 'X509_crl_info_st', 'i2d_of_void',
           'LHASH_HASH_FN_TYPE', 'N15STORE_OBJECT_st4DOT_38E',
           '__compar_d_fn_t', 'ssl_st', 'ENGINE_GEN_INT_FUNC_PTR',
           'evp_pkey_st', 'pkcs7_signedandenveloped_st', 'X509V3_CTX',
           'STORE_INITIALISE_FUNC_PTR', 'EVP_PBE_KEYGEN', '__dev_t',
           'ASN1_UTCTIME', 'STORE_ATTR_TYPE_NUM',
           'dynamic_bind_engine', 'X509_POLICY_LEVEL_st',
           'crypto_ex_data_func_st', '__suseconds_t', 'STORE_ATTR_OR',
           'u_long', 'PBKDF2PARAM_st', 'ECDSA_SIG', 'rc4_key_st',
           'DSA_METHOD', 'STORE_OBJECT', 'EVP_CIPHER',
           'ocsp_response_st', 'BIT_STRING_BITNAME',
           'PKCS7_RECIP_INFO', 'EC_GROUP', 'X509_revoked_st',
           'X509_CERT_AUX', 'X509_VERIFY_PARAM',
           'X509_VERIFY_PARAM_st', 'STORE_OBJECT_TYPE_PUBLIC_KEY',
           'time_t', 'u_short', 'N23_ossl_old_des_ks_struct4DOT_31E',
           'error_t', '_ossl_old_des_key_schedule', '_IO_marker',
           'fsblkcnt64_t', 'v3_ext_ctx', 'ASN1_GENERALSTRING',
           'STACK', 'X509_name_entry_st', '__io_write_fn', 'caddr_t',
           '__ino_t', 'bignum_st', 'X509_CINF', '_IO_lock_t',
           'ASN1_TLC', 'PKCS7_ENCRYPT', 'NETSCAPE_SPKAC',
           'Netscape_spkac_st', 'X509_CERT_PAIR',
           'dyn_lock_add_lock_cb', '__int64_t', 'pkcs7_st',
           'ocsp_responder_id_st', 'rand_meth_st', 'suseconds_t',
           'ASN1_OBJECT', 'X509_val_st', 'private_key_st',
           'X509_objects_st', 'CRYPTO_EX_DATA_IMPL', 'pthread_once_t',
           '__timer_t', 'CONF', 'ERR_STRING_DATA', 'u_int16_t',
           '__uint32_t', 'register_t', 'rsa_meth_st', 'X509_crl_st',
           '__ino64_t', 'N14SHA512state_st4DOT_34E',
           'store_method_st', 'loff_t', 'PBE2PARAM', 'blksize_t',
           'STORE_attribs', 'Netscape_certificate_sequence',
           'bignum_ctx', '_G_uint32_t', 'ASN1_UTF8STRING',
           'dyn_MEM_realloc_cb', 'pkcs7_encrypted_st',
           'STORE_ATTR_ISSUERSERIALHASH', '_G_fpos64_t',
           'STORE_X509_SUSPENDED', 'PBKDF2PARAM', '__nlink_t',
           '__compar_fn_t', 'CAST_KEY', '__io_close_fn',
           'LHASH_DOALL_FN_TYPE', 'OCSP_RESPONSE',
           'evp_cipher_ctx_st', 'X509_ALGOR', '__id_t',
           'cookie_io_functions_t', 'const_DES_cblock',
           'dyn_dynlock_destroy_cb', 'dsa_st', 'dyn_lock_locking_cb',
           'STORE_PARAM_KEY_NO_PARAMETERS', 'X509_EXTENSION',
           'PKCS7_ENVELOPE', 'N11bn_gencb_st4DOT_26E', 'ec_key_st',
           'x509_lookup_method_st', '_G_uint16_t',
           'ENGINE_DIGESTS_PTR', 'STORE_OBJECT_TYPE_ARBITRARY',
           'bn_recp_ctx_st', 'X509_info_st', 'x509_store_st',
           'X509_pubkey_st', 'pkcs7_digest_st', 'ASN1_STRING_TABLE',
           'ENGINE_CMD_DEFN_st', 'X509_EXTENSIONS',
           'pkcs7_enveloped_st', 'UI', 'ptrdiff_t', 'X509_REQ',
           'CRYPTO_dynlock_value', 'X509_req_st', 'x509_store_ctx_st',
           'asn1_const_ctx_st', 'lhash_node_st', 'store_st',
           'LHASH_COMP_FN_TYPE', 'STORE_OBJECT_st', '__gid_t',
           'STORE_OBJECT_TYPE_X509_CERTIFICATE', 'd2i_of_void',
           'X509_ATTRIBUTE', 'ECDSA_METHOD', '__daddr_t',
           '__sig_atomic_t', '__io_seek_fn', 'u_int',
           'ASN1_T61STRING', 'gid_t', 'ASN1_ITEM', 'ASN1_ENUMERATED',
           'pkcs8_priv_key_info_st', 'PBE2PARAM_st',
           'N15STORE_OBJECT_st4DOT_384DOT_39E',
           'cookie_read_function_t', 'blkcnt64_t', 'X509_OBJECTS',
           'x509_object_st', 'STORE_object_types', 'DES_ks',
           'N14x509_object_st4DOT_36E', 'dsa_method', 'int64_t',
           'bio_st', 'bf_key_st', 'ASN1_GENERALIZEDTIME',
           'PKCS7_ENC_CONTENT', 'ECPKPARAMETERS', 'EVP_MD_CTX',
           '__u_quad_t', '__u_short', 'evp_cipher_st', 'X509_name_st',
           'x509_st', 'fsid_t', '__pid_t', 'AUTHORITY_KEYID_st',
           'STORE_PARAM_TYPES', 'x509_hash_dir_st', 'evp_sign_method',
           'X509_POLICY_TREE', 'useconds_t',
           'STORE_HANDLE_OBJECT_FUNC_PTR', '__uid_t', 'locale_t',
           'STORE_ATTR_CERTHASH', 'X509_ALGORS', '__socklen_t',
           'dh_st', 'STORE_ATTR_INFO', '_G_int32_t',
           'STORE_ATTR_EMAIL', 'X509_CERT_FILE_CTX']
