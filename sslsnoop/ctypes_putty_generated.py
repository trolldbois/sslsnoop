from ctypes import *

STRING = c_char_p


KEXTYPE_DH = 0
X11_TRANS_IPV6 = 6
__codecvt_error = 2
X11_TRANS_UNIX = 256
X11_TRANS_IPV4 = 0
REL234_EQ = 0
SSH_KEYTYPE_UNOPENABLE = 0
SSH_KEYTYPE_OPENSSH = 4
SSH_KEYTYPE_SSH2 = 3
SSH_KEYTYPE_SSH1 = 2
SSH_KEYTYPE_SSHCOM = 5
__codecvt_noconv = 3
__codecvt_partial = 1
SSH_KEYTYPE_UNKNOWN = 1
__codecvt_ok = 0
KEXTYPE_RSA = 1
REL234_GT = 3
REL234_LE = 2
REL234_GE = 4
REL234_LT = 1
class uint64(Structure):
    pass
uint64._fields_ = [
    ('hi', c_ulong),
    ('lo', c_ulong),
]
class Filename(Structure):
    pass
Filename._fields_ = [
]
class FontSpec(Structure):
    pass
FontSpec._fields_ = [
]
class bufchain_granule(Structure):
    pass
bufchain_granule._fields_ = [
]
class bufchain_tag(Structure):
    pass
bufchain_tag._fields_ = [
    ('head', POINTER(bufchain_granule)),
    ('tail', POINTER(bufchain_granule)),
    ('buffersize', c_int),
]
bufchain = bufchain_tag
class config_tag(Structure):
    pass
config_tag._fields_ = [
]
Config = config_tag
class backend_tag(Structure):
    pass
backend_tag._fields_ = [
]
Backend = backend_tag
class terminal_tag(Structure):
    pass
terminal_tag._fields_ = [
]
Terminal = terminal_tag
class SockAddr_tag(Structure):
    pass
SockAddr = POINTER(SockAddr_tag)
SockAddr_tag._fields_ = [
]
class socket_function_table(Structure):
    pass
Socket = POINTER(POINTER(socket_function_table))
class plug_function_table(Structure):
    pass
Plug = POINTER(POINTER(plug_function_table))
OSSocket = c_void_p
socket_function_table._fields_ = [
    ('plug', CFUNCTYPE(Plug, Socket, Plug)),
    ('close', CFUNCTYPE(None, Socket)),
    ('write', CFUNCTYPE(c_int, Socket, STRING, c_int)),
    ('write_oob', CFUNCTYPE(c_int, Socket, STRING, c_int)),
    ('flush', CFUNCTYPE(None, Socket)),
    ('set_private_ptr', CFUNCTYPE(None, Socket, c_void_p)),
    ('get_private_ptr', CFUNCTYPE(c_void_p, Socket)),
    ('set_frozen', CFUNCTYPE(None, Socket, c_int)),
    ('socket_error', CFUNCTYPE(STRING, Socket)),
]
plug_function_table._fields_ = [
    ('log', CFUNCTYPE(None, Plug, c_int, SockAddr, c_int, STRING, c_int)),
    ('closing', CFUNCTYPE(c_int, Plug, STRING, c_int, c_int)),
    ('receive', CFUNCTYPE(c_int, Plug, c_int, STRING, c_int)),
    ('sent', CFUNCTYPE(None, Plug, c_int)),
    ('accepting', CFUNCTYPE(c_int, Plug, OSSocket)),
]
class certificate(Structure):
    pass
certificate._fields_ = [
]
Certificate = POINTER(certificate)
class our_certificate(Structure):
    pass
Our_Certificate = POINTER(our_certificate)
our_certificate._fields_ = [
]
class ssl_client_socket_function_table(Structure):
    pass
SSL_Client_Socket = POINTER(POINTER(ssl_client_socket_function_table))
class ssl_client_plug_function_table(Structure):
    pass
SSL_Client_Plug = POINTER(POINTER(ssl_client_plug_function_table))
ssl_client_socket_function_table._fields_ = [
    ('base', socket_function_table),
    ('renegotiate', CFUNCTYPE(None, SSL_Client_Socket)),
]
ssl_client_plug_function_table._fields_ = [
    ('base', plug_function_table),
    ('refuse_cert', CFUNCTYPE(c_int, SSL_Client_Plug, POINTER(Certificate))),
    ('client_cert', CFUNCTYPE(Our_Certificate, SSL_Client_Plug)),
]
class ssh_channel(Structure):
    pass
ssh_channel._fields_ = [
]
Bignum = c_void_p
class RSAKey(Structure):
    pass
RSAKey._fields_ = [
    ('bits', c_int),
    ('bytes', c_int),
    ('modulus', Bignum),
    ('exponent', Bignum),
    ('private_exponent', Bignum),
    ('p', Bignum),
    ('q', Bignum),
    ('iqmp', Bignum),
    ('comment', STRING),
]
class dss_key(Structure):
    pass
dss_key._fields_ = [
    ('p', Bignum),
    ('q', Bignum),
    ('g', Bignum),
    ('y', Bignum),
    ('x', Bignum),
]
uint32 = c_uint
word32 = uint32
class MD5_Core_State(Structure):
    pass
MD5_Core_State._fields_ = [
    ('h', uint32 * 4),
]
class MD5Context(Structure):
    pass
MD5Context._fields_ = [
    ('core', MD5_Core_State),
    ('block', c_ubyte * 64),
    ('blkused', c_int),
    ('lenhi', uint32),
    ('lenlo', uint32),
]
class SHA_State(Structure):
    pass
SHA_State._fields_ = [
    ('h', uint32 * 5),
    ('block', c_ubyte * 64),
    ('blkused', c_int),
    ('lenhi', uint32),
    ('lenlo', uint32),
]
class SHA256_State(Structure):
    pass
SHA256_State._fields_ = [
    ('h', uint32 * 8),
    ('block', c_ubyte * 64),
    ('blkused', c_int),
    ('lenhi', uint32),
    ('lenlo', uint32),
]
class SHA512_State(Structure):
    pass
SHA512_State._fields_ = [
    ('h', uint64 * 8),
    ('block', c_ubyte * 128),
    ('blkused', c_int),
    ('len', uint32 * 4),
]
class ssh_cipher(Structure):
    pass
ssh_cipher._fields_ = [
    ('make_context', CFUNCTYPE(c_void_p)),
    ('free_context', CFUNCTYPE(None, c_void_p)),
    ('sesskey', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte))),
    ('encrypt', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_int)),
    ('decrypt', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_int)),
    ('blksize', c_int),
    ('text_name', STRING),
]
class ssh2_cipher(Structure):
    pass
ssh2_cipher._fields_ = [
    ('make_context', CFUNCTYPE(c_void_p)),
    ('free_context', CFUNCTYPE(None, c_void_p)),
    ('setiv', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte))),
    ('setkey', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte))),
    ('encrypt', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_int)),
    ('decrypt', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_int)),
    ('name', STRING),
    ('blksize', c_int),
    ('keylen', c_int),
    ('flags', c_uint),
    ('text_name', STRING),
]
class ssh2_ciphers(Structure):
    pass
ssh2_ciphers._fields_ = [
    ('nciphers', c_int),
    ('list', POINTER(POINTER(ssh2_cipher))),
]
class ssh_mac(Structure):
    pass
ssh_mac._fields_ = [
    ('make_context', CFUNCTYPE(c_void_p)),
    ('free_context', CFUNCTYPE(None, c_void_p)),
    ('setkey', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte))),
    ('generate', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_int, c_ulong)),
    ('verify', CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_int, c_ulong)),
    ('start', CFUNCTYPE(None, c_void_p)),
    ('bytes', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte), c_int)),
    ('genresult', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte))),
    ('verresult', CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte))),
    ('name', STRING),
    ('len', c_int),
    ('text_name', STRING),
]
class ssh_hash(Structure):
    pass
ssh_hash._fields_ = [
    ('init', CFUNCTYPE(c_void_p)),
    ('bytes', CFUNCTYPE(None, c_void_p, c_void_p, c_int)),
    ('final', CFUNCTYPE(None, c_void_p, POINTER(c_ubyte))),
    ('hlen', c_int),
    ('text_name', STRING),
]
class ssh_kex(Structure):
    pass

# values for unnamed enumeration
ssh_kex._fields_ = [
    ('name', STRING),
    ('groupname', STRING),
    ('main_type', c_int),
    ('pdata', POINTER(c_ubyte)),
    ('gdata', POINTER(c_ubyte)),
    ('plen', c_int),
    ('glen', c_int),
    ('hash', POINTER(ssh_hash)),
]
class ssh_kexes(Structure):
    pass
ssh_kexes._fields_ = [
    ('nkexes', c_int),
    ('list', POINTER(POINTER(ssh_kex))),
]
class ssh_signkey(Structure):
    pass
ssh_signkey._fields_ = [
    ('newkey', CFUNCTYPE(c_void_p, STRING, c_int)),
    ('freekey', CFUNCTYPE(None, c_void_p)),
    ('fmtkey', CFUNCTYPE(STRING, c_void_p)),
    ('public_blob', CFUNCTYPE(POINTER(c_ubyte), c_void_p, POINTER(c_int))),
    ('private_blob', CFUNCTYPE(POINTER(c_ubyte), c_void_p, POINTER(c_int))),
    ('createkey', CFUNCTYPE(c_void_p, POINTER(c_ubyte), c_int, POINTER(c_ubyte), c_int)),
    ('openssh_createkey', CFUNCTYPE(c_void_p, POINTER(POINTER(c_ubyte)), POINTER(c_int))),
    ('openssh_fmtkey', CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_int)),
    ('pubkey_bits', CFUNCTYPE(c_int, c_void_p, c_int)),
    ('fingerprint', CFUNCTYPE(STRING, c_void_p)),
    ('verifysig', CFUNCTYPE(c_int, c_void_p, STRING, c_int, STRING, c_int)),
    ('sign', CFUNCTYPE(POINTER(c_ubyte), c_void_p, STRING, c_int, POINTER(c_int))),
    ('name', STRING),
    ('keytype', STRING),
]
class ssh_compress(Structure):
    pass
ssh_compress._fields_ = [
    ('name', STRING),
    ('delayed_name', STRING),
    ('compress_init', CFUNCTYPE(c_void_p)),
    ('compress_cleanup', CFUNCTYPE(None, c_void_p)),
    ('compress', CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_int, POINTER(POINTER(c_ubyte)), POINTER(c_int))),
    ('decompress_init', CFUNCTYPE(c_void_p)),
    ('decompress_cleanup', CFUNCTYPE(None, c_void_p)),
    ('decompress', CFUNCTYPE(c_int, c_void_p, POINTER(c_ubyte), c_int, POINTER(POINTER(c_ubyte)), POINTER(c_int))),
    ('disable_compression', CFUNCTYPE(c_int, c_void_p)),
    ('text_name', STRING),
]
class ssh2_userkey(Structure):
    pass
ssh2_userkey._fields_ = [
    ('alg', POINTER(ssh_signkey)),
    ('data', c_void_p),
    ('comment', STRING),
]

# values for unnamed enumeration
class X11Display(Structure):
    pass
class tree234_Tag(Structure):
    pass
tree234 = tree234_Tag
X11Display._fields_ = [
    ('unixdomain', c_int),
    ('hostname', STRING),
    ('displaynum', c_int),
    ('screennum', c_int),
    ('unixsocketpath', STRING),
    ('addr', SockAddr),
    ('port', c_int),
    ('realhost', STRING),
    ('remoteauthproto', c_int),
    ('remoteauthdata', POINTER(c_ubyte)),
    ('remoteauthdatalen', c_int),
    ('remoteauthprotoname', STRING),
    ('remoteauthdatastring', STRING),
    ('localauthproto', c_int),
    ('localauthdata', POINTER(c_ubyte)),
    ('localauthdatalen', c_int),
    ('xdmseen', POINTER(tree234)),
]

# values for unnamed enumeration
progfn_t = CFUNCTYPE(None, c_void_p, c_int, c_int, c_int)
tree234_Tag._fields_ = [
]
cmpfn234 = CFUNCTYPE(c_int, c_void_p, c_void_p)

# values for unnamed enumeration
class _G_fpos_t(Structure):
    pass
__off_t = c_long
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
class _G_fpos64_t(Structure):
    pass
__quad_t = c_longlong
__off64_t = __quad_t
_G_fpos64_t._pack_ = 4
_G_fpos64_t._fields_ = [
    ('__pos', __off64_t),
    ('__state', __mbstate_t),
]
_G_int16_t = c_short
_G_int32_t = c_int
_G_uint16_t = c_ushort
_G_uint32_t = c_uint
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
__u_quad_t = c_ulonglong
__dev_t = __u_quad_t
__uid_t = c_uint
__gid_t = c_uint
__ino_t = c_ulong
__ino64_t = __u_quad_t
__mode_t = c_uint
__nlink_t = c_uint
__pid_t = c_int
class __fsid_t(Structure):
    pass
__fsid_t._fields_ = [
    ('__val', c_int * 2),
]
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
size_t = c_uint
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
FILE = _IO_FILE
__FILE = _IO_FILE
__gnuc_va_list = STRING
va_list = __gnuc_va_list
off_t = __off_t
off64_t = __off64_t
ssize_t = __ssize_t
fpos_t = _G_fpos_t
fpos64_t = _G_fpos64_t
class obstack(Structure):
    pass
obstack._fields_ = [
]
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
class tm(Structure):
    pass
tm._fields_ = [
    ('tm_sec', c_int),
    ('tm_min', c_int),
    ('tm_hour', c_int),
    ('tm_mday', c_int),
    ('tm_mon', c_int),
    ('tm_year', c_int),
    ('tm_wday', c_int),
    ('tm_yday', c_int),
    ('tm_isdst', c_int),
    ('tm_gmtoff', c_long),
    ('tm_zone', STRING),
]
class itimerspec(Structure):
    pass
itimerspec._fields_ = [
    ('it_interval', timespec),
    ('it_value', timespec),
]
class sigevent(Structure):
    pass
sigevent._fields_ = [
]
pid_t = __pid_t
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
ptrdiff_t = c_int
__all__ = ['__uint16_t', '__int16_t', 'Filename', '__fsid_t', 'FILE',
           '__off64_t', 'size_t', 'ssh2_ciphers', '__uint32_t',
           'fpos_t', '__time_t', 'tm', '__ino64_t', '_G_int16_t',
           'Plug', 'Socket', '__FILE', 'FontSpec',
           'cookie_seek_function_t', 'fpos64_t',
           'cookie_write_function_t', '_G_uint32_t', '_G_fpos64_t',
           'uint32', 'SockAddr_tag', '_IO_jump_t', '__int32_t',
           '__nlink_t', 'progfn_t', '__swblk_t',
           'cookie_close_function_t', '__uint64_t', '__ssize_t',
           '__io_close_fn', 'X11_TRANS_UNIX', 'KEXTYPE_DH',
           'SSH_KEYTYPE_UNKNOWN', '__codecvt_ok', 'clock_t',
           'terminal_tag', 'X11Display', 'cookie_io_functions_t',
           '__clockid_t', 'bufchain', '__useconds_t', '__timer_t',
           'KEXTYPE_RSA', '_IO_FILE', '__codecvt_partial',
           '_G_uint16_t', 'word32', 'SSH_KEYTYPE_OPENSSH',
           '_IO_cookie_io_functions_t', 'config_tag',
           '__codecvt_result', '__gnuc_va_list', '__intptr_t',
           '__u_long', 'SHA256_State', 'Bignum', '_IO_FILE_plus',
           '__loff_t', '__blkcnt_t', 'clockid_t', 'ptrdiff_t',
           'sigevent', '__rlim64_t', 'ssh2_cipher', 'Backend',
           'Certificate', 'bufchain_tag', '__mode_t', 'off64_t',
           'ssh_compress', '__blksize_t', '__off_t', 'Config',
           '__locale_data', '__gid_t', '__qaddr_t', 'timespec',
           'certificate', 'REL234_EQ', 'obstack', 'cmpfn234',
           'N11__mbstate_t3DOT_2E', 'X11_TRANS_IPV6',
           'X11_TRANS_IPV4', '__daddr_t', 'ssh_kexes', '__caddr_t',
           'backend_tag', 'SHA512_State', 'SockAddr',
           '_IO_cookie_file', '__uint8_t', 'ssh2_userkey',
           '__io_seek_fn', 'Our_Certificate', '__u_char', 'ssh_kex',
           'RSAKey', 'SSH_KEYTYPE_UNOPENABLE', '__blkcnt64_t',
           '__dev_t', 'socket_function_table', 'uint64',
           '__suseconds_t', 'ssh_cipher', 'pid_t', 'ssh_signkey',
           'timer_t', 'ssl_client_plug_function_table',
           '__fsfilcnt64_t', 'va_list', 'tree234',
           'cookie_read_function_t', 'SSL_Client_Plug',
           'SSL_Client_Socket', '__locale_struct', '__io_read_fn',
           'SSH_KEYTYPE_SSH2', 'SSH_KEYTYPE_SSH1', 'REL234_LE',
           'MD5_Core_State', 'off_t', 'Terminal', 'itimerspec',
           'REL234_LT', '__fsblkcnt_t', '__rlim_t', 'time_t',
           'OSSocket', 'ssl_client_socket_function_table',
           '__locale_t', 'bufchain_granule', 'REL234_GT', 'SHA_State',
           '_IO_marker', '__u_quad_t', '__u_short', 'our_certificate',
           'REL234_GE', '__int8_t', '__id_t', 'dss_key', '__pid_t',
           'ssize_t', '__fsblkcnt64_t', '__codecvt_error',
           '__io_write_fn', '__clock_t', 'SSH_KEYTYPE_SSHCOM',
           '__ino_t', 'ssh_hash', '_IO_lock_t', '__key_t',
           '__mbstate_t', 'locale_t', '__socklen_t',
           'plug_function_table', '__u_int', '_G_fpos_t', '__quad_t',
           '__int64_t', 'tree234_Tag', '__codecvt_noconv',
           'MD5Context', '_G_int32_t', 'ssh_channel', '__uid_t',
           '__fsfilcnt_t', 'ssh_mac']
