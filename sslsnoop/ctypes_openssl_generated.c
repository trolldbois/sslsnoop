extern "C" {
}
typedef struct asn1_string_st ASN1_INTEGER;
typedef struct asn1_string_st ASN1_ENUMERATED;
typedef struct asn1_string_st ASN1_BIT_STRING;
typedef struct asn1_string_st ASN1_OCTET_STRING;
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
typedef struct asn1_string_st ASN1_T61STRING;
typedef struct asn1_string_st ASN1_IA5STRING;
typedef struct asn1_string_st ASN1_GENERALSTRING;
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
typedef struct asn1_string_st ASN1_BMPSTRING;
typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
typedef struct asn1_string_st ASN1_VISIBLESTRING;
typedef struct asn1_string_st ASN1_UTF8STRING;
typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
typedef struct bn_blinding_st BN_BLINDING;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct bn_recp_ctx_st BN_RECP_CTX;
typedef struct bn_gencb_st BN_GENCB;
typedef struct buf_mem_st BUF_MEM;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct env_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct dh_st DH;
typedef struct dh_method DH_METHOD;
typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;
typedef struct rsa_st RSA;
typedef struct rsa_meth_st RSA_METHOD;
typedef struct rand_meth_st RAND_METHOD;
typedef struct ecdh_method ECDH_METHOD;
typedef struct ecdsa_method ECDSA_METHOD;
typedef struct x509_st X509;
typedef struct X509_algor_st X509_ALGOR;
typedef struct X509_crl_st X509_CRL;
typedef struct X509_name_st X509_NAME;
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct v3_ext_ctx X509V3_CTX;
typedef struct conf_st CONF;
typedef struct store_st STORE;
typedef struct store_method_st STORE_METHOD;
typedef struct ui_st UI;
typedef struct ui_method_st UI_METHOD;
typedef struct st_ERR_FNS ERR_FNS;
typedef struct engine_st ENGINE;
typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
typedef struct X509_POLICY_TREE_st X509_POLICY_TREE;
typedef struct X509_POLICY_CACHE_st X509_POLICY_CACHE;
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
typedef int CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
     int idx, long argl, void *argp);
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
     int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, CRYPTO_EX_DATA *from, void *from_d,
     int idx, long argl, void *argp);
typedef struct ocsp_req_ctx_st OCSP_REQ_CTX;
typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_responder_id_st OCSP_RESPID;
extern "C" {
typedef unsigned int size_t;
typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;
typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;
__extension__ typedef signed long long int __int64_t;
__extension__ typedef unsigned long long int __uint64_t;
__extension__ typedef long long int __quad_t;
__extension__ typedef unsigned long long int __u_quad_t;
__extension__ typedef __u_quad_t __dev_t;
__extension__ typedef unsigned int __uid_t;
__extension__ typedef unsigned int __gid_t;
__extension__ typedef unsigned long int __ino_t;
__extension__ typedef __u_quad_t __ino64_t;
__extension__ typedef unsigned int __mode_t;
__extension__ typedef unsigned int __nlink_t;
__extension__ typedef long int __off_t;
__extension__ typedef __quad_t __off64_t;
__extension__ typedef int __pid_t;
__extension__ typedef struct { int __val[2]; } __fsid_t;
__extension__ typedef long int __clock_t;
__extension__ typedef unsigned long int __rlim_t;
__extension__ typedef __u_quad_t __rlim64_t;
__extension__ typedef unsigned int __id_t;
__extension__ typedef long int __time_t;
__extension__ typedef unsigned int __useconds_t;
__extension__ typedef long int __suseconds_t;
__extension__ typedef int __daddr_t;
__extension__ typedef long int __swblk_t;
__extension__ typedef int __key_t;
__extension__ typedef int __clockid_t;
__extension__ typedef void * __timer_t;
__extension__ typedef long int __blksize_t;
__extension__ typedef long int __blkcnt_t;
__extension__ typedef __quad_t __blkcnt64_t;
__extension__ typedef unsigned long int __fsblkcnt_t;
__extension__ typedef __u_quad_t __fsblkcnt64_t;
__extension__ typedef unsigned long int __fsfilcnt_t;
__extension__ typedef __u_quad_t __fsfilcnt64_t;
__extension__ typedef int __ssize_t;
typedef __off64_t __loff_t;
typedef __quad_t *__qaddr_t;
typedef char *__caddr_t;
__extension__ typedef int __intptr_t;
__extension__ typedef unsigned int __socklen_t;
struct _IO_FILE;

typedef struct _IO_FILE FILE;


typedef struct _IO_FILE __FILE;
typedef struct
{
  int __count;
  union
  {
    unsigned int __wch;
    char __wchb[4];
  } __value;
} __mbstate_t;
typedef struct
{
  __off_t __pos;
  __mbstate_t __state;
} _G_fpos_t;
typedef struct
{
  __off64_t __pos;
  __mbstate_t __state;
} _G_fpos64_t;
typedef int _G_int16_t __attribute__ ((__mode__ (__HI__)));
typedef int _G_int32_t __attribute__ ((__mode__ (__SI__)));
typedef unsigned int _G_uint16_t __attribute__ ((__mode__ (__HI__)));
typedef unsigned int _G_uint32_t __attribute__ ((__mode__ (__SI__)));
typedef __builtin_va_list __gnuc_va_list;
struct _IO_jump_t; struct _IO_FILE;
typedef void _IO_lock_t;
struct _IO_marker {
  struct _IO_marker *_next;
  struct _IO_FILE *_sbuf;
  int _pos;
};
enum __codecvt_result
{
  __codecvt_ok,
  __codecvt_partial,
  __codecvt_error,
  __codecvt_noconv
};
struct _IO_FILE {
  int _flags;
  char* _IO_read_ptr;
  char* _IO_read_end;
  char* _IO_read_base;
  char* _IO_write_base;
  char* _IO_write_ptr;
  char* _IO_write_end;
  char* _IO_buf_base;
  char* _IO_buf_end;
  char *_IO_save_base;
  char *_IO_backup_base;
  char *_IO_save_end;
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset;
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
  __off64_t _offset;
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
  size_t __pad5;
  int _mode;
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
struct _IO_FILE_plus;
extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;
typedef __ssize_t __io_read_fn (void *__cookie, char *__buf, size_t __nbytes);
typedef __ssize_t __io_write_fn (void *__cookie, __const char *__buf,
     size_t __n);
typedef int __io_seek_fn (void *__cookie, __off64_t *__pos, int __w);
typedef int __io_close_fn (void *__cookie);
typedef __io_read_fn cookie_read_function_t;
typedef __io_write_fn cookie_write_function_t;
typedef __io_seek_fn cookie_seek_function_t;
typedef __io_close_fn cookie_close_function_t;
typedef struct
{
  __io_read_fn *read;
  __io_write_fn *write;
  __io_seek_fn *seek;
  __io_close_fn *close;
} _IO_cookie_io_functions_t;
typedef _IO_cookie_io_functions_t cookie_io_functions_t;
struct _IO_cookie_file;
extern void _IO_cookie_init (struct _IO_cookie_file *__cfile, int __read_write,
        void *__cookie, _IO_cookie_io_functions_t __fns);
extern "C" {
extern int __underflow (_IO_FILE *);
extern int __uflow (_IO_FILE *);
extern int __overflow (_IO_FILE *, int);
extern int _IO_getc (_IO_FILE *__fp);
extern int _IO_putc (int __c, _IO_FILE *__fp);
extern int _IO_feof (_IO_FILE *__fp) throw ();
extern int _IO_ferror (_IO_FILE *__fp) throw ();
extern int _IO_peekc_locked (_IO_FILE *__fp);
extern void _IO_flockfile (_IO_FILE *) throw ();
extern void _IO_funlockfile (_IO_FILE *) throw ();
extern int _IO_ftrylockfile (_IO_FILE *) throw ();
extern int _IO_vfscanf (_IO_FILE * __restrict, const char * __restrict,
   __gnuc_va_list, int *__restrict);
extern int _IO_vfprintf (_IO_FILE *__restrict, const char *__restrict,
    __gnuc_va_list);
extern __ssize_t _IO_padn (_IO_FILE *, int, __ssize_t);
extern size_t _IO_sgetn (_IO_FILE *, void *, size_t);
extern __off64_t _IO_seekoff (_IO_FILE *, __off64_t, int, int);
extern __off64_t _IO_seekpos (_IO_FILE *, __off64_t, int);
extern void _IO_free_backup_area (_IO_FILE *) throw ();
}
typedef __gnuc_va_list va_list;
typedef __off_t off_t;
typedef __off64_t off64_t;
typedef __ssize_t ssize_t;

typedef _G_fpos_t fpos_t;

typedef _G_fpos64_t fpos64_t;
extern struct _IO_FILE *stdin;
extern struct _IO_FILE *stdout;
extern struct _IO_FILE *stderr;

extern int remove (__const char *__filename) throw ();
extern int rename (__const char *__old, __const char *__new) throw ();

extern int renameat (int __oldfd, __const char *__old, int __newfd,
       __const char *__new) throw ();

extern FILE *tmpfile (void) __attribute__ ((__warn_unused_result__));
extern FILE *tmpfile64 (void) __attribute__ ((__warn_unused_result__));
extern char *tmpnam (char *__s) throw () __attribute__ ((__warn_unused_result__));

extern char *tmpnam_r (char *__s) throw () __attribute__ ((__warn_unused_result__));
extern char *tempnam (__const char *__dir, __const char *__pfx)
     throw () __attribute__ ((__malloc__)) __attribute__ ((__warn_unused_result__));

extern int fclose (FILE *__stream);
extern int fflush (FILE *__stream);

extern int fflush_unlocked (FILE *__stream);
extern int fcloseall (void);

extern FILE *fopen (__const char *__restrict __filename,
      __const char *__restrict __modes) __attribute__ ((__warn_unused_result__));
extern FILE *freopen (__const char *__restrict __filename,
        __const char *__restrict __modes,
        FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));

extern FILE *fopen64 (__const char *__restrict __filename,
        __const char *__restrict __modes) __attribute__ ((__warn_unused_result__));
extern FILE *freopen64 (__const char *__restrict __filename,
   __const char *__restrict __modes,
   FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern FILE *fdopen (int __fd, __const char *__modes) throw () __attribute__ ((__warn_unused_result__));
extern FILE *fopencookie (void *__restrict __magic_cookie,
     __const char *__restrict __modes,
     _IO_cookie_io_functions_t __io_funcs) throw () __attribute__ ((__warn_unused_result__));
extern FILE *fmemopen (void *__s, size_t __len, __const char *__modes)
  throw () __attribute__ ((__warn_unused_result__));
extern FILE *open_memstream (char **__bufloc, size_t *__sizeloc) throw () __attribute__ ((__warn_unused_result__));

extern void setbuf (FILE *__restrict __stream, char *__restrict __buf) throw ();
extern int setvbuf (FILE *__restrict __stream, char *__restrict __buf,
      int __modes, size_t __n) throw ();

extern void setbuffer (FILE *__restrict __stream, char *__restrict __buf,
         size_t __size) throw ();
extern void setlinebuf (FILE *__stream) throw ();

extern int fprintf (FILE *__restrict __stream,
      __const char *__restrict __format, ...);
extern int printf (__const char *__restrict __format, ...);
extern int sprintf (char *__restrict __s,
      __const char *__restrict __format, ...) throw ();
extern int vfprintf (FILE *__restrict __s, __const char *__restrict __format,
       __gnuc_va_list __arg);
extern int vprintf (__const char *__restrict __format, __gnuc_va_list __arg);
extern int vsprintf (char *__restrict __s, __const char *__restrict __format,
       __gnuc_va_list __arg) throw ();


extern int snprintf (char *__restrict __s, size_t __maxlen,
       __const char *__restrict __format, ...)
     throw () __attribute__ ((__format__ (__printf__, 3, 4)));
extern int vsnprintf (char *__restrict __s, size_t __maxlen,
        __const char *__restrict __format, __gnuc_va_list __arg)
     throw () __attribute__ ((__format__ (__printf__, 3, 0)));

extern int vasprintf (char **__restrict __ptr, __const char *__restrict __f,
        __gnuc_va_list __arg)
     throw () __attribute__ ((__format__ (__printf__, 2, 0))) __attribute__ ((__warn_unused_result__));
extern int __asprintf (char **__restrict __ptr,
         __const char *__restrict __fmt, ...)
     throw () __attribute__ ((__format__ (__printf__, 2, 3))) __attribute__ ((__warn_unused_result__));
extern int asprintf (char **__restrict __ptr,
       __const char *__restrict __fmt, ...)
     throw () __attribute__ ((__format__ (__printf__, 2, 3))) __attribute__ ((__warn_unused_result__));
extern int vdprintf (int __fd, __const char *__restrict __fmt,
       __gnuc_va_list __arg)
     __attribute__ ((__format__ (__printf__, 2, 0)));
extern int dprintf (int __fd, __const char *__restrict __fmt, ...)
     __attribute__ ((__format__ (__printf__, 2, 3)));

extern int fscanf (FILE *__restrict __stream,
     __const char *__restrict __format, ...) __attribute__ ((__warn_unused_result__));
extern int scanf (__const char *__restrict __format, ...) __attribute__ ((__warn_unused_result__));
extern int sscanf (__const char *__restrict __s,
     __const char *__restrict __format, ...) throw ();


extern int vfscanf (FILE *__restrict __s, __const char *__restrict __format,
      __gnuc_va_list __arg)
     __attribute__ ((__format__ (__scanf__, 2, 0))) __attribute__ ((__warn_unused_result__));
extern int vscanf (__const char *__restrict __format, __gnuc_va_list __arg)
     __attribute__ ((__format__ (__scanf__, 1, 0))) __attribute__ ((__warn_unused_result__));
extern int vsscanf (__const char *__restrict __s,
      __const char *__restrict __format, __gnuc_va_list __arg)
     throw () __attribute__ ((__format__ (__scanf__, 2, 0)));


extern int fgetc (FILE *__stream);
extern int getc (FILE *__stream);
extern int getchar (void);

extern int getc_unlocked (FILE *__stream);
extern int getchar_unlocked (void);
extern int fgetc_unlocked (FILE *__stream);

extern int fputc (int __c, FILE *__stream);
extern int putc (int __c, FILE *__stream);
extern int putchar (int __c);

extern int fputc_unlocked (int __c, FILE *__stream);
extern int putc_unlocked (int __c, FILE *__stream);
extern int putchar_unlocked (int __c);
extern int getw (FILE *__stream);
extern int putw (int __w, FILE *__stream);

extern char *fgets (char *__restrict __s, int __n, FILE *__restrict __stream)
     __attribute__ ((__warn_unused_result__));
extern char *gets (char *__s) __attribute__ ((__warn_unused_result__));

extern char *fgets_unlocked (char *__restrict __s, int __n,
        FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern __ssize_t __getdelim (char **__restrict __lineptr,
          size_t *__restrict __n, int __delimiter,
          FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern __ssize_t getdelim (char **__restrict __lineptr,
        size_t *__restrict __n, int __delimiter,
        FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern __ssize_t getline (char **__restrict __lineptr,
       size_t *__restrict __n,
       FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));

extern int fputs (__const char *__restrict __s, FILE *__restrict __stream);
extern int puts (__const char *__s);
extern int ungetc (int __c, FILE *__stream);
extern size_t fread (void *__restrict __ptr, size_t __size,
       size_t __n, FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern size_t fwrite (__const void *__restrict __ptr, size_t __size,
        size_t __n, FILE *__restrict __s);

extern int fputs_unlocked (__const char *__restrict __s,
      FILE *__restrict __stream);
extern size_t fread_unlocked (void *__restrict __ptr, size_t __size,
         size_t __n, FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern size_t fwrite_unlocked (__const void *__restrict __ptr, size_t __size,
          size_t __n, FILE *__restrict __stream);

extern int fseek (FILE *__stream, long int __off, int __whence);
extern long int ftell (FILE *__stream) __attribute__ ((__warn_unused_result__));
extern void rewind (FILE *__stream);

extern int fseeko (FILE *__stream, __off_t __off, int __whence);
extern __off_t ftello (FILE *__stream) __attribute__ ((__warn_unused_result__));

extern int fgetpos (FILE *__restrict __stream, fpos_t *__restrict __pos);
extern int fsetpos (FILE *__stream, __const fpos_t *__pos);

extern int fseeko64 (FILE *__stream, __off64_t __off, int __whence);
extern __off64_t ftello64 (FILE *__stream) __attribute__ ((__warn_unused_result__));
extern int fgetpos64 (FILE *__restrict __stream, fpos64_t *__restrict __pos);
extern int fsetpos64 (FILE *__stream, __const fpos64_t *__pos);

extern void clearerr (FILE *__stream) throw ();
extern int feof (FILE *__stream) throw () __attribute__ ((__warn_unused_result__));
extern int ferror (FILE *__stream) throw () __attribute__ ((__warn_unused_result__));

extern void clearerr_unlocked (FILE *__stream) throw ();
extern int feof_unlocked (FILE *__stream) throw () __attribute__ ((__warn_unused_result__));
extern int ferror_unlocked (FILE *__stream) throw () __attribute__ ((__warn_unused_result__));

extern void perror (__const char *__s);

extern int sys_nerr;
extern __const char *__const sys_errlist[];
extern int _sys_nerr;
extern __const char *__const _sys_errlist[];
extern int fileno (FILE *__stream) throw () __attribute__ ((__warn_unused_result__));
extern int fileno_unlocked (FILE *__stream) throw () __attribute__ ((__warn_unused_result__));
extern FILE *popen (__const char *__command, __const char *__modes) __attribute__ ((__warn_unused_result__));
extern int pclose (FILE *__stream);
extern char *ctermid (char *__s) throw ();
extern char *cuserid (char *__s);
struct obstack;
extern int obstack_printf (struct obstack *__restrict __obstack,
      __const char *__restrict __format, ...)
     throw () __attribute__ ((__format__ (__printf__, 2, 3)));
extern int obstack_vprintf (struct obstack *__restrict __obstack,
       __const char *__restrict __format,
       __gnuc_va_list __args)
     throw () __attribute__ ((__format__ (__printf__, 2, 0)));
extern void flockfile (FILE *__stream) throw ();
extern int ftrylockfile (FILE *__stream) throw () __attribute__ ((__warn_unused_result__));
extern void funlockfile (FILE *__stream) throw ();
extern __inline __attribute__ ((__gnu_inline__)) int
getchar (void)
{
  return _IO_getc (stdin);
}
extern __inline __attribute__ ((__gnu_inline__)) int
fgetc_unlocked (FILE *__fp)
{
  return (__builtin_expect (((__fp)->_IO_read_ptr >= (__fp)->_IO_read_end), 0) ? __uflow (__fp) : *(unsigned char *) (__fp)->_IO_read_ptr++);
}
extern __inline __attribute__ ((__gnu_inline__)) int
getc_unlocked (FILE *__fp)
{
  return (__builtin_expect (((__fp)->_IO_read_ptr >= (__fp)->_IO_read_end), 0) ? __uflow (__fp) : *(unsigned char *) (__fp)->_IO_read_ptr++);
}
extern __inline __attribute__ ((__gnu_inline__)) int
getchar_unlocked (void)
{
  return (__builtin_expect (((stdin)->_IO_read_ptr >= (stdin)->_IO_read_end), 0) ? __uflow (stdin) : *(unsigned char *) (stdin)->_IO_read_ptr++);
}
extern __inline __attribute__ ((__gnu_inline__)) int
putchar (int __c)
{
  return _IO_putc (__c, stdout);
}
extern __inline __attribute__ ((__gnu_inline__)) int
fputc_unlocked (int __c, FILE *__stream)
{
  return (__builtin_expect (((__stream)->_IO_write_ptr >= (__stream)->_IO_write_end), 0) ? __overflow (__stream, (unsigned char) (__c)) : (unsigned char) (*(__stream)->_IO_write_ptr++ = (__c)));
}
extern __inline __attribute__ ((__gnu_inline__)) int
putc_unlocked (int __c, FILE *__stream)
{
  return (__builtin_expect (((__stream)->_IO_write_ptr >= (__stream)->_IO_write_end), 0) ? __overflow (__stream, (unsigned char) (__c)) : (unsigned char) (*(__stream)->_IO_write_ptr++ = (__c)));
}
extern __inline __attribute__ ((__gnu_inline__)) int
putchar_unlocked (int __c)
{
  return (__builtin_expect (((stdout)->_IO_write_ptr >= (stdout)->_IO_write_end), 0) ? __overflow (stdout, (unsigned char) (__c)) : (unsigned char) (*(stdout)->_IO_write_ptr++ = (__c)));
}
extern __inline __attribute__ ((__gnu_inline__)) __ssize_t
getline (char **__lineptr, size_t *__n, FILE *__stream)
{
  return __getdelim (__lineptr, __n, '\n', __stream);
}
extern __inline __attribute__ ((__gnu_inline__)) int
feof_unlocked (FILE *__stream) throw ()
{
  return (((__stream)->_flags & 0x10) != 0);
}
extern __inline __attribute__ ((__gnu_inline__)) int
ferror_unlocked (FILE *__stream) throw ()
{
  return (((__stream)->_flags & 0x20) != 0);
}
extern int __sprintf_chk (char *__restrict __s, int __flag, size_t __slen,
     __const char *__restrict __format, ...) throw ();
extern int __vsprintf_chk (char *__restrict __s, int __flag, size_t __slen,
      __const char *__restrict __format,
      __gnuc_va_list __ap) throw ();
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
sprintf (char *__restrict __s, __const char *__restrict __fmt, ...) throw ()
{
  return __builtin___sprintf_chk (__s, 2 - 1,
      __builtin_object_size (__s, 2 > 1), __fmt, __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
vsprintf (char *__restrict __s, __const char *__restrict __fmt, __gnuc_va_list __ap) throw ()
{
  return __builtin___vsprintf_chk (__s, 2 - 1,
       __builtin_object_size (__s, 2 > 1), __fmt, __ap);
}
extern int __snprintf_chk (char *__restrict __s, size_t __n, int __flag,
      size_t __slen, __const char *__restrict __format,
      ...) throw ();
extern int __vsnprintf_chk (char *__restrict __s, size_t __n, int __flag,
       size_t __slen, __const char *__restrict __format,
       __gnuc_va_list __ap) throw ();
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
snprintf (char *__restrict __s, size_t __n, __const char *__restrict __fmt, ...) throw ()
{
  return __builtin___snprintf_chk (__s, __n, 2 - 1,
       __builtin_object_size (__s, 2 > 1), __fmt, __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
vsnprintf (char *__restrict __s, size_t __n, __const char *__restrict __fmt, __gnuc_va_list __ap) throw ()
{
  return __builtin___vsnprintf_chk (__s, __n, 2 - 1,
        __builtin_object_size (__s, 2 > 1), __fmt, __ap);
}
extern int __fprintf_chk (FILE *__restrict __stream, int __flag,
     __const char *__restrict __format, ...);
extern int __printf_chk (int __flag, __const char *__restrict __format, ...);
extern int __vfprintf_chk (FILE *__restrict __stream, int __flag,
      __const char *__restrict __format, __gnuc_va_list __ap);
extern int __vprintf_chk (int __flag, __const char *__restrict __format,
     __gnuc_va_list __ap);
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
fprintf (FILE *__restrict __stream, __const char *__restrict __fmt, ...)
{
  return __fprintf_chk (__stream, 2 - 1, __fmt,
   __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
printf (__const char *__restrict __fmt, ...)
{
  return __printf_chk (2 - 1, __fmt, __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
vprintf (__const char *__restrict __fmt, __gnuc_va_list __ap)
{
  return __vfprintf_chk (stdout, 2 - 1, __fmt, __ap);
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
vfprintf (FILE *__restrict __stream,
   __const char *__restrict __fmt, __gnuc_va_list __ap)
{
  return __vfprintf_chk (__stream, 2 - 1, __fmt, __ap);
}
extern int __asprintf_chk (char **__restrict __ptr, int __flag,
      __const char *__restrict __fmt, ...)
     throw () __attribute__ ((__format__ (__printf__, 3, 4))) __attribute__ ((__warn_unused_result__));
extern int __vasprintf_chk (char **__restrict __ptr, int __flag,
       __const char *__restrict __fmt, __gnuc_va_list __arg)
     throw () __attribute__ ((__format__ (__printf__, 3, 0))) __attribute__ ((__warn_unused_result__));
extern int __dprintf_chk (int __fd, int __flag, __const char *__restrict __fmt,
     ...) __attribute__ ((__format__ (__printf__, 3, 4)));
extern int __vdprintf_chk (int __fd, int __flag,
      __const char *__restrict __fmt, __gnuc_va_list __arg)
     __attribute__ ((__format__ (__printf__, 3, 0)));
extern int __obstack_printf_chk (struct obstack *__restrict __obstack,
     int __flag, __const char *__restrict __format,
     ...)
     throw () __attribute__ ((__format__ (__printf__, 3, 4)));
extern int __obstack_vprintf_chk (struct obstack *__restrict __obstack,
      int __flag,
      __const char *__restrict __format,
      __gnuc_va_list __args)
     throw () __attribute__ ((__format__ (__printf__, 3, 0)));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
asprintf (char **__restrict __ptr, __const char *__restrict __fmt, ...) throw ()
{
  return __asprintf_chk (__ptr, 2 - 1, __fmt,
    __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
__asprintf (char **__restrict __ptr, __const char *__restrict __fmt, ...) throw ()
{
  return __asprintf_chk (__ptr, 2 - 1, __fmt,
    __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
dprintf (int __fd, __const char *__restrict __fmt, ...)
{
  return __dprintf_chk (__fd, 2 - 1, __fmt,
   __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
obstack_printf (struct obstack *__restrict __obstack, __const char *__restrict __fmt, ...) throw ()
{
  return __obstack_printf_chk (__obstack, 2 - 1, __fmt,
          __builtin_va_arg_pack ());
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
vasprintf (char **__restrict __ptr, __const char *__restrict __fmt, __gnuc_va_list __ap) throw ()
{
  return __vasprintf_chk (__ptr, 2 - 1, __fmt, __ap);
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
vdprintf (int __fd, __const char *__restrict __fmt, __gnuc_va_list __ap)
{
  return __vdprintf_chk (__fd, 2 - 1, __fmt, __ap);
}
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
obstack_vprintf (struct obstack *__restrict __obstack, __const char *__restrict __fmt, __gnuc_va_list __ap) throw ()
{
  return __obstack_vprintf_chk (__obstack, 2 - 1, __fmt,
    __ap);
}
extern char *__gets_chk (char *__str, size_t) __attribute__ ((__warn_unused_result__));
extern char *__gets_warn (char *__str) __asm__ ("" "gets")
     __attribute__ ((__warn_unused_result__)) __attribute__((__warning__ ("please use fgets or getline instead, gets can't " "specify buffer size")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) __attribute__ ((__warn_unused_result__)) char *
gets (char *__str)
{
  if (__builtin_object_size (__str, 2 > 1) != (size_t) -1)
    return __gets_chk (__str, __builtin_object_size (__str, 2 > 1));
  return __gets_warn (__str);
}
extern char *__fgets_chk (char *__restrict __s, size_t __size, int __n,
     FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern char *__fgets_alias (char *__restrict __s, int __n, FILE *__restrict __stream) __asm__ ("" "fgets") __attribute__ ((__warn_unused_result__));
extern char *__fgets_chk_warn (char *__restrict __s, size_t __size, int __n, FILE *__restrict __stream) __asm__ ("" "__fgets_chk")
     __attribute__ ((__warn_unused_result__)) __attribute__((__warning__ ("fgets called with bigger size than length " "of destination buffer")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) __attribute__ ((__warn_unused_result__)) char *
fgets (char *__restrict __s, int __n, FILE *__restrict __stream)
{
  if (__builtin_object_size (__s, 2 > 1) != (size_t) -1)
    {
      if (!__builtin_constant_p (__n) || __n <= 0)
 return __fgets_chk (__s, __builtin_object_size (__s, 2 > 1), __n, __stream);
      if ((size_t) __n > __builtin_object_size (__s, 2 > 1))
 return __fgets_chk_warn (__s, __builtin_object_size (__s, 2 > 1), __n, __stream);
    }
  return __fgets_alias (__s, __n, __stream);
}
extern size_t __fread_chk (void *__restrict __ptr, size_t __ptrlen,
      size_t __size, size_t __n,
      FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern size_t __fread_alias (void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) __asm__ ("" "fread") __attribute__ ((__warn_unused_result__));
extern size_t __fread_chk_warn (void *__restrict __ptr, size_t __ptrlen, size_t __size, size_t __n, FILE *__restrict __stream) __asm__ ("" "__fread_chk")
     __attribute__ ((__warn_unused_result__)) __attribute__((__warning__ ("fread called with bigger size * nmemb than length " "of destination buffer")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) __attribute__ ((__warn_unused_result__)) size_t
fread (void *__restrict __ptr, size_t __size, size_t __n,
       FILE *__restrict __stream)
{
  if (__builtin_object_size (__ptr, 0) != (size_t) -1)
    {
      if (!__builtin_constant_p (__size)
   || !__builtin_constant_p (__n)
   || (__size | __n) >= (((size_t) 1) << (8 * sizeof (size_t) / 2)))
 return __fread_chk (__ptr, __builtin_object_size (__ptr, 0), __size, __n, __stream);
      if (__size * __n > __builtin_object_size (__ptr, 0))
 return __fread_chk_warn (__ptr, __builtin_object_size (__ptr, 0), __size, __n, __stream);
    }
  return __fread_alias (__ptr, __size, __n, __stream);
}
extern char *__fgets_unlocked_chk (char *__restrict __s, size_t __size,
       int __n, FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern char *__fgets_unlocked_alias (char *__restrict __s, int __n, FILE *__restrict __stream) __asm__ ("" "fgets_unlocked") __attribute__ ((__warn_unused_result__));
extern char *__fgets_unlocked_chk_warn (char *__restrict __s, size_t __size, int __n, FILE *__restrict __stream) __asm__ ("" "__fgets_unlocked_chk")
     __attribute__ ((__warn_unused_result__)) __attribute__((__warning__ ("fgets_unlocked called with bigger size than length " "of destination buffer")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) __attribute__ ((__warn_unused_result__)) char *
fgets_unlocked (char *__restrict __s, int __n, FILE *__restrict __stream)
{
  if (__builtin_object_size (__s, 2 > 1) != (size_t) -1)
    {
      if (!__builtin_constant_p (__n) || __n <= 0)
 return __fgets_unlocked_chk (__s, __builtin_object_size (__s, 2 > 1), __n, __stream);
      if ((size_t) __n > __builtin_object_size (__s, 2 > 1))
 return __fgets_unlocked_chk_warn (__s, __builtin_object_size (__s, 2 > 1), __n, __stream);
    }
  return __fgets_unlocked_alias (__s, __n, __stream);
}
extern size_t __fread_unlocked_chk (void *__restrict __ptr, size_t __ptrlen,
        size_t __size, size_t __n,
        FILE *__restrict __stream) __attribute__ ((__warn_unused_result__));
extern size_t __fread_unlocked_alias (void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) __asm__ ("" "fread_unlocked") __attribute__ ((__warn_unused_result__));
extern size_t __fread_unlocked_chk_warn (void *__restrict __ptr, size_t __ptrlen, size_t __size, size_t __n, FILE *__restrict __stream) __asm__ ("" "__fread_unlocked_chk")
     __attribute__ ((__warn_unused_result__)) __attribute__((__warning__ ("fread_unlocked called with bigger size * nmemb than " "length of destination buffer")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) __attribute__ ((__warn_unused_result__)) size_t
fread_unlocked (void *__restrict __ptr, size_t __size, size_t __n,
  FILE *__restrict __stream)
{
  if (__builtin_object_size (__ptr, 0) != (size_t) -1)
    {
      if (!__builtin_constant_p (__size)
   || !__builtin_constant_p (__n)
   || (__size | __n) >= (((size_t) 1) << (8 * sizeof (size_t) / 2)))
 return __fread_unlocked_chk (__ptr, __builtin_object_size (__ptr, 0), __size, __n,
         __stream);
      if (__size * __n > __builtin_object_size (__ptr, 0))
 return __fread_unlocked_chk_warn (__ptr, __builtin_object_size (__ptr, 0), __size, __n,
       __stream);
    }
  if (__builtin_constant_p (__size)
      && __builtin_constant_p (__n)
      && (__size | __n) < (((size_t) 1) << (8 * sizeof (size_t) / 2))
      && __size * __n <= 8)
    {
      size_t __cnt = __size * __n;
      char *__cptr = (char *) __ptr;
      if (__cnt == 0)
 return 0;
      for (; __cnt > 0; --__cnt)
 {
   int __c = (__builtin_expect (((__stream)->_IO_read_ptr >= (__stream)->_IO_read_end), 0) ? __uflow (__stream) : *(unsigned char *) (__stream)->_IO_read_ptr++);
   if (__c == (-1))
     break;
   *__cptr++ = __c;
 }
      return (__cptr - (char *) __ptr) / __size;
    }
  return __fread_unlocked_alias (__ptr, __size, __n, __stream);
}
}
extern "C" {
union wait
  {
    int w_status;
    struct
      {
 unsigned int __w_termsig:7;
 unsigned int __w_coredump:1;
 unsigned int __w_retcode:8;
 unsigned int:16;
      } __wait_terminated;
    struct
      {
 unsigned int __w_stopval:8;
 unsigned int __w_stopsig:8;
 unsigned int:16;
      } __wait_stopped;
  };

typedef struct
  {
    int quot;
    int rem;
  } div_t;
typedef struct
  {
    long int quot;
    long int rem;
  } ldiv_t;


__extension__ typedef struct
  {
    long long int quot;
    long long int rem;
  } lldiv_t;

extern size_t __ctype_get_mb_cur_max (void) throw () __attribute__ ((__warn_unused_result__));

extern double atof (__const char *__nptr)
     throw () __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int atoi (__const char *__nptr)
     throw () __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern long int atol (__const char *__nptr)
     throw () __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));


__extension__ extern long long int atoll (__const char *__nptr)
     throw () __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));


extern double strtod (__const char *__restrict __nptr,
        char **__restrict __endptr)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));


extern float strtof (__const char *__restrict __nptr,
       char **__restrict __endptr) throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern long double strtold (__const char *__restrict __nptr,
       char **__restrict __endptr)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));


extern long int strtol (__const char *__restrict __nptr,
   char **__restrict __endptr, int __base)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern unsigned long int strtoul (__const char *__restrict __nptr,
      char **__restrict __endptr, int __base)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));

__extension__
extern long long int strtoq (__const char *__restrict __nptr,
        char **__restrict __endptr, int __base)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
__extension__
extern unsigned long long int strtouq (__const char *__restrict __nptr,
           char **__restrict __endptr, int __base)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));

__extension__
extern long long int strtoll (__const char *__restrict __nptr,
         char **__restrict __endptr, int __base)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
__extension__
extern unsigned long long int strtoull (__const char *__restrict __nptr,
     char **__restrict __endptr, int __base)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));

typedef struct __locale_struct
{
  struct __locale_data *__locales[13];
  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;
  const char *__names[13];
} *__locale_t;
typedef __locale_t locale_t;
extern long int strtol_l (__const char *__restrict __nptr,
     char **__restrict __endptr, int __base,
     __locale_t __loc) throw () __attribute__ ((__nonnull__ (1, 4))) __attribute__ ((__warn_unused_result__));
extern unsigned long int strtoul_l (__const char *__restrict __nptr,
        char **__restrict __endptr,
        int __base, __locale_t __loc)
     throw () __attribute__ ((__nonnull__ (1, 4))) __attribute__ ((__warn_unused_result__));
__extension__
extern long long int strtoll_l (__const char *__restrict __nptr,
    char **__restrict __endptr, int __base,
    __locale_t __loc)
     throw () __attribute__ ((__nonnull__ (1, 4))) __attribute__ ((__warn_unused_result__));
__extension__
extern unsigned long long int strtoull_l (__const char *__restrict __nptr,
       char **__restrict __endptr,
       int __base, __locale_t __loc)
     throw () __attribute__ ((__nonnull__ (1, 4))) __attribute__ ((__warn_unused_result__));
extern double strtod_l (__const char *__restrict __nptr,
   char **__restrict __endptr, __locale_t __loc)
     throw () __attribute__ ((__nonnull__ (1, 3))) __attribute__ ((__warn_unused_result__));
extern float strtof_l (__const char *__restrict __nptr,
         char **__restrict __endptr, __locale_t __loc)
     throw () __attribute__ ((__nonnull__ (1, 3))) __attribute__ ((__warn_unused_result__));
extern long double strtold_l (__const char *__restrict __nptr,
         char **__restrict __endptr,
         __locale_t __loc)
     throw () __attribute__ ((__nonnull__ (1, 3))) __attribute__ ((__warn_unused_result__));

extern __inline __attribute__ ((__gnu_inline__)) double
atof (__const char *__nptr) throw ()
{
  return strtod (__nptr, (char **) __null);
}
extern __inline __attribute__ ((__gnu_inline__)) int
atoi (__const char *__nptr) throw ()
{
  return (int) strtol (__nptr, (char **) __null, 10);
}
extern __inline __attribute__ ((__gnu_inline__)) long int
atol (__const char *__nptr) throw ()
{
  return strtol (__nptr, (char **) __null, 10);
}


__extension__ extern __inline __attribute__ ((__gnu_inline__)) long long int
atoll (__const char *__nptr) throw ()
{
  return strtoll (__nptr, (char **) __null, 10);
}

extern char *l64a (long int __n) throw () __attribute__ ((__warn_unused_result__));
extern long int a64l (__const char *__s)
     throw () __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern "C" {
typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;
typedef __quad_t quad_t;
typedef __u_quad_t u_quad_t;
typedef __fsid_t fsid_t;
typedef __loff_t loff_t;
typedef __ino_t ino_t;
typedef __ino64_t ino64_t;
typedef __dev_t dev_t;
typedef __gid_t gid_t;
typedef __mode_t mode_t;
typedef __nlink_t nlink_t;
typedef __uid_t uid_t;
typedef __pid_t pid_t;
typedef __id_t id_t;
typedef __daddr_t daddr_t;
typedef __caddr_t caddr_t;
typedef __key_t key_t;

typedef __clock_t clock_t;



typedef __time_t time_t;


typedef __clockid_t clockid_t;
typedef __timer_t timer_t;
typedef __useconds_t useconds_t;
typedef __suseconds_t suseconds_t;
typedef unsigned long int ulong;
typedef unsigned short int ushort;
typedef unsigned int uint;
typedef int int8_t __attribute__ ((__mode__ (__QI__)));
typedef int int16_t __attribute__ ((__mode__ (__HI__)));
typedef int int32_t __attribute__ ((__mode__ (__SI__)));
typedef int int64_t __attribute__ ((__mode__ (__DI__)));
typedef unsigned int u_int8_t __attribute__ ((__mode__ (__QI__)));
typedef unsigned int u_int16_t __attribute__ ((__mode__ (__HI__)));
typedef unsigned int u_int32_t __attribute__ ((__mode__ (__SI__)));
typedef unsigned int u_int64_t __attribute__ ((__mode__ (__DI__)));
typedef int register_t __attribute__ ((__mode__ (__word__)));
typedef int __sig_atomic_t;
typedef struct
  {
    unsigned long int __val[(1024 / (8 * sizeof (unsigned long int)))];
  } __sigset_t;
typedef __sigset_t sigset_t;
struct timespec
  {
    __time_t tv_sec;
    long int tv_nsec;
  };
struct timeval
  {
    __time_t tv_sec;
    __suseconds_t tv_usec;
  };
typedef long int __fd_mask;
typedef struct
  {
    __fd_mask fds_bits[1024 / (8 * (int) sizeof (__fd_mask))];
  } fd_set;
typedef __fd_mask fd_mask;
extern "C" {
extern int select (int __nfds, fd_set *__restrict __readfds,
     fd_set *__restrict __writefds,
     fd_set *__restrict __exceptfds,
     struct timeval *__restrict __timeout);
extern int pselect (int __nfds, fd_set *__restrict __readfds,
      fd_set *__restrict __writefds,
      fd_set *__restrict __exceptfds,
      const struct timespec *__restrict __timeout,
      const __sigset_t *__restrict __sigmask);
}
__extension__
extern unsigned int gnu_dev_major (unsigned long long int __dev)
     throw ();
__extension__
extern unsigned int gnu_dev_minor (unsigned long long int __dev)
     throw ();
__extension__
extern unsigned long long int gnu_dev_makedev (unsigned int __major,
            unsigned int __minor)
     throw ();
__extension__ extern __inline __attribute__ ((__gnu_inline__)) unsigned int
gnu_dev_major (unsigned long long int __dev) throw ()
{
  return ((__dev >> 8) & 0xfff) | ((unsigned int) (__dev >> 32) & ~0xfff);
}
__extension__ extern __inline __attribute__ ((__gnu_inline__)) unsigned int
gnu_dev_minor (unsigned long long int __dev) throw ()
{
  return (__dev & 0xff) | ((unsigned int) (__dev >> 12) & ~0xff);
}
__extension__ extern __inline __attribute__ ((__gnu_inline__)) unsigned long long int
gnu_dev_makedev (unsigned int __major, unsigned int __minor) throw ()
{
  return ((__minor & 0xff) | ((__major & 0xfff) << 8)
   | (((unsigned long long int) (__minor & ~0xff)) << 12)
   | (((unsigned long long int) (__major & ~0xfff)) << 32));
}
typedef __blksize_t blksize_t;
typedef __blkcnt_t blkcnt_t;
typedef __fsblkcnt_t fsblkcnt_t;
typedef __fsfilcnt_t fsfilcnt_t;
typedef __blkcnt64_t blkcnt64_t;
typedef __fsblkcnt64_t fsblkcnt64_t;
typedef __fsfilcnt64_t fsfilcnt64_t;
typedef unsigned long int pthread_t;
typedef union
{
  char __size[36];
  long int __align;
} pthread_attr_t;
typedef struct __pthread_internal_slist
{
  struct __pthread_internal_slist *__next;
} __pthread_slist_t;
typedef union
{
  struct __pthread_mutex_s
  {
    int __lock;
    unsigned int __count;
    int __owner;
    int __kind;
    unsigned int __nusers;
    __extension__ union
    {
      int __spins;
      __pthread_slist_t __list;
    };
  } __data;
  char __size[24];
  long int __align;
} pthread_mutex_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_mutexattr_t;
typedef union
{
  struct
  {
    int __lock;
    unsigned int __futex;
    __extension__ unsigned long long int __total_seq;
    __extension__ unsigned long long int __wakeup_seq;
    __extension__ unsigned long long int __woken_seq;
    void *__mutex;
    unsigned int __nwaiters;
    unsigned int __broadcast_seq;
  } __data;
  char __size[48];
  __extension__ long long int __align;
} pthread_cond_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_condattr_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;
typedef union
{
  struct
  {
    int __lock;
    unsigned int __nr_readers;
    unsigned int __readers_wakeup;
    unsigned int __writer_wakeup;
    unsigned int __nr_readers_queued;
    unsigned int __nr_writers_queued;
    unsigned char __flags;
    unsigned char __shared;
    unsigned char __pad1;
    unsigned char __pad2;
    int __writer;
  } __data;
  char __size[32];
  long int __align;
} pthread_rwlock_t;
typedef union
{
  char __size[8];
  long int __align;
} pthread_rwlockattr_t;
typedef volatile int pthread_spinlock_t;
typedef union
{
  char __size[20];
  long int __align;
} pthread_barrier_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_barrierattr_t;
}
extern long int random (void) throw ();
extern void srandom (unsigned int __seed) throw ();
extern char *initstate (unsigned int __seed, char *__statebuf,
   size_t __statelen) throw () __attribute__ ((__nonnull__ (2)));
extern char *setstate (char *__statebuf) throw () __attribute__ ((__nonnull__ (1)));
struct random_data
  {
    int32_t *fptr;
    int32_t *rptr;
    int32_t *state;
    int rand_type;
    int rand_deg;
    int rand_sep;
    int32_t *end_ptr;
  };
extern int random_r (struct random_data *__restrict __buf,
       int32_t *__restrict __result) throw () __attribute__ ((__nonnull__ (1, 2)));
extern int srandom_r (unsigned int __seed, struct random_data *__buf)
     throw () __attribute__ ((__nonnull__ (2)));
extern int initstate_r (unsigned int __seed, char *__restrict __statebuf,
   size_t __statelen,
   struct random_data *__restrict __buf)
     throw () __attribute__ ((__nonnull__ (2, 4)));
extern int setstate_r (char *__restrict __statebuf,
         struct random_data *__restrict __buf)
     throw () __attribute__ ((__nonnull__ (1, 2)));

extern int rand (void) throw ();
extern void srand (unsigned int __seed) throw ();

extern int rand_r (unsigned int *__seed) throw ();
extern double drand48 (void) throw ();
extern double erand48 (unsigned short int __xsubi[3]) throw () __attribute__ ((__nonnull__ (1)));
extern long int lrand48 (void) throw ();
extern long int nrand48 (unsigned short int __xsubi[3])
     throw () __attribute__ ((__nonnull__ (1)));
extern long int mrand48 (void) throw ();
extern long int jrand48 (unsigned short int __xsubi[3])
     throw () __attribute__ ((__nonnull__ (1)));
extern void srand48 (long int __seedval) throw ();
extern unsigned short int *seed48 (unsigned short int __seed16v[3])
     throw () __attribute__ ((__nonnull__ (1)));
extern void lcong48 (unsigned short int __param[7]) throw () __attribute__ ((__nonnull__ (1)));
struct drand48_data
  {
    unsigned short int __x[3];
    unsigned short int __old_x[3];
    unsigned short int __c;
    unsigned short int __init;
    unsigned long long int __a;
  };
extern int drand48_r (struct drand48_data *__restrict __buffer,
        double *__restrict __result) throw () __attribute__ ((__nonnull__ (1, 2)));
extern int erand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        double *__restrict __result) throw () __attribute__ ((__nonnull__ (1, 2)));
extern int lrand48_r (struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     throw () __attribute__ ((__nonnull__ (1, 2)));
extern int nrand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     throw () __attribute__ ((__nonnull__ (1, 2)));
extern int mrand48_r (struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     throw () __attribute__ ((__nonnull__ (1, 2)));
extern int jrand48_r (unsigned short int __xsubi[3],
        struct drand48_data *__restrict __buffer,
        long int *__restrict __result)
     throw () __attribute__ ((__nonnull__ (1, 2)));
extern int srand48_r (long int __seedval, struct drand48_data *__buffer)
     throw () __attribute__ ((__nonnull__ (2)));
extern int seed48_r (unsigned short int __seed16v[3],
       struct drand48_data *__buffer) throw () __attribute__ ((__nonnull__ (1, 2)));
extern int lcong48_r (unsigned short int __param[7],
        struct drand48_data *__buffer)
     throw () __attribute__ ((__nonnull__ (1, 2)));

extern void *malloc (size_t __size) throw () __attribute__ ((__malloc__)) __attribute__ ((__warn_unused_result__));
extern void *calloc (size_t __nmemb, size_t __size)
     throw () __attribute__ ((__malloc__)) __attribute__ ((__warn_unused_result__));


extern void *realloc (void *__ptr, size_t __size)
     throw () __attribute__ ((__warn_unused_result__));
extern void free (void *__ptr) throw ();

extern void cfree (void *__ptr) throw ();
extern "C" {
extern void *alloca (size_t __size) throw ();
}
extern void *valloc (size_t __size) throw () __attribute__ ((__malloc__)) __attribute__ ((__warn_unused_result__));
extern int posix_memalign (void **__memptr, size_t __alignment, size_t __size)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));

extern void abort (void) throw () __attribute__ ((__noreturn__));
extern int atexit (void (*__func) (void)) throw () __attribute__ ((__nonnull__ (1)));
extern "C++" int at_quick_exit (void (*__func) (void))
     throw () __asm ("at_quick_exit") __attribute__ ((__nonnull__ (1)));

extern int on_exit (void (*__func) (int __status, void *__arg), void *__arg)
     throw () __attribute__ ((__nonnull__ (1)));

extern void exit (int __status) throw () __attribute__ ((__noreturn__));
extern void quick_exit (int __status) throw () __attribute__ ((__noreturn__));


extern void _Exit (int __status) throw () __attribute__ ((__noreturn__));


extern char *getenv (__const char *__name) throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));

extern char *__secure_getenv (__const char *__name)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int putenv (char *__string) throw () __attribute__ ((__nonnull__ (1)));
extern int setenv (__const char *__name, __const char *__value, int __replace)
     throw () __attribute__ ((__nonnull__ (2)));
extern int unsetenv (__const char *__name) throw () __attribute__ ((__nonnull__ (1)));
extern int clearenv (void) throw ();
extern char *mktemp (char *__template) throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkstemp (char *__template) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkstemp64 (char *__template) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkstemps (char *__template, int __suffixlen) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkstemps64 (char *__template, int __suffixlen)
     __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern char *mkdtemp (char *__template) throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkostemp (char *__template, int __flags) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkostemp64 (char *__template, int __flags) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkostemps (char *__template, int __suffixlen, int __flags)
     __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int mkostemps64 (char *__template, int __suffixlen, int __flags)
     __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));

extern int system (__const char *__command) __attribute__ ((__warn_unused_result__));

extern char *canonicalize_file_name (__const char *__name)
     throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern char *realpath (__const char *__restrict __name,
         char *__restrict __resolved) throw () __attribute__ ((__warn_unused_result__));
typedef int (*__compar_fn_t) (__const void *, __const void *);
typedef __compar_fn_t comparison_fn_t;
typedef int (*__compar_d_fn_t) (__const void *, __const void *, void *);

extern void *bsearch (__const void *__key, __const void *__base,
        size_t __nmemb, size_t __size, __compar_fn_t __compar)
     __attribute__ ((__nonnull__ (1, 2, 5))) __attribute__ ((__warn_unused_result__));
extern void qsort (void *__base, size_t __nmemb, size_t __size,
     __compar_fn_t __compar) __attribute__ ((__nonnull__ (1, 4)));
extern void qsort_r (void *__base, size_t __nmemb, size_t __size,
       __compar_d_fn_t __compar, void *__arg)
  __attribute__ ((__nonnull__ (1, 4)));
extern int abs (int __x) throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));
extern long int labs (long int __x) throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));

__extension__ extern long long int llabs (long long int __x)
     throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));

extern div_t div (int __numer, int __denom)
     throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));
extern ldiv_t ldiv (long int __numer, long int __denom)
     throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));


__extension__ extern lldiv_t lldiv (long long int __numer,
        long long int __denom)
     throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));

extern char *ecvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign) throw () __attribute__ ((__nonnull__ (3, 4))) __attribute__ ((__warn_unused_result__));
extern char *fcvt (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign) throw () __attribute__ ((__nonnull__ (3, 4))) __attribute__ ((__warn_unused_result__));
extern char *gcvt (double __value, int __ndigit, char *__buf)
     throw () __attribute__ ((__nonnull__ (3))) __attribute__ ((__warn_unused_result__));
extern char *qecvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
     throw () __attribute__ ((__nonnull__ (3, 4))) __attribute__ ((__warn_unused_result__));
extern char *qfcvt (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign)
     throw () __attribute__ ((__nonnull__ (3, 4))) __attribute__ ((__warn_unused_result__));
extern char *qgcvt (long double __value, int __ndigit, char *__buf)
     throw () __attribute__ ((__nonnull__ (3))) __attribute__ ((__warn_unused_result__));
extern int ecvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len) throw () __attribute__ ((__nonnull__ (3, 4, 5)));
extern int fcvt_r (double __value, int __ndigit, int *__restrict __decpt,
     int *__restrict __sign, char *__restrict __buf,
     size_t __len) throw () __attribute__ ((__nonnull__ (3, 4, 5)));
extern int qecvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
     throw () __attribute__ ((__nonnull__ (3, 4, 5)));
extern int qfcvt_r (long double __value, int __ndigit,
      int *__restrict __decpt, int *__restrict __sign,
      char *__restrict __buf, size_t __len)
     throw () __attribute__ ((__nonnull__ (3, 4, 5)));

extern int mblen (__const char *__s, size_t __n) throw () __attribute__ ((__warn_unused_result__));
extern int mbtowc (wchar_t *__restrict __pwc,
     __const char *__restrict __s, size_t __n) throw () __attribute__ ((__warn_unused_result__));
extern int wctomb (char *__s, wchar_t __wchar) throw () __attribute__ ((__warn_unused_result__));
extern size_t mbstowcs (wchar_t *__restrict __pwcs,
   __const char *__restrict __s, size_t __n) throw ();
extern size_t wcstombs (char *__restrict __s,
   __const wchar_t *__restrict __pwcs, size_t __n)
     throw ();

extern int rpmatch (__const char *__response) throw () __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));
extern int getsubopt (char **__restrict __optionp,
        char *__const *__restrict __tokens,
        char **__restrict __valuep)
     throw () __attribute__ ((__nonnull__ (1, 2, 3))) __attribute__ ((__warn_unused_result__));
extern void setkey (__const char *__key) throw () __attribute__ ((__nonnull__ (1)));
extern int posix_openpt (int __oflag) __attribute__ ((__warn_unused_result__));
extern int grantpt (int __fd) throw ();
extern int unlockpt (int __fd) throw ();
extern char *ptsname (int __fd) throw () __attribute__ ((__warn_unused_result__));
extern int ptsname_r (int __fd, char *__buf, size_t __buflen)
     throw () __attribute__ ((__nonnull__ (2)));
extern int getpt (void);
extern int getloadavg (double __loadavg[], int __nelem)
     throw () __attribute__ ((__nonnull__ (1)));
extern char *__realpath_chk (__const char *__restrict __name,
        char *__restrict __resolved,
        size_t __resolvedlen) throw () __attribute__ ((__warn_unused_result__));
extern char *__realpath_alias (__const char *__restrict __name, char *__restrict __resolved) throw () __asm__ ("" "realpath") __attribute__ ((__warn_unused_result__));
extern char *__realpath_chk_warn (__const char *__restrict __name, char *__restrict __resolved, size_t __resolvedlen) throw () __asm__ ("" "__realpath_chk") __attribute__ ((__warn_unused_result__))
     __attribute__((__warning__ ("second argument of realpath must be either NULL or at " "least PATH_MAX bytes long buffer")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) __attribute__ ((__warn_unused_result__)) char *
realpath (__const char *__restrict __name, char *__restrict __resolved) throw ()
{
  if (__builtin_object_size (__resolved, 2 > 1) != (size_t) -1)
    {
      return __realpath_chk (__name, __resolved, __builtin_object_size (__resolved, 2 > 1));
    }
  return __realpath_alias (__name, __resolved);
}
extern int __ptsname_r_chk (int __fd, char *__buf, size_t __buflen,
       size_t __nreal) throw () __attribute__ ((__nonnull__ (2)));
extern int __ptsname_r_alias (int __fd, char *__buf, size_t __buflen) throw () __asm__ ("" "ptsname_r")
     __attribute__ ((__nonnull__ (2)));
extern int __ptsname_r_chk_warn (int __fd, char *__buf, size_t __buflen, size_t __nreal) throw () __asm__ ("" "__ptsname_r_chk")
     __attribute__ ((__nonnull__ (2))) __attribute__((__warning__ ("ptsname_r called with buflen bigger than " "size of buf")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) int
ptsname_r (int __fd, char *__buf, size_t __buflen) throw ()
{
  if (__builtin_object_size (__buf, 2 > 1) != (size_t) -1)
    {
      if (!__builtin_constant_p (__buflen))
 return __ptsname_r_chk (__fd, __buf, __buflen, __builtin_object_size (__buf, 2 > 1));
      if (__buflen > __builtin_object_size (__buf, 2 > 1))
 return __ptsname_r_chk_warn (__fd, __buf, __buflen, __builtin_object_size (__buf, 2 > 1));
    }
  return __ptsname_r_alias (__fd, __buf, __buflen);
}
extern int __wctomb_chk (char *__s, wchar_t __wchar, size_t __buflen)
  throw () __attribute__ ((__warn_unused_result__));
extern int __wctomb_alias (char *__s, wchar_t __wchar) throw () __asm__ ("" "wctomb") __attribute__ ((__warn_unused_result__));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) __attribute__ ((__warn_unused_result__)) int
wctomb (char *__s, wchar_t __wchar) throw ()
{
  if (__builtin_object_size (__s, 2 > 1) != (size_t) -1 && 16 > __builtin_object_size (__s, 2 > 1))
    return __wctomb_chk (__s, __wchar, __builtin_object_size (__s, 2 > 1));
  return __wctomb_alias (__s, __wchar);
}
extern size_t __mbstowcs_chk (wchar_t *__restrict __dst,
         __const char *__restrict __src,
         size_t __len, size_t __dstlen) throw ();
extern size_t __mbstowcs_alias (wchar_t *__restrict __dst, __const char *__restrict __src, size_t __len) throw () __asm__ ("" "mbstowcs");
extern size_t __mbstowcs_chk_warn (wchar_t *__restrict __dst, __const char *__restrict __src, size_t __len, size_t __dstlen) throw () __asm__ ("" "__mbstowcs_chk")
     __attribute__((__warning__ ("mbstowcs called with dst buffer smaller than len " "* sizeof (wchar_t)")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) size_t
mbstowcs (wchar_t *__restrict __dst, __const char *__restrict __src, size_t __len) throw ()
{
  if (__builtin_object_size (__dst, 2 > 1) != (size_t) -1)
    {
      if (!__builtin_constant_p (__len))
 return __mbstowcs_chk (__dst, __src, __len,
          __builtin_object_size (__dst, 2 > 1) / sizeof (wchar_t));
      if (__len > __builtin_object_size (__dst, 2 > 1) / sizeof (wchar_t))
 return __mbstowcs_chk_warn (__dst, __src, __len,
         __builtin_object_size (__dst, 2 > 1) / sizeof (wchar_t));
    }
  return __mbstowcs_alias (__dst, __src, __len);
}
extern size_t __wcstombs_chk (char *__restrict __dst,
         __const wchar_t *__restrict __src,
         size_t __len, size_t __dstlen) throw ();
extern size_t __wcstombs_alias (char *__restrict __dst, __const wchar_t *__restrict __src, size_t __len) throw () __asm__ ("" "wcstombs");
extern size_t __wcstombs_chk_warn (char *__restrict __dst, __const wchar_t *__restrict __src, size_t __len, size_t __dstlen) throw () __asm__ ("" "__wcstombs_chk")
     __attribute__((__warning__ ("wcstombs called with dst buffer smaller than len")));
extern __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__, __artificial__)) size_t
wcstombs (char *__restrict __dst, __const wchar_t *__restrict __src, size_t __len) throw ()
{
  if (__builtin_object_size (__dst, 2 > 1) != (size_t) -1)
    {
      if (!__builtin_constant_p (__len))
 return __wcstombs_chk (__dst, __src, __len, __builtin_object_size (__dst, 2 > 1));
      if (__len > __builtin_object_size (__dst, 2 > 1))
 return __wcstombs_chk_warn (__dst, __src, __len, __builtin_object_size (__dst, 2 > 1));
    }
  return __wcstombs_alias (__dst, __src, __len);
}
}
extern "C" {
typedef struct stack_st
 {
 int num;
 char **data;
 int sorted;
 int num_alloc;
 int (*comp)(const char * const *, const char * const *);
 } STACK;
int sk_num(const STACK *);
char *sk_value(const STACK *, int);
char *sk_set(STACK *, int, char *);
STACK *sk_new(int (*cmp)(const char * const *, const char * const *));
STACK *sk_new_null(void);
void sk_free(STACK *);
void sk_pop_free(STACK *st, void (*func)(void *));
int sk_insert(STACK *sk,char *data,int where);
char *sk_delete(STACK *st,int loc);
char *sk_delete_ptr(STACK *st, char *p);
int sk_find(STACK *st,char *data);
int sk_find_ex(STACK *st,char *data);
int sk_push(STACK *st,char *data);
int sk_unshift(STACK *st,char *data);
char *sk_shift(STACK *st);
char *sk_pop(STACK *st);
void sk_zero(STACK *st);
int (*sk_set_cmp_func(STACK *sk, int (*c)(const char * const *,
   const char * const *)))
   (const char * const *, const char * const *);
STACK *sk_dup(STACK *st);
void sk_sort(STACK *st);
int sk_is_sorted(const STACK *st);
}
extern "C" {
typedef struct openssl_item_st
 {
 int code;
 void *value;
 size_t value_size;
 size_t *value_length;
 } OPENSSL_ITEM;
typedef struct
 {
 int references;
 struct CRYPTO_dynlock_value *data;
 } CRYPTO_dynlock;
typedef struct bio_st BIO_dummy;
struct crypto_ex_data_st
 {
 STACK *sk;
 int dummy;
 };
typedef struct crypto_ex_data_func_st
 {
 long argl;
 void *argp;
 CRYPTO_EX_new *new_func;
 CRYPTO_EX_free *free_func;
 CRYPTO_EX_dup *dup_func;
 } CRYPTO_EX_DATA_FUNCS;

void CRYPTO_malloc_debug_init(void);
int CRYPTO_mem_ctrl(int mode);
int CRYPTO_is_mem_check_on(void);
const char *SSLeay_version(int type);
unsigned long SSLeay(void);
int OPENSSL_issetugid(void);
typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;
const CRYPTO_EX_DATA_IMPL *CRYPTO_get_ex_data_implementation(void);
int CRYPTO_set_ex_data_implementation(const CRYPTO_EX_DATA_IMPL *i);
int CRYPTO_ex_data_new_class(void);
int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
  CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
  CRYPTO_EX_free *free_func);
int CRYPTO_new_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_dup_ex_data(int class_index, CRYPTO_EX_DATA *to,
  CRYPTO_EX_DATA *from);
void CRYPTO_free_ex_data(int class_index, void *obj, CRYPTO_EX_DATA *ad);
int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int idx, void *val);
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad,int idx);
void CRYPTO_cleanup_all_ex_data(void);
int CRYPTO_get_new_lockid(char *name);
int CRYPTO_num_locks(void);
void CRYPTO_lock(int mode, int type,const char *file,int line);
void CRYPTO_set_locking_callback(void (*func)(int mode,int type,
           const char *file,int line));
void (*CRYPTO_get_locking_callback(void))(int mode,int type,const char *file,
  int line);
void CRYPTO_set_add_lock_callback(int (*func)(int *num,int mount,int type,
           const char *file, int line));
int (*CRYPTO_get_add_lock_callback(void))(int *num,int mount,int type,
       const char *file,int line);
void CRYPTO_set_id_callback(unsigned long (*func)(void));
unsigned long (*CRYPTO_get_id_callback(void))(void);
unsigned long CRYPTO_thread_id(void);
const char *CRYPTO_get_lock_name(int type);
int CRYPTO_add_lock(int *pointer,int amount,int type, const char *file,
      int line);
void int_CRYPTO_set_do_dynlock_callback(
 void (*do_dynlock_cb)(int mode, int type, const char *file, int line));
int CRYPTO_get_new_dynlockid(void);
void CRYPTO_destroy_dynlockid(int i);
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(*dyn_create_function)(const char *file, int line));
void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line));
void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)(struct CRYPTO_dynlock_value *l, const char *file, int line));
struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))(const char *file,int line);
void (*CRYPTO_get_dynlock_lock_callback(void))(int mode, struct CRYPTO_dynlock_value *l, const char *file,int line);
void (*CRYPTO_get_dynlock_destroy_callback(void))(struct CRYPTO_dynlock_value *l, const char *file,int line);
int CRYPTO_set_mem_functions(void *(*m)(size_t),void *(*r)(void *,size_t), void (*f)(void *));
int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*free_func)(void *));
int CRYPTO_set_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                void *(*r)(void *,size_t,const char *,int),
                                void (*f)(void *));
int CRYPTO_set_locked_mem_ex_functions(void *(*m)(size_t,const char *,int),
                                       void (*free_func)(void *));
int CRYPTO_set_mem_debug_functions(void (*m)(void *,int,const char *,int,int),
       void (*r)(void *,void *,int,const char *,int,int),
       void (*f)(void *,int),
       void (*so)(long),
       long (*go)(void));
void CRYPTO_set_mem_info_functions(
 int (*push_info_fn)(const char *info, const char *file, int line),
 int (*pop_info_fn)(void),
 int (*remove_all_info_fn)(void));
void CRYPTO_get_mem_functions(void *(**m)(size_t),void *(**r)(void *, size_t), void (**f)(void *));
void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *));
void CRYPTO_get_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                 void *(**r)(void *, size_t,const char *,int),
                                 void (**f)(void *));
void CRYPTO_get_locked_mem_ex_functions(void *(**m)(size_t,const char *,int),
                                        void (**f)(void *));
void CRYPTO_get_mem_debug_functions(void (**m)(void *,int,const char *,int,int),
        void (**r)(void *,void *,int,const char *,int,int),
        void (**f)(void *,int),
        void (**so)(long),
        long (**go)(void));
void *CRYPTO_malloc_locked(int num, const char *file, int line);
void CRYPTO_free_locked(void *);
void *CRYPTO_malloc(int num, const char *file, int line);
char *CRYPTO_strdup(const char *str, const char *file, int line);
void CRYPTO_free(void *);
void *CRYPTO_realloc(void *addr,int num, const char *file, int line);
void *CRYPTO_realloc_clean(void *addr,int old_num,int num,const char *file,
      int line);
void *CRYPTO_remalloc(void *addr,int num, const char *file, int line);
void OPENSSL_cleanse(void *ptr, size_t len);
void CRYPTO_set_mem_debug_options(long bits);
long CRYPTO_get_mem_debug_options(void);
int CRYPTO_push_info_(const char *info, const char *file, int line);
int CRYPTO_pop_info(void);
int CRYPTO_remove_all_info(void);
void CRYPTO_dbg_malloc(void *addr,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_realloc(void *addr1,void *addr2,int num,const char *file,int line,int before_p);
void CRYPTO_dbg_free(void *addr,int before_p);
void CRYPTO_dbg_set_options(long bits);
long CRYPTO_dbg_get_options(void);
int CRYPTO_dbg_push_info(const char *info, const char *file, int line);
int CRYPTO_dbg_pop_info(void);
int CRYPTO_dbg_remove_all_info(void);
void CRYPTO_mem_leaks_fp(FILE *);
void CRYPTO_mem_leaks(struct bio_st *bio);
typedef void *CRYPTO_MEM_LEAK_CB(unsigned long, const char *, int, int, void *);
void CRYPTO_mem_leaks_cb(CRYPTO_MEM_LEAK_CB *cb);
void OpenSSLDie(const char *file,int line,const char *assertion);
unsigned long *OPENSSL_ia32cap_loc(void);
int OPENSSL_isservice(void);
void ERR_load_CRYPTO_strings(void);
void OPENSSL_init(void);
}
extern "C" {
typedef struct bio_st BIO;
void BIO_set_flags(BIO *b, int flags);
int BIO_test_flags(const BIO *b, int flags);
void BIO_clear_flags(BIO *b, int flags);
long (*BIO_get_callback(const BIO *b)) (struct bio_st *,int,const char *,int, long,long);
void BIO_set_callback(BIO *b,
 long (*callback)(struct bio_st *,int,const char *,int, long,long));
char *BIO_get_callback_arg(const BIO *b);
void BIO_set_callback_arg(BIO *b, char *arg);
const char * BIO_method_name(const BIO *b);
int BIO_method_type(const BIO *b);
typedef void bio_info_cb(struct bio_st *, int, const char *, int, long, long);
typedef struct bio_method_st
 {
 int type;
 const char *name;
 int (*bwrite)(BIO *, const char *, int);
 int (*bread)(BIO *, char *, int);
 int (*bputs)(BIO *, const char *);
 int (*bgets)(BIO *, char *, int);
 long (*ctrl)(BIO *, int, long, void *);
 int (*create)(BIO *);
 int (*destroy)(BIO *);
        long (*callback_ctrl)(BIO *, int, bio_info_cb *);
 } BIO_METHOD;
struct bio_st
 {
 BIO_METHOD *method;
 long (*callback)(struct bio_st *,int,const char *,int, long,long);
 char *cb_arg;
 int init;
 int shutdown;
 int flags;
 int retry_reason;
 int num;
 void *ptr;
 struct bio_st *next_bio;
 struct bio_st *prev_bio;
 int references;
 unsigned long num_read;
 unsigned long num_write;
 CRYPTO_EX_DATA ex_data;
 };

typedef struct bio_f_buffer_ctx_struct
 {
 int ibuf_size;
 int obuf_size;
 char *ibuf;
 int ibuf_len;
 int ibuf_off;
 char *obuf;
 int obuf_len;
 int obuf_off;
 } BIO_F_BUFFER_CTX;
size_t BIO_ctrl_pending(BIO *b);
size_t BIO_ctrl_wpending(BIO *b);
size_t BIO_ctrl_get_write_guarantee(BIO *b);
size_t BIO_ctrl_get_read_request(BIO *b);
int BIO_ctrl_reset_read_request(BIO *b);
int BIO_set_ex_data(BIO *bio,int idx,void *data);
void *BIO_get_ex_data(BIO *bio,int idx);
int BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
unsigned long BIO_number_read(BIO *bio);
unsigned long BIO_number_written(BIO *bio);
BIO_METHOD *BIO_s_file(void );
BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new_fp(FILE *stream, int close_flag);
BIO * BIO_new(BIO_METHOD *type);
int BIO_set(BIO *a,BIO_METHOD *type);
int BIO_free(BIO *a);
void BIO_vfree(BIO *a);
int BIO_read(BIO *b, void *data, int len);
int BIO_gets(BIO *bp,char *buf, int size);
int BIO_write(BIO *b, const void *data, int len);
int BIO_puts(BIO *bp,const char *buf);
int BIO_indent(BIO *b,int indent,int max);
long BIO_ctrl(BIO *bp,int cmd,long larg,void *parg);
long BIO_callback_ctrl(BIO *b, int cmd, void (*fp)(struct bio_st *, int, const char *, int, long, long));
char * BIO_ptr_ctrl(BIO *bp,int cmd,long larg);
long BIO_int_ctrl(BIO *bp,int cmd,long larg,int iarg);
BIO * BIO_push(BIO *b,BIO *append);
BIO * BIO_pop(BIO *b);
void BIO_free_all(BIO *a);
BIO * BIO_find_type(BIO *b,int bio_type);
BIO * BIO_next(BIO *b);
BIO * BIO_get_retry_BIO(BIO *bio, int *reason);
int BIO_get_retry_reason(BIO *bio);
BIO * BIO_dup_chain(BIO *in);
int BIO_nread0(BIO *bio, char **buf);
int BIO_nread(BIO *bio, char **buf, int num);
int BIO_nwrite0(BIO *bio, char **buf);
int BIO_nwrite(BIO *bio, char **buf, int num);
long BIO_debug_callback(BIO *bio,int cmd,const char *argp,int argi,
 long argl,long ret);
BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new_mem_buf(void *buf, int len);
BIO_METHOD *BIO_s_socket(void);
BIO_METHOD *BIO_s_connect(void);
BIO_METHOD *BIO_s_accept(void);
BIO_METHOD *BIO_s_fd(void);
BIO_METHOD *BIO_s_log(void);
BIO_METHOD *BIO_s_bio(void);
BIO_METHOD *BIO_s_null(void);
BIO_METHOD *BIO_f_null(void);
BIO_METHOD *BIO_f_buffer(void);
BIO_METHOD *BIO_f_nbio_test(void);
BIO_METHOD *BIO_s_datagram(void);
int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);
int BIO_dgram_non_fatal_error(int error);
int BIO_fd_should_retry(int i);
int BIO_fd_non_fatal_error(int error);
int BIO_dump_cb(int (*cb)(const void *data, size_t len, void *u),
  void *u, const char *s, int len);
int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
         void *u, const char *s, int len, int indent);
int BIO_dump(BIO *b,const char *bytes,int len);
int BIO_dump_indent(BIO *b,const char *bytes,int len,int indent);
int BIO_dump_fp(FILE *fp, const char *s, int len);
int BIO_dump_indent_fp(FILE *fp, const char *s, int len, int indent);
struct hostent *BIO_gethostbyname(const char *name);
int BIO_sock_error(int sock);
int BIO_socket_ioctl(int fd, long type, void *arg);
int BIO_socket_nbio(int fd,int mode);
int BIO_get_port(const char *str, unsigned short *port_ptr);
int BIO_get_host_ip(const char *str, unsigned char *ip);
int BIO_get_accept_socket(char *host_port,int mode);
int BIO_accept(int sock,char **ip_port);
int BIO_sock_init(void );
void BIO_sock_cleanup(void);
int BIO_set_tcp_ndelay(int sock,int turn_on);
BIO *BIO_new_socket(int sock, int close_flag);
BIO *BIO_new_dgram(int fd, int close_flag);
BIO *BIO_new_fd(int fd, int close_flag);
BIO *BIO_new_connect(char *host_port);
BIO *BIO_new_accept(char *host_port);
int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
 BIO **bio2, size_t writebuf2);
void BIO_copy_next_retry(BIO *b);
int BIO_printf(BIO *bio, const char *format, ...)
 __attribute__((__format__(__printf__,2,3)));
int BIO_vprintf(BIO *bio, const char *format, va_list args)
 __attribute__((__format__(__printf__,2,0)));
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
 __attribute__((__format__(__printf__,3,4)));
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
 __attribute__((__format__(__printf__,3,0)));
void ERR_load_BIO_strings(void);
}
extern "C" {

struct tm
{
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
  long int tm_gmtoff;
  __const char *tm_zone;
};


struct itimerspec
  {
    struct timespec it_interval;
    struct timespec it_value;
  };
struct sigevent;

extern clock_t clock (void) throw ();
extern time_t time (time_t *__timer) throw ();
extern double difftime (time_t __time1, time_t __time0)
     throw () __attribute__ ((__const__));
extern time_t mktime (struct tm *__tp) throw ();
extern size_t strftime (char *__restrict __s, size_t __maxsize,
   __const char *__restrict __format,
   __const struct tm *__restrict __tp) throw ();

extern char *strptime (__const char *__restrict __s,
         __const char *__restrict __fmt, struct tm *__tp)
     throw ();
extern size_t strftime_l (char *__restrict __s, size_t __maxsize,
     __const char *__restrict __format,
     __const struct tm *__restrict __tp,
     __locale_t __loc) throw ();
extern char *strptime_l (__const char *__restrict __s,
    __const char *__restrict __fmt, struct tm *__tp,
    __locale_t __loc) throw ();

extern struct tm *gmtime (__const time_t *__timer) throw ();
extern struct tm *localtime (__const time_t *__timer) throw ();

extern struct tm *gmtime_r (__const time_t *__restrict __timer,
       struct tm *__restrict __tp) throw ();
extern struct tm *localtime_r (__const time_t *__restrict __timer,
          struct tm *__restrict __tp) throw ();

extern char *asctime (__const struct tm *__tp) throw ();
extern char *ctime (__const time_t *__timer) throw ();

extern char *asctime_r (__const struct tm *__restrict __tp,
   char *__restrict __buf) throw ();
extern char *ctime_r (__const time_t *__restrict __timer,
        char *__restrict __buf) throw ();
extern char *__tzname[2];
extern int __daylight;
extern long int __timezone;
extern char *tzname[2];
extern void tzset (void) throw ();
extern int daylight;
extern long int timezone;
extern int stime (__const time_t *__when) throw ();
extern time_t timegm (struct tm *__tp) throw ();
extern time_t timelocal (struct tm *__tp) throw ();
extern int dysize (int __year) throw () __attribute__ ((__const__));
extern int nanosleep (__const struct timespec *__requested_time,
        struct timespec *__remaining);
extern int clock_getres (clockid_t __clock_id, struct timespec *__res) throw ();
extern int clock_gettime (clockid_t __clock_id, struct timespec *__tp) throw ();
extern int clock_settime (clockid_t __clock_id, __const struct timespec *__tp)
     throw ();
extern int clock_nanosleep (clockid_t __clock_id, int __flags,
       __const struct timespec *__req,
       struct timespec *__rem);
extern int clock_getcpuclockid (pid_t __pid, clockid_t *__clock_id) throw ();
extern int timer_create (clockid_t __clock_id,
    struct sigevent *__restrict __evp,
    timer_t *__restrict __timerid) throw ();
extern int timer_delete (timer_t __timerid) throw ();
extern int timer_settime (timer_t __timerid, int __flags,
     __const struct itimerspec *__restrict __value,
     struct itimerspec *__restrict __ovalue) throw ();
extern int timer_gettime (timer_t __timerid, struct itimerspec *__value)
     throw ();
extern int timer_getoverrun (timer_t __timerid) throw ();
extern int getdate_err;
extern struct tm *getdate (__const char *__string);
extern int getdate_r (__const char *__restrict __string,
        struct tm *__restrict __resbufp);
}
extern "C" {
struct bignum_st
 {
 unsigned long *d;
 int top;
 int dmax;
 int neg;
 int flags;
 };
struct bn_mont_ctx_st
 {
 int ri;
 BIGNUM RR;
 BIGNUM N;
 BIGNUM Ni;
 unsigned long n0;
 int flags;
 };
struct bn_recp_ctx_st
 {
 BIGNUM N;
 BIGNUM Nr;
 int num_bits;
 int shift;
 int flags;
 };
struct bn_gencb_st
 {
 unsigned int ver;
 void *arg;
 union
  {
  void (*cb_1)(int, int, void *);
  int (*cb_2)(int, int, BN_GENCB *);
  } cb;
 };
int BN_GENCB_call(BN_GENCB *cb, int a, int b);
const BIGNUM *BN_value_one(void);
char * BN_options(void);
BN_CTX *BN_CTX_new(void);
void BN_CTX_init(BN_CTX *c);
void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
int BN_rand(BIGNUM *rnd, int bits, int top,int bottom);
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top,int bottom);
int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_num_bits(const BIGNUM *a);
int BN_num_bits_word(unsigned long);
BIGNUM *BN_new(void);
void BN_init(BIGNUM *);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
BIGNUM *BN_mpi2bn(const unsigned char *s,int len,BIGNUM *ret);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a,BN_CTX *ctx);
void BN_set_negative(BIGNUM *b, int n);
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
 BN_CTX *ctx);
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *m, BN_CTX *ctx);
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);
unsigned long BN_mod_word(const BIGNUM *a, unsigned long w);
unsigned long BN_div_word(BIGNUM *a, unsigned long w);
int BN_mul_word(BIGNUM *a, unsigned long w);
int BN_add_word(BIGNUM *a, unsigned long w);
int BN_sub_word(BIGNUM *a, unsigned long w);
int BN_set_word(BIGNUM *a, unsigned long w);
unsigned long BN_get_word(const BIGNUM *a);
int BN_cmp(const BIGNUM *a, const BIGNUM *b);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,BN_CTX *ctx);
int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m,BN_CTX *ctx);
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont);
int BN_mod_exp_mont_word(BIGNUM *r, unsigned long a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
 const BIGNUM *a2, const BIGNUM *p2,const BIGNUM *m,
 BN_CTX *ctx,BN_MONT_CTX *m_ctx);
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m,BN_CTX *ctx);
int BN_mask_bits(BIGNUM *a,int n);
int BN_print_fp(FILE *fp, const BIGNUM *a);
int BN_print(BIO *fp, const BIGNUM *a);
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
void BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char * BN_bn2hex(const BIGNUM *a);
char * BN_bn2dec(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_dec2bn(BIGNUM **a, const char *str);
int BN_gcd(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
int BN_kronecker(const BIGNUM *a,const BIGNUM *b,BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *ret,
 const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
 const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_generate_prime(BIGNUM *ret,int bits,int safe,
 const BIGNUM *add, const BIGNUM *rem,
 void (*callback)(int,int,void *),void *cb_arg);
int BN_is_prime(const BIGNUM *p,int nchecks,
 void (*callback)(int,int,void *),
 BN_CTX *ctx,void *cb_arg);
int BN_is_prime_fasttest(const BIGNUM *p,int nchecks,
 void (*callback)(int,int,void *),BN_CTX *ctx,void *cb_arg,
 int do_trial_division);
int BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add,
  const BIGNUM *rem, BN_GENCB *cb);
int BN_is_prime_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int BN_is_prime_fasttest_ex(const BIGNUM *p,int nchecks, BN_CTX *ctx,
  int do_trial_division, BN_GENCB *cb);
int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);
int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
   const BIGNUM *Xp, const BIGNUM *Xp1, const BIGNUM *Xp2,
   const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb);
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2,
   BIGNUM *Xp1, BIGNUM *Xp2,
   const BIGNUM *Xp,
   const BIGNUM *e, BN_CTX *ctx,
   BN_GENCB *cb);
BN_MONT_CTX *BN_MONT_CTX_new(void );
void BN_MONT_CTX_init(BN_MONT_CTX *ctx);
int BN_mod_mul_montgomery(BIGNUM *r,const BIGNUM *a,const BIGNUM *b,
 BN_MONT_CTX *mont, BN_CTX *ctx);
int BN_from_montgomery(BIGNUM *r,const BIGNUM *a,
 BN_MONT_CTX *mont, BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont,const BIGNUM *mod,BN_CTX *ctx);
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
     const BIGNUM *mod, BN_CTX *ctx);
BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_update(BN_BLINDING *b,BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b, BN_CTX *);
unsigned long BN_BLINDING_get_thread_id(const BN_BLINDING *);
void BN_BLINDING_set_thread_id(BN_BLINDING *, unsigned long);
unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
 const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
 int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
 BN_MONT_CTX *m_ctx);
void BN_set_params(int mul,int high,int low,int mont);
int BN_get_params(int which);
void BN_RECP_CTX_init(BN_RECP_CTX *recp);
BN_RECP_CTX *BN_RECP_CTX_new(void);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp,const BIGNUM *rdiv,BN_CTX *ctx);
int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
 BN_RECP_CTX *recp,BN_CTX *ctx);
int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 const BIGNUM *m, BN_CTX *ctx);
int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
 BN_RECP_CTX *recp, BN_CTX *ctx);
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 BN_CTX *ctx);
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p,
 BN_CTX *ctx);
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 BN_CTX *ctx);
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
 BN_CTX *ctx);
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[]);
int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const unsigned int p[], BN_CTX *ctx);
int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const unsigned int p[],
 BN_CTX *ctx);
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const unsigned int p[],
 BN_CTX *ctx);
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const unsigned int p[], BN_CTX *ctx);
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
 const unsigned int p[], BN_CTX *ctx);
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a,
 const unsigned int p[], BN_CTX *ctx);
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a,
 const unsigned int p[], BN_CTX *ctx);
int BN_GF2m_poly2arr(const BIGNUM *a, unsigned int p[], int max);
int BN_GF2m_arr2poly(const unsigned int p[], BIGNUM *a);
int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
const BIGNUM *BN_get0_nist_prime_192(void);
const BIGNUM *BN_get0_nist_prime_224(void);
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
const BIGNUM *BN_get0_nist_prime_521(void);
BIGNUM *bn_expand2(BIGNUM *a, int words);
BIGNUM *bn_dup_expand(const BIGNUM *a, int words);
unsigned long bn_mul_add_words(unsigned long *rp, const unsigned long *ap, int num, unsigned long w);
unsigned long bn_mul_words(unsigned long *rp, const unsigned long *ap, int num, unsigned long w);
void bn_sqr_words(unsigned long *rp, const unsigned long *ap, int num);
unsigned long bn_div_words(unsigned long h, unsigned long l, unsigned long d);
unsigned long bn_add_words(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,int num);
unsigned long bn_sub_words(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,int num);
BIGNUM *get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn);
int BN_bntest_rand(BIGNUM *rnd, int bits, int top,int bottom);
void ERR_load_BN_strings(void);
}
extern "C" {
struct X509_algor_st;

typedef struct asn1_ctx_st
 {
 unsigned char *p;
 int eos;
 int error;
 int inf;
 int tag;
 int xclass;
 long slen;
 unsigned char *max;
 unsigned char *q;
 unsigned char **pp;
 int line;
 } ASN1_CTX;
typedef struct asn1_const_ctx_st
 {
 const unsigned char *p;
 int eos;
 int error;
 int inf;
 int tag;
 int xclass;
 long slen;
 const unsigned char *max;
 const unsigned char *q;
 const unsigned char **pp;
 int line;
 } ASN1_const_CTX;
typedef struct asn1_object_st
 {
 const char *sn,*ln;
 int nid;
 int length;
 unsigned char *data;
 int flags;
 } ASN1_OBJECT;
typedef struct asn1_string_st
 {
 int length;
 int type;
 unsigned char *data;
 long flags;
 } ASN1_STRING;
typedef struct ASN1_ENCODING_st
 {
 unsigned char *enc;
 long len;
 int modified;
 } ASN1_ENCODING;
typedef struct asn1_string_table_st {
 int nid;
 long minsize;
 long maxsize;
 unsigned long mask;
 unsigned long flags;
} ASN1_STRING_TABLE;

typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_ITEM_st ASN1_ITEM;
typedef struct ASN1_TLC_st ASN1_TLC;
typedef struct ASN1_VALUE_st ASN1_VALUE;
typedef void *d2i_of_void(void **,const unsigned char **,long); typedef int i2d_of_void(void *,unsigned char **);
typedef const ASN1_ITEM ASN1_ITEM_EXP;



typedef struct asn1_type_st
 {
 int type;
 union {
  char *ptr;
  ASN1_BOOLEAN boolean;
  ASN1_STRING * asn1_string;
  ASN1_OBJECT * object;
  ASN1_INTEGER * integer;
  ASN1_ENUMERATED * enumerated;
  ASN1_BIT_STRING * bit_string;
  ASN1_OCTET_STRING * octet_string;
  ASN1_PRINTABLESTRING * printablestring;
  ASN1_T61STRING * t61string;
  ASN1_IA5STRING * ia5string;
  ASN1_GENERALSTRING * generalstring;
  ASN1_BMPSTRING * bmpstring;
  ASN1_UNIVERSALSTRING * universalstring;
  ASN1_UTCTIME * utctime;
  ASN1_GENERALIZEDTIME * generalizedtime;
  ASN1_VISIBLESTRING * visiblestring;
  ASN1_UTF8STRING * utf8string;
  ASN1_STRING * set;
  ASN1_STRING * sequence;
  ASN1_VALUE * asn1_value;
  } value;
 } ASN1_TYPE;


typedef struct asn1_method_st
 {
 i2d_of_void *i2d;
 d2i_of_void *d2i;
 void *(*create)(void);
 void (*destroy)(void *);
 } ASN1_METHOD;
typedef struct asn1_header_st
 {
 ASN1_OCTET_STRING *header;
 void *data;
 ASN1_METHOD *meth;
 } ASN1_HEADER;
typedef struct BIT_STRING_BITNAME_st {
 int bitnum;
 const char *lname;
 const char *sname;
} BIT_STRING_BITNAME;
ASN1_TYPE *ASN1_TYPE_new(void); void ASN1_TYPE_free(ASN1_TYPE *a); ASN1_TYPE *d2i_ASN1_TYPE(ASN1_TYPE **a, const unsigned char **in, long len); int i2d_ASN1_TYPE(ASN1_TYPE *a, unsigned char **out); extern const ASN1_ITEM ASN1_ANY_it;
int ASN1_TYPE_get(ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
ASN1_OBJECT * ASN1_OBJECT_new(void );
void ASN1_OBJECT_free(ASN1_OBJECT *a);
int i2d_ASN1_OBJECT(ASN1_OBJECT *a,unsigned char **pp);
ASN1_OBJECT * c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);
ASN1_OBJECT * d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);
extern const ASN1_ITEM ASN1_OBJECT_it;


ASN1_STRING * ASN1_STRING_new(void);
void ASN1_STRING_free(ASN1_STRING *a);
ASN1_STRING * ASN1_STRING_dup(ASN1_STRING *a);
ASN1_STRING * ASN1_STRING_type_new(int type );
int ASN1_STRING_cmp(ASN1_STRING *a, ASN1_STRING *b);
int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(ASN1_STRING *x);
void ASN1_STRING_length_set(ASN1_STRING *x, int n);
int ASN1_STRING_type(ASN1_STRING *x);
unsigned char * ASN1_STRING_data(ASN1_STRING *x);
ASN1_BIT_STRING *ASN1_BIT_STRING_new(void); void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a); ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const unsigned char **in, long len); int i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BIT_STRING_it;
int i2c_ASN1_BIT_STRING(ASN1_BIT_STRING *a,unsigned char **pp);
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,const unsigned char **pp,
   long length);
int ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d,
   int length );
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n);
int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
    BIT_STRING_BITNAME *tbl, int indent);
int ASN1_BIT_STRING_num_asc(char *name, BIT_STRING_BITNAME *tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, char *name, int value,
    BIT_STRING_BITNAME *tbl);
int i2d_ASN1_BOOLEAN(int a,unsigned char **pp);
int d2i_ASN1_BOOLEAN(int *a,const unsigned char **pp,long length);
ASN1_INTEGER *ASN1_INTEGER_new(void); void ASN1_INTEGER_free(ASN1_INTEGER *a); ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **in, long len); int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out); extern const ASN1_ITEM ASN1_INTEGER_it;
int i2c_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **pp);
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER * ASN1_INTEGER_dup(ASN1_INTEGER *x);
int ASN1_INTEGER_cmp(ASN1_INTEGER *x, ASN1_INTEGER *y);
ASN1_ENUMERATED *ASN1_ENUMERATED_new(void); void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a); ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const unsigned char **in, long len); int i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a, unsigned char **out); extern const ASN1_ITEM ASN1_ENUMERATED_it;
int ASN1_UTCTIME_check(ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);
int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);
ASN1_OCTET_STRING *ASN1_OCTET_STRING_new(void); void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a); ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a, const unsigned char **in, long len); int i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_OCTET_STRING_it;
ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup(ASN1_OCTET_STRING *a);
int ASN1_OCTET_STRING_cmp(ASN1_OCTET_STRING *a, ASN1_OCTET_STRING *b);
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data, int len);
ASN1_VISIBLESTRING *ASN1_VISIBLESTRING_new(void); void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a); ASN1_VISIBLESTRING *d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_VISIBLESTRING_it;
ASN1_UNIVERSALSTRING *ASN1_UNIVERSALSTRING_new(void); void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *a); ASN1_UNIVERSALSTRING *d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UNIVERSALSTRING_it;
ASN1_UTF8STRING *ASN1_UTF8STRING_new(void); void ASN1_UTF8STRING_free(ASN1_UTF8STRING *a); ASN1_UTF8STRING *d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a, const unsigned char **in, long len); int i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTF8STRING_it;
ASN1_NULL *ASN1_NULL_new(void); void ASN1_NULL_free(ASN1_NULL *a); ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, const unsigned char **in, long len); int i2d_ASN1_NULL(ASN1_NULL *a, unsigned char **out); extern const ASN1_ITEM ASN1_NULL_it;
ASN1_BMPSTRING *ASN1_BMPSTRING_new(void); void ASN1_BMPSTRING_free(ASN1_BMPSTRING *a); ASN1_BMPSTRING *d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, const unsigned char **in, long len); int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BMPSTRING_it;
int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);
ASN1_STRING *ASN1_PRINTABLE_new(void); void ASN1_PRINTABLE_free(ASN1_STRING *a); ASN1_STRING *d2i_ASN1_PRINTABLE(ASN1_STRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLE(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLE_it;
ASN1_STRING *DIRECTORYSTRING_new(void); void DIRECTORYSTRING_free(ASN1_STRING *a); ASN1_STRING *d2i_DIRECTORYSTRING(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DIRECTORYSTRING(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DIRECTORYSTRING_it;
ASN1_STRING *DISPLAYTEXT_new(void); void DISPLAYTEXT_free(ASN1_STRING *a); ASN1_STRING *d2i_DISPLAYTEXT(ASN1_STRING **a, const unsigned char **in, long len); int i2d_DISPLAYTEXT(ASN1_STRING *a, unsigned char **out); extern const ASN1_ITEM DISPLAYTEXT_it;
ASN1_PRINTABLESTRING *ASN1_PRINTABLESTRING_new(void); void ASN1_PRINTABLESTRING_free(ASN1_PRINTABLESTRING *a); ASN1_PRINTABLESTRING *d2i_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_PRINTABLESTRING(ASN1_PRINTABLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_PRINTABLESTRING_it;
ASN1_T61STRING *ASN1_T61STRING_new(void); void ASN1_T61STRING_free(ASN1_T61STRING *a); ASN1_T61STRING *d2i_ASN1_T61STRING(ASN1_T61STRING **a, const unsigned char **in, long len); int i2d_ASN1_T61STRING(ASN1_T61STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_T61STRING_it;
ASN1_IA5STRING *ASN1_IA5STRING_new(void); void ASN1_IA5STRING_free(ASN1_IA5STRING *a); ASN1_IA5STRING *d2i_ASN1_IA5STRING(ASN1_IA5STRING **a, const unsigned char **in, long len); int i2d_ASN1_IA5STRING(ASN1_IA5STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_IA5STRING_it;
ASN1_GENERALSTRING *ASN1_GENERALSTRING_new(void); void ASN1_GENERALSTRING_free(ASN1_GENERALSTRING *a); ASN1_GENERALSTRING *d2i_ASN1_GENERALSTRING(ASN1_GENERALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_GENERALSTRING(ASN1_GENERALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALSTRING_it;
ASN1_UTCTIME *ASN1_UTCTIME_new(void); void ASN1_UTCTIME_free(ASN1_UTCTIME *a); ASN1_UTCTIME *d2i_ASN1_UTCTIME(ASN1_UTCTIME **a, const unsigned char **in, long len); int i2d_ASN1_UTCTIME(ASN1_UTCTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTCTIME_it;
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_new(void); void ASN1_GENERALIZEDTIME_free(ASN1_GENERALIZEDTIME *a); ASN1_GENERALIZEDTIME *d2i_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME **a, const unsigned char **in, long len); int i2d_ASN1_GENERALIZEDTIME(ASN1_GENERALIZEDTIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_GENERALIZEDTIME_it;
ASN1_TIME *ASN1_TIME_new(void); void ASN1_TIME_free(ASN1_TIME *a); ASN1_TIME *d2i_ASN1_TIME(ASN1_TIME **a, const unsigned char **in, long len); int i2d_ASN1_TIME(ASN1_TIME *a, unsigned char **out); extern const ASN1_ITEM ASN1_TIME_it;
extern const ASN1_ITEM ASN1_OCTET_STRING_NDEF_it;
ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s,time_t t);
int ASN1_TIME_check(ASN1_TIME *t);
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out);
int i2d_ASN1_SET(STACK *a, unsigned char **pp,
   i2d_of_void *i2d, int ex_tag, int ex_class, int is_set);
STACK * d2i_ASN1_SET(STACK **a, const unsigned char **pp, long length,
       d2i_of_void *d2i, void (*free_func)(void *),
       int ex_tag, int ex_class);
int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size);
int i2a_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp,ASN1_ENUMERATED *bs,char *buf,int size);
int i2a_ASN1_OBJECT(BIO *bp,ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size);
int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type);
int i2t_ASN1_OBJECT(char *buf,int buf_len,ASN1_OBJECT *a);
int a2d_ASN1_OBJECT(unsigned char *out,int olen, const char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len,
 const char *sn, const char *ln);
int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(ASN1_INTEGER *ai,BIGNUM *bn);
int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(ASN1_ENUMERATED *a);
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn);
int ASN1_PRINTABLE_type(const unsigned char *s, int max);
int i2d_ASN1_bytes(ASN1_STRING *a, unsigned char **pp, int tag, int xclass);
ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a, const unsigned char **pp,
 long length, int Ptag, int Pclass);
unsigned long ASN1_tag2bit(int tag);
ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a,const unsigned char **pp,
  long length,int type);
int asn1_Finish(ASN1_CTX *c);
int asn1_const_Finish(ASN1_const_CTX *c);
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
 int *pclass, long omax);
int ASN1_check_infinite_end(unsigned char **p,long len);
int ASN1_const_check_infinite_end(const unsigned char **p,long len);
void ASN1_put_object(unsigned char **pp, int constructed, int length,
 int tag, int xclass);
int ASN1_put_eoc(unsigned char **pp);
int ASN1_object_size(int constructed, int length, int tag);
void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, char *x);
void *ASN1_item_dup(const ASN1_ITEM *it, void *x);
void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x);
void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
int ASN1_i2d_fp(i2d_of_void *i2d,FILE *out,void *x);
int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, void *x);
int ASN1_STRING_print_ex_fp(FILE *fp, ASN1_STRING *str, unsigned long flags);
int ASN1_STRING_to_UTF8(unsigned char **out, ASN1_STRING *in);
void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x);
void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x);
int ASN1_i2d_bio(i2d_of_void *i2d,BIO *out, unsigned char *x);
int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, void *x);
int ASN1_UTCTIME_print(BIO *fp,ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp,ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *fp,ASN1_TIME *a);
int ASN1_STRING_print(BIO *bp,ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, ASN1_STRING *str, unsigned long flags);
int ASN1_parse(BIO *bp,const unsigned char *pp,long len,int indent);
int ASN1_parse_dump(BIO *bp,const unsigned char *pp,long len,int indent,int dump);
const char *ASN1_tag2str(int tag);
int i2d_ASN1_HEADER(ASN1_HEADER *a,unsigned char **pp);
ASN1_HEADER *d2i_ASN1_HEADER(ASN1_HEADER **a,const unsigned char **pp, long length);
ASN1_HEADER *ASN1_HEADER_new(void );
void ASN1_HEADER_free(ASN1_HEADER *a);
int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);
ASN1_METHOD *X509_asn1_meth(void);
ASN1_METHOD *RSAPrivateKey_asn1_meth(void);
ASN1_METHOD *ASN1_IA5STRING_asn1_meth(void);
ASN1_METHOD *ASN1_BIT_STRING_asn1_meth(void);
int ASN1_TYPE_set_octetstring(ASN1_TYPE *a,
 unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(ASN1_TYPE *a,
 unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
 unsigned char *data, int len);
int ASN1_TYPE_get_int_octetstring(ASN1_TYPE *a,long *num,
 unsigned char *data, int max_len);
STACK *ASN1_seq_unpack(const unsigned char *buf, int len,
         d2i_of_void *d2i, void (*free_func)(void *));
unsigned char *ASN1_seq_pack(STACK *safes, i2d_of_void *i2d,
        unsigned char **buf, int *len );
void *ASN1_unpack_string(ASN1_STRING *oct, d2i_of_void *d2i);
void *ASN1_item_unpack(ASN1_STRING *oct, const ASN1_ITEM *it);
ASN1_STRING *ASN1_pack_string(void *obj, i2d_of_void *i2d,
         ASN1_OCTET_STRING **oct);
ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it, ASN1_OCTET_STRING **oct);
void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
     int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
     int inform, unsigned long mask,
     long minsize, long maxsize);
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
  const unsigned char *in, int inlen, int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);
ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
int ASN1_item_ndef_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
void ASN1_add_oid_module(void);
ASN1_TYPE *ASN1_generate_nconf(char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);
typedef int asn1_output_data_fn(BIO *out, BIO *data, ASN1_VALUE *val, int flags,
     const ASN1_ITEM *it);
int int_smime_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    int ctype_nid, int econt_nid,
    STACK *mdalgs,
    asn1_output_data_fn *data_fn,
    const ASN1_ITEM *it);
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
void ERR_load_ASN1_strings(void);
}
extern "C" {
typedef struct obj_name_st
 {
 int type;
 int alias;
 const char *name;
 const char *data;
 } OBJ_NAME;
int OBJ_NAME_init(void);
int OBJ_NAME_new_index(unsigned long (*hash_func)(const char *),
         int (*cmp_func)(const char *, const char *),
         void (*free_func)(const char *, int, const char *));
const char *OBJ_NAME_get(const char *name,int type);
int OBJ_NAME_add(const char *name,int type,const char *data);
int OBJ_NAME_remove(const char *name,int type);
void OBJ_NAME_cleanup(int type);
void OBJ_NAME_do_all(int type,void (*fn)(const OBJ_NAME *,void *arg),
       void *arg);
void OBJ_NAME_do_all_sorted(int type,void (*fn)(const OBJ_NAME *,void *arg),
       void *arg);
ASN1_OBJECT * OBJ_dup(const ASN1_OBJECT *o);
ASN1_OBJECT * OBJ_nid2obj(int n);
const char * OBJ_nid2ln(int n);
const char * OBJ_nid2sn(int n);
int OBJ_obj2nid(const ASN1_OBJECT *o);
ASN1_OBJECT * OBJ_txt2obj(const char *s, int no_name);
int OBJ_obj2txt(char *buf, int buf_len, const ASN1_OBJECT *a, int no_name);
int OBJ_txt2nid(const char *s);
int OBJ_ln2nid(const char *s);
int OBJ_sn2nid(const char *s);
int OBJ_cmp(const ASN1_OBJECT *a,const ASN1_OBJECT *b);
const char * OBJ_bsearch(const char *key,const char *base,int num,int size,
 int (*cmp)(const void *, const void *));
const char * OBJ_bsearch_ex(const char *key,const char *base,int num,
 int size, int (*cmp)(const void *, const void *), int flags);
int OBJ_new_nid(int num);
int OBJ_add_object(const ASN1_OBJECT *obj);
int OBJ_create(const char *oid,const char *sn,const char *ln);
void OBJ_cleanup(void );
int OBJ_create_objects(BIO *in);
void ERR_load_OBJ_strings(void);
}
extern "C" {
struct evp_pkey_st
 {
 int type;
 int save_type;
 int references;
 union {
  char *ptr;
  struct rsa_st *rsa;
  struct dsa_st *dsa;
  struct dh_st *dh;
  struct ec_key_st *ec;
  } pkey;
 int save_parameters;
 STACK *attributes;
 } ;
struct env_md_st
 {
 int type;
 int pkey_type;
 int md_size;
 unsigned long flags;
 int (*init)(EVP_MD_CTX *ctx);
 int (*update)(EVP_MD_CTX *ctx,const void *data,size_t count);
 int (*final)(EVP_MD_CTX *ctx,unsigned char *md);
 int (*copy)(EVP_MD_CTX *to,const EVP_MD_CTX *from);
 int (*cleanup)(EVP_MD_CTX *ctx);
 int (*sign)(int type, const unsigned char *m, unsigned int m_length,
      unsigned char *sigret, unsigned int *siglen, void *key);
 int (*verify)(int type, const unsigned char *m, unsigned int m_length,
        const unsigned char *sigbuf, unsigned int siglen,
        void *key);
 int required_pkey_type[5];
 int block_size;
 int ctx_size;
 } ;
typedef int evp_sign_method(int type,const unsigned char *m,
       unsigned int m_length,unsigned char *sigret,
       unsigned int *siglen, void *key);
typedef int evp_verify_method(int type,const unsigned char *m,
       unsigned int m_length,const unsigned char *sigbuf,
       unsigned int siglen, void *key);
typedef struct
 {
 EVP_MD_CTX *mctx;
 void *key;
 } EVP_MD_SVCTX;
struct env_md_ctx_st
 {
 const EVP_MD *digest;
 ENGINE *engine;
 unsigned long flags;
 void *md_data;
 } ;
struct evp_cipher_st
 {
 int nid;
 int block_size;
 int key_len;
 int iv_len;
 unsigned long flags;
 int (*init)(EVP_CIPHER_CTX *ctx, const unsigned char *key,
      const unsigned char *iv, int enc);
 int (*do_cipher)(EVP_CIPHER_CTX *ctx, unsigned char *out,
    const unsigned char *in, unsigned int inl);
 int (*cleanup)(EVP_CIPHER_CTX *);
 int ctx_size;
 int (*set_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
 int (*get_asn1_parameters)(EVP_CIPHER_CTX *, ASN1_TYPE *);
 int (*ctrl)(EVP_CIPHER_CTX *, int type, int arg, void *ptr);
 void *app_data;
 } ;
typedef struct evp_cipher_info_st
 {
 const EVP_CIPHER *cipher;
 unsigned char iv[16];
 } EVP_CIPHER_INFO;
struct evp_cipher_ctx_st
 {
 const EVP_CIPHER *cipher;
 ENGINE *engine;
 int encrypt;
 int buf_len;
 unsigned char oiv[16];
 unsigned char iv[16];
 unsigned char buf[32];
 int num;
 void *app_data;
 int key_len;
 unsigned long flags;
 void *cipher_data;
 int final_used;
 int block_mask;
 unsigned char final[32];
 } ;
typedef struct evp_Encode_Ctx_st
 {
 int num;
 int length;
 unsigned char enc_data[80];
 int line_num;
 int expect_nl;
 } EVP_ENCODE_CTX;
typedef int (EVP_PBE_KEYGEN)(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
  ASN1_TYPE *param, const EVP_CIPHER *cipher,
                const EVP_MD *md, int en_de);
int EVP_MD_type(const EVP_MD *md);
int EVP_MD_pkey_type(const EVP_MD *md);
int EVP_MD_size(const EVP_MD *md);
int EVP_MD_block_size(const EVP_MD *md);
const EVP_MD * EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
int EVP_CIPHER_nid(const EVP_CIPHER *cipher);
int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);
int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);
unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);
const EVP_CIPHER * EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
void * EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);
unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx);
int EVP_Cipher(EVP_CIPHER_CTX *c,
  unsigned char *out,
  const unsigned char *in,
  unsigned int inl);
void EVP_MD_CTX_init(EVP_MD_CTX *ctx);
int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out,const EVP_MD_CTX *in);
void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags);
void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags);
int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx,int flags);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx,const void *d,
    size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);
int EVP_Digest(const void *data, size_t count,
  unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);
int EVP_MD_CTX_copy(EVP_MD_CTX *out,const EVP_MD_CTX *in);
int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
int EVP_DigestFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s);
int EVP_read_pw_string(char *buf,int length,const char *prompt,int verify);
void EVP_set_pw_prompt(const char *prompt);
char * EVP_get_pw_prompt(void);
int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
  const unsigned char *salt, const unsigned char *data,
  int datal, int count, unsigned char *key,unsigned char *iv);
void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags);
void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags);
int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx,int flags);
int EVP_EncryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
  const unsigned char *key, const unsigned char *iv);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
  const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_DecryptInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
  const unsigned char *key, const unsigned char *iv);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
  const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_CipherInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher,
         const unsigned char *key,const unsigned char *iv,
         int enc);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *cipher, ENGINE *impl,
         const unsigned char *key,const unsigned char *iv,
         int enc);
int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
  int *outl, const unsigned char *in, int inl);
int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
int EVP_SignFinal(EVP_MD_CTX *ctx,unsigned char *md,unsigned int *s,
  EVP_PKEY *pkey);
int EVP_VerifyFinal(EVP_MD_CTX *ctx,const unsigned char *sigbuf,
  unsigned int siglen,EVP_PKEY *pkey);
int EVP_OpenInit(EVP_CIPHER_CTX *ctx,const EVP_CIPHER *type,
  const unsigned char *ek, int ekl, const unsigned char *iv,
  EVP_PKEY *priv);
int EVP_OpenFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
   unsigned char **ek, int *ekl, unsigned char *iv,
  EVP_PKEY **pubk, int npubk);
int EVP_SealFinal(EVP_CIPHER_CTX *ctx,unsigned char *out,int *outl);
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
  const unsigned char *in,int inl);
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl);
int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx,unsigned char *out,int *outl,
  const unsigned char *in, int inl);
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, unsigned
  char *out, int *outl);
int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *a);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);
BIO_METHOD *BIO_f_md(void);
BIO_METHOD *BIO_f_base64(void);
BIO_METHOD *BIO_f_cipher(void);
BIO_METHOD *BIO_f_reliable(void);
void BIO_set_cipher(BIO *b,const EVP_CIPHER *c,const unsigned char *k,
  const unsigned char *i, int enc);
const EVP_MD *EVP_md_null(void);
const EVP_MD *EVP_md2(void);
const EVP_MD *EVP_md4(void);
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_sha(void);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_dss(void);
const EVP_MD *EVP_dss1(void);
const EVP_MD *EVP_ecdsa(void);
const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);
const EVP_MD *EVP_ripemd160(void);
const EVP_CIPHER *EVP_enc_null(void);
const EVP_CIPHER *EVP_des_ecb(void);
const EVP_CIPHER *EVP_des_ede(void);
const EVP_CIPHER *EVP_des_ede3(void);
const EVP_CIPHER *EVP_des_ede_ecb(void);
const EVP_CIPHER *EVP_des_ede3_ecb(void);
const EVP_CIPHER *EVP_des_cfb64(void);
const EVP_CIPHER *EVP_des_cfb1(void);
const EVP_CIPHER *EVP_des_cfb8(void);
const EVP_CIPHER *EVP_des_ede_cfb64(void);
const EVP_CIPHER *EVP_des_ede3_cfb64(void);
const EVP_CIPHER *EVP_des_ede3_cfb1(void);
const EVP_CIPHER *EVP_des_ede3_cfb8(void);
const EVP_CIPHER *EVP_des_ofb(void);
const EVP_CIPHER *EVP_des_ede_ofb(void);
const EVP_CIPHER *EVP_des_ede3_ofb(void);
const EVP_CIPHER *EVP_des_cbc(void);
const EVP_CIPHER *EVP_des_ede_cbc(void);
const EVP_CIPHER *EVP_des_ede3_cbc(void);
const EVP_CIPHER *EVP_desx_cbc(void);
const EVP_CIPHER *EVP_rc4(void);
const EVP_CIPHER *EVP_rc4_40(void);
const EVP_CIPHER *EVP_rc2_ecb(void);
const EVP_CIPHER *EVP_rc2_cbc(void);
const EVP_CIPHER *EVP_rc2_40_cbc(void);
const EVP_CIPHER *EVP_rc2_64_cbc(void);
const EVP_CIPHER *EVP_rc2_cfb64(void);
const EVP_CIPHER *EVP_rc2_ofb(void);
const EVP_CIPHER *EVP_bf_ecb(void);
const EVP_CIPHER *EVP_bf_cbc(void);
const EVP_CIPHER *EVP_bf_cfb64(void);
const EVP_CIPHER *EVP_bf_ofb(void);
const EVP_CIPHER *EVP_cast5_ecb(void);
const EVP_CIPHER *EVP_cast5_cbc(void);
const EVP_CIPHER *EVP_cast5_cfb64(void);
const EVP_CIPHER *EVP_cast5_ofb(void);
const EVP_CIPHER *EVP_aes_128_ecb(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
const EVP_CIPHER *EVP_aes_128_cfb1(void);
const EVP_CIPHER *EVP_aes_128_cfb8(void);
const EVP_CIPHER *EVP_aes_128_cfb128(void);
const EVP_CIPHER *EVP_aes_128_ofb(void);
const EVP_CIPHER *EVP_aes_192_ecb(void);
const EVP_CIPHER *EVP_aes_192_cbc(void);
const EVP_CIPHER *EVP_aes_192_cfb1(void);
const EVP_CIPHER *EVP_aes_192_cfb8(void);
const EVP_CIPHER *EVP_aes_192_cfb128(void);
const EVP_CIPHER *EVP_aes_192_ofb(void);
const EVP_CIPHER *EVP_aes_256_ecb(void);
const EVP_CIPHER *EVP_aes_256_cbc(void);
const EVP_CIPHER *EVP_aes_256_cfb1(void);
const EVP_CIPHER *EVP_aes_256_cfb8(void);
const EVP_CIPHER *EVP_aes_256_cfb128(void);
const EVP_CIPHER *EVP_aes_256_ofb(void);
void OPENSSL_add_all_algorithms_noconf(void);
void OPENSSL_add_all_algorithms_conf(void);
void OpenSSL_add_all_ciphers(void);
void OpenSSL_add_all_digests(void);
int EVP_add_cipher(const EVP_CIPHER *cipher);
int EVP_add_digest(const EVP_MD *digest);
const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
const EVP_MD *EVP_get_digestbyname(const char *name);
void EVP_cleanup(void);
int EVP_PKEY_decrypt(unsigned char *dec_key,
   const unsigned char *enc_key,int enc_key_len,
   EVP_PKEY *private_key);
int EVP_PKEY_encrypt(unsigned char *enc_key,
   const unsigned char *key,int key_len,
   EVP_PKEY *pub_key);
int EVP_PKEY_type(int type);
int EVP_PKEY_bits(EVP_PKEY *pkey);
int EVP_PKEY_size(EVP_PKEY *pkey);
int EVP_PKEY_assign(EVP_PKEY *pkey,int type,char *key);
struct rsa_st;
int EVP_PKEY_set1_RSA(EVP_PKEY *pkey,struct rsa_st *key);
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
struct dsa_st;
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey,struct dsa_st *key);
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
struct dh_st;
int EVP_PKEY_set1_DH(EVP_PKEY *pkey,struct dh_st *key);
struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
struct ec_key_st;
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey,struct ec_key_st *key);
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
EVP_PKEY * EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *pkey);
EVP_PKEY * d2i_PublicKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
int i2d_PublicKey(EVP_PKEY *a, unsigned char **pp);
EVP_PKEY * d2i_PrivateKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
EVP_PKEY * d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
   long length);
int i2d_PrivateKey(EVP_PKEY *a, unsigned char **pp);
int EVP_PKEY_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from);
int EVP_PKEY_missing_parameters(const EVP_PKEY *pkey);
int EVP_PKEY_save_parameters(EVP_PKEY *pkey,int mode);
int EVP_PKEY_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b);
int EVP_CIPHER_type(const EVP_CIPHER *ctx);
int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c,ASN1_TYPE *type);
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de);
int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
      const unsigned char *salt, int saltlen, int iter,
      int keylen, unsigned char *out);
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md,
    int en_de);
void PKCS5_PBE_add(void);
int EVP_PBE_CipherInit (ASN1_OBJECT *pbe_obj, const char *pass, int passlen,
      ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de);
int EVP_PBE_alg_add(int nid, const EVP_CIPHER *cipher, const EVP_MD *md,
      EVP_PBE_KEYGEN *keygen);
void EVP_PBE_cleanup(void);
void EVP_add_alg_module(void);
void ERR_load_EVP_strings(void);
}
extern "C" {
struct aes_key_st {
    unsigned int rd_key[4 *(14 + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;
const char *AES_options(void);
int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
 AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
 AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out,
 const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,
 const AES_KEY *key);
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
 const AES_KEY *key, const int enc);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
 const unsigned long length, const AES_KEY *key,
 unsigned char *ivec, const int enc);
void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out,
 const unsigned long length, const AES_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out,
 const unsigned long length, const AES_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out,
 const unsigned long length, const AES_KEY *key,
 unsigned char *ivec, int *num, const int enc);
void AES_cfbr_encrypt_block(const unsigned char *in,unsigned char *out,
       const int nbits,const AES_KEY *key,
       unsigned char *ivec,const int enc);
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out,
 const unsigned long length, const AES_KEY *key,
 unsigned char *ivec, int *num);
void AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
 const unsigned long length, const AES_KEY *key,
 unsigned char ivec[16],
 unsigned char ecount_buf[16],
 unsigned int *num);
void AES_ige_encrypt(const unsigned char *in, unsigned char *out,
       const unsigned long length, const AES_KEY *key,
       unsigned char *ivec, const int enc);
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out,
   const unsigned long length, const AES_KEY *key,
   const AES_KEY *key2, const unsigned char *ivec,
   const int enc);
int AES_wrap_key(AES_KEY *key, const unsigned char *iv,
  unsigned char *out,
  const unsigned char *in, unsigned int inlen);
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
  unsigned char *out,
  const unsigned char *in, unsigned int inlen);
}
extern "C" {
typedef struct rc4_key_st
 {
 unsigned int x,y;
 unsigned int data[256];
 } RC4_KEY;
const char *RC4_options(void);
void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void RC4(RC4_KEY *key, unsigned long len, const unsigned char *indata,
  unsigned char *outdata);
}
extern "C" {
typedef struct bf_key_st
 {
 unsigned int P[16 +2];
 unsigned int S[4*256];
 } BF_KEY;
void BF_set_key(BF_KEY *key, int len, const unsigned char *data);
void BF_encrypt(unsigned int *data,const BF_KEY *key);
void BF_decrypt(unsigned int *data,const BF_KEY *key);
void BF_ecb_encrypt(const unsigned char *in, unsigned char *out,
 const BF_KEY *key, int enc);
void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
 const BF_KEY *schedule, unsigned char *ivec, int enc);
void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length,
 const BF_KEY *schedule, unsigned char *ivec, int *num, int enc);
void BF_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length,
 const BF_KEY *schedule, unsigned char *ivec, int *num);
const char *BF_options(void);
}
extern "C" {
typedef unsigned char DES_cblock[8];
typedef unsigned char const_DES_cblock[8];
typedef struct DES_ks
    {
    union
 {
 DES_cblock cblock;
 unsigned long deslong[2];
 } ks[16];
    } DES_key_schedule;
extern "C" {
typedef unsigned char _ossl_old_des_cblock[8];
typedef struct _ossl_old_des_ks_struct
 {
 union {
  _ossl_old_des_cblock _;
  unsigned long pad[2];
  } ks;
 } _ossl_old_des_key_schedule[16];
const char *_ossl_old_des_options(void);
void _ossl_old_des_ecb3_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 _ossl_old_des_key_schedule ks1,_ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, int enc);
unsigned long _ossl_old_des_cbc_cksum(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec);
void _ossl_old_des_cbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
void _ossl_old_des_ncbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
void _ossl_old_des_xcbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,
 _ossl_old_des_cblock *inw,_ossl_old_des_cblock *outw,int enc);
void _ossl_old_des_cfb_encrypt(unsigned char *in,unsigned char *out,int numbits,
 long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
void _ossl_old_des_ecb_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 _ossl_old_des_key_schedule ks,int enc);
void _ossl_old_des_encrypt(unsigned long *data,_ossl_old_des_key_schedule ks, int enc);
void _ossl_old_des_encrypt2(unsigned long *data,_ossl_old_des_key_schedule ks, int enc);
void _ossl_old_des_encrypt3(unsigned long *data, _ossl_old_des_key_schedule ks1,
 _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3);
void _ossl_old_des_decrypt3(unsigned long *data, _ossl_old_des_key_schedule ks1,
 _ossl_old_des_key_schedule ks2, _ossl_old_des_key_schedule ks3);
void _ossl_old_des_ede3_cbc_encrypt(_ossl_old_des_cblock *input, _ossl_old_des_cblock *output,
 long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int enc);
void _ossl_old_des_ede3_cfb64_encrypt(unsigned char *in, unsigned char *out,
 long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int *num, int enc);
void _ossl_old_des_ede3_ofb64_encrypt(unsigned char *in, unsigned char *out,
 long length, _ossl_old_des_key_schedule ks1, _ossl_old_des_key_schedule ks2,
 _ossl_old_des_key_schedule ks3, _ossl_old_des_cblock *ivec, int *num);
int _ossl_old_des_enc_read(int fd,char *buf,int len,_ossl_old_des_key_schedule sched,
 _ossl_old_des_cblock *iv);
int _ossl_old_des_enc_write(int fd,char *buf,int len,_ossl_old_des_key_schedule sched,
 _ossl_old_des_cblock *iv);
char *_ossl_old_des_fcrypt(const char *buf,const char *salt, char *ret);
char *_ossl_old_des_crypt(const char *buf,const char *salt);
char *_ossl_old_crypt(const char *buf,const char *salt);
void _ossl_old_des_ofb_encrypt(unsigned char *in,unsigned char *out,
 int numbits,long length,_ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec);
void _ossl_old_des_pcbc_encrypt(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,long length,
 _ossl_old_des_key_schedule schedule,_ossl_old_des_cblock *ivec,int enc);
unsigned long _ossl_old_des_quad_cksum(_ossl_old_des_cblock *input,_ossl_old_des_cblock *output,
 long length,int out_count,_ossl_old_des_cblock *seed);
void _ossl_old_des_random_seed(_ossl_old_des_cblock key);
void _ossl_old_des_random_key(_ossl_old_des_cblock ret);
int _ossl_old_des_read_password(_ossl_old_des_cblock *key,const char *prompt,int verify);
int _ossl_old_des_read_2passwords(_ossl_old_des_cblock *key1,_ossl_old_des_cblock *key2,
 const char *prompt,int verify);
void _ossl_old_des_set_odd_parity(_ossl_old_des_cblock *key);
int _ossl_old_des_is_weak_key(_ossl_old_des_cblock *key);
int _ossl_old_des_set_key(_ossl_old_des_cblock *key,_ossl_old_des_key_schedule schedule);
int _ossl_old_des_key_sched(_ossl_old_des_cblock *key,_ossl_old_des_key_schedule schedule);
void _ossl_old_des_string_to_key(char *str,_ossl_old_des_cblock *key);
void _ossl_old_des_string_to_2keys(char *str,_ossl_old_des_cblock *key1,_ossl_old_des_cblock *key2);
void _ossl_old_des_cfb64_encrypt(unsigned char *in, unsigned char *out, long length,
 _ossl_old_des_key_schedule schedule, _ossl_old_des_cblock *ivec, int *num, int enc);
void _ossl_old_des_ofb64_encrypt(unsigned char *in, unsigned char *out, long length,
 _ossl_old_des_key_schedule schedule, _ossl_old_des_cblock *ivec, int *num);
void _ossl_096_des_random_seed(DES_cblock *key);
}
extern "C" {
UI *UI_new(void);
UI *UI_new_method(const UI_METHOD *method);
void UI_free(UI *ui);
int UI_add_input_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize);
int UI_dup_input_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize);
int UI_add_verify_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize, const char *test_buf);
int UI_dup_verify_string(UI *ui, const char *prompt, int flags,
 char *result_buf, int minsize, int maxsize, const char *test_buf);
int UI_add_input_boolean(UI *ui, const char *prompt, const char *action_desc,
 const char *ok_chars, const char *cancel_chars,
 int flags, char *result_buf);
int UI_dup_input_boolean(UI *ui, const char *prompt, const char *action_desc,
 const char *ok_chars, const char *cancel_chars,
 int flags, char *result_buf);
int UI_add_info_string(UI *ui, const char *text);
int UI_dup_info_string(UI *ui, const char *text);
int UI_add_error_string(UI *ui, const char *text);
int UI_dup_error_string(UI *ui, const char *text);
char *UI_construct_prompt(UI *ui_method,
 const char *object_desc, const char *object_name);
void *UI_add_user_data(UI *ui, void *user_data);
void *UI_get0_user_data(UI *ui);
const char *UI_get0_result(UI *ui, int i);
int UI_process(UI *ui);
int UI_ctrl(UI *ui, int cmd, long i, void *p, void (*f)(void));
int UI_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int UI_set_ex_data(UI *r,int idx,void *arg);
void *UI_get_ex_data(UI *r, int idx);
void UI_set_default_method(const UI_METHOD *meth);
const UI_METHOD *UI_get_default_method(void);
const UI_METHOD *UI_get_method(UI *ui);
const UI_METHOD *UI_set_method(UI *ui, const UI_METHOD *meth);
UI_METHOD *UI_OpenSSL(void);

typedef struct ui_string_st UI_STRING;
enum UI_string_types
 {
 UIT_NONE=0,
 UIT_PROMPT,
 UIT_VERIFY,
 UIT_BOOLEAN,
 UIT_INFO,
 UIT_ERROR
 };
UI_METHOD *UI_create_method(char *name);
void UI_destroy_method(UI_METHOD *ui_method);
int UI_method_set_opener(UI_METHOD *method, int (*opener)(UI *ui));
int UI_method_set_writer(UI_METHOD *method, int (*writer)(UI *ui, UI_STRING *uis));
int UI_method_set_flusher(UI_METHOD *method, int (*flusher)(UI *ui));
int UI_method_set_reader(UI_METHOD *method, int (*reader)(UI *ui, UI_STRING *uis));
int UI_method_set_closer(UI_METHOD *method, int (*closer)(UI *ui));
int (*UI_method_get_opener(UI_METHOD *method))(UI*);
int (*UI_method_get_writer(UI_METHOD *method))(UI*,UI_STRING*);
int (*UI_method_get_flusher(UI_METHOD *method))(UI*);
int (*UI_method_get_reader(UI_METHOD *method))(UI*,UI_STRING*);
int (*UI_method_get_closer(UI_METHOD *method))(UI*);
enum UI_string_types UI_get_string_type(UI_STRING *uis);
int UI_get_input_flags(UI_STRING *uis);
const char *UI_get0_output_string(UI_STRING *uis);
const char *UI_get0_action_string(UI_STRING *uis);
const char *UI_get0_result_string(UI_STRING *uis);
const char *UI_get0_test_string(UI_STRING *uis);
int UI_get_result_minsize(UI_STRING *uis);
int UI_get_result_maxsize(UI_STRING *uis);
int UI_set_result(UI *ui, UI_STRING *uis, const char *result);
int UI_UTIL_read_pw_string(char *buf,int length,const char *prompt,int verify);
int UI_UTIL_read_pw(char *buf,char *buff,int size,const char *prompt,int verify);
void ERR_load_UI_strings(void);
}
extern "C" {
int _ossl_old_des_read_pw_string(char *buf,int length,const char *prompt,int verify);
int _ossl_old_des_read_pw(char *buf,char *buff,int size,const char *prompt,int verify);
}
extern int _shadow_DES_check_key;
extern int _shadow_DES_rw_mode;
const char *DES_options(void);
void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output,
        DES_key_schedule *ks1,DES_key_schedule *ks2,
        DES_key_schedule *ks3, int enc);
unsigned long DES_cbc_cksum(const unsigned char *input,DES_cblock *output,
         long length,DES_key_schedule *schedule,
         const_DES_cblock *ivec);
void DES_cbc_encrypt(const unsigned char *input,unsigned char *output,
       long length,DES_key_schedule *schedule,DES_cblock *ivec,
       int enc);
void DES_ncbc_encrypt(const unsigned char *input,unsigned char *output,
        long length,DES_key_schedule *schedule,DES_cblock *ivec,
        int enc);
void DES_xcbc_encrypt(const unsigned char *input,unsigned char *output,
        long length,DES_key_schedule *schedule,DES_cblock *ivec,
        const_DES_cblock *inw,const_DES_cblock *outw,int enc);
void DES_cfb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
       long length,DES_key_schedule *schedule,DES_cblock *ivec,
       int enc);
void DES_ecb_encrypt(const_DES_cblock *input,DES_cblock *output,
       DES_key_schedule *ks,int enc);
void DES_encrypt1(unsigned long *data,DES_key_schedule *ks, int enc);
void DES_encrypt2(unsigned long *data,DES_key_schedule *ks, int enc);
void DES_encrypt3(unsigned long *data, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_decrypt3(unsigned long *data, DES_key_schedule *ks1,
    DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_ede3_cbc_encrypt(const unsigned char *input,unsigned char *output,
     long length,
     DES_key_schedule *ks1,DES_key_schedule *ks2,
     DES_key_schedule *ks3,DES_cblock *ivec,int enc);
void DES_ede3_cbcm_encrypt(const unsigned char *in,unsigned char *out,
      long length,
      DES_key_schedule *ks1,DES_key_schedule *ks2,
      DES_key_schedule *ks3,
      DES_cblock *ivec1,DES_cblock *ivec2,
      int enc);
void DES_ede3_cfb64_encrypt(const unsigned char *in,unsigned char *out,
       long length,DES_key_schedule *ks1,
       DES_key_schedule *ks2,DES_key_schedule *ks3,
       DES_cblock *ivec,int *num,int enc);
void DES_ede3_cfb_encrypt(const unsigned char *in,unsigned char *out,
     int numbits,long length,DES_key_schedule *ks1,
     DES_key_schedule *ks2,DES_key_schedule *ks3,
     DES_cblock *ivec,int enc);
void DES_ede3_ofb64_encrypt(const unsigned char *in,unsigned char *out,
       long length,DES_key_schedule *ks1,
       DES_key_schedule *ks2,DES_key_schedule *ks3,
       DES_cblock *ivec,int *num);
int DES_enc_read(int fd,void *buf,int len,DES_key_schedule *sched,
   DES_cblock *iv);
int DES_enc_write(int fd,const void *buf,int len,DES_key_schedule *sched,
    DES_cblock *iv);
char *DES_fcrypt(const char *buf,const char *salt, char *ret);
char *DES_crypt(const char *buf,const char *salt);
void DES_ofb_encrypt(const unsigned char *in,unsigned char *out,int numbits,
       long length,DES_key_schedule *schedule,DES_cblock *ivec);
void DES_pcbc_encrypt(const unsigned char *input,unsigned char *output,
        long length,DES_key_schedule *schedule,DES_cblock *ivec,
        int enc);
unsigned long DES_quad_cksum(const unsigned char *input,DES_cblock output[],
   long length,int out_count,DES_cblock *seed);
int DES_random_key(DES_cblock *ret);
void DES_set_odd_parity(DES_cblock *key);
int DES_check_key_parity(const_DES_cblock *key);
int DES_is_weak_key(const_DES_cblock *key);
int DES_set_key(const_DES_cblock *key,DES_key_schedule *schedule);
int DES_key_sched(const_DES_cblock *key,DES_key_schedule *schedule);
int DES_set_key_checked(const_DES_cblock *key,DES_key_schedule *schedule);
void DES_set_key_unchecked(const_DES_cblock *key,DES_key_schedule *schedule);
void DES_string_to_key(const char *str,DES_cblock *key);
void DES_string_to_2keys(const char *str,DES_cblock *key1,DES_cblock *key2);
void DES_cfb64_encrypt(const unsigned char *in,unsigned char *out,long length,
         DES_key_schedule *schedule,DES_cblock *ivec,int *num,
         int enc);
void DES_ofb64_encrypt(const unsigned char *in,unsigned char *out,long length,
         DES_key_schedule *schedule,DES_cblock *ivec,int *num);
int DES_read_password(DES_cblock *key, const char *prompt, int verify);
int DES_read_2passwords(DES_cblock *key1, DES_cblock *key2, const char *prompt,
 int verify);
}
extern "C" {
typedef struct cast_key_st
 {
 unsigned long data[32];
 int short_key;
 } CAST_KEY;
void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data);
void CAST_ecb_encrypt(const unsigned char *in, unsigned char *out, const CAST_KEY *key,
        int enc);
void CAST_encrypt(unsigned long *data, const CAST_KEY *key);
void CAST_decrypt(unsigned long *data, const CAST_KEY *key);
void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
        const CAST_KEY *ks, unsigned char *iv, int enc);
void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out,
   long length, const CAST_KEY *schedule, unsigned char *ivec,
   int *num, int enc);
void CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out,
   long length, const CAST_KEY *schedule, unsigned char *ivec,
   int *num);
}
extern "C" {
typedef struct hmac_ctx_st
 {
 const EVP_MD *md;
 EVP_MD_CTX md_ctx;
 EVP_MD_CTX i_ctx;
 EVP_MD_CTX o_ctx;
 unsigned int key_length;
 unsigned char key[128];
 } HMAC_CTX;
void HMAC_CTX_init(HMAC_CTX *ctx);
void HMAC_CTX_cleanup(HMAC_CTX *ctx);
void HMAC_Init(HMAC_CTX *ctx, const void *key, int len,
        const EVP_MD *md);
void HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
    const EVP_MD *md, ENGINE *impl);
void HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
void HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
      const unsigned char *d, size_t n, unsigned char *md,
      unsigned int *md_len);
void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
}
extern "C" {
struct dh_method
 {
 const char *name;
 int (*generate_key)(DH *dh);
 int (*compute_key)(unsigned char *key,const BIGNUM *pub_key,DH *dh);
 int (*bn_mod_exp)(const DH *dh, BIGNUM *r, const BIGNUM *a,
    const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);
 int (*init)(DH *dh);
 int (*finish)(DH *dh);
 int flags;
 char *app_data;
 int (*generate_params)(DH *dh, int prime_len, int generator, BN_GENCB *cb);
 };
struct dh_st
 {
 int pad;
 int version;
 BIGNUM *p;
 BIGNUM *g;
 long length;
 BIGNUM *pub_key;
 BIGNUM *priv_key;
 int flags;
 BN_MONT_CTX *method_mont_p;
 BIGNUM *q;
 BIGNUM *j;
 unsigned char *seed;
 int seedlen;
 BIGNUM *counter;
 int references;
 CRYPTO_EX_DATA ex_data;
 const DH_METHOD *meth;
 ENGINE *engine;
 };
const DH_METHOD *DH_OpenSSL(void);
void DH_set_default_method(const DH_METHOD *meth);
const DH_METHOD *DH_get_default_method(void);
int DH_set_method(DH *dh, const DH_METHOD *meth);
DH *DH_new_method(ENGINE *engine);
DH * DH_new(void);
void DH_free(DH *dh);
int DH_up_ref(DH *dh);
int DH_size(const DH *dh);
int DH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int DH_set_ex_data(DH *d, int idx, void *arg);
void *DH_get_ex_data(DH *d, int idx);
DH * DH_generate_parameters(int prime_len,int generator,
  void (*callback)(int,int,void *),void *cb_arg);
int DH_generate_parameters_ex(DH *dh, int prime_len,int generator, BN_GENCB *cb);
int DH_check(const DH *dh,int *codes);
int DH_check_pub_key(const DH *dh,const BIGNUM *pub_key, int *codes);
int DH_generate_key(DH *dh);
int DH_compute_key(unsigned char *key,const BIGNUM *pub_key,DH *dh);
DH * d2i_DHparams(DH **a,const unsigned char **pp, long length);
int i2d_DHparams(const DH *a,unsigned char **pp);
int DHparams_print_fp(FILE *fp, const DH *x);
int DHparams_print(BIO *bp, const DH *x);
void ERR_load_DH_strings(void);
}
extern "C" {
typedef struct DSA_SIG_st
 {
 BIGNUM *r;
 BIGNUM *s;
 } DSA_SIG;
struct dsa_method
 {
 const char *name;
 DSA_SIG * (*dsa_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa);
 int (*dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
        BIGNUM **rp);
 int (*dsa_do_verify)(const unsigned char *dgst, int dgst_len,
       DSA_SIG *sig, DSA *dsa);
 int (*dsa_mod_exp)(DSA *dsa, BIGNUM *rr, BIGNUM *a1, BIGNUM *p1,
   BIGNUM *a2, BIGNUM *p2, BIGNUM *m, BN_CTX *ctx,
   BN_MONT_CTX *in_mont);
 int (*bn_mod_exp)(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *m_ctx);
 int (*init)(DSA *dsa);
 int (*finish)(DSA *dsa);
 int flags;
 char *app_data;
 int (*dsa_paramgen)(DSA *dsa, int bits,
   unsigned char *seed, int seed_len,
   int *counter_ret, unsigned long *h_ret,
   BN_GENCB *cb);
 int (*dsa_keygen)(DSA *dsa);
 };
struct dsa_st
 {
 int pad;
 long version;
 int write_params;
 BIGNUM *p;
 BIGNUM *q;
 BIGNUM *g;
 BIGNUM *pub_key;
 BIGNUM *priv_key;
 BIGNUM *kinv;
 BIGNUM *r;
 int flags;
 BN_MONT_CTX *method_mont_p;
 int references;
 CRYPTO_EX_DATA ex_data;
 const DSA_METHOD *meth;
 ENGINE *engine;
 };
DSA_SIG * DSA_SIG_new(void);
void DSA_SIG_free(DSA_SIG *a);
int i2d_DSA_SIG(const DSA_SIG *a, unsigned char **pp);
DSA_SIG * d2i_DSA_SIG(DSA_SIG **v, const unsigned char **pp, long length);
DSA_SIG * DSA_do_sign(const unsigned char *dgst,int dlen,DSA *dsa);
int DSA_do_verify(const unsigned char *dgst,int dgst_len,
        DSA_SIG *sig,DSA *dsa);
const DSA_METHOD *DSA_OpenSSL(void);
void DSA_set_default_method(const DSA_METHOD *);
const DSA_METHOD *DSA_get_default_method(void);
int DSA_set_method(DSA *dsa, const DSA_METHOD *);
DSA * DSA_new(void);
DSA * DSA_new_method(ENGINE *engine);
void DSA_free (DSA *r);
int DSA_up_ref(DSA *r);
int DSA_size(const DSA *);
int DSA_sign_setup( DSA *dsa,BN_CTX *ctx_in,BIGNUM **kinvp,BIGNUM **rp);
int DSA_sign(int type,const unsigned char *dgst,int dlen,
  unsigned char *sig, unsigned int *siglen, DSA *dsa);
int DSA_verify(int type,const unsigned char *dgst,int dgst_len,
  const unsigned char *sigbuf, int siglen, DSA *dsa);
int DSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int DSA_set_ex_data(DSA *d, int idx, void *arg);
void *DSA_get_ex_data(DSA *d, int idx);
DSA * d2i_DSAPublicKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAPrivateKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAparams(DSA **a, const unsigned char **pp, long length);
DSA * DSA_generate_parameters(int bits,
  unsigned char *seed,int seed_len,
  int *counter_ret, unsigned long *h_ret,void
  (*callback)(int, int, void *),void *cb_arg);
int DSA_generate_parameters_ex(DSA *dsa, int bits,
  unsigned char *seed,int seed_len,
  int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
int DSA_generate_key(DSA *a);
int i2d_DSAPublicKey(const DSA *a, unsigned char **pp);
int i2d_DSAPrivateKey(const DSA *a, unsigned char **pp);
int i2d_DSAparams(const DSA *a,unsigned char **pp);
int DSAparams_print(BIO *bp, const DSA *x);
int DSA_print(BIO *bp, const DSA *x, int off);
int DSAparams_print_fp(FILE *fp, const DSA *x);
int DSA_print_fp(FILE *bp, const DSA *x, int off);
DH *DSA_dup_DH(const DSA *r);
void ERR_load_DSA_strings(void);
}
extern "C" {
struct rsa_meth_st
 {
 const char *name;
 int (*rsa_pub_enc)(int flen,const unsigned char *from,
      unsigned char *to,
      RSA *rsa,int padding);
 int (*rsa_pub_dec)(int flen,const unsigned char *from,
      unsigned char *to,
      RSA *rsa,int padding);
 int (*rsa_priv_enc)(int flen,const unsigned char *from,
       unsigned char *to,
       RSA *rsa,int padding);
 int (*rsa_priv_dec)(int flen,const unsigned char *from,
       unsigned char *to,
       RSA *rsa,int padding);
 int (*rsa_mod_exp)(BIGNUM *r0,const BIGNUM *I,RSA *rsa,BN_CTX *ctx);
 int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx,
     BN_MONT_CTX *m_ctx);
 int (*init)(RSA *rsa);
 int (*finish)(RSA *rsa);
 int flags;
 char *app_data;
 int (*rsa_sign)(int type,
  const unsigned char *m, unsigned int m_length,
  unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
 int (*rsa_verify)(int dtype,
  const unsigned char *m, unsigned int m_length,
  unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);
 int (*rsa_keygen)(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
 };
struct rsa_st
 {
 int pad;
 long version;
 const RSA_METHOD *meth;
 ENGINE *engine;
 BIGNUM *n;
 BIGNUM *e;
 BIGNUM *d;
 BIGNUM *p;
 BIGNUM *q;
 BIGNUM *dmp1;
 BIGNUM *dmq1;
 BIGNUM *iqmp;
 CRYPTO_EX_DATA ex_data;
 int references;
 int flags;
 BN_MONT_CTX *_method_mod_n;
 BN_MONT_CTX *_method_mod_p;
 BN_MONT_CTX *_method_mod_q;
 char *bignum_data;
 BN_BLINDING *blinding;
 BN_BLINDING *mt_blinding;
 };
RSA * RSA_new(void);
RSA * RSA_new_method(ENGINE *engine);
int RSA_size(const RSA *);
RSA * RSA_generate_key(int bits, unsigned long e,void
  (*callback)(int,int,void *),void *cb_arg);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2,
   const BIGNUM *Xp1, const BIGNUM *Xp2, const BIGNUM *Xp,
   const BIGNUM *Xq1, const BIGNUM *Xq2, const BIGNUM *Xq,
   const BIGNUM *e, BN_GENCB *cb);
int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e, BN_GENCB *cb);
int RSA_check_key(const RSA *);
int RSA_public_encrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_private_encrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_public_decrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
int RSA_private_decrypt(int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa,int padding);
void RSA_free (RSA *r);
int RSA_up_ref(RSA *r);
int RSA_flags(const RSA *r);
void RSA_set_default_method(const RSA_METHOD *meth);
const RSA_METHOD *RSA_get_default_method(void);
const RSA_METHOD *RSA_get_method(const RSA *rsa);
int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);
int RSA_memory_lock(RSA *r);
const RSA_METHOD *RSA_PKCS1_SSLeay(void);
const RSA_METHOD *RSA_null_method(void);
RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPublicKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPublicKey_it;
RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPrivateKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPrivateKey_it;
int RSA_print_fp(FILE *fp, const RSA *r,int offset);
int RSA_print(BIO *bp, const RSA *r,int offset);
int i2d_RSA_NET(const RSA *a, unsigned char **pp,
  int (*cb)(char *buf, int len, const char *prompt, int verify),
  int sgckey);
RSA *d2i_RSA_NET(RSA **a, const unsigned char **pp, long length,
   int (*cb)(char *buf, int len, const char *prompt, int verify),
   int sgckey);
int i2d_Netscape_RSA(const RSA *a, unsigned char **pp,
       int (*cb)(char *buf, int len, const char *prompt,
          int verify));
RSA *d2i_Netscape_RSA(RSA **a, const unsigned char **pp, long length,
        int (*cb)(char *buf, int len, const char *prompt,
    int verify));
int RSA_sign(int type, const unsigned char *m, unsigned int m_length,
 unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
 unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
int RSA_sign_ASN1_OCTET_STRING(int type,
 const unsigned char *m, unsigned int m_length,
 unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int type,
 const unsigned char *m, unsigned int m_length,
 unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
void RSA_blinding_off(RSA *rsa);
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);
int RSA_padding_add_PKCS1_type_1(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_1(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_PKCS1_type_2(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_PKCS1_type_2(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int PKCS1_MGF1(unsigned char *mask, long len,
 const unsigned char *seed, long seedlen, const EVP_MD *dgst);
int RSA_padding_add_PKCS1_OAEP(unsigned char *to,int tlen,
 const unsigned char *f,int fl,
 const unsigned char *p,int pl);
int RSA_padding_check_PKCS1_OAEP(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len,
 const unsigned char *p,int pl);
int RSA_padding_add_SSLv23(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_SSLv23(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_none(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_none(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_padding_add_X931(unsigned char *to,int tlen,
 const unsigned char *f,int fl);
int RSA_padding_check_X931(unsigned char *to,int tlen,
 const unsigned char *f,int fl,int rsa_len);
int RSA_X931_hash_id(int nid);
int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash,
   const EVP_MD *Hash, const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM,
   const unsigned char *mHash,
   const EVP_MD *Hash, int sLen);
int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int RSA_set_ex_data(RSA *r,int idx,void *arg);
void *RSA_get_ex_data(const RSA *r, int idx);
RSA *RSAPublicKey_dup(RSA *rsa);
RSA *RSAPrivateKey_dup(RSA *rsa);
void ERR_load_RSA_strings(void);
}
extern "C" {
typedef enum {
 POINT_CONVERSION_COMPRESSED = 2,
 POINT_CONVERSION_UNCOMPRESSED = 4,
 POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;
typedef struct ec_method_st EC_METHOD;
typedef struct ec_group_st
 EC_GROUP;
typedef struct ec_point_st EC_POINT;
const EC_METHOD *EC_GFp_simple_method(void);
const EC_METHOD *EC_GFp_mont_method(void);
const EC_METHOD *EC_GFp_nist_method(void);
const EC_METHOD *EC_GF2m_simple_method(void);
EC_GROUP *EC_GROUP_new(const EC_METHOD *);
void EC_GROUP_free(EC_GROUP *);
void EC_GROUP_clear_free(EC_GROUP *);
int EC_GROUP_copy(EC_GROUP *, const EC_GROUP *);
EC_GROUP *EC_GROUP_dup(const EC_GROUP *);
const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *);
int EC_METHOD_get_field_type(const EC_METHOD *);
int EC_GROUP_set_generator(EC_GROUP *, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
int EC_GROUP_get_order(const EC_GROUP *, BIGNUM *order, BN_CTX *);
int EC_GROUP_get_cofactor(const EC_GROUP *, BIGNUM *cofactor, BN_CTX *);
void EC_GROUP_set_curve_name(EC_GROUP *, int nid);
int EC_GROUP_get_curve_name(const EC_GROUP *);
void EC_GROUP_set_asn1_flag(EC_GROUP *, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *);
void EC_GROUP_set_point_conversion_form(EC_GROUP *, point_conversion_form_t);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);
unsigned char *EC_GROUP_get0_seed(const EC_GROUP *);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
int EC_GROUP_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int EC_GROUP_get_curve_GFp(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int EC_GROUP_set_curve_GF2m(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int EC_GROUP_get_curve_GF2m(const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *);
int EC_GROUP_get_degree(const EC_GROUP *);
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_check_discriminant(const EC_GROUP *, BN_CTX *);
int EC_GROUP_cmp(const EC_GROUP *, const EC_GROUP *, BN_CTX *);
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
typedef struct {
 int nid;
 const char *comment;
 } EC_builtin_curve;
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
void EC_POINT_clear_free(EC_POINT *);
int EC_POINT_copy(EC_POINT *, const EC_POINT *);
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);
const EC_METHOD *EC_POINT_method_of(const EC_POINT *);
int EC_POINT_set_to_infinity(const EC_GROUP *, EC_POINT *);
int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
 const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *);
int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
 BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *);
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *, EC_POINT *,
 const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *, const EC_POINT *,
 BIGNUM *x, BIGNUM *y, BN_CTX *);
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *, EC_POINT *,
 const BIGNUM *x, int y_bit, BN_CTX *);
int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
 const BIGNUM *x, const BIGNUM *y, BN_CTX *);
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *, const EC_POINT *,
 BIGNUM *x, BIGNUM *y, BN_CTX *);
int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *, EC_POINT *,
 const BIGNUM *x, int y_bit, BN_CTX *);
size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
        const unsigned char *buf, size_t len, BN_CTX *);
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
 EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
 EC_POINT *, BN_CTX *);
int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
int EC_POINT_invert(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);
int EC_POINT_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);
int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *a, const EC_POINT *b, BN_CTX *);
int EC_POINT_make_affine(const EC_GROUP *, EC_POINT *, BN_CTX *);
int EC_POINTs_make_affine(const EC_GROUP *, size_t num, EC_POINT *[], BN_CTX *);
int EC_POINTs_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, size_t num, const EC_POINT *[], const BIGNUM *[], BN_CTX *);
int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *, const EC_POINT *, const BIGNUM *, BN_CTX *);
int EC_GROUP_precompute_mult(EC_GROUP *, BN_CTX *);
int EC_GROUP_have_precompute_mult(const EC_GROUP *);
int EC_GROUP_get_basis_type(const EC_GROUP *);
int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);
int EC_GROUP_get_pentanomial_basis(const EC_GROUP *, unsigned int *k1,
 unsigned int *k2, unsigned int *k3);
typedef struct ecpk_parameters_st ECPKPARAMETERS;
EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);
int ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);
int ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off);
typedef struct ec_key_st EC_KEY;
EC_KEY *EC_KEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *);
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);
int EC_KEY_up_ref(EC_KEY *);
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
int EC_KEY_set_group(EC_KEY *, const EC_GROUP *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);
unsigned EC_KEY_get_enc_flags(const EC_KEY *);
void EC_KEY_set_enc_flags(EC_KEY *, unsigned int);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *);
void EC_KEY_set_conv_form(EC_KEY *, point_conversion_form_t);
void *EC_KEY_get_key_method_data(EC_KEY *,
 void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
void EC_KEY_insert_key_method_data(EC_KEY *, void *data,
 void *(*dup_func)(void *), void (*free_func)(void *), void (*clear_free_func)(void *));
void EC_KEY_set_asn1_flag(EC_KEY *, int);
int EC_KEY_precompute_mult(EC_KEY *, BN_CTX *ctx);
int EC_KEY_generate_key(EC_KEY *);
int EC_KEY_check_key(const EC_KEY *);
EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len);
int i2d_ECPrivateKey(EC_KEY *a, unsigned char **out);
EC_KEY *d2i_ECParameters(EC_KEY **a, const unsigned char **in, long len);
int i2d_ECParameters(EC_KEY *a, unsigned char **out);
EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len);
int i2o_ECPublicKey(EC_KEY *a, unsigned char **out);
int ECParameters_print(BIO *bp, const EC_KEY *x);
int EC_KEY_print(BIO *bp, const EC_KEY *x, int off);
int ECParameters_print_fp(FILE *fp, const EC_KEY *x);
int EC_KEY_print_fp(FILE *fp, const EC_KEY *x, int off);
void ERR_load_EC_strings(void);
}
extern "C" {
const ECDH_METHOD *ECDH_OpenSSL(void);
void ECDH_set_default_method(const ECDH_METHOD *);
const ECDH_METHOD *ECDH_get_default_method(void);
int ECDH_set_method(EC_KEY *, const ECDH_METHOD *);
int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
                     void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
int ECDH_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new
  *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ECDH_set_ex_data(EC_KEY *d, int idx, void *arg);
void *ECDH_get_ex_data(EC_KEY *d, int idx);
void ERR_load_ECDH_strings(void);
}
extern "C" {
typedef struct ECDSA_SIG_st
 {
 BIGNUM *r;
 BIGNUM *s;
 } ECDSA_SIG;
ECDSA_SIG *ECDSA_SIG_new(void);
void ECDSA_SIG_free(ECDSA_SIG *a);
int i2d_ECDSA_SIG(const ECDSA_SIG *a, unsigned char **pp);
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **v, const unsigned char **pp, long len);
ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst,int dgst_len,EC_KEY *eckey);
ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen,
  const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
  const ECDSA_SIG *sig, EC_KEY* eckey);
const ECDSA_METHOD *ECDSA_OpenSSL(void);
void ECDSA_set_default_method(const ECDSA_METHOD *meth);
const ECDSA_METHOD *ECDSA_get_default_method(void);
int ECDSA_set_method(EC_KEY *eckey, const ECDSA_METHOD *meth);
int ECDSA_size(const EC_KEY *eckey);
int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
  BIGNUM **rp);
int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen,
  unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen,
  unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
  const BIGNUM *rp, EC_KEY *eckey);
int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen,
  const unsigned char *sig, int siglen, EC_KEY *eckey);
int ECDSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new
  *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ECDSA_set_ex_data(EC_KEY *d, int idx, void *arg);
void *ECDSA_get_ex_data(EC_KEY *d, int idx);
void ERR_load_ECDSA_strings(void);
}
extern "C" {
struct rand_meth_st
 {
 void (*seed)(const void *buf, int num);
 int (*bytes)(unsigned char *buf, int num);
 void (*cleanup)(void);
 void (*add)(const void *buf, int num, double entropy);
 int (*pseudorand)(unsigned char *buf, int num);
 int (*status)(void);
 };
int RAND_set_rand_method(const RAND_METHOD *meth);
const RAND_METHOD *RAND_get_rand_method(void);
int RAND_set_rand_engine(ENGINE *engine);
RAND_METHOD *RAND_SSLeay(void);
void RAND_cleanup(void );
int RAND_bytes(unsigned char *buf,int num);
int RAND_pseudo_bytes(unsigned char *buf,int num);
void RAND_seed(const void *buf,int num);
void RAND_add(const void *buf,int num,double entropy);
int RAND_load_file(const char *file,long max_bytes);
int RAND_write_file(const char *file);
const char *RAND_file_name(char *file,size_t num);
int RAND_status(void);
int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);
int RAND_egd(const char *path);
int RAND_egd_bytes(const char *path,int bytes);
int RAND_poll(void);
void ERR_load_RAND_strings(void);
}
extern "C" {
typedef int ptrdiff_t;
struct buf_mem_st
 {
 int length;
 char *data;
 int max;
 };
BUF_MEM *BUF_MEM_new(void);
void BUF_MEM_free(BUF_MEM *a);
int BUF_MEM_grow(BUF_MEM *str, int len);
int BUF_MEM_grow_clean(BUF_MEM *str, int len);
char * BUF_strdup(const char *str);
char * BUF_strndup(const char *str, size_t siz);
void * BUF_memdup(const void *data, size_t siz);
size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
size_t BUF_strlcat(char *dst,const char *src,size_t siz);
void ERR_load_BUF_strings(void);
}
extern "C" {
typedef struct SHAstate_st
 {
 unsigned int h0,h1,h2,h3,h4;
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num;
 } SHA_CTX;
int SHA_Init(SHA_CTX *c);
int SHA_Update(SHA_CTX *c, const void *data, size_t len);
int SHA_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA(const unsigned char *d, size_t n, unsigned char *md);
void SHA_Transform(SHA_CTX *c, const unsigned char *data);
int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
typedef struct SHA256state_st
 {
 unsigned int h[8];
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num,md_len;
 } SHA256_CTX;
int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n,unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n,unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);
typedef struct SHA512state_st
 {
 unsigned long long h[8];
 unsigned long long Nl,Nh;
 union {
  unsigned long long d[16];
  unsigned char p[(16*8)];
 } u;
 unsigned int num,md_len;
 } SHA512_CTX;
int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n,unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, size_t n,unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);
}
extern "C" {
typedef struct X509_objects_st
 {
 int nid;
 int (*a2i)(void);
 int (*i2a)(void);
 } X509_OBJECTS;
struct X509_algor_st
 {
 ASN1_OBJECT *algorithm;
 ASN1_TYPE *parameter;
 } ;

typedef STACK X509_ALGORS;
typedef struct X509_val_st
 {
 ASN1_TIME *notBefore;
 ASN1_TIME *notAfter;
 } X509_VAL;
typedef struct X509_pubkey_st
 {
 X509_ALGOR *algor;
 ASN1_BIT_STRING *public_key;
 EVP_PKEY *pkey;
 } X509_PUBKEY;
typedef struct X509_sig_st
 {
 X509_ALGOR *algor;
 ASN1_OCTET_STRING *digest;
 } X509_SIG;
typedef struct X509_name_entry_st
 {
 ASN1_OBJECT *object;
 ASN1_STRING *value;
 int set;
 int size;
 } X509_NAME_ENTRY;


struct X509_name_st
 {
 STACK *entries;
 int modified;
 BUF_MEM *bytes;
 unsigned long hash;
 } ;

typedef struct X509_extension_st
 {
 ASN1_OBJECT *object;
 ASN1_BOOLEAN critical;
 ASN1_OCTET_STRING *value;
 } X509_EXTENSION;
typedef STACK X509_EXTENSIONS;


typedef struct x509_attributes_st
 {
 ASN1_OBJECT *object;
 int single;
 union {
  char *ptr;
         STACK *set;
         ASN1_TYPE *single;
  } value;
 } X509_ATTRIBUTE;


typedef struct X509_req_info_st
 {
 ASN1_ENCODING enc;
 ASN1_INTEGER *version;
 X509_NAME *subject;
 X509_PUBKEY *pubkey;
 STACK *attributes;
 } X509_REQ_INFO;
typedef struct X509_req_st
 {
 X509_REQ_INFO *req_info;
 X509_ALGOR *sig_alg;
 ASN1_BIT_STRING *signature;
 int references;
 } X509_REQ;
typedef struct x509_cinf_st
 {
 ASN1_INTEGER *version;
 ASN1_INTEGER *serialNumber;
 X509_ALGOR *signature;
 X509_NAME *issuer;
 X509_VAL *validity;
 X509_NAME *subject;
 X509_PUBKEY *key;
 ASN1_BIT_STRING *issuerUID;
 ASN1_BIT_STRING *subjectUID;
 STACK *extensions;
 } X509_CINF;
typedef struct x509_cert_aux_st
 {
 STACK *trust;
 STACK *reject;
 ASN1_UTF8STRING *alias;
 ASN1_OCTET_STRING *keyid;
 STACK *other;
 } X509_CERT_AUX;
struct x509_st
 {
 X509_CINF *cert_info;
 X509_ALGOR *sig_alg;
 ASN1_BIT_STRING *signature;
 int valid;
 int references;
 char *name;
 CRYPTO_EX_DATA ex_data;
 long ex_pathlen;
 long ex_pcpathlen;
 unsigned long ex_flags;
 unsigned long ex_kusage;
 unsigned long ex_xkusage;
 unsigned long ex_nscert;
 ASN1_OCTET_STRING *skid;
 struct AUTHORITY_KEYID_st *akid;
 X509_POLICY_CACHE *policy_cache;
 unsigned char sha1_hash[20];
 X509_CERT_AUX *aux;
 } ;


typedef struct x509_trust_st {
 int trust;
 int flags;
 int (*check_trust)(struct x509_trust_st *, X509 *, int);
 char *name;
 int arg1;
 void *arg2;
} X509_TRUST;

typedef struct x509_cert_pair_st {
 X509 *forward;
 X509 *reverse;
} X509_CERT_PAIR;
typedef struct X509_revoked_st
 {
 ASN1_INTEGER *serialNumber;
 ASN1_TIME *revocationDate;
 STACK *extensions;
 int sequence;
 } X509_REVOKED;


typedef struct X509_crl_info_st
 {
 ASN1_INTEGER *version;
 X509_ALGOR *sig_alg;
 X509_NAME *issuer;
 ASN1_TIME *lastUpdate;
 ASN1_TIME *nextUpdate;
 STACK *revoked;
 STACK *extensions;
 ASN1_ENCODING enc;
 } X509_CRL_INFO;
struct X509_crl_st
 {
 X509_CRL_INFO *crl;
 X509_ALGOR *sig_alg;
 ASN1_BIT_STRING *signature;
 int references;
 } ;


typedef struct private_key_st
 {
 int version;
 X509_ALGOR *enc_algor;
 ASN1_OCTET_STRING *enc_pkey;
 EVP_PKEY *dec_pkey;
 int key_length;
 char *key_data;
 int key_free;
 EVP_CIPHER_INFO cipher;
 int references;
 } X509_PKEY;
typedef struct X509_info_st
 {
 X509 *x509;
 X509_CRL *crl;
 X509_PKEY *x_pkey;
 EVP_CIPHER_INFO enc_cipher;
 int enc_len;
 char *enc_data;
 int references;
 } X509_INFO;

typedef struct Netscape_spkac_st
 {
 X509_PUBKEY *pubkey;
 ASN1_IA5STRING *challenge;
 } NETSCAPE_SPKAC;
typedef struct Netscape_spki_st
 {
 NETSCAPE_SPKAC *spkac;
 X509_ALGOR *sig_algor;
 ASN1_BIT_STRING *signature;
 } NETSCAPE_SPKI;
typedef struct Netscape_certificate_sequence
 {
 ASN1_OBJECT *type;
 STACK *certs;
 } NETSCAPE_CERT_SEQUENCE;
typedef struct PBEPARAM_st {
ASN1_OCTET_STRING *salt;
ASN1_INTEGER *iter;
} PBEPARAM;
typedef struct PBE2PARAM_st {
X509_ALGOR *keyfunc;
X509_ALGOR *encryption;
} PBE2PARAM;
typedef struct PBKDF2PARAM_st {
ASN1_TYPE *salt;
ASN1_INTEGER *iter;
ASN1_INTEGER *keylength;
X509_ALGOR *prf;
} PBKDF2PARAM;
typedef struct pkcs8_priv_key_info_st
        {
        int broken;
        ASN1_INTEGER *version;
        X509_ALGOR *pkeyalg;
        ASN1_TYPE *pkey;
        STACK *attributes;
        } PKCS8_PRIV_KEY_INFO;
}
extern "C" {
typedef struct lhash_node_st
 {
 void *data;
 struct lhash_node_st *next;
 unsigned long hash;
 } LHASH_NODE;
typedef int (*LHASH_COMP_FN_TYPE)(const void *, const void *);
typedef unsigned long (*LHASH_HASH_FN_TYPE)(const void *);
typedef void (*LHASH_DOALL_FN_TYPE)(void *);
typedef void (*LHASH_DOALL_ARG_FN_TYPE)(void *, void *);
typedef struct lhash_st
 {
 LHASH_NODE **b;
 LHASH_COMP_FN_TYPE comp;
 LHASH_HASH_FN_TYPE hash;
 unsigned int num_nodes;
 unsigned int num_alloc_nodes;
 unsigned int p;
 unsigned int pmax;
 unsigned long up_load;
 unsigned long down_load;
 unsigned long num_items;
 unsigned long num_expands;
 unsigned long num_expand_reallocs;
 unsigned long num_contracts;
 unsigned long num_contract_reallocs;
 unsigned long num_hash_calls;
 unsigned long num_comp_calls;
 unsigned long num_insert;
 unsigned long num_replace;
 unsigned long num_delete;
 unsigned long num_no_delete;
 unsigned long num_retrieve;
 unsigned long num_retrieve_miss;
 unsigned long num_hash_comps;
 int error;
 } LHASH;
LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c);
void lh_free(LHASH *lh);
void *lh_insert(LHASH *lh, void *data);
void *lh_delete(LHASH *lh, const void *data);
void *lh_retrieve(LHASH *lh, const void *data);
void lh_doall(LHASH *lh, LHASH_DOALL_FN_TYPE func);
void lh_doall_arg(LHASH *lh, LHASH_DOALL_ARG_FN_TYPE func, void *arg);
unsigned long lh_strhash(const char *c);
unsigned long lh_num_items(const LHASH *lh);
void lh_stats(const LHASH *lh, FILE *out);
void lh_node_stats(const LHASH *lh, FILE *out);
void lh_node_usage_stats(const LHASH *lh, FILE *out);
void lh_stats_bio(const LHASH *lh, BIO *out);
void lh_node_stats_bio(const LHASH *lh, BIO *out);
void lh_node_usage_stats_bio(const LHASH *lh, BIO *out);
}
extern "C" {
typedef struct x509_hash_dir_st
 {
 int num_dirs;
 char **dirs;
 int *dirs_type;
 int num_dirs_alloced;
 } X509_HASH_DIR_CTX;
typedef struct x509_file_st
 {
 int num_paths;
 int num_alloced;
 char **paths;
 int *path_type;
 } X509_CERT_FILE_CTX;
typedef struct x509_object_st
 {
 int type;
 union {
  char *ptr;
  X509 *x509;
  X509_CRL *crl;
  EVP_PKEY *pkey;
  } data;
 } X509_OBJECT;
typedef struct x509_lookup_st X509_LOOKUP;


typedef struct x509_lookup_method_st
 {
 const char *name;
 int (*new_item)(X509_LOOKUP *ctx);
 void (*free)(X509_LOOKUP *ctx);
 int (*init)(X509_LOOKUP *ctx);
 int (*shutdown)(X509_LOOKUP *ctx);
 int (*ctrl)(X509_LOOKUP *ctx,int cmd,const char *argc,long argl,
   char **ret);
 int (*get_by_subject)(X509_LOOKUP *ctx,int type,X509_NAME *name,
         X509_OBJECT *ret);
 int (*get_by_issuer_serial)(X509_LOOKUP *ctx,int type,X509_NAME *name,
        ASN1_INTEGER *serial,X509_OBJECT *ret);
 int (*get_by_fingerprint)(X509_LOOKUP *ctx,int type,
      unsigned char *bytes,int len,
      X509_OBJECT *ret);
 int (*get_by_alias)(X509_LOOKUP *ctx,int type,char *str,int len,
       X509_OBJECT *ret);
 } X509_LOOKUP_METHOD;
typedef struct X509_VERIFY_PARAM_st
 {
 char *name;
 time_t check_time;
 unsigned long inh_flags;
 unsigned long flags;
 int purpose;
 int trust;
 int depth;
 STACK *policies;
 } X509_VERIFY_PARAM;

struct x509_store_st
 {
 int cache;
 STACK *objs;
 STACK *get_cert_methods;
 X509_VERIFY_PARAM *param;
 int (*verify)(X509_STORE_CTX *ctx);
 int (*verify_cb)(int ok,X509_STORE_CTX *ctx);
 int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
 int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
 int (*check_revocation)(X509_STORE_CTX *ctx);
 int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
 int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl);
 int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
 int (*cleanup)(X509_STORE_CTX *ctx);
 CRYPTO_EX_DATA ex_data;
 int references;
 } ;
int X509_STORE_set_depth(X509_STORE *store, int depth);
struct x509_lookup_st
 {
 int init;
 int skip;
 X509_LOOKUP_METHOD *method;
 char *method_data;
 X509_STORE *store_ctx;
 } ;
struct x509_store_ctx_st
 {
 X509_STORE *ctx;
 int current_method;
 X509 *cert;
 STACK *untrusted;
 STACK *crls;
 X509_VERIFY_PARAM *param;
 void *other_ctx;
 int (*verify)(X509_STORE_CTX *ctx);
 int (*verify_cb)(int ok,X509_STORE_CTX *ctx);
 int (*get_issuer)(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
 int (*check_issued)(X509_STORE_CTX *ctx, X509 *x, X509 *issuer);
 int (*check_revocation)(X509_STORE_CTX *ctx);
 int (*get_crl)(X509_STORE_CTX *ctx, X509_CRL **crl, X509 *x);
 int (*check_crl)(X509_STORE_CTX *ctx, X509_CRL *crl);
 int (*cert_crl)(X509_STORE_CTX *ctx, X509_CRL *crl, X509 *x);
 int (*check_policy)(X509_STORE_CTX *ctx);
 int (*cleanup)(X509_STORE_CTX *ctx);
 int valid;
 int last_untrusted;
 STACK *chain;
 X509_POLICY_TREE *tree;
 int explicit_policy;
 int error_depth;
 int error;
 X509 *current_cert;
 X509 *current_issuer;
 X509_CRL *current_crl;
 CRYPTO_EX_DATA ex_data;
 } ;
void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth);
int X509_OBJECT_idx_by_subject(STACK *h, int type,
      X509_NAME *name);
X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK *h,int type,X509_NAME *name);
X509_OBJECT *X509_OBJECT_retrieve_match(STACK *h, X509_OBJECT *x);
void X509_OBJECT_up_ref_count(X509_OBJECT *a);
void X509_OBJECT_free_contents(X509_OBJECT *a);
X509_STORE *X509_STORE_new(void );
void X509_STORE_free(X509_STORE *v);
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);
int X509_STORE_set_purpose(X509_STORE *ctx, int purpose);
int X509_STORE_set_trust(X509_STORE *ctx, int trust);
int X509_STORE_set1_param(X509_STORE *ctx, X509_VERIFY_PARAM *pm);
X509_STORE_CTX *X509_STORE_CTX_new(void);
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
    X509 *x509, STACK *chain);
void X509_STORE_CTX_trusted_stack(X509_STORE_CTX *ctx, STACK *sk);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m);
X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);
int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);
int X509_STORE_get_by_subject(X509_STORE_CTX *vs,int type,X509_NAME *name,
 X509_OBJECT *ret);
int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
 long argl, char **ret);
int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);
X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
void X509_LOOKUP_free(X509_LOOKUP *ctx);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, int type, X509_NAME *name,
 X509_OBJECT *ret);
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, int type, X509_NAME *name,
 ASN1_INTEGER *serial, X509_OBJECT *ret);
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, int type,
 unsigned char *bytes, int len, X509_OBJECT *ret);
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, int type, char *str,
 int len, X509_OBJECT *ret);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);
int X509_STORE_load_locations (X509_STORE *ctx,
  const char *file, const char *dir);
int X509_STORE_set_default_paths(X509_STORE *ctx);
int X509_STORE_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx,int idx,void *data);
void * X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx,int idx);
int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx,int s);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
STACK *X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);
STACK *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_cert(X509_STORE_CTX *c,X509 *x);
void X509_STORE_CTX_set_chain(X509_STORE_CTX *c,STACK *sk);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *c,STACK *sk);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
    int purpose, int trust);
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags);
void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags,
        time_t t);
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx,
      int (*verify_cb)(int, X509_STORE_CTX *));
X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_explicit_policy(X509_STORE_CTX *ctx);
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *to,
      const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,
      const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags);
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,
       unsigned long flags);
unsigned long X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);
int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param,
      ASN1_OBJECT *policy);
int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
     STACK *policies);
int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name);
void X509_VERIFY_PARAM_table_cleanup(void);
int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy,
   STACK *certs,
   STACK *policy_oids,
   unsigned int flags);
void X509_policy_tree_free(X509_POLICY_TREE *tree);
int X509_policy_tree_level_count(const X509_POLICY_TREE *tree);
X509_POLICY_LEVEL *
 X509_policy_tree_get0_level(const X509_POLICY_TREE *tree, int i);
STACK *
 X509_policy_tree_get0_policies(const X509_POLICY_TREE *tree);
STACK *
 X509_policy_tree_get0_user_policies(const X509_POLICY_TREE *tree);
int X509_policy_level_node_count(X509_POLICY_LEVEL *level);
X509_POLICY_NODE *X509_policy_level_get0_node(X509_POLICY_LEVEL *level, int i);
const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node);
STACK *
 X509_policy_node_get0_qualifiers(const X509_POLICY_NODE *node);
const X509_POLICY_NODE *
 X509_policy_node_get0_parent(const X509_POLICY_NODE *node);
}
extern "C" {
typedef struct pkcs7_issuer_and_serial_st
 {
 X509_NAME *issuer;
 ASN1_INTEGER *serial;
 } PKCS7_ISSUER_AND_SERIAL;
typedef struct pkcs7_signer_info_st
 {
 ASN1_INTEGER *version;
 PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
 X509_ALGOR *digest_alg;
 STACK *auth_attr;
 X509_ALGOR *digest_enc_alg;
 ASN1_OCTET_STRING *enc_digest;
 STACK *unauth_attr;
 EVP_PKEY *pkey;
 } PKCS7_SIGNER_INFO;


typedef struct pkcs7_recip_info_st
 {
 ASN1_INTEGER *version;
 PKCS7_ISSUER_AND_SERIAL *issuer_and_serial;
 X509_ALGOR *key_enc_algor;
 ASN1_OCTET_STRING *enc_key;
 X509 *cert;
 } PKCS7_RECIP_INFO;


typedef struct pkcs7_signed_st
 {
 ASN1_INTEGER *version;
 STACK *md_algs;
 STACK *cert;
 STACK *crl;
 STACK *signer_info;
 struct pkcs7_st *contents;
 } PKCS7_SIGNED;
typedef struct pkcs7_enc_content_st
 {
 ASN1_OBJECT *content_type;
 X509_ALGOR *algorithm;
 ASN1_OCTET_STRING *enc_data;
 const EVP_CIPHER *cipher;
 } PKCS7_ENC_CONTENT;
typedef struct pkcs7_enveloped_st
 {
 ASN1_INTEGER *version;
 STACK *recipientinfo;
 PKCS7_ENC_CONTENT *enc_data;
 } PKCS7_ENVELOPE;
typedef struct pkcs7_signedandenveloped_st
 {
 ASN1_INTEGER *version;
 STACK *md_algs;
 STACK *cert;
 STACK *crl;
 STACK *signer_info;
 PKCS7_ENC_CONTENT *enc_data;
 STACK *recipientinfo;
 } PKCS7_SIGN_ENVELOPE;
typedef struct pkcs7_digest_st
 {
 ASN1_INTEGER *version;
 X509_ALGOR *md;
 struct pkcs7_st *contents;
 ASN1_OCTET_STRING *digest;
 } PKCS7_DIGEST;
typedef struct pkcs7_encrypted_st
 {
 ASN1_INTEGER *version;
 PKCS7_ENC_CONTENT *enc_data;
 } PKCS7_ENCRYPT;
typedef struct pkcs7_st
 {
 unsigned char *asn1;
 long length;
 int state;
 int detached;
 ASN1_OBJECT *type;
 union {
  char *ptr;
  ASN1_OCTET_STRING *data;
  PKCS7_SIGNED *sign;
  PKCS7_ENVELOPE *enveloped;
  PKCS7_SIGN_ENVELOPE *signed_and_enveloped;
  PKCS7_DIGEST *digest;
  PKCS7_ENCRYPT *encrypted;
  ASN1_TYPE *other;
  } d;
 } PKCS7;



PKCS7_ISSUER_AND_SERIAL *PKCS7_ISSUER_AND_SERIAL_new(void); void PKCS7_ISSUER_AND_SERIAL_free(PKCS7_ISSUER_AND_SERIAL *a); PKCS7_ISSUER_AND_SERIAL *d2i_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL **a, const unsigned char **in, long len); int i2d_PKCS7_ISSUER_AND_SERIAL(PKCS7_ISSUER_AND_SERIAL *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ISSUER_AND_SERIAL_it;
int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data,const EVP_MD *type,
 unsigned char *md,unsigned int *len);
PKCS7 *d2i_PKCS7_fp(FILE *fp,PKCS7 **p7);
int i2d_PKCS7_fp(FILE *fp,PKCS7 *p7);
PKCS7 *PKCS7_dup(PKCS7 *p7);
PKCS7 *d2i_PKCS7_bio(BIO *bp,PKCS7 **p7);
int i2d_PKCS7_bio(BIO *bp,PKCS7 *p7);
PKCS7_SIGNER_INFO *PKCS7_SIGNER_INFO_new(void); void PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO *a); PKCS7_SIGNER_INFO *d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO **a, const unsigned char **in, long len); int i2d_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGNER_INFO_it;
PKCS7_RECIP_INFO *PKCS7_RECIP_INFO_new(void); void PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO *a); PKCS7_RECIP_INFO *d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO **a, const unsigned char **in, long len); int i2d_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS7_RECIP_INFO_it;
PKCS7_SIGNED *PKCS7_SIGNED_new(void); void PKCS7_SIGNED_free(PKCS7_SIGNED *a); PKCS7_SIGNED *d2i_PKCS7_SIGNED(PKCS7_SIGNED **a, const unsigned char **in, long len); int i2d_PKCS7_SIGNED(PKCS7_SIGNED *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGNED_it;
PKCS7_ENC_CONTENT *PKCS7_ENC_CONTENT_new(void); void PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT *a); PKCS7_ENC_CONTENT *d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT **a, const unsigned char **in, long len); int i2d_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENC_CONTENT_it;
PKCS7_ENVELOPE *PKCS7_ENVELOPE_new(void); void PKCS7_ENVELOPE_free(PKCS7_ENVELOPE *a); PKCS7_ENVELOPE *d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE **a, const unsigned char **in, long len); int i2d_PKCS7_ENVELOPE(PKCS7_ENVELOPE *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENVELOPE_it;
PKCS7_SIGN_ENVELOPE *PKCS7_SIGN_ENVELOPE_new(void); void PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE *a); PKCS7_SIGN_ENVELOPE *d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE **a, const unsigned char **in, long len); int i2d_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGN_ENVELOPE_it;
PKCS7_DIGEST *PKCS7_DIGEST_new(void); void PKCS7_DIGEST_free(PKCS7_DIGEST *a); PKCS7_DIGEST *d2i_PKCS7_DIGEST(PKCS7_DIGEST **a, const unsigned char **in, long len); int i2d_PKCS7_DIGEST(PKCS7_DIGEST *a, unsigned char **out); extern const ASN1_ITEM PKCS7_DIGEST_it;
PKCS7_ENCRYPT *PKCS7_ENCRYPT_new(void); void PKCS7_ENCRYPT_free(PKCS7_ENCRYPT *a); PKCS7_ENCRYPT *d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT **a, const unsigned char **in, long len); int i2d_PKCS7_ENCRYPT(PKCS7_ENCRYPT *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENCRYPT_it;
PKCS7 *PKCS7_new(void); void PKCS7_free(PKCS7 *a); PKCS7 *d2i_PKCS7(PKCS7 **a, const unsigned char **in, long len); int i2d_PKCS7(PKCS7 *a, unsigned char **out); extern const ASN1_ITEM PKCS7_it;
extern const ASN1_ITEM PKCS7_ATTR_SIGN_it;
extern const ASN1_ITEM PKCS7_ATTR_VERIFY_it;
int i2d_PKCS7_NDEF(PKCS7 *a, unsigned char **out);
long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg);
int PKCS7_set_type(PKCS7 *p7, int type);
int PKCS7_set0_type_other(PKCS7 *p7, int type, ASN1_TYPE *other);
int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data);
int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey,
 const EVP_MD *dgst);
int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *p7i);
int PKCS7_add_certificate(PKCS7 *p7, X509 *x509);
int PKCS7_add_crl(PKCS7 *p7, X509_CRL *x509);
int PKCS7_content_new(PKCS7 *p7, int nid);
int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx,
 BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si);
int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si,
        X509 *x509);
BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio);
int PKCS7_dataFinal(PKCS7 *p7, BIO *bio);
BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert);
PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509,
 EVP_PKEY *pkey, const EVP_MD *dgst);
X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si);
int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md);
STACK *PKCS7_get_signer_info(PKCS7 *p7);
PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509);
int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri);
int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509);
int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher);
PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx);
ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK *sk);
int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si,int nid,int type,
 void *data);
int PKCS7_add_attribute (PKCS7_SIGNER_INFO *p7si, int nid, int atrtype,
 void *value);
ASN1_TYPE *PKCS7_get_attribute(PKCS7_SIGNER_INFO *si, int nid);
ASN1_TYPE *PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si, int nid);
int PKCS7_set_signed_attributes(PKCS7_SIGNER_INFO *p7si,
    STACK *sk);
int PKCS7_set_attributes(PKCS7_SIGNER_INFO *p7si,STACK *sk);
PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK *certs,
       BIO *data, int flags);
int PKCS7_verify(PKCS7 *p7, STACK *certs, X509_STORE *store,
     BIO *indata, BIO *out, int flags);
STACK *PKCS7_get0_signers(PKCS7 *p7, STACK *certs, int flags);
PKCS7 *PKCS7_encrypt(STACK *certs, BIO *in, const EVP_CIPHER *cipher,
        int flags);
int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags);
int PKCS7_add_attrib_smimecap(PKCS7_SIGNER_INFO *si,
         STACK *cap);
STACK *PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si);
int PKCS7_simple_smimecap(STACK *sk, int nid, int arg);
int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags);
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);
void ERR_load_PKCS7_strings(void);
}
extern "C" {
const char *X509_verify_cert_error_string(long n);
int X509_verify(X509 *a, EVP_PKEY *r);
int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r);
NETSCAPE_SPKI * NETSCAPE_SPKI_b64_decode(const char *str, int len);
char * NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);
int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);
int X509_signature_print(BIO *bp,X509_ALGOR *alg, ASN1_STRING *sig);
int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_pubkey_digest(const X509 *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_digest(const X509 *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_CRL_digest(const X509_CRL *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_REQ_digest(const X509_REQ *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
int X509_NAME_digest(const X509_NAME *data,const EVP_MD *type,
  unsigned char *md, unsigned int *len);
X509 *d2i_X509_fp(FILE *fp, X509 **x509);
int i2d_X509_fp(FILE *fp,X509 *x509);
X509_CRL *d2i_X509_CRL_fp(FILE *fp,X509_CRL **crl);
int i2d_X509_CRL_fp(FILE *fp,X509_CRL *crl);
X509_REQ *d2i_X509_REQ_fp(FILE *fp,X509_REQ **req);
int i2d_X509_REQ_fp(FILE *fp,X509_REQ *req);
RSA *d2i_RSAPrivateKey_fp(FILE *fp,RSA **rsa);
int i2d_RSAPrivateKey_fp(FILE *fp,RSA *rsa);
RSA *d2i_RSAPublicKey_fp(FILE *fp,RSA **rsa);
int i2d_RSAPublicKey_fp(FILE *fp,RSA *rsa);
RSA *d2i_RSA_PUBKEY_fp(FILE *fp,RSA **rsa);
int i2d_RSA_PUBKEY_fp(FILE *fp,RSA *rsa);
DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
X509_SIG *d2i_PKCS8_fp(FILE *fp,X509_SIG **p8);
int i2d_PKCS8_fp(FILE *fp,X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
      PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
X509 *d2i_X509_bio(BIO *bp,X509 **x509);
int i2d_X509_bio(BIO *bp,X509 *x509);
X509_CRL *d2i_X509_CRL_bio(BIO *bp,X509_CRL **crl);
int i2d_X509_CRL_bio(BIO *bp,X509_CRL *crl);
X509_REQ *d2i_X509_REQ_bio(BIO *bp,X509_REQ **req);
int i2d_X509_REQ_bio(BIO *bp,X509_REQ *req);
RSA *d2i_RSAPrivateKey_bio(BIO *bp,RSA **rsa);
int i2d_RSAPrivateKey_bio(BIO *bp,RSA *rsa);
RSA *d2i_RSAPublicKey_bio(BIO *bp,RSA **rsa);
int i2d_RSAPublicKey_bio(BIO *bp,RSA *rsa);
RSA *d2i_RSA_PUBKEY_bio(BIO *bp,RSA **rsa);
int i2d_RSA_PUBKEY_bio(BIO *bp,RSA *rsa);
DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa);
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa);
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);
int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey);
X509_SIG *d2i_PKCS8_bio(BIO *bp,X509_SIG **p8);
int i2d_PKCS8_bio(BIO *bp,X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
      PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key);
int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
X509 *X509_dup(X509 *x509);
X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *xa);
X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex);
X509_CRL *X509_CRL_dup(X509_CRL *crl);
X509_REQ *X509_REQ_dup(X509_REQ *req);
X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn);
int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval);
void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval,
      X509_ALGOR *algor);
X509_NAME *X509_NAME_dup(X509_NAME *xn);
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);
int X509_cmp_time(ASN1_TIME *s, time_t *t);
int X509_cmp_current_time(ASN1_TIME *s);
ASN1_TIME * X509_time_adj(ASN1_TIME *s, long adj, time_t *t);
ASN1_TIME * X509_gmtime_adj(ASN1_TIME *s, long adj);
const char * X509_get_default_cert_area(void );
const char * X509_get_default_cert_dir(void );
const char * X509_get_default_cert_file(void );
const char * X509_get_default_cert_dir_env(void );
const char * X509_get_default_cert_file_env(void );
const char * X509_get_default_private_dir(void );
X509_REQ * X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
X509 * X509_REQ_to_X509(X509_REQ *r, int days,EVP_PKEY *pkey);
X509_ALGOR *X509_ALGOR_new(void); void X509_ALGOR_free(X509_ALGOR *a); X509_ALGOR *d2i_X509_ALGOR(X509_ALGOR **a, const unsigned char **in, long len); int i2d_X509_ALGOR(X509_ALGOR *a, unsigned char **out); extern const ASN1_ITEM X509_ALGOR_it;
X509_ALGORS *d2i_X509_ALGORS(X509_ALGORS **a, const unsigned char **in, long len); int i2d_X509_ALGORS(X509_ALGORS *a, unsigned char **out); extern const ASN1_ITEM X509_ALGORS_it;
X509_VAL *X509_VAL_new(void); void X509_VAL_free(X509_VAL *a); X509_VAL *d2i_X509_VAL(X509_VAL **a, const unsigned char **in, long len); int i2d_X509_VAL(X509_VAL *a, unsigned char **out); extern const ASN1_ITEM X509_VAL_it;
X509_PUBKEY *X509_PUBKEY_new(void); void X509_PUBKEY_free(X509_PUBKEY *a); X509_PUBKEY *d2i_X509_PUBKEY(X509_PUBKEY **a, const unsigned char **in, long len); int i2d_X509_PUBKEY(X509_PUBKEY *a, unsigned char **out); extern const ASN1_ITEM X509_PUBKEY_it;
int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
EVP_PKEY * X509_PUBKEY_get(X509_PUBKEY *key);
int X509_get_pubkey_parameters(EVP_PKEY *pkey,
        STACK *chain);
int i2d_PUBKEY(EVP_PKEY *a,unsigned char **pp);
EVP_PKEY * d2i_PUBKEY(EVP_PKEY **a,const unsigned char **pp,
   long length);
int i2d_RSA_PUBKEY(RSA *a,unsigned char **pp);
RSA * d2i_RSA_PUBKEY(RSA **a,const unsigned char **pp,
   long length);
int i2d_DSA_PUBKEY(DSA *a,unsigned char **pp);
DSA * d2i_DSA_PUBKEY(DSA **a,const unsigned char **pp,
   long length);
int i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp);
EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp,
   long length);
X509_SIG *X509_SIG_new(void); void X509_SIG_free(X509_SIG *a); X509_SIG *d2i_X509_SIG(X509_SIG **a, const unsigned char **in, long len); int i2d_X509_SIG(X509_SIG *a, unsigned char **out); extern const ASN1_ITEM X509_SIG_it;
X509_REQ_INFO *X509_REQ_INFO_new(void); void X509_REQ_INFO_free(X509_REQ_INFO *a); X509_REQ_INFO *d2i_X509_REQ_INFO(X509_REQ_INFO **a, const unsigned char **in, long len); int i2d_X509_REQ_INFO(X509_REQ_INFO *a, unsigned char **out); extern const ASN1_ITEM X509_REQ_INFO_it;
X509_REQ *X509_REQ_new(void); void X509_REQ_free(X509_REQ *a); X509_REQ *d2i_X509_REQ(X509_REQ **a, const unsigned char **in, long len); int i2d_X509_REQ(X509_REQ *a, unsigned char **out); extern const ASN1_ITEM X509_REQ_it;
X509_ATTRIBUTE *X509_ATTRIBUTE_new(void); void X509_ATTRIBUTE_free(X509_ATTRIBUTE *a); X509_ATTRIBUTE *d2i_X509_ATTRIBUTE(X509_ATTRIBUTE **a, const unsigned char **in, long len); int i2d_X509_ATTRIBUTE(X509_ATTRIBUTE *a, unsigned char **out); extern const ASN1_ITEM X509_ATTRIBUTE_it;
X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value);
X509_EXTENSION *X509_EXTENSION_new(void); void X509_EXTENSION_free(X509_EXTENSION *a); X509_EXTENSION *d2i_X509_EXTENSION(X509_EXTENSION **a, const unsigned char **in, long len); int i2d_X509_EXTENSION(X509_EXTENSION *a, unsigned char **out); extern const ASN1_ITEM X509_EXTENSION_it;
X509_EXTENSIONS *d2i_X509_EXTENSIONS(X509_EXTENSIONS **a, const unsigned char **in, long len); int i2d_X509_EXTENSIONS(X509_EXTENSIONS *a, unsigned char **out); extern const ASN1_ITEM X509_EXTENSIONS_it;
X509_NAME_ENTRY *X509_NAME_ENTRY_new(void); void X509_NAME_ENTRY_free(X509_NAME_ENTRY *a); X509_NAME_ENTRY *d2i_X509_NAME_ENTRY(X509_NAME_ENTRY **a, const unsigned char **in, long len); int i2d_X509_NAME_ENTRY(X509_NAME_ENTRY *a, unsigned char **out); extern const ASN1_ITEM X509_NAME_ENTRY_it;
X509_NAME *X509_NAME_new(void); void X509_NAME_free(X509_NAME *a); X509_NAME *d2i_X509_NAME(X509_NAME **a, const unsigned char **in, long len); int i2d_X509_NAME(X509_NAME *a, unsigned char **out); extern const ASN1_ITEM X509_NAME_it;
int X509_NAME_set(X509_NAME **xn, X509_NAME *name);
X509_CINF *X509_CINF_new(void); void X509_CINF_free(X509_CINF *a); X509_CINF *d2i_X509_CINF(X509_CINF **a, const unsigned char **in, long len); int i2d_X509_CINF(X509_CINF *a, unsigned char **out); extern const ASN1_ITEM X509_CINF_it;
X509 *X509_new(void); void X509_free(X509 *a); X509 *d2i_X509(X509 **a, const unsigned char **in, long len); int i2d_X509(X509 *a, unsigned char **out); extern const ASN1_ITEM X509_it;
X509_CERT_AUX *X509_CERT_AUX_new(void); void X509_CERT_AUX_free(X509_CERT_AUX *a); X509_CERT_AUX *d2i_X509_CERT_AUX(X509_CERT_AUX **a, const unsigned char **in, long len); int i2d_X509_CERT_AUX(X509_CERT_AUX *a, unsigned char **out); extern const ASN1_ITEM X509_CERT_AUX_it;
X509_CERT_PAIR *X509_CERT_PAIR_new(void); void X509_CERT_PAIR_free(X509_CERT_PAIR *a); X509_CERT_PAIR *d2i_X509_CERT_PAIR(X509_CERT_PAIR **a, const unsigned char **in, long len); int i2d_X509_CERT_PAIR(X509_CERT_PAIR *a, unsigned char **out); extern const ASN1_ITEM X509_CERT_PAIR_it;
int X509_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
      CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int X509_set_ex_data(X509 *r, int idx, void *arg);
void *X509_get_ex_data(X509 *r, int idx);
int i2d_X509_AUX(X509 *a,unsigned char **pp);
X509 * d2i_X509_AUX(X509 **a,const unsigned char **pp,long length);
int X509_alias_set1(X509 *x, unsigned char *name, int len);
int X509_keyid_set1(X509 *x, unsigned char *id, int len);
unsigned char * X509_alias_get0(X509 *x, int *len);
unsigned char * X509_keyid_get0(X509 *x, int *len);
int (*X509_TRUST_set_default(int (*trust)(int , X509 *, int)))(int, X509 *, int);
int X509_TRUST_set(int *t, int trust);
int X509_add1_trust_object(X509 *x, ASN1_OBJECT *obj);
int X509_add1_reject_object(X509 *x, ASN1_OBJECT *obj);
void X509_trust_clear(X509 *x);
void X509_reject_clear(X509 *x);
X509_REVOKED *X509_REVOKED_new(void); void X509_REVOKED_free(X509_REVOKED *a); X509_REVOKED *d2i_X509_REVOKED(X509_REVOKED **a, const unsigned char **in, long len); int i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **out); extern const ASN1_ITEM X509_REVOKED_it;
X509_CRL_INFO *X509_CRL_INFO_new(void); void X509_CRL_INFO_free(X509_CRL_INFO *a); X509_CRL_INFO *d2i_X509_CRL_INFO(X509_CRL_INFO **a, const unsigned char **in, long len); int i2d_X509_CRL_INFO(X509_CRL_INFO *a, unsigned char **out); extern const ASN1_ITEM X509_CRL_INFO_it;
X509_CRL *X509_CRL_new(void); void X509_CRL_free(X509_CRL *a); X509_CRL *d2i_X509_CRL(X509_CRL **a, const unsigned char **in, long len); int i2d_X509_CRL(X509_CRL *a, unsigned char **out); extern const ASN1_ITEM X509_CRL_it;
int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
X509_PKEY * X509_PKEY_new(void );
void X509_PKEY_free(X509_PKEY *a);
int i2d_X509_PKEY(X509_PKEY *a,unsigned char **pp);
X509_PKEY * d2i_X509_PKEY(X509_PKEY **a,const unsigned char **pp,long length);
NETSCAPE_SPKI *NETSCAPE_SPKI_new(void); void NETSCAPE_SPKI_free(NETSCAPE_SPKI *a); NETSCAPE_SPKI *d2i_NETSCAPE_SPKI(NETSCAPE_SPKI **a, const unsigned char **in, long len); int i2d_NETSCAPE_SPKI(NETSCAPE_SPKI *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_SPKI_it;
NETSCAPE_SPKAC *NETSCAPE_SPKAC_new(void); void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC *a); NETSCAPE_SPKAC *d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC **a, const unsigned char **in, long len); int i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_SPKAC_it;
NETSCAPE_CERT_SEQUENCE *NETSCAPE_CERT_SEQUENCE_new(void); void NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE *a); NETSCAPE_CERT_SEQUENCE *d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE **a, const unsigned char **in, long len); int i2d_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_CERT_SEQUENCE_it;
X509_INFO * X509_INFO_new(void);
void X509_INFO_free(X509_INFO *a);
char * X509_NAME_oneline(X509_NAME *a,char *buf,int size);
int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *algor1,
  ASN1_BIT_STRING *signature,char *data,EVP_PKEY *pkey);
int ASN1_digest(i2d_of_void *i2d,const EVP_MD *type,char *data,
  unsigned char *md,unsigned int *len);
int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1,
       X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
       char *data,EVP_PKEY *pkey, const EVP_MD *type);
int ASN1_item_digest(const ASN1_ITEM *it,const EVP_MD *type,void *data,
 unsigned char *md,unsigned int *len);
int ASN1_item_verify(const ASN1_ITEM *it, X509_ALGOR *algor1,
 ASN1_BIT_STRING *signature,void *data,EVP_PKEY *pkey);
int ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2,
 ASN1_BIT_STRING *signature,
 void *data, EVP_PKEY *pkey, const EVP_MD *type);
int X509_set_version(X509 *x,long version);
int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
ASN1_INTEGER * X509_get_serialNumber(X509 *x);
int X509_set_issuer_name(X509 *x, X509_NAME *name);
X509_NAME * X509_get_issuer_name(X509 *a);
int X509_set_subject_name(X509 *x, X509_NAME *name);
X509_NAME * X509_get_subject_name(X509 *a);
int X509_set_notBefore(X509 *x, ASN1_TIME *tm);
int X509_set_notAfter(X509 *x, ASN1_TIME *tm);
int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
EVP_PKEY * X509_get_pubkey(X509 *x);
ASN1_BIT_STRING * X509_get0_pubkey_bitstr(const X509 *x);
int X509_certificate_type(X509 *x,EVP_PKEY *pubkey );
int X509_REQ_set_version(X509_REQ *x,long version);
int X509_REQ_set_subject_name(X509_REQ *req,X509_NAME *name);
int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
EVP_PKEY * X509_REQ_get_pubkey(X509_REQ *req);
int X509_REQ_extension_nid(int nid);
int * X509_REQ_get_extension_nids(void);
void X509_REQ_set_extension_nids(int *nids);
STACK *X509_REQ_get_extensions(X509_REQ *req);
int X509_REQ_add_extensions_nid(X509_REQ *req, STACK *exts,
    int nid);
int X509_REQ_add_extensions(X509_REQ *req, STACK *exts);
int X509_REQ_get_attr_count(const X509_REQ *req);
int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid,
     int lastpos);
int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc);
X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc);
int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr);
int X509_REQ_add1_attr_by_OBJ(X509_REQ *req,
   const ASN1_OBJECT *obj, int type,
   const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_NID(X509_REQ *req,
   int nid, int type,
   const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_txt(X509_REQ *req,
   const char *attrname, int type,
   const unsigned char *bytes, int len);
int X509_CRL_set_version(X509_CRL *x, long version);
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
int X509_CRL_set_lastUpdate(X509_CRL *x, ASN1_TIME *tm);
int X509_CRL_set_nextUpdate(X509_CRL *x, ASN1_TIME *tm);
int X509_CRL_sort(X509_CRL *crl);
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm);
int X509_REQ_check_private_key(X509_REQ *x509,EVP_PKEY *pkey);
int X509_check_private_key(X509 *x509,EVP_PKEY *pkey);
int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_and_serial_hash(X509 *a);
int X509_issuer_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_name_hash(X509 *a);
int X509_subject_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_subject_name_hash(X509 *x);
int X509_cmp(const X509 *a, const X509 *b);
int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
unsigned long X509_NAME_hash(X509_NAME *x);
int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b);
int X509_print_ex_fp(FILE *bp,X509 *x, unsigned long nmflag, unsigned long cflag);
int X509_print_fp(FILE *bp,X509 *x);
int X509_CRL_print_fp(FILE *bp,X509_CRL *x);
int X509_REQ_print_fp(FILE *bp,X509_REQ *req);
int X509_NAME_print_ex_fp(FILE *fp, X509_NAME *nm, int indent, unsigned long flags);
int X509_NAME_print(BIO *bp, X509_NAME *name, int obase);
int X509_NAME_print_ex(BIO *out, X509_NAME *nm, int indent, unsigned long flags);
int X509_print_ex(BIO *bp,X509 *x, unsigned long nmflag, unsigned long cflag);
int X509_print(BIO *bp,X509 *x);
int X509_ocspid_print(BIO *bp,X509 *x);
int X509_CERT_AUX_print(BIO *bp,X509_CERT_AUX *x, int indent);
int X509_CRL_print(BIO *bp,X509_CRL *x);
int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag, unsigned long cflag);
int X509_REQ_print(BIO *bp,X509_REQ *req);
int X509_NAME_entry_count(X509_NAME *name);
int X509_NAME_get_text_by_NID(X509_NAME *name, int nid,
   char *buf,int len);
int X509_NAME_get_text_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj,
   char *buf,int len);
int X509_NAME_get_index_by_NID(X509_NAME *name,int nid,int lastpos);
int X509_NAME_get_index_by_OBJ(X509_NAME *name,ASN1_OBJECT *obj,
   int lastpos);
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
int X509_NAME_add_entry(X509_NAME *name,X509_NAME_ENTRY *ne,
   int loc, int set);
int X509_NAME_add_entry_by_OBJ(X509_NAME *name, ASN1_OBJECT *obj, int type,
   unsigned char *bytes, int len, int loc, int set);
int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type,
   unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
  const char *field, int type, const unsigned char *bytes, int len);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid,
   int type,unsigned char *bytes, int len);
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type,
   const unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
   ASN1_OBJECT *obj, int type,const unsigned char *bytes,
   int len);
int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne,
   ASN1_OBJECT *obj);
int X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type,
   const unsigned char *bytes, int len);
ASN1_OBJECT * X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);
ASN1_STRING * X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);
int X509v3_get_ext_count(const STACK *x);
int X509v3_get_ext_by_NID(const STACK *x,
          int nid, int lastpos);
int X509v3_get_ext_by_OBJ(const STACK *x,
          ASN1_OBJECT *obj,int lastpos);
int X509v3_get_ext_by_critical(const STACK *x,
        int crit, int lastpos);
X509_EXTENSION *X509v3_get_ext(const STACK *x, int loc);
X509_EXTENSION *X509v3_delete_ext(STACK *x, int loc);
STACK *X509v3_add_ext(STACK **x,
      X509_EXTENSION *ex, int loc);
int X509_get_ext_count(X509 *x);
int X509_get_ext_by_NID(X509 *x, int nid, int lastpos);
int X509_get_ext_by_OBJ(X509 *x,ASN1_OBJECT *obj,int lastpos);
int X509_get_ext_by_critical(X509 *x, int crit, int lastpos);
X509_EXTENSION *X509_get_ext(X509 *x, int loc);
X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
void * X509_get_ext_d2i(X509 *x, int nid, int *crit, int *idx);
int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit,
       unsigned long flags);
int X509_CRL_get_ext_count(X509_CRL *x);
int X509_CRL_get_ext_by_NID(X509_CRL *x, int nid, int lastpos);
int X509_CRL_get_ext_by_OBJ(X509_CRL *x,ASN1_OBJECT *obj,int lastpos);
int X509_CRL_get_ext_by_critical(X509_CRL *x, int crit, int lastpos);
X509_EXTENSION *X509_CRL_get_ext(X509_CRL *x, int loc);
X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
void * X509_CRL_get_ext_d2i(X509_CRL *x, int nid, int *crit, int *idx);
int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,
       unsigned long flags);
int X509_REVOKED_get_ext_count(X509_REVOKED *x);
int X509_REVOKED_get_ext_by_NID(X509_REVOKED *x, int nid, int lastpos);
int X509_REVOKED_get_ext_by_OBJ(X509_REVOKED *x,ASN1_OBJECT *obj,int lastpos);
int X509_REVOKED_get_ext_by_critical(X509_REVOKED *x, int crit, int lastpos);
X509_EXTENSION *X509_REVOKED_get_ext(X509_REVOKED *x, int loc);
X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc);
int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
void * X509_REVOKED_get_ext_d2i(X509_REVOKED *x, int nid, int *crit, int *idx);
int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit,
       unsigned long flags);
X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,
   int nid, int crit, ASN1_OCTET_STRING *data);
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
   ASN1_OBJECT *obj,int crit,ASN1_OCTET_STRING *data);
int X509_EXTENSION_set_object(X509_EXTENSION *ex,ASN1_OBJECT *obj);
int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
int X509_EXTENSION_set_data(X509_EXTENSION *ex,
   ASN1_OCTET_STRING *data);
ASN1_OBJECT * X509_EXTENSION_get_object(X509_EXTENSION *ex);
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);
int X509_EXTENSION_get_critical(X509_EXTENSION *ex);
int X509at_get_attr_count(const STACK *x);
int X509at_get_attr_by_NID(const STACK *x, int nid,
     int lastpos);
int X509at_get_attr_by_OBJ(const STACK *sk, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *X509at_get_attr(const STACK *x, int loc);
X509_ATTRIBUTE *X509at_delete_attr(STACK *x, int loc);
STACK *X509at_add1_attr(STACK **x,
      X509_ATTRIBUTE *attr);
STACK *X509at_add1_attr_by_OBJ(STACK **x,
   const ASN1_OBJECT *obj, int type,
   const unsigned char *bytes, int len);
STACK *X509at_add1_attr_by_NID(STACK **x,
   int nid, int type,
   const unsigned char *bytes, int len);
STACK *X509at_add1_attr_by_txt(STACK **x,
   const char *attrname, int type,
   const unsigned char *bytes, int len);
void *X509at_get0_data_by_OBJ(STACK *x,
    ASN1_OBJECT *obj, int lastpos, int type);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid,
      int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
      const ASN1_OBJECT *obj, int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
  const char *atrname, int type, const unsigned char *bytes, int len);
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj);
int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype, const void *data, int len);
void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx,
     int atrtype, void *data);
int X509_ATTRIBUTE_count(X509_ATTRIBUTE *attr);
ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx);
int EVP_PKEY_get_attr_count(const EVP_PKEY *key);
int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid,
     int lastpos);
int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, ASN1_OBJECT *obj,
     int lastpos);
X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc);
X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc);
int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr);
int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key,
   const ASN1_OBJECT *obj, int type,
   const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key,
   int nid, int type,
   const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key,
   const char *attrname, int type,
   const unsigned char *bytes, int len);
int X509_verify_cert(X509_STORE_CTX *ctx);
X509 *X509_find_by_issuer_and_serial(STACK *sk,X509_NAME *name,
         ASN1_INTEGER *serial);
X509 *X509_find_by_subject(STACK *sk,X509_NAME *name);
PBEPARAM *PBEPARAM_new(void); void PBEPARAM_free(PBEPARAM *a); PBEPARAM *d2i_PBEPARAM(PBEPARAM **a, const unsigned char **in, long len); int i2d_PBEPARAM(PBEPARAM *a, unsigned char **out); extern const ASN1_ITEM PBEPARAM_it;
PBE2PARAM *PBE2PARAM_new(void); void PBE2PARAM_free(PBE2PARAM *a); PBE2PARAM *d2i_PBE2PARAM(PBE2PARAM **a, const unsigned char **in, long len); int i2d_PBE2PARAM(PBE2PARAM *a, unsigned char **out); extern const ASN1_ITEM PBE2PARAM_it;
PBKDF2PARAM *PBKDF2PARAM_new(void); void PBKDF2PARAM_free(PBKDF2PARAM *a); PBKDF2PARAM *d2i_PBKDF2PARAM(PBKDF2PARAM **a, const unsigned char **in, long len); int i2d_PBKDF2PARAM(PBKDF2PARAM *a, unsigned char **out); extern const ASN1_ITEM PBKDF2PARAM_it;
X509_ALGOR *PKCS5_pbe_set(int alg, int iter, unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
      unsigned char *salt, int saltlen);
PKCS8_PRIV_KEY_INFO *PKCS8_PRIV_KEY_INFO_new(void); void PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *a); PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO **a, const unsigned char **in, long len); int i2d_PKCS8_PRIV_KEY_INFO(PKCS8_PRIV_KEY_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS8_PRIV_KEY_INFO_it;
EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8);
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey);
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey, int broken);
PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken);
int X509_check_trust(X509 *x, int id, int flags);
int X509_TRUST_get_count(void);
X509_TRUST * X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
int X509_TRUST_add(int id, int flags, int (*ck)(X509_TRUST *, X509 *, int),
     char *name, int arg1, void *arg2);
void X509_TRUST_cleanup(void);
int X509_TRUST_get_flags(X509_TRUST *xp);
char *X509_TRUST_get0_name(X509_TRUST *xp);
int X509_TRUST_get_trust(X509_TRUST *xp);
void ERR_load_X509_strings(void);
}
extern "C" {
STORE *STORE_new_method(const STORE_METHOD *method);
STORE *STORE_new_engine(ENGINE *engine);
void STORE_free(STORE *ui);
int STORE_ctrl(STORE *store, int cmd, long i, void *p, void (*f)(void));
int STORE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
 CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int STORE_set_ex_data(STORE *r,int idx,void *arg);
void *STORE_get_ex_data(STORE *r, int idx);
const STORE_METHOD *STORE_get_method(STORE *store);
const STORE_METHOD *STORE_set_method(STORE *store, const STORE_METHOD *meth);
const STORE_METHOD *STORE_Memory(void);
typedef enum STORE_object_types
 {
 STORE_OBJECT_TYPE_X509_CERTIFICATE= 0x01,
 STORE_OBJECT_TYPE_X509_CRL= 0x02,
 STORE_OBJECT_TYPE_PRIVATE_KEY= 0x03,
 STORE_OBJECT_TYPE_PUBLIC_KEY= 0x04,
 STORE_OBJECT_TYPE_NUMBER= 0x05,
 STORE_OBJECT_TYPE_ARBITRARY= 0x06,
 STORE_OBJECT_TYPE_NUM= 0x06
 } STORE_OBJECT_TYPES;
extern const char * const STORE_object_type_string[STORE_OBJECT_TYPE_NUM+1];
typedef enum STORE_params
 {
 STORE_PARAM_EVP_TYPE= 0x01,
 STORE_PARAM_BITS= 0x02,
 STORE_PARAM_KEY_PARAMETERS= 0x03,
 STORE_PARAM_KEY_NO_PARAMETERS= 0x04,
 STORE_PARAM_AUTH_PASSPHRASE= 0x05,
 STORE_PARAM_AUTH_KRB5_TICKET= 0x06,
 STORE_PARAM_TYPE_NUM= 0x06
 } STORE_PARAM_TYPES;
extern const int STORE_param_sizes[STORE_PARAM_TYPE_NUM+1];
typedef enum STORE_attribs
 {
 STORE_ATTR_END= 0x00,
 STORE_ATTR_FRIENDLYNAME= 0x01,
 STORE_ATTR_KEYID= 0x02,
 STORE_ATTR_ISSUERKEYID= 0x03,
 STORE_ATTR_SUBJECTKEYID= 0x04,
 STORE_ATTR_ISSUERSERIALHASH= 0x05,
 STORE_ATTR_ISSUER= 0x06,
 STORE_ATTR_SERIAL= 0x07,
 STORE_ATTR_SUBJECT= 0x08,
 STORE_ATTR_CERTHASH= 0x09,
 STORE_ATTR_EMAIL= 0x0a,
 STORE_ATTR_FILENAME= 0x0b,
 STORE_ATTR_TYPE_NUM= 0x0b,
 STORE_ATTR_OR= 0xff
 } STORE_ATTR_TYPES;
extern const int STORE_attr_sizes[STORE_ATTR_TYPE_NUM+1];
typedef enum STORE_certificate_status
 {
 STORE_X509_VALID= 0x00,
 STORE_X509_EXPIRED= 0x01,
 STORE_X509_SUSPENDED= 0x02,
 STORE_X509_REVOKED= 0x03
 } STORE_CERTIFICATE_STATUS;
typedef struct STORE_OBJECT_st
 {
 STORE_OBJECT_TYPES type;
 union
  {
  struct
   {
   STORE_CERTIFICATE_STATUS status;
   X509 *certificate;
   } x509;
  X509_CRL *crl;
  EVP_PKEY *key;
  BIGNUM *number;
  BUF_MEM *arbitrary;
  } data;
 } STORE_OBJECT;

STORE_OBJECT *STORE_OBJECT_new(void);
void STORE_OBJECT_free(STORE_OBJECT *data);
X509 *STORE_get_certificate(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_store_certificate(STORE *e, X509 *data, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_modify_certificate(STORE *e, OPENSSL_ITEM search_attributes[],
 OPENSSL_ITEM add_attributes[], OPENSSL_ITEM modify_attributes[],
 OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
int STORE_revoke_certificate(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_delete_certificate(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
void *STORE_list_certificate_start(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
X509 *STORE_list_certificate_next(STORE *e, void *handle);
int STORE_list_certificate_end(STORE *e, void *handle);
int STORE_list_certificate_endp(STORE *e, void *handle);
EVP_PKEY *STORE_generate_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
EVP_PKEY *STORE_get_private_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_store_private_key(STORE *e, EVP_PKEY *data,
 OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
int STORE_modify_private_key(STORE *e, OPENSSL_ITEM search_attributes[],
 OPENSSL_ITEM add_sttributes[], OPENSSL_ITEM modify_attributes[],
 OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
int STORE_revoke_private_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_delete_private_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
void *STORE_list_private_key_start(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
EVP_PKEY *STORE_list_private_key_next(STORE *e, void *handle);
int STORE_list_private_key_end(STORE *e, void *handle);
int STORE_list_private_key_endp(STORE *e, void *handle);
EVP_PKEY *STORE_get_public_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_store_public_key(STORE *e, EVP_PKEY *data, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_modify_public_key(STORE *e, OPENSSL_ITEM search_attributes[],
 OPENSSL_ITEM add_sttributes[], OPENSSL_ITEM modify_attributes[],
 OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
int STORE_revoke_public_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_delete_public_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
void *STORE_list_public_key_start(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
EVP_PKEY *STORE_list_public_key_next(STORE *e, void *handle);
int STORE_list_public_key_end(STORE *e, void *handle);
int STORE_list_public_key_endp(STORE *e, void *handle);
X509_CRL *STORE_generate_crl(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
X509_CRL *STORE_get_crl(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_store_crl(STORE *e, X509_CRL *data, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_modify_crl(STORE *e, OPENSSL_ITEM search_attributes[],
 OPENSSL_ITEM add_sttributes[], OPENSSL_ITEM modify_attributes[],
 OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
int STORE_delete_crl(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
void *STORE_list_crl_start(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
X509_CRL *STORE_list_crl_next(STORE *e, void *handle);
int STORE_list_crl_end(STORE *e, void *handle);
int STORE_list_crl_endp(STORE *e, void *handle);
int STORE_store_number(STORE *e, BIGNUM *data, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_modify_number(STORE *e, OPENSSL_ITEM search_attributes[],
 OPENSSL_ITEM add_sttributes[], OPENSSL_ITEM modify_attributes[],
 OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
BIGNUM *STORE_get_number(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_delete_number(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_store_arbitrary(STORE *e, BUF_MEM *data, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_modify_arbitrary(STORE *e, OPENSSL_ITEM search_attributes[],
 OPENSSL_ITEM add_sttributes[], OPENSSL_ITEM modify_attributes[],
 OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
BUF_MEM *STORE_get_arbitrary(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
int STORE_delete_arbitrary(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
STORE_METHOD *STORE_create_method(char *name);
void STORE_destroy_method(STORE_METHOD *store_method);
typedef int (*STORE_INITIALISE_FUNC_PTR)(STORE *);
typedef void (*STORE_CLEANUP_FUNC_PTR)(STORE *);
typedef STORE_OBJECT *(*STORE_GENERATE_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
typedef STORE_OBJECT *(*STORE_GET_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
typedef void *(*STORE_START_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
typedef STORE_OBJECT *(*STORE_NEXT_OBJECT_FUNC_PTR)(STORE *, void *handle);
typedef int (*STORE_END_OBJECT_FUNC_PTR)(STORE *, void *handle);
typedef int (*STORE_HANDLE_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
typedef int (*STORE_STORE_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, STORE_OBJECT *data, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
typedef int (*STORE_MODIFY_OBJECT_FUNC_PTR)(STORE *, STORE_OBJECT_TYPES type, OPENSSL_ITEM search_attributes[], OPENSSL_ITEM add_attributes[], OPENSSL_ITEM modify_attributes[], OPENSSL_ITEM delete_attributes[], OPENSSL_ITEM parameters[]);
typedef int (*STORE_GENERIC_FUNC_PTR)(STORE *, OPENSSL_ITEM attributes[], OPENSSL_ITEM parameters[]);
typedef int (*STORE_CTRL_FUNC_PTR)(STORE *, int cmd, long l, void *p, void (*f)(void));
int STORE_method_set_initialise_function(STORE_METHOD *sm, STORE_INITIALISE_FUNC_PTR init_f);
int STORE_method_set_cleanup_function(STORE_METHOD *sm, STORE_CLEANUP_FUNC_PTR clean_f);
int STORE_method_set_generate_function(STORE_METHOD *sm, STORE_GENERATE_OBJECT_FUNC_PTR generate_f);
int STORE_method_set_get_function(STORE_METHOD *sm, STORE_GET_OBJECT_FUNC_PTR get_f);
int STORE_method_set_store_function(STORE_METHOD *sm, STORE_STORE_OBJECT_FUNC_PTR store_f);
int STORE_method_set_modify_function(STORE_METHOD *sm, STORE_MODIFY_OBJECT_FUNC_PTR store_f);
int STORE_method_set_revoke_function(STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR revoke_f);
int STORE_method_set_delete_function(STORE_METHOD *sm, STORE_HANDLE_OBJECT_FUNC_PTR delete_f);
int STORE_method_set_list_start_function(STORE_METHOD *sm, STORE_START_OBJECT_FUNC_PTR list_start_f);
int STORE_method_set_list_next_function(STORE_METHOD *sm, STORE_NEXT_OBJECT_FUNC_PTR list_next_f);
int STORE_method_set_list_end_function(STORE_METHOD *sm, STORE_END_OBJECT_FUNC_PTR list_end_f);
int STORE_method_set_update_store_function(STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_lock_store_function(STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_unlock_store_function(STORE_METHOD *sm, STORE_GENERIC_FUNC_PTR);
int STORE_method_set_ctrl_function(STORE_METHOD *sm, STORE_CTRL_FUNC_PTR ctrl_f);
STORE_INITIALISE_FUNC_PTR STORE_method_get_initialise_function(STORE_METHOD *sm);
STORE_CLEANUP_FUNC_PTR STORE_method_get_cleanup_function(STORE_METHOD *sm);
STORE_GENERATE_OBJECT_FUNC_PTR STORE_method_get_generate_function(STORE_METHOD *sm);
STORE_GET_OBJECT_FUNC_PTR STORE_method_get_get_function(STORE_METHOD *sm);
STORE_STORE_OBJECT_FUNC_PTR STORE_method_get_store_function(STORE_METHOD *sm);
STORE_MODIFY_OBJECT_FUNC_PTR STORE_method_get_modify_function(STORE_METHOD *sm);
STORE_HANDLE_OBJECT_FUNC_PTR STORE_method_get_revoke_function(STORE_METHOD *sm);
STORE_HANDLE_OBJECT_FUNC_PTR STORE_method_get_delete_function(STORE_METHOD *sm);
STORE_START_OBJECT_FUNC_PTR STORE_method_get_list_start_function(STORE_METHOD *sm);
STORE_NEXT_OBJECT_FUNC_PTR STORE_method_get_list_next_function(STORE_METHOD *sm);
STORE_END_OBJECT_FUNC_PTR STORE_method_get_list_end_function(STORE_METHOD *sm);
STORE_GENERIC_FUNC_PTR STORE_method_get_update_store_function(STORE_METHOD *sm);
STORE_GENERIC_FUNC_PTR STORE_method_get_lock_store_function(STORE_METHOD *sm);
STORE_GENERIC_FUNC_PTR STORE_method_get_unlock_store_function(STORE_METHOD *sm);
STORE_CTRL_FUNC_PTR STORE_method_get_ctrl_function(STORE_METHOD *sm);
typedef struct STORE_attr_info_st STORE_ATTR_INFO;
void *STORE_parse_attrs_start(OPENSSL_ITEM *attributes);
STORE_ATTR_INFO *STORE_parse_attrs_next(void *handle);
int STORE_parse_attrs_end(void *handle);
int STORE_parse_attrs_endp(void *handle);
STORE_ATTR_INFO *STORE_ATTR_INFO_new(void);
int STORE_ATTR_INFO_free(STORE_ATTR_INFO *attrs);
char *STORE_ATTR_INFO_get0_cstr(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code);
unsigned char *STORE_ATTR_INFO_get0_sha1str(STORE_ATTR_INFO *attrs,
 STORE_ATTR_TYPES code);
X509_NAME *STORE_ATTR_INFO_get0_dn(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code);
BIGNUM *STORE_ATTR_INFO_get0_number(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code);
int STORE_ATTR_INFO_set_cstr(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 char *cstr, size_t cstr_size);
int STORE_ATTR_INFO_set_sha1str(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 unsigned char *sha1str, size_t sha1str_size);
int STORE_ATTR_INFO_set_dn(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 X509_NAME *dn);
int STORE_ATTR_INFO_set_number(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 BIGNUM *number);
int STORE_ATTR_INFO_modify_cstr(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 char *cstr, size_t cstr_size);
int STORE_ATTR_INFO_modify_sha1str(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 unsigned char *sha1str, size_t sha1str_size);
int STORE_ATTR_INFO_modify_dn(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 X509_NAME *dn);
int STORE_ATTR_INFO_modify_number(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code,
 BIGNUM *number);
int STORE_ATTR_INFO_compare(STORE_ATTR_INFO *a, STORE_ATTR_INFO *b);
int STORE_ATTR_INFO_in_range(STORE_ATTR_INFO *a, STORE_ATTR_INFO *b);
int STORE_ATTR_INFO_in(STORE_ATTR_INFO *a, STORE_ATTR_INFO *b);
int STORE_ATTR_INFO_in_ex(STORE_ATTR_INFO *a, STORE_ATTR_INFO *b);
void ERR_load_STORE_strings(void);
}
extern "C" {
extern "C" {
extern int *__errno_location (void) throw () __attribute__ ((__const__));
extern char *program_invocation_name, *program_invocation_short_name;
}
typedef int error_t;
typedef struct err_state_st
 {
 unsigned long pid;
 int err_flags[16];
 unsigned long err_buffer[16];
 char *err_data[16];
 int err_data_flags[16];
 const char *err_file[16];
 int err_line[16];
 int top,bottom;
 } ERR_STATE;
typedef struct ERR_string_data_st
 {
 unsigned long error;
 const char *string;
 } ERR_STRING_DATA;
void ERR_put_error(int lib, int func,int reason,const char *file,int line);
void ERR_set_error_data(char *data,int flags);
unsigned long ERR_get_error(void);
unsigned long ERR_get_error_line(const char **file,int *line);
unsigned long ERR_get_error_line_data(const char **file,int *line,
          const char **data, int *flags);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_error_line(const char **file,int *line);
unsigned long ERR_peek_error_line_data(const char **file,int *line,
           const char **data,int *flags);
unsigned long ERR_peek_last_error(void);
unsigned long ERR_peek_last_error_line(const char **file,int *line);
unsigned long ERR_peek_last_error_line_data(const char **file,int *line,
           const char **data,int *flags);
void ERR_clear_error(void );
char *ERR_error_string(unsigned long e,char *buf);
void ERR_error_string_n(unsigned long e, char *buf, size_t len);
const char *ERR_lib_error_string(unsigned long e);
const char *ERR_func_error_string(unsigned long e);
const char *ERR_reason_error_string(unsigned long e);
void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
    void *u);
void ERR_print_errors_fp(FILE *fp);
void ERR_print_errors(BIO *bp);
void ERR_add_error_data(int num, ...);
void ERR_load_strings(int lib,ERR_STRING_DATA str[]);
void ERR_unload_strings(int lib,ERR_STRING_DATA str[]);
void ERR_load_ERR_strings(void);
void ERR_load_crypto_strings(void);
void ERR_free_strings(void);
void ERR_remove_state(unsigned long pid);
ERR_STATE *ERR_get_state(void);
LHASH *ERR_get_string_table(void);
LHASH *ERR_get_err_state_table(void);
void ERR_release_err_state_table(LHASH **hash);
int ERR_get_next_error_library(void);
int ERR_set_mark(void);
int ERR_pop_to_mark(void);
const ERR_FNS *ERR_get_implementation(void);
int ERR_set_implementation(const ERR_FNS *fns);
}
extern "C" {
typedef struct ENGINE_CMD_DEFN_st
 {
 unsigned int cmd_num;
 const char *cmd_name;
 const char *cmd_desc;
 unsigned int cmd_flags;
 } ENGINE_CMD_DEFN;
typedef int (*ENGINE_GEN_FUNC_PTR)(void);
typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
typedef int (*ENGINE_CTRL_FUNC_PTR)(ENGINE *, int, long, void *, void (*f)(void));
typedef EVP_PKEY * (*ENGINE_LOAD_KEY_PTR)(ENGINE *, const char *,
 UI_METHOD *ui_method, void *callback_data);
typedef int (*ENGINE_SSL_CLIENT_CERT_PTR)(ENGINE *, SSL *ssl,
 STACK *ca_dn, X509 **pcert, EVP_PKEY **pkey,
 STACK **pother, UI_METHOD *ui_method, void *callback_data);
typedef int (*ENGINE_CIPHERS_PTR)(ENGINE *, const EVP_CIPHER **, const int **, int);
typedef int (*ENGINE_DIGESTS_PTR)(ENGINE *, const EVP_MD **, const int **, int);
ENGINE *ENGINE_get_first(void);
ENGINE *ENGINE_get_last(void);
ENGINE *ENGINE_get_next(ENGINE *e);
ENGINE *ENGINE_get_prev(ENGINE *e);
int ENGINE_add(ENGINE *e);
int ENGINE_remove(ENGINE *e);
ENGINE *ENGINE_by_id(const char *id);
void ENGINE_load_openssl(void);
void ENGINE_load_dynamic(void);
void ENGINE_load_cryptodev(void);
void ENGINE_load_aesni(void);
void ENGINE_load_padlock(void);
void ENGINE_load_builtin_engines(void);
unsigned int ENGINE_get_table_flags(void);
void ENGINE_set_table_flags(unsigned int flags);
int ENGINE_register_RSA(ENGINE *e);
void ENGINE_unregister_RSA(ENGINE *e);
void ENGINE_register_all_RSA(void);
int ENGINE_register_DSA(ENGINE *e);
void ENGINE_unregister_DSA(ENGINE *e);
void ENGINE_register_all_DSA(void);
int ENGINE_register_ECDH(ENGINE *e);
void ENGINE_unregister_ECDH(ENGINE *e);
void ENGINE_register_all_ECDH(void);
int ENGINE_register_ECDSA(ENGINE *e);
void ENGINE_unregister_ECDSA(ENGINE *e);
void ENGINE_register_all_ECDSA(void);
int ENGINE_register_DH(ENGINE *e);
void ENGINE_unregister_DH(ENGINE *e);
void ENGINE_register_all_DH(void);
int ENGINE_register_RAND(ENGINE *e);
void ENGINE_unregister_RAND(ENGINE *e);
void ENGINE_register_all_RAND(void);
int ENGINE_register_STORE(ENGINE *e);
void ENGINE_unregister_STORE(ENGINE *e);
void ENGINE_register_all_STORE(void);
int ENGINE_register_ciphers(ENGINE *e);
void ENGINE_unregister_ciphers(ENGINE *e);
void ENGINE_register_all_ciphers(void);
int ENGINE_register_digests(ENGINE *e);
void ENGINE_unregister_digests(ENGINE *e);
void ENGINE_register_all_digests(void);
int ENGINE_register_complete(ENGINE *e);
int ENGINE_register_all_complete(void);
int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));
int ENGINE_cmd_is_executable(ENGINE *e, int cmd);
int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name,
        long i, void *p, void (*f)(void), int cmd_optional);
int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
    int cmd_optional);
ENGINE *ENGINE_new(void);
int ENGINE_free(ENGINE *e);
int ENGINE_up_ref(ENGINE *e);
int ENGINE_set_id(ENGINE *e, const char *id);
int ENGINE_set_name(ENGINE *e, const char *name);
int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth);
int ENGINE_set_DSA(ENGINE *e, const DSA_METHOD *dsa_meth);
int ENGINE_set_ECDH(ENGINE *e, const ECDH_METHOD *ecdh_meth);
int ENGINE_set_ECDSA(ENGINE *e, const ECDSA_METHOD *ecdsa_meth);
int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth);
int ENGINE_set_RAND(ENGINE *e, const RAND_METHOD *rand_meth);
int ENGINE_set_STORE(ENGINE *e, const STORE_METHOD *store_meth);
int ENGINE_set_destroy_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR destroy_f);
int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f);
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f);
int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f);
int ENGINE_set_load_ssl_client_cert_function(ENGINE *e,
    ENGINE_SSL_CLIENT_CERT_PTR loadssl_f);
int ENGINE_set_ciphers(ENGINE *e, ENGINE_CIPHERS_PTR f);
int ENGINE_set_digests(ENGINE *e, ENGINE_DIGESTS_PTR f);
int ENGINE_set_flags(ENGINE *e, int flags);
int ENGINE_set_cmd_defns(ENGINE *e, const ENGINE_CMD_DEFN *defns);
int ENGINE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
  CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg);
void *ENGINE_get_ex_data(const ENGINE *e, int idx);
void ENGINE_cleanup(void);
const char *ENGINE_get_id(const ENGINE *e);
const char *ENGINE_get_name(const ENGINE *e);
const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e);
const DSA_METHOD *ENGINE_get_DSA(const ENGINE *e);
const ECDH_METHOD *ENGINE_get_ECDH(const ENGINE *e);
const ECDSA_METHOD *ENGINE_get_ECDSA(const ENGINE *e);
const DH_METHOD *ENGINE_get_DH(const ENGINE *e);
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
const STORE_METHOD *ENGINE_get_STORE(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_destroy_function(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e);
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e);
ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE *e);
ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE *e);
ENGINE_SSL_CLIENT_CERT_PTR ENGINE_get_ssl_client_cert_function(const ENGINE *e);
ENGINE_CIPHERS_PTR ENGINE_get_ciphers(const ENGINE *e);
ENGINE_DIGESTS_PTR ENGINE_get_digests(const ENGINE *e);
const EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid);
const EVP_MD *ENGINE_get_digest(ENGINE *e, int nid);
const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e);
int ENGINE_get_flags(const ENGINE *e);
int ENGINE_init(ENGINE *e);
int ENGINE_finish(ENGINE *e);
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
 UI_METHOD *ui_method, void *callback_data);
EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
 UI_METHOD *ui_method, void *callback_data);
int ENGINE_load_ssl_client_cert(ENGINE *e, SSL *s,
 STACK *ca_dn, X509 **pcert, EVP_PKEY **ppkey,
 STACK **pother,
 UI_METHOD *ui_method, void *callback_data);
ENGINE *ENGINE_get_default_RSA(void);
ENGINE *ENGINE_get_default_DSA(void);
ENGINE *ENGINE_get_default_ECDH(void);
ENGINE *ENGINE_get_default_ECDSA(void);
ENGINE *ENGINE_get_default_DH(void);
ENGINE *ENGINE_get_default_RAND(void);
ENGINE *ENGINE_get_cipher_engine(int nid);
ENGINE *ENGINE_get_digest_engine(int nid);
int ENGINE_set_default_RSA(ENGINE *e);
int ENGINE_set_default_string(ENGINE *e, const char *def_list);
int ENGINE_set_default_DSA(ENGINE *e);
int ENGINE_set_default_ECDH(ENGINE *e);
int ENGINE_set_default_ECDSA(ENGINE *e);
int ENGINE_set_default_DH(ENGINE *e);
int ENGINE_set_default_RAND(ENGINE *e);
int ENGINE_set_default_ciphers(ENGINE *e);
int ENGINE_set_default_digests(ENGINE *e);
int ENGINE_set_default(ENGINE *e, unsigned int flags);
void ENGINE_add_conf_module(void);
typedef void *(*dyn_MEM_malloc_cb)(size_t);
typedef void *(*dyn_MEM_realloc_cb)(void *, size_t);
typedef void (*dyn_MEM_free_cb)(void *);
typedef struct st_dynamic_MEM_fns {
 dyn_MEM_malloc_cb malloc_cb;
 dyn_MEM_realloc_cb realloc_cb;
 dyn_MEM_free_cb free_cb;
 } dynamic_MEM_fns;
typedef void (*dyn_lock_locking_cb)(int,int,const char *,int);
typedef int (*dyn_lock_add_lock_cb)(int*,int,int,const char *,int);
typedef struct CRYPTO_dynlock_value *(*dyn_dynlock_create_cb)(
      const char *,int);
typedef void (*dyn_dynlock_lock_cb)(int,struct CRYPTO_dynlock_value *,
      const char *,int);
typedef void (*dyn_dynlock_destroy_cb)(struct CRYPTO_dynlock_value *,
      const char *,int);
typedef struct st_dynamic_LOCK_fns {
 dyn_lock_locking_cb lock_locking_cb;
 dyn_lock_add_lock_cb lock_add_lock_cb;
 dyn_dynlock_create_cb dynlock_create_cb;
 dyn_dynlock_lock_cb dynlock_lock_cb;
 dyn_dynlock_destroy_cb dynlock_destroy_cb;
 } dynamic_LOCK_fns;
typedef struct st_dynamic_fns {
 void *static_state;
 const ERR_FNS *err_fns;
 const CRYPTO_EX_DATA_IMPL *ex_data_fns;
 dynamic_MEM_fns mem_fns;
 dynamic_LOCK_fns lock_fns;
 } dynamic_fns;
typedef unsigned long (*dynamic_v_check_fn)(unsigned long ossl_version);
typedef int (*dynamic_bind_engine)(ENGINE *e, const char *id,
    const dynamic_fns *fns);
void *ENGINE_get_static_state(void);
void ERR_load_ENGINE_strings(void);
}
