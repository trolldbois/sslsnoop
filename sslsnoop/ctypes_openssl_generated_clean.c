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
/** // supprimed extern  */
extern "C" {
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
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

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */


/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */


/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */


/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
struct obstack;
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
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

/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */


__extension__ extern long long int atoll (__const char *__nptr)
     throw () __attribute__ ((__pure__)) __attribute__ ((__nonnull__ (1))) __attribute__ ((__warn_unused_result__));


/** // supprimed extern  */


/** // supprimed extern  */
/** // supprimed extern  */


/** // supprimed extern  */
/** // supprimed extern  */

__extension__
/** // supprimed extern  */
__extension__
/** // supprimed extern  */

__extension__
/** // supprimed extern  */
__extension__
/** // supprimed extern  */

typedef struct __locale_struct
{
  struct __locale_data *__locales[13];
  const unsigned short int *__ctype_b;
  const int *__ctype_tolower;
  const int *__ctype_toupper;
  const char *__names[13];
} *__locale_t;
typedef __locale_t locale_t;
/** // supprimed extern  */
/** // supprimed extern  */
__extension__
/** // supprimed extern  */
__extension__
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */


/** // supprimed function c:  */

/** // supprimed extern  */
/** // supprimed extern  */
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
/** // supprimed extern  */
/** // supprimed extern  */
}
__extension__
/** // supprimed extern  */
__extension__
/** // supprimed extern  */
__extension__
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed function c:  */
/** // supprimed function c:  */
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
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
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
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
struct drand48_data
  {
    unsigned short int __x[3];
    unsigned short int __old_x[3];
    unsigned short int __c;
    unsigned short int __init;
    unsigned long long int __a;
  };
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */


/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
extern "C" {
/** // supprimed extern  */
}
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */


/** // supprimed extern  */


/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
typedef int (*__compar_fn_t) (__const void *, __const void *);
typedef __compar_fn_t comparison_fn_t;
typedef int (*__compar_d_fn_t) (__const void *, __const void *, void *);

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

__extension__ extern long long int llabs (long long int __x)
     throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));

/** // supprimed extern  */
/** // supprimed extern  */


__extension__ extern lldiv_t lldiv (long long int __numer,
        long long int __denom)
     throw () __attribute__ ((__const__)) __attribute__ ((__warn_unused_result__));

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function c:  */
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
/** // supprimed function sig  */
char *sk_value(const STACK *, int);
char *sk_set(STACK *, int, char *);
STACK *sk_new(int (*cmp)(const char * const *, const char * const *));
STACK *sk_new_null(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *sk_delete(STACK *st,int loc);
char *sk_delete_ptr(STACK *st, char *p);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *sk_shift(STACK *st);
char *sk_pop(STACK *st);
/** // supprimed function sig  */
/** // supprimed function sig  */
STACK *sk_dup(STACK *st);
/** // supprimed function sig  */
/** // supprimed function sig  */
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

/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const char *SSLeay_version(int type);
/** // supprimed function sig  */
/** // supprimed function sig  */
typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;
const CRYPTO_EX_DATA_IMPL *CRYPTO_get_ex_data_implementation(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const char *CRYPTO_get_lock_name(int type);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
struct CRYPTO_dynlock_value *CRYPTO_get_dynlock_value(int i);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
struct CRYPTO_dynlock_value *(*CRYPTO_get_dynlock_create_callback(void))(const char *file,int line);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *CRYPTO_strdup(const char *str, const char *file, int line);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
typedef void *CRYPTO_MEM_LEAK_CB(unsigned long, const char *, int, int, void *);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
typedef struct bio_st BIO;
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *BIO_get_callback_arg(const BIO *b);
/** // supprimed function sig  */
const char * BIO_method_name(const BIO *b);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIO_METHOD *BIO_s_file(void );
BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new_fp(FILE *stream, int close_flag);
BIO * BIO_new(BIO_METHOD *type);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char * BIO_ptr_ctrl(BIO *bp,int cmd,long larg);
/** // supprimed function sig  */
BIO * BIO_push(BIO *b,BIO *append);
BIO * BIO_pop(BIO *b);
/** // supprimed function sig  */
BIO * BIO_find_type(BIO *b,int bio_type);
BIO * BIO_next(BIO *b);
BIO * BIO_get_retry_BIO(BIO *bio, int *reason);
/** // supprimed function sig  */
BIO * BIO_dup_chain(BIO *in);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
struct hostent *BIO_gethostbyname(const char *name);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIO *BIO_new_socket(int sock, int close_flag);
BIO *BIO_new_dgram(int fd, int close_flag);
BIO *BIO_new_fd(int fd, int close_flag);
BIO *BIO_new_connect(char *host_port);
BIO *BIO_new_accept(char *host_port);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */

extern struct tm *gmtime (__const time_t *__timer) throw ();
extern struct tm *localtime (__const time_t *__timer) throw ();

extern struct tm *gmtime_r (__const time_t *__restrict __timer,
       struct tm *__restrict __tp) throw ();
extern struct tm *localtime_r (__const time_t *__restrict __timer,
          struct tm *__restrict __tp) throw ();

/** // supprimed extern  */
/** // supprimed extern  */

/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed extern  */
extern struct tm *getdate (__const char *__string);
/** // supprimed extern  */
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
/** // supprimed function sig  */
const BIGNUM *BN_value_one(void);
char * BN_options(void);
BN_CTX *BN_CTX_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIGNUM *BN_CTX_get(BN_CTX *ctx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIGNUM *BN_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
/** // supprimed function sig  */
BIGNUM *BN_bin2bn(const unsigned char *s,int len,BIGNUM *ret);
/** // supprimed function sig  */
BIGNUM *BN_mpi2bn(const unsigned char *s,int len,BIGNUM *ret);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIGNUM *BN_dup(const BIGNUM *a);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char * BN_bn2hex(const BIGNUM *a);
char * BN_bn2dec(const BIGNUM *a);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIGNUM *BN_mod_inverse(BIGNUM *ret,
 const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
 const BIGNUM *a, const BIGNUM *n,BN_CTX *ctx);
BIGNUM *BN_generate_prime(BIGNUM *ret,int bits,int safe,
 const BIGNUM *add, const BIGNUM *rem,
 void (*callback)(int,int,void *),void *cb_arg);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BN_MONT_CTX *BN_MONT_CTX_new(void );
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to,BN_MONT_CTX *from);
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock,
     const BIGNUM *mod, BN_CTX *ctx);
BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BN_BLINDING *BN_BLINDING_create_param(BN_BLINDING *b,
 const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
 int (*bn_mod_exp)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx),
 BN_MONT_CTX *m_ctx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BN_RECP_CTX *BN_RECP_CTX_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const BIGNUM *BN_get0_nist_prime_192(void);
const BIGNUM *BN_get0_nist_prime_224(void);
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
const BIGNUM *BN_get0_nist_prime_521(void);
BIGNUM *bn_expand2(BIGNUM *a, int words);
BIGNUM *bn_dup_expand(const BIGNUM *a, int words);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIGNUM *get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *get_rfc2409_prime_1024(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *get_rfc3526_prime_8192(BIGNUM *bn);
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_OBJECT * ASN1_OBJECT_new(void );
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_OBJECT * c2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);
ASN1_OBJECT * d2i_ASN1_OBJECT(ASN1_OBJECT **a,const unsigned char **pp,
   long length);
/** // supprimed extern  */


ASN1_STRING * ASN1_STRING_new(void);
/** // supprimed function sig  */
ASN1_STRING * ASN1_STRING_dup(ASN1_STRING *a);
ASN1_STRING * ASN1_STRING_type_new(int type );
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_BIT_STRING *ASN1_BIT_STRING_new(void); void ASN1_BIT_STRING_free(ASN1_BIT_STRING *a); ASN1_BIT_STRING *d2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a, const unsigned char **in, long len); int i2d_ASN1_BIT_STRING(ASN1_BIT_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BIT_STRING_it;
/** // supprimed function sig  */
ASN1_BIT_STRING *c2i_ASN1_BIT_STRING(ASN1_BIT_STRING **a,const unsigned char **pp,
   long length);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_INTEGER *ASN1_INTEGER_new(void); void ASN1_INTEGER_free(ASN1_INTEGER *a); ASN1_INTEGER *d2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **in, long len); int i2d_ASN1_INTEGER(ASN1_INTEGER *a, unsigned char **out); extern const ASN1_ITEM ASN1_INTEGER_it;
/** // supprimed function sig  */
ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a,const unsigned char **pp,
   long length);
ASN1_INTEGER * ASN1_INTEGER_dup(ASN1_INTEGER *x);
/** // supprimed function sig  */
ASN1_ENUMERATED *ASN1_ENUMERATED_new(void); void ASN1_ENUMERATED_free(ASN1_ENUMERATED *a); ASN1_ENUMERATED *d2i_ASN1_ENUMERATED(ASN1_ENUMERATED **a, const unsigned char **in, long len); int i2d_ASN1_ENUMERATED(ASN1_ENUMERATED *a, unsigned char **out); extern const ASN1_ITEM ASN1_ENUMERATED_it;
/** // supprimed function sig  */
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s,time_t t);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,time_t t);
/** // supprimed function sig  */
ASN1_OCTET_STRING *ASN1_OCTET_STRING_new(void); void ASN1_OCTET_STRING_free(ASN1_OCTET_STRING *a); ASN1_OCTET_STRING *d2i_ASN1_OCTET_STRING(ASN1_OCTET_STRING **a, const unsigned char **in, long len); int i2d_ASN1_OCTET_STRING(ASN1_OCTET_STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_OCTET_STRING_it;
ASN1_OCTET_STRING * ASN1_OCTET_STRING_dup(ASN1_OCTET_STRING *a);
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_VISIBLESTRING *ASN1_VISIBLESTRING_new(void); void ASN1_VISIBLESTRING_free(ASN1_VISIBLESTRING *a); ASN1_VISIBLESTRING *d2i_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING **a, const unsigned char **in, long len); int i2d_ASN1_VISIBLESTRING(ASN1_VISIBLESTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_VISIBLESTRING_it;
ASN1_UNIVERSALSTRING *ASN1_UNIVERSALSTRING_new(void); void ASN1_UNIVERSALSTRING_free(ASN1_UNIVERSALSTRING *a); ASN1_UNIVERSALSTRING *d2i_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING **a, const unsigned char **in, long len); int i2d_ASN1_UNIVERSALSTRING(ASN1_UNIVERSALSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UNIVERSALSTRING_it;
ASN1_UTF8STRING *ASN1_UTF8STRING_new(void); void ASN1_UTF8STRING_free(ASN1_UTF8STRING *a); ASN1_UTF8STRING *d2i_ASN1_UTF8STRING(ASN1_UTF8STRING **a, const unsigned char **in, long len); int i2d_ASN1_UTF8STRING(ASN1_UTF8STRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_UTF8STRING_it;
ASN1_NULL *ASN1_NULL_new(void); void ASN1_NULL_free(ASN1_NULL *a); ASN1_NULL *d2i_ASN1_NULL(ASN1_NULL **a, const unsigned char **in, long len); int i2d_ASN1_NULL(ASN1_NULL *a, unsigned char **out); extern const ASN1_ITEM ASN1_NULL_it;
ASN1_BMPSTRING *ASN1_BMPSTRING_new(void); void ASN1_BMPSTRING_free(ASN1_BMPSTRING *a); ASN1_BMPSTRING *d2i_ASN1_BMPSTRING(ASN1_BMPSTRING **a, const unsigned char **in, long len); int i2d_ASN1_BMPSTRING(ASN1_BMPSTRING *a, unsigned char **out); extern const ASN1_ITEM ASN1_BMPSTRING_it;
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed extern  */
ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s,time_t t);
/** // supprimed function sig  */
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(ASN1_TIME *t, ASN1_GENERALIZEDTIME **out);
/** // supprimed function sig  */
STACK * d2i_ASN1_SET(STACK **a, const unsigned char **pp, long length,
       d2i_of_void *d2i, void (*free_func)(void *),
       int ex_tag, int ex_class);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data,int len,
 const char *sn, const char *ln);
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_INTEGER *BN_to_ASN1_INTEGER(BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(ASN1_INTEGER *ai,BIGNUM *bn);
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai,BIGNUM *bn);
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_STRING *d2i_ASN1_bytes(ASN1_STRING **a, const unsigned char **pp,
 long length, int Ptag, int Pclass);
/** // supprimed function sig  */
ASN1_STRING *d2i_ASN1_type_bytes(ASN1_STRING **a,const unsigned char **pp,
  long length,int type);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const char *ASN1_tag2str(int tag);
/** // supprimed function sig  */
ASN1_HEADER *d2i_ASN1_HEADER(ASN1_HEADER **a,const unsigned char **pp, long length);
ASN1_HEADER *ASN1_HEADER_new(void );
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_METHOD *X509_asn1_meth(void);
ASN1_METHOD *RSAPrivateKey_asn1_meth(void);
ASN1_METHOD *ASN1_IA5STRING_asn1_meth(void);
ASN1_METHOD *ASN1_BIT_STRING_asn1_meth(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
STACK *ASN1_seq_unpack(const unsigned char *buf, int len,
         d2i_of_void *d2i, void (*free_func)(void *));
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_STRING *ASN1_pack_string(void *obj, i2d_of_void *i2d,
         ASN1_OCTET_STRING **oct);
ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it, ASN1_OCTET_STRING **oct);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
  const unsigned char *in, int inlen, int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
/** // supprimed function sig  */
ASN1_VALUE * ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in, long len, const ASN1_ITEM *it);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_TYPE *ASN1_generate_nconf(char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(char *str, X509V3_CTX *cnf);
typedef int asn1_output_data_fn(BIO *out, BIO *data, ASN1_VALUE *val, int flags,
     const ASN1_ITEM *it);
/** // supprimed function sig  */
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
/** // supprimed function sig  */
}
extern "C" {
typedef struct obj_name_st
 {
 int type;
 int alias;
 const char *name;
 const char *data;
 } OBJ_NAME;
/** // supprimed function sig  */
/** // supprimed function sig  */
const char *OBJ_NAME_get(const char *name,int type);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_OBJECT * OBJ_dup(const ASN1_OBJECT *o);
ASN1_OBJECT * OBJ_nid2obj(int n);
const char * OBJ_nid2ln(int n);
const char * OBJ_nid2sn(int n);
/** // supprimed function sig  */
ASN1_OBJECT * OBJ_txt2obj(const char *s, int no_name);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const char * OBJ_bsearch(const char *key,const char *base,int num,int size,
 int (*cmp)(const void *, const void *));
const char * OBJ_bsearch_ex(const char *key,const char *base,int num,
 int size, int (*cmp)(const void *, const void *), int flags);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const EVP_MD * EVP_MD_CTX_md(const EVP_MD_CTX *ctx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const EVP_CIPHER * EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_MD_CTX *EVP_MD_CTX_create(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char * EVP_get_pw_prompt(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIO_METHOD *BIO_f_md(void);
BIO_METHOD *BIO_f_base64(void);
BIO_METHOD *BIO_f_cipher(void);
BIO_METHOD *BIO_f_reliable(void);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
const EVP_MD *EVP_get_digestbyname(const char *name);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
struct rsa_st;
/** // supprimed function sig  */
struct rsa_st *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
struct dsa_st;
/** // supprimed function sig  */
struct dsa_st *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
struct dh_st;
/** // supprimed function sig  */
struct dh_st *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
struct ec_key_st;
/** // supprimed function sig  */
struct ec_key_st *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
EVP_PKEY * EVP_PKEY_new(void);
/** // supprimed function sig  */
EVP_PKEY * d2i_PublicKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
/** // supprimed function sig  */
EVP_PKEY * d2i_PrivateKey(int type,EVP_PKEY **a, const unsigned char **pp,
   long length);
EVP_PKEY * d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp,
   long length);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
struct aes_key_st {
    unsigned int rd_key[4 *(14 + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;
const char *AES_options(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
typedef struct rc4_key_st
 {
 unsigned int x,y;
 unsigned int data[256];
 } RC4_KEY;
const char *RC4_options(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
typedef struct bf_key_st
 {
 unsigned int P[16 +2];
 unsigned int S[4*256];
 } BF_KEY;
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *_ossl_old_des_fcrypt(const char *buf,const char *salt, char *ret);
char *_ossl_old_des_crypt(const char *buf,const char *salt);
char *_ossl_old_crypt(const char *buf,const char *salt);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
UI *UI_new(void);
UI *UI_new_method(const UI_METHOD *method);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *UI_construct_prompt(UI *ui_method,
 const char *object_desc, const char *object_name);
/** // supprimed function sig  */
/** // supprimed function sig  */
const char *UI_get0_result(UI *ui, int i);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
enum UI_string_types UI_get_string_type(UI_STRING *uis);
/** // supprimed function sig  */
const char *UI_get0_output_string(UI_STRING *uis);
const char *UI_get0_action_string(UI_STRING *uis);
const char *UI_get0_result_string(UI_STRING *uis);
const char *UI_get0_test_string(UI_STRING *uis);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
/** // supprimed function sig  */
/** // supprimed function sig  */
}
/** // supprimed extern  */
/** // supprimed extern  */
const char *DES_options(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *DES_fcrypt(const char *buf,const char *salt, char *ret);
char *DES_crypt(const char *buf,const char *salt);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
typedef struct cast_key_st
 {
 unsigned long data[32];
 int short_key;
 } CAST_KEY;
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
const DH_METHOD *DH_get_default_method(void);
/** // supprimed function sig  */
DH *DH_new_method(ENGINE *engine);
DH * DH_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
DH * DH_generate_parameters(int prime_len,int generator,
  void (*callback)(int,int,void *),void *cb_arg);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
DH * d2i_DHparams(DH **a,const unsigned char **pp, long length);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
DSA_SIG * d2i_DSA_SIG(DSA_SIG **v, const unsigned char **pp, long length);
DSA_SIG * DSA_do_sign(const unsigned char *dgst,int dlen,DSA *dsa);
/** // supprimed function sig  */
const DSA_METHOD *DSA_OpenSSL(void);
/** // supprimed function sig  */
const DSA_METHOD *DSA_get_default_method(void);
/** // supprimed function sig  */
DSA * DSA_new(void);
DSA * DSA_new_method(ENGINE *engine);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
DSA * d2i_DSAPublicKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAPrivateKey(DSA **a, const unsigned char **pp, long length);
DSA * d2i_DSAparams(DSA **a, const unsigned char **pp, long length);
DSA * DSA_generate_parameters(int bits,
  unsigned char *seed,int seed_len,
  int *counter_ret, unsigned long *h_ret,void
  (*callback)(int, int, void *),void *cb_arg);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
DH *DSA_dup_DH(const DSA *r);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
RSA * RSA_generate_key(int bits, unsigned long e,void
  (*callback)(int,int,void *),void *cb_arg);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const RSA_METHOD *RSA_get_default_method(void);
const RSA_METHOD *RSA_get_method(const RSA *rsa);
/** // supprimed function sig  */
/** // supprimed function sig  */
const RSA_METHOD *RSA_PKCS1_SSLeay(void);
const RSA_METHOD *RSA_null_method(void);
RSA *d2i_RSAPublicKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPublicKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPublicKey_it;
RSA *d2i_RSAPrivateKey(RSA **a, const unsigned char **in, long len); int i2d_RSAPrivateKey(const RSA *a, unsigned char **out); extern const ASN1_ITEM RSAPrivateKey_it;
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
RSA *d2i_RSA_NET(RSA **a, const unsigned char **pp, long length,
   int (*cb)(char *buf, int len, const char *prompt, int verify),
   int sgckey);
/** // supprimed function sig  */
RSA *d2i_Netscape_RSA(RSA **a, const unsigned char **pp, long length,
        int (*cb)(char *buf, int len, const char *prompt,
    int verify));
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
RSA *RSAPublicKey_dup(RSA *rsa);
RSA *RSAPrivateKey_dup(RSA *rsa);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EC_GROUP *EC_GROUP_dup(const EC_GROUP *);
const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *);
/** // supprimed function sig  */
/** // supprimed function sig  */
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);
/** // supprimed function sig  */
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
typedef struct {
 int nid;
 const char *comment;
 } EC_builtin_curve;
size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems);
EC_POINT *EC_POINT_new(const EC_GROUP *);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EC_POINT *EC_POINT_dup(const EC_POINT *, const EC_GROUP *);
const EC_METHOD *EC_POINT_method_of(const EC_POINT *);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form,
        unsigned char *buf, size_t len, BN_CTX *);
/** // supprimed function sig  */
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *,
 EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *,
 point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *,
 EC_POINT *, BN_CTX *);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
typedef struct ecpk_parameters_st ECPKPARAMETERS;
EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
typedef struct ec_key_st EC_KEY;
EC_KEY *EC_KEY_new(void);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
/** // supprimed function sig  */
EC_KEY *EC_KEY_copy(EC_KEY *, const EC_KEY *);
EC_KEY *EC_KEY_dup(const EC_KEY *);
/** // supprimed function sig  */
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
/** // supprimed function sig  */
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
/** // supprimed function sig  */
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EC_KEY *d2i_ECPrivateKey(EC_KEY **a, const unsigned char **in, long len);
/** // supprimed function sig  */
EC_KEY *d2i_ECParameters(EC_KEY **a, const unsigned char **in, long len);
/** // supprimed function sig  */
EC_KEY *o2i_ECPublicKey(EC_KEY **a, const unsigned char **in, long len);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
const ECDH_METHOD *ECDH_OpenSSL(void);
/** // supprimed function sig  */
const ECDH_METHOD *ECDH_get_default_method(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
typedef struct ECDSA_SIG_st
 {
 BIGNUM *r;
 BIGNUM *s;
 } ECDSA_SIG;
ECDSA_SIG *ECDSA_SIG_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **v, const unsigned char **pp, long len);
ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst,int dgst_len,EC_KEY *eckey);
ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen,
  const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);
/** // supprimed function sig  */
const ECDSA_METHOD *ECDSA_OpenSSL(void);
/** // supprimed function sig  */
const ECDSA_METHOD *ECDSA_get_default_method(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
const RAND_METHOD *RAND_get_rand_method(void);
/** // supprimed function sig  */
RAND_METHOD *RAND_SSLeay(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const char *RAND_file_name(char *file,size_t num);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char * BUF_strdup(const char *str);
char * BUF_strndup(const char *str, size_t siz);
/** // supprimed function sig  */
size_t BUF_strlcpy(char *dst,const char *src,size_t siz);
size_t BUF_strlcat(char *dst,const char *src,size_t siz);
/** // supprimed function sig  */
}
extern "C" {
typedef struct SHAstate_st
 {
 unsigned int h0,h1,h2,h3,h4;
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num;
 } SHA_CTX;
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
typedef struct SHA256state_st
 {
 unsigned int h[8];
 unsigned int Nl,Nh;
 unsigned int data[16];
 unsigned int num,md_len;
 } SHA256_CTX;
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK *h,int type,X509_NAME *name);
X509_OBJECT *X509_OBJECT_retrieve_match(STACK *h, X509_OBJECT *x);
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_STORE *X509_STORE_new(void );
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_STORE_CTX *X509_STORE_CTX_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m);
X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509 * X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
STACK *X509_STORE_CTX_get_chain(X509_STORE_CTX *ctx);
STACK *X509_STORE_CTX_get1_chain(X509_STORE_CTX *ctx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX *ctx);
/** // supprimed function sig  */
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_POLICY_LEVEL *
 X509_policy_tree_get0_level(const X509_POLICY_TREE *tree, int i);
STACK *
 X509_policy_tree_get0_policies(const X509_POLICY_TREE *tree);
STACK *
 X509_policy_tree_get0_user_policies(const X509_POLICY_TREE *tree);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
PKCS7 *d2i_PKCS7_fp(FILE *fp,PKCS7 **p7);
/** // supprimed function sig  */
PKCS7 *PKCS7_dup(PKCS7 *p7);
PKCS7 *d2i_PKCS7_bio(BIO *bp,PKCS7 **p7);
/** // supprimed function sig  */
PKCS7_SIGNER_INFO *PKCS7_SIGNER_INFO_new(void); void PKCS7_SIGNER_INFO_free(PKCS7_SIGNER_INFO *a); PKCS7_SIGNER_INFO *d2i_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO **a, const unsigned char **in, long len); int i2d_PKCS7_SIGNER_INFO(PKCS7_SIGNER_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGNER_INFO_it;
PKCS7_RECIP_INFO *PKCS7_RECIP_INFO_new(void); void PKCS7_RECIP_INFO_free(PKCS7_RECIP_INFO *a); PKCS7_RECIP_INFO *d2i_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO **a, const unsigned char **in, long len); int i2d_PKCS7_RECIP_INFO(PKCS7_RECIP_INFO *a, unsigned char **out); extern const ASN1_ITEM PKCS7_RECIP_INFO_it;
PKCS7_SIGNED *PKCS7_SIGNED_new(void); void PKCS7_SIGNED_free(PKCS7_SIGNED *a); PKCS7_SIGNED *d2i_PKCS7_SIGNED(PKCS7_SIGNED **a, const unsigned char **in, long len); int i2d_PKCS7_SIGNED(PKCS7_SIGNED *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGNED_it;
PKCS7_ENC_CONTENT *PKCS7_ENC_CONTENT_new(void); void PKCS7_ENC_CONTENT_free(PKCS7_ENC_CONTENT *a); PKCS7_ENC_CONTENT *d2i_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT **a, const unsigned char **in, long len); int i2d_PKCS7_ENC_CONTENT(PKCS7_ENC_CONTENT *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENC_CONTENT_it;
PKCS7_ENVELOPE *PKCS7_ENVELOPE_new(void); void PKCS7_ENVELOPE_free(PKCS7_ENVELOPE *a); PKCS7_ENVELOPE *d2i_PKCS7_ENVELOPE(PKCS7_ENVELOPE **a, const unsigned char **in, long len); int i2d_PKCS7_ENVELOPE(PKCS7_ENVELOPE *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENVELOPE_it;
PKCS7_SIGN_ENVELOPE *PKCS7_SIGN_ENVELOPE_new(void); void PKCS7_SIGN_ENVELOPE_free(PKCS7_SIGN_ENVELOPE *a); PKCS7_SIGN_ENVELOPE *d2i_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE **a, const unsigned char **in, long len); int i2d_PKCS7_SIGN_ENVELOPE(PKCS7_SIGN_ENVELOPE *a, unsigned char **out); extern const ASN1_ITEM PKCS7_SIGN_ENVELOPE_it;
PKCS7_DIGEST *PKCS7_DIGEST_new(void); void PKCS7_DIGEST_free(PKCS7_DIGEST *a); PKCS7_DIGEST *d2i_PKCS7_DIGEST(PKCS7_DIGEST **a, const unsigned char **in, long len); int i2d_PKCS7_DIGEST(PKCS7_DIGEST *a, unsigned char **out); extern const ASN1_ITEM PKCS7_DIGEST_it;
PKCS7_ENCRYPT *PKCS7_ENCRYPT_new(void); void PKCS7_ENCRYPT_free(PKCS7_ENCRYPT *a); PKCS7_ENCRYPT *d2i_PKCS7_ENCRYPT(PKCS7_ENCRYPT **a, const unsigned char **in, long len); int i2d_PKCS7_ENCRYPT(PKCS7_ENCRYPT *a, unsigned char **out); extern const ASN1_ITEM PKCS7_ENCRYPT_it;
PKCS7 *PKCS7_new(void); void PKCS7_free(PKCS7 *a); PKCS7 *d2i_PKCS7(PKCS7 **a, const unsigned char **in, long len); int i2d_PKCS7(PKCS7 *a, unsigned char **out); extern const ASN1_ITEM PKCS7_it;
/** // supprimed extern  */
/** // supprimed extern  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio);
/** // supprimed function sig  */
BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert);
PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509,
 EVP_PKEY *pkey, const EVP_MD *dgst);
X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si);
/** // supprimed function sig  */
STACK *PKCS7_get_signer_info(PKCS7 *p7);
PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx);
ASN1_OCTET_STRING *PKCS7_digest_from_attributes(STACK *sk);
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_TYPE *PKCS7_get_attribute(PKCS7_SIGNER_INFO *si, int nid);
ASN1_TYPE *PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si, int nid);
/** // supprimed function sig  */
/** // supprimed function sig  */
PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK *certs,
       BIO *data, int flags);
/** // supprimed function sig  */
STACK *PKCS7_get0_signers(PKCS7 *p7, STACK *certs, int flags);
PKCS7 *PKCS7_encrypt(STACK *certs, BIO *in, const EVP_CIPHER *cipher,
        int flags);
/** // supprimed function sig  */
/** // supprimed function sig  */
STACK *PKCS7_get_smimecap(PKCS7_SIGNER_INFO *si);
/** // supprimed function sig  */
/** // supprimed function sig  */
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
const char *X509_verify_cert_error_string(long n);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
NETSCAPE_SPKI * NETSCAPE_SPKI_b64_decode(const char *str, int len);
char * NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509 *d2i_X509_fp(FILE *fp, X509 **x509);
/** // supprimed function sig  */
X509_CRL *d2i_X509_CRL_fp(FILE *fp,X509_CRL **crl);
/** // supprimed function sig  */
X509_REQ *d2i_X509_REQ_fp(FILE *fp,X509_REQ **req);
/** // supprimed function sig  */
RSA *d2i_RSAPrivateKey_fp(FILE *fp,RSA **rsa);
/** // supprimed function sig  */
RSA *d2i_RSAPublicKey_fp(FILE *fp,RSA **rsa);
/** // supprimed function sig  */
RSA *d2i_RSA_PUBKEY_fp(FILE *fp,RSA **rsa);
/** // supprimed function sig  */
DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
/** // supprimed function sig  */
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
/** // supprimed function sig  */
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
/** // supprimed function sig  */
EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
/** // supprimed function sig  */
X509_SIG *d2i_PKCS8_fp(FILE *fp,X509_SIG **p8);
/** // supprimed function sig  */
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
      PKCS8_PRIV_KEY_INFO **p8inf);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
/** // supprimed function sig  */
EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
X509 *d2i_X509_bio(BIO *bp,X509 **x509);
/** // supprimed function sig  */
X509_CRL *d2i_X509_CRL_bio(BIO *bp,X509_CRL **crl);
/** // supprimed function sig  */
X509_REQ *d2i_X509_REQ_bio(BIO *bp,X509_REQ **req);
/** // supprimed function sig  */
RSA *d2i_RSAPrivateKey_bio(BIO *bp,RSA **rsa);
/** // supprimed function sig  */
RSA *d2i_RSAPublicKey_bio(BIO *bp,RSA **rsa);
/** // supprimed function sig  */
RSA *d2i_RSA_PUBKEY_bio(BIO *bp,RSA **rsa);
/** // supprimed function sig  */
DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
/** // supprimed function sig  */
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
/** // supprimed function sig  */
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
/** // supprimed function sig  */
EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);
/** // supprimed function sig  */
X509_SIG *d2i_PKCS8_bio(BIO *bp,X509_SIG **p8);
/** // supprimed function sig  */
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
      PKCS8_PRIV_KEY_INFO **p8inf);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
/** // supprimed function sig  */
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
X509 *X509_dup(X509 *x509);
X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *xa);
X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex);
X509_CRL *X509_CRL_dup(X509_CRL *crl);
X509_REQ *X509_REQ_dup(X509_REQ *req);
X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn);
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_NAME *X509_NAME_dup(X509_NAME *xn);
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
EVP_PKEY * X509_PUBKEY_get(X509_PUBKEY *key);
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY * d2i_PUBKEY(EVP_PKEY **a,const unsigned char **pp,
   long length);
/** // supprimed function sig  */
RSA * d2i_RSA_PUBKEY(RSA **a,const unsigned char **pp,
   long length);
/** // supprimed function sig  */
DSA * d2i_DSA_PUBKEY(DSA **a,const unsigned char **pp,
   long length);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
X509_CINF *X509_CINF_new(void); void X509_CINF_free(X509_CINF *a); X509_CINF *d2i_X509_CINF(X509_CINF **a, const unsigned char **in, long len); int i2d_X509_CINF(X509_CINF *a, unsigned char **out); extern const ASN1_ITEM X509_CINF_it;
X509 *X509_new(void); void X509_free(X509 *a); X509 *d2i_X509(X509 **a, const unsigned char **in, long len); int i2d_X509(X509 *a, unsigned char **out); extern const ASN1_ITEM X509_it;
X509_CERT_AUX *X509_CERT_AUX_new(void); void X509_CERT_AUX_free(X509_CERT_AUX *a); X509_CERT_AUX *d2i_X509_CERT_AUX(X509_CERT_AUX **a, const unsigned char **in, long len); int i2d_X509_CERT_AUX(X509_CERT_AUX *a, unsigned char **out); extern const ASN1_ITEM X509_CERT_AUX_it;
X509_CERT_PAIR *X509_CERT_PAIR_new(void); void X509_CERT_PAIR_free(X509_CERT_PAIR *a); X509_CERT_PAIR *d2i_X509_CERT_PAIR(X509_CERT_PAIR **a, const unsigned char **in, long len); int i2d_X509_CERT_PAIR(X509_CERT_PAIR *a, unsigned char **out); extern const ASN1_ITEM X509_CERT_PAIR_it;
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509 * d2i_X509_AUX(X509 **a,const unsigned char **pp,long length);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_REVOKED *X509_REVOKED_new(void); void X509_REVOKED_free(X509_REVOKED *a); X509_REVOKED *d2i_X509_REVOKED(X509_REVOKED **a, const unsigned char **in, long len); int i2d_X509_REVOKED(X509_REVOKED *a, unsigned char **out); extern const ASN1_ITEM X509_REVOKED_it;
X509_CRL_INFO *X509_CRL_INFO_new(void); void X509_CRL_INFO_free(X509_CRL_INFO *a); X509_CRL_INFO *d2i_X509_CRL_INFO(X509_CRL_INFO **a, const unsigned char **in, long len); int i2d_X509_CRL_INFO(X509_CRL_INFO *a, unsigned char **out); extern const ASN1_ITEM X509_CRL_INFO_it;
X509_CRL *X509_CRL_new(void); void X509_CRL_free(X509_CRL *a); X509_CRL *d2i_X509_CRL(X509_CRL **a, const unsigned char **in, long len); int i2d_X509_CRL(X509_CRL *a, unsigned char **out); extern const ASN1_ITEM X509_CRL_it;
/** // supprimed function sig  */
X509_PKEY * X509_PKEY_new(void );
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_PKEY * d2i_X509_PKEY(X509_PKEY **a,const unsigned char **pp,long length);
NETSCAPE_SPKI *NETSCAPE_SPKI_new(void); void NETSCAPE_SPKI_free(NETSCAPE_SPKI *a); NETSCAPE_SPKI *d2i_NETSCAPE_SPKI(NETSCAPE_SPKI **a, const unsigned char **in, long len); int i2d_NETSCAPE_SPKI(NETSCAPE_SPKI *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_SPKI_it;
NETSCAPE_SPKAC *NETSCAPE_SPKAC_new(void); void NETSCAPE_SPKAC_free(NETSCAPE_SPKAC *a); NETSCAPE_SPKAC *d2i_NETSCAPE_SPKAC(NETSCAPE_SPKAC **a, const unsigned char **in, long len); int i2d_NETSCAPE_SPKAC(NETSCAPE_SPKAC *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_SPKAC_it;
NETSCAPE_CERT_SEQUENCE *NETSCAPE_CERT_SEQUENCE_new(void); void NETSCAPE_CERT_SEQUENCE_free(NETSCAPE_CERT_SEQUENCE *a); NETSCAPE_CERT_SEQUENCE *d2i_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE **a, const unsigned char **in, long len); int i2d_NETSCAPE_CERT_SEQUENCE(NETSCAPE_CERT_SEQUENCE *a, unsigned char **out); extern const ASN1_ITEM NETSCAPE_CERT_SEQUENCE_it;
X509_INFO * X509_INFO_new(void);
/** // supprimed function sig  */
char * X509_NAME_oneline(X509_NAME *a,char *buf,int size);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_INTEGER * X509_get_serialNumber(X509 *x);
/** // supprimed function sig  */
X509_NAME * X509_get_issuer_name(X509 *a);
/** // supprimed function sig  */
X509_NAME * X509_get_subject_name(X509 *a);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY * X509_get_pubkey(X509 *x);
ASN1_BIT_STRING * X509_get0_pubkey_bitstr(const X509 *x);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY * X509_REQ_get_pubkey(X509_REQ *req);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
STACK *X509_REQ_get_extensions(X509_REQ *req);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc);
X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *name, int loc);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne,
  const char *field, int type, const unsigned char *bytes, int len);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid,
   int type,unsigned char *bytes, int len);
/** // supprimed function sig  */
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne,
   ASN1_OBJECT *obj, int type,const unsigned char *bytes,
   int len);
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_OBJECT * X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne);
ASN1_STRING * X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_EXTENSION *X509v3_get_ext(const STACK *x, int loc);
X509_EXTENSION *X509v3_delete_ext(STACK *x, int loc);
STACK *X509v3_add_ext(STACK **x,
      X509_EXTENSION *ex, int loc);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_EXTENSION *X509_get_ext(X509 *x, int loc);
X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_EXTENSION *X509_CRL_get_ext(X509_CRL *x, int loc);
X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_EXTENSION *X509_REVOKED_get_ext(X509_REVOKED *x, int loc);
X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex,
   int nid, int crit, ASN1_OCTET_STRING *data);
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex,
   ASN1_OBJECT *obj,int crit,ASN1_OCTET_STRING *data);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_OBJECT * X509_EXTENSION_get_object(X509_EXTENSION *ex);
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid,
      int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr,
      const ASN1_OBJECT *obj, int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr,
  const char *atrname, int type, const unsigned char *bytes, int len);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc);
X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_TRUST * X509_TRUST_get0(int idx);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *X509_TRUST_get0_name(X509_TRUST *xp);
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
STORE *STORE_new_method(const STORE_METHOD *method);
STORE *STORE_new_engine(ENGINE *engine);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed extern  */
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
/** // supprimed extern  */
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
/** // supprimed extern  */
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
/** // supprimed function sig  */
X509 *STORE_get_certificate(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509 *STORE_list_certificate_next(STORE *e, void *handle);
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY *STORE_generate_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
EVP_PKEY *STORE_get_private_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY *STORE_list_private_key_next(STORE *e, void *handle);
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY *STORE_get_public_key(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY *STORE_list_public_key_next(STORE *e, void *handle);
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_CRL *STORE_generate_crl(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
X509_CRL *STORE_get_crl(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
X509_CRL *STORE_list_crl_next(STORE *e, void *handle);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BIGNUM *STORE_get_number(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
BUF_MEM *STORE_get_arbitrary(STORE *e, OPENSSL_ITEM attributes[],
 OPENSSL_ITEM parameters[]);
/** // supprimed function sig  */
STORE_METHOD *STORE_create_method(char *name);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
STORE_ATTR_INFO *STORE_parse_attrs_next(void *handle);
/** // supprimed function sig  */
/** // supprimed function sig  */
STORE_ATTR_INFO *STORE_ATTR_INFO_new(void);
/** // supprimed function sig  */
char *STORE_ATTR_INFO_get0_cstr(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code);
/** // supprimed function sig  */
X509_NAME *STORE_ATTR_INFO_get0_dn(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code);
BIGNUM *STORE_ATTR_INFO_get0_number(STORE_ATTR_INFO *attrs, STORE_ATTR_TYPES code);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
}
extern "C" {
extern "C" {
/** // supprimed extern  */
/** // supprimed extern  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
char *ERR_error_string(unsigned long e,char *buf);
/** // supprimed function sig  */
const char *ERR_lib_error_string(unsigned long e);
const char *ERR_func_error_string(unsigned long e);
const char *ERR_reason_error_string(unsigned long e);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ERR_STATE *ERR_get_state(void);
LHASH *ERR_get_string_table(void);
LHASH *ERR_get_err_state_table(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
const ERR_FNS *ERR_get_implementation(void);
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
ENGINE *ENGINE_by_id(const char *id);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
ENGINE *ENGINE_new(void);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
 UI_METHOD *ui_method, void *callback_data);
EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
 UI_METHOD *ui_method, void *callback_data);
/** // supprimed function sig  */
ENGINE *ENGINE_get_default_RSA(void);
ENGINE *ENGINE_get_default_DSA(void);
ENGINE *ENGINE_get_default_ECDH(void);
ENGINE *ENGINE_get_default_ECDSA(void);
ENGINE *ENGINE_get_default_DH(void);
ENGINE *ENGINE_get_default_RAND(void);
ENGINE *ENGINE_get_cipher_engine(int nid);
ENGINE *ENGINE_get_digest_engine(int nid);
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
/** // supprimed function sig  */
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
/** // supprimed function sig  */
/** // supprimed function sig  */
}
