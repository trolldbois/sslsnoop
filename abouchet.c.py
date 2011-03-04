#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+python@gmail.com
#

__author__ = "Loic Jaquemet loic.jaquemet+python@gmail.com"

import os,logging,re
#use volatility?

import ssl


log=logging.getLogger('abouchet')
MAX_KEYS=255

verbose = 0

# memory extraction functions {{{ 

''' returns 0 if the address seems to be valid
          -1 else.
'''
def is_valid_address(addr,proc):
'''static int is_valid_address(unsigned long addr, proc_t *proc) {'''
  #if ( ((long)addr) & (sizeof(char *)-1) )
  #  return -1 ;

 return not dbg_map_lookup_by_address(proc, addr, None)


''' returns 0/True if all addresses seems to be valid
          -1/False else.
'''
def might_be_RSA(rsa, proc):
  '''static int might_be_RSA(RSA *rsa, proc_t *proc) {'''
    return 
	rsa->pad || rsa->version ||
	(rsa->references < 0) || (rsa->references > 0xff)  ||
        is_valid_address( (unsigned long) rsa->n, proc)    ||
        is_valid_address( (unsigned long) rsa->e, proc)    ||
        is_valid_address( (unsigned long) rsa->d, proc)    ||
        is_valid_address( (unsigned long) rsa->p, proc)    ||
        is_valid_address( (unsigned long) rsa->q, proc)    ||
        is_valid_address( (unsigned long) rsa->dmp1, proc) ||
        is_valid_address( (unsigned long) rsa->dmq1, proc) ||
        is_valid_address( (unsigned long) rsa->iqmp, proc);
}

/* returns 0 if all addresses seems to be valid
          -1 else.
*/
static int might_be_DSA(DSA *dsa, proc_t *proc) {
    return
        dsa->pad || dsa->version ||
        (dsa->references < 0) || (dsa->references > 0xff)  ||
        is_valid_address( (unsigned long) dsa->p, proc)        ||
        is_valid_address( (unsigned long) dsa->q, proc)        ||
        is_valid_address( (unsigned long) dsa->g, proc)        ||
        is_valid_address( (unsigned long) dsa->priv_key, proc) ||
        is_valid_address( (unsigned long) dsa->pub_key, proc)  ||
       //  pre-calc -> may be NULL
        (dsa->kinv && is_valid_address( (unsigned long) dsa->kinv, proc)) ||
        (dsa->r && is_valid_address( (unsigned long) dsa->r, proc));
}


static void *extract_from_mem(void *addr, unsigned int size, proc_t *proc) {
	mapping_t *map;
	unsigned int off;

	map = dbg_map_lookup_by_address(proc, (xaddr_t)addr, &off);
	if (!map || !map->data)
		return NULL;

	return map->data + off;
}

static int is_valid_BN(BIGNUM *bn) {
    
    printf("BN { d=%p, top=%i, dmax=%i, neg=%i, flags=%i }\n",
		bn->d, bn->top, bn->dmax, bn->neg, bn->flags);
	  if ( bn->dmax < 0 || bn->top < 0 || bn->dmax < bn->top )
				return -1;

    if ( !(bn->neg == 1 || bn->neg == 0 ) ) {
        return -1;
    }
    return 0;
}
/*
   struct bignum_st
   {
   BN_ULONG *d;     Pointer to an array of 'BN_BITS2' bit chunks. 
   int top;     Index of last used d +1. 
   The next are internal book keeping for bn_expand. 
   int dmax;    Size of the d array. 
   int neg;     one if the number is negative 
   int flags;
   };

   Extract a BIGNUM structure from memory.
   Set error to 1 if an error occured, else set it to 0.
   */

BIGNUM * BN_extract_from_mem(void * bn_addr, proc_t * proc, int * error) {
	BIGNUM *bn_tmp;

	*error = 0;
//printf("=a= %p\n", bn_addr);
	bn_tmp = extract_from_mem( bn_addr, sizeof(BIGNUM), proc);
	if (!bn_tmp) {
//printf("=z=\n");
		*error = 1;
		return NULL;
	}
	BIGNUM *bn = malloc(sizeof(BIGNUM));
	if ( bn == NULL ) {
		exit(EXIT_FAILURE);
	}
	memcpy(bn, bn_tmp, sizeof(BIGNUM));
	/* tests heuristiques */
	if ( is_valid_BN(bn) == -1 ) { 
			*error = 1;
			free(bn);
			return NULL;
	}

//printf("=b=\n");
	bn->d = extract_from_mem( bn->d, bn->top * sizeof(BN_ULONG), proc);
	if (!bn->d) {
		*error = 1;
		free(bn);
		return NULL;
	}
//printf("=c=\n");
	return bn;
}
/* }}} */

/* key saving {{{ */

/* returns 0 if file does not exist
           1 if file exists */
static int file_exists(char *filename) {
    struct stat stat_st;
    return !stat(filename, &stat_st);
}

char * get_valid_filename(char *string) {
    int i = 0 ;
    char filename[128] ;
    sprintf(filename, "%s-%d.key", string, i);
    while ( file_exists(filename) && i < MAX_KEYS ) {
        i++;
        sprintf(filename, "%s-%d.key", string, i);
    } 
    if ( i >= MAX_KEYS )
        return NULL ;
    
    
    return strdup(filename);
}

int write_rsa_key(RSA * rsa, char *prefix) {

    char *filename = get_valid_filename(prefix) ;
    
    FILE *f = fopen(filename, "w");
    if ( f == NULL ) {
        perror("fopen");
        return -1;
    }
    if ( ! PEM_write_RSAPrivateKey(f, rsa, NULL,
            NULL, 0, NULL, NULL) ) {
        fprintf(stderr, "Error saving key to file %s\n", filename);
        return -1;
    }
    fclose(f);
    printf("[X] Key saved to file %s\n", filename);
    free(filename);
    return 0;
}


int write_dsa_key(DSA * dsa, char *prefix) {

    char *filename = get_valid_filename(prefix) ;
    
    FILE *f = fopen(filename, "w");
    if ( f == NULL ) {
        perror("fopen");
        return -1;
    }
    if ( ! PEM_write_DSAPrivateKey(f, dsa, NULL,
            NULL, 0, NULL, NULL) ) {
        fprintf(stderr, "Error saving key to file %s\n", filename);
        return -1;
    }
    fclose(f);
    printf("[X] Key saved to file %s\n", filename);
    free(filename);
    return 0;
}


/* key saving }}} */

/* key extraction {{{ */

int extract_rsa_key(RSA *rsa, proc_t *p) {

    int error = 0;

		if ( verbose > 1 ) {
				printf("RSA { pad=%i, ver=%li, ref=%i, flags=%i, engine=%p\n"
								"      n=%p, e=%p, d=%p, p=%p, q=%p\n"    
								"      dmp1=%p, dmq1=%p, iqmp=%p, bn_data=%p\n"
								"      blinding=%p, mont_bn=%p/%p/%p }\n",
								rsa->pad, rsa->version, rsa->references, rsa->flags, rsa->engine,
								rsa->n, rsa->e, rsa->d, rsa->p, rsa->q, rsa->dmp1, rsa->dmq1,
								rsa->iqmp, rsa->bignum_data, rsa->blinding,
								rsa->_method_mod_n, rsa->_method_mod_p, rsa->_method_mod_q);
		}

    rsa->n =    BN_extract_from_mem(rsa->n, p, &error);
    if ( error ) return -1;
    rsa->e =    BN_extract_from_mem(rsa->e, p, &error);
    if ( error ) { goto free_n; }
    rsa->d =    BN_extract_from_mem(rsa->d, p, &error);
    if ( error ) { goto free_e; }
    rsa->p =    BN_extract_from_mem(rsa->p, p, &error);
    if ( error ) { goto free_d; }
    rsa->q =    BN_extract_from_mem(rsa->q, p, &error);
    if ( error ) { goto free_p; }
    rsa->dmp1 = BN_extract_from_mem(rsa->dmp1, p, &error);
    if ( error ) { goto free_q; }
    rsa->dmq1 = BN_extract_from_mem(rsa->dmq1, p, &error);
    if ( error ) { goto free_dmp1; }
    rsa->iqmp = BN_extract_from_mem(rsa->iqmp, p, &error);
    if ( error ) { goto free_dmq1; }

	rsa->meth = NULL;
	rsa->_method_mod_n = NULL;
	rsa->_method_mod_p = NULL;
	rsa->_method_mod_q = NULL;
	rsa->bignum_data = NULL;
	rsa->blinding = NULL;
//#if OPENSSL_VERSION_NUMBER >
	//rsa->mt_blinding = NULL;
//#endif

	 switch ( RSA_check_key( rsa )) {
		 case 1 :
			 return 0;
		 case 0 :
			 if (verbose > 1)
				 fprintf(stderr, "warn: invalid RSA key found.\n");
			 break;
		 case -1 :
			 if (verbose > 1)
				 fprintf(stderr, "warn: unable to check key.\n");
			 break;
	 }

    free(rsa->iqmp);
free_dmq1 :
    free(rsa->dmq1);
free_dmp1 :
    free(rsa->dmp1);
free_q :
    free(rsa->q);
free_p :
    free(rsa->p);
free_d :
    free(rsa->d);
free_e :
    free(rsa->e);
free_n :
    free(rsa->n);

    return -1 ;
}

void free_rsa_key(RSA *rsa) {
    free(rsa->iqmp);
    free(rsa->dmq1);
    free(rsa->dmp1);
    free(rsa->q);
    free(rsa->p);
    free(rsa->d);
    free(rsa->e);
    free(rsa->n);
}
/*
   struct
   {
   BIGNUM *p;              // prime number (public)
   BIGNUM *q;              // 160-bit subprime, q | p-1 (public)
   BIGNUM *g;              // generator of subgroup (public)
   BIGNUM *priv_key;       // private key x
   BIGNUM *pub_key;        // public key y = g^x
// ...
}
DSA;
*/

int extract_dsa_key( DSA * dsa, proc_t *p ) {
	int error;

	if ( verbose > 1 ) {
			printf("DSA { pad=%i, ver=%li, ref=%i, flags=%i, engine=%p\n"
							"      p=%p, q=%p, g=%p, pubkey=%p, pvkey=%p\n"    
							"      kinv=%p, r=%p, mont_p=%p, meth=%p }\n",
							dsa->pad, dsa->version, dsa->references, dsa->flags, dsa->engine,
							dsa->p, dsa->q, dsa->g, dsa->pub_key, dsa->priv_key, dsa->kinv,
							dsa->r, dsa->method_mont_p, dsa->meth);
	}

	dsa->priv_key = BN_extract_from_mem(dsa->priv_key, p, &error);
	if ( error ) return -1;

	dsa->pub_key = BN_extract_from_mem(dsa->pub_key, p, &error);
	if ( error ) goto free_priv_key;
	dsa->p = BN_extract_from_mem(dsa->p, p, &error);
	if ( error ) goto free_pub_key;
	dsa->q = BN_extract_from_mem(dsa->q, p, &error);
	if ( error ) goto free_p;
	dsa->g = BN_extract_from_mem(dsa->g, p, &error);
	if ( error ) goto free_q;
	dsa->kinv = BN_extract_from_mem(dsa->kinv, p, &error);
	if ( error ) dsa->kinv = NULL;
	dsa->r = BN_extract_from_mem(dsa->r, p, &error);
	if ( error ) dsa->r = NULL;

	dsa->method_mont_p = NULL;
	dsa->meth = NULL;
	dsa->engine = NULL;

	/* in DSA, we should have :
	 * pub_key = g^priv_key mod p
	 */
	BIGNUM * res = BN_new();
	if ( res == NULL )
		err(p, "failed to allocate result BN");

	BN_CTX * ctx = BN_CTX_new();
	if ( ctx == NULL ) {
		fprintf(stderr, "[-] error allocating BN_CTX ctx\n");
		goto free_res;
	}
	/* a ^ p % m
		int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);
		*/
	error = BN_mod_exp(res, dsa->g, dsa->priv_key, dsa->p, ctx);
	if ( error == 0 ) {
		if (verbose > 0)
			fprintf(stderr, "warn: failed to check DSA key.\n");
		goto free_ctx;
	}
	if ( BN_cmp(res, dsa->pub_key) != 0 ) {
		if (verbose > 0)
			fprintf(stderr, "warn: invalid DSA key.\n");
		goto free_ctx;
	}
	BN_clear_free(res);
	BN_CTX_free(ctx);

	fprintf(stderr, "[X] Valid DSA key found.\n");

	return 0;


free_ctx:
	BN_CTX_free(ctx);
free_res:
	BN_free(res);
	if ( dsa->r    != NULL ) { free(dsa->r); }
	if ( dsa->kinv != NULL ) { free(dsa->kinv); }
	free(dsa->g); 
free_q:
	free(dsa->q);
free_p:
	free(dsa->p);
free_pub_key:
	free(dsa->pub_key);
free_priv_key:
	free(dsa->priv_key);

	return -1;

}

void free_dsa_key(DSA *dsa) {
    if ( dsa->r    != NULL ) { free(dsa->r); }
    if ( dsa->kinv != NULL ) { free(dsa->kinv); }
    free(dsa->g); 
    free(dsa->q);
    free(dsa->p);
    free(dsa->pub_key);
    free(dsa->priv_key);
}

/* }}} */

static void find_keys(mapping_t *map, unsigned int off, unsigned int end)
{
	const char *data;
	proc_t *p;
	unsigned int j;
	RSA rsa;
	DSA dsa;

	p = map->proc;
  	data = map->data;

	if (verbose > 0) {
		printf("scanning 0x%lx --> 0x%lx %s\n",
					map->address+off, map->address+end, map->name);
	}

	for ( j = off; j <= end; j+=sizeof(char*)) {

		if (verbose > 1)
			printf("checking 0x%lx\n", map->address+j);

		if ( j <= map->size - sizeof(RSA) ) {
			memcpy(&rsa, data + j, sizeof(RSA));

			if ( might_be_RSA(&rsa, p) == 0 ) { 

				if ( ! extract_rsa_key(&rsa, p) ) {
					printf("found RSA key @ 0x%lx\n", map->address+j);
					write_rsa_key(&rsa, "id_rsa");
					free_rsa_key(&rsa);
					continue ;
				}
			}
		}

		if ( j <= map->size - sizeof(DSA) ) {
			memcpy(&dsa, data + j, sizeof(DSA));

			//printf("==A==\n");
			if ( might_be_DSA(&dsa, p) == 0 ) {
			//printf("==B==\n");

				if ( ! extract_dsa_key(&dsa, p) > 0 ) {
					printf("found DSA key @ 0x%lx\n", map->address+j);
					write_dsa_key(&dsa, "id_dsa");
					free_dsa_key(&dsa);
					continue ;
				}
			}
		}
	}
}

static void usage(char *n)
{
	fprintf(stderr, "Usage : %s [-v] [-a from[-to]] pid\n", n);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
	pid_t pid;
	proc_t p;
	int i;
	char *end;
	mapping_t *map, *map2;
	unsigned int off_start, off_end, min_key_size;
	unsigned long from, to;

	if ( argc < 2 )
		usage(argv[0]);

	verbose = 0;
	from = 0;
	to = 0;
	min_key_size = (sizeof(RSA) < sizeof(DSA)) ? sizeof(RSA) : sizeof(DSA);

	for (i=1; i<argc-1; ++i) {
		if ((argv[i][0] != '-') || !argv[i][1] || argv[i][2])
			usage(argv[0]);

		switch (argv[i][1]) {
			case 'v':
				++verbose;
				break;
			case 'a':
				from = strtoul(argv[++i], &end, 16);
				if (end) {
					if (!*end)
						to = from + min_key_size;
					else if (*end != '-')
						usage(argv[0]);
					else if (!*++end)
						to = 0;
					else
						to = strtoul(end, NULL, 16);
				}
				if ((from|to) & (sizeof(char *)-1)) {
					fprintf(stderr, "error: unaligned map range\n");
					return EXIT_FAILURE;
				}	
				break;
			default:
				usage(argv[0]);
		}
	}

	pid = (pid_t) atoi(argv[i]);
	fprintf(stderr, "Target has pid %d\n", pid);

	if ( dbg_init(&p, pid) ) {
		fprintf(stderr, "Error initializing proc_t for %d\n", pid);
		return EXIT_FAILURE;
	}

	if ( dbg_attach(&p, 0) ) {
		dbg_exit(&p);
		return EXIT_FAILURE;
	}

	if (from) {
		if ( dbg_get_memory(&p) )
			err(&p, "unable to fetch memory for process %d", pid);
		map = dbg_map_lookup_by_address(&p, from, &off_start);
		if (!map)
			err(&p, "0x%lx not mapped into process %i", from, pid);
		if (to) {
			map2 = dbg_map_lookup_by_address(&p, to, &off_end);
			if (!map2)
				err(&p, "0x%lx not mapped into process %i",	to, pid);
			if (to <= from)
				err(&p, "bad memory range");
			if (map != map2)
				err(&p, "0x%lx and 0x%lx not mapped in same page", from, to);
		} else {
			off_end = map->size;
		}
		if (dbg_map_cache(map) < 0)
			err(&p, "failed to map 0x%lx", from);

		find_keys(map, off_start, off_end-min_key_size);

	} else {
		if ( dbg_get_memory(&p) )
			err(&p, "unable to fetch memory for process %d", pid);

		dbg_map_for_each(&p, map) {

			if (!map->data)
				continue;

			find_keys(map, 0, map->size-min_key_size);
		}
	}
	fprintf(stderr, "done for pid %d\n", p.pid);

	dbg_detach(&p);
	dbg_exit(&p);

	return EXIT_SUCCESS;
}
