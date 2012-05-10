/* 
 * Cryptographic helper process.
 * Copyright (C) 2004-2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/*
 * this is an internal interface from a master pluto process
 * and a cryptographic helper child.
 *
 * the child performs the heavy lifting of cryptographic functions
 * for pluto. It does this to avoid head-of-queue problems with aggressive
 * mode, to deal with the asynchronous nature of hardware offload,
 * and to compartamentalize lookups to LDAP/HTTP/FTP for CRL fetching
 * and checking.
 *
 */

#ifndef _PLUTO_CRYPT_H
#define _PLUTO_CRYPT_H

#include "osw_select.h"
#include "crypto.h"

typedef unsigned int pcr_req_id;

typedef struct wire_chunk {
  unsigned int start;
  size_t       len;
} wire_chunk_t;

#define KENONCE_SIZE 1280
struct pcr_kenonce {
  wire_chunk_t thespace;
  unsigned char space[KENONCE_SIZE];

  /* inputs */
  u_int16_t oakley_group;
  
  /* outputs */
  wire_chunk_t secret;
  wire_chunk_t gi;
  wire_chunk_t n;
  wire_chunk_t pubk;
};

#define DHCALC_SIZE 2560
struct pcr_skeyid_q {
  wire_chunk_t thespace;
  unsigned char space[DHCALC_SIZE];

  /* inputs */
  u_int16_t     oakley_group;
  oakley_auth_t auth;	            
  oakley_hash_t integ_hash;
  oakley_hash_t prf_hash;               
  enum phase1_role init;
  size_t        keysize;     /* of encryptor */
  wire_chunk_t gi;
  wire_chunk_t gr;
  wire_chunk_t pss;
  wire_chunk_t ni;
  wire_chunk_t nr;
  wire_chunk_t icookie;
  wire_chunk_t rcookie;
  wire_chunk_t secret;
  /* u_int16_t encrypt_algo; */
  struct encrypt_desc *encrypter;
  wire_chunk_t   pubk;
};

struct pcr_skeyid_r {
  wire_chunk_t thespace;
  unsigned char space[DHCALC_SIZE];

  /* outputs */
  wire_chunk_t shared;
  wire_chunk_t skeyid;          /* output */
  wire_chunk_t skeyid_d;        /* output */
  wire_chunk_t skeyid_a;        /* output */
  wire_chunk_t skeyid_e;        /* output */
  wire_chunk_t new_iv;          
  wire_chunk_t enc_key;
};

struct pcr_skeycalc_v2 {
  wire_chunk_t thespace;
  unsigned char space[DHCALC_SIZE];

  /* outputs */
  wire_chunk_t shared;
  wire_chunk_t skeyseed;        /* output */
  wire_chunk_t skeyid_d;        /* output */
  wire_chunk_t skeyid_ai;       /* output */
  wire_chunk_t skeyid_ar;       /* output */
  wire_chunk_t skeyid_ei;       /* output */
  wire_chunk_t skeyid_er;       /* output */
  wire_chunk_t skeyid_pi;       /* output */
  wire_chunk_t skeyid_pr;       /* output */
};

#define space_chunk_ptr(SPACE, wire) ((void *)&((SPACE)[(wire)->start]))
#define wire_chunk_ptr(k, wire) space_chunk_ptr((k)->space, wire)

#define setchunk_fromwire(chunk, wire, ctner) setchunk(chunk, wire_chunk_ptr(ctner, wire), (wire)->len)

#define setwirechunk_fromchunk(wire, chunk, ctner) do { \
    wire_chunk_t *w = &(wire);				\
    chunk_t      *c = &(chunk);				\
    pluto_crypto_allocchunk(&((ctner)->thespace), w, c->len);	\
    memcpy(wire_chunk_ptr(ctner, w), c->ptr, c->len);	\
  } while(0)

struct pluto_crypto_req {
  size_t                     pcr_len;

  enum pluto_crypto_requests pcr_type;
  pcr_req_id                 pcr_id;
  enum crypto_importance     pcr_pcim;
  int                        pcr_slot;
  union {
      struct pcr_kenonce      kn;
      struct pcr_skeyid_q     dhq;
      struct pcr_skeyid_r     dhr;
      struct pcr_skeycalc_v2  dhv2;
  } pcr_d;
};

struct pluto_crypto_req_cont;  /* forward reference */

typedef void (*crypto_req_func)(struct pluto_crypto_req_cont *
				, struct pluto_crypto_req *
				, err_t ugh);

struct pluto_crypto_req_cont {
  TAILQ_ENTRY(pluto_crypto_req_cont) pcrc_list;
  struct pluto_crypto_req      *pcrc_pcr;
  so_serial_t                   pcrc_serialno;
  pcr_req_id                    pcrc_id;
  crypto_req_func               pcrc_func;
  crypto_req_func               pcrc_free;
  pb_stream			pcrc_reply_stream;
  u_int8_t		       *pcrc_reply_buffer;
#ifdef IPSEC_PLUTO_PCRC_DEBUG
  char                         *pcrc_function;
  char                         *pcrc_file;
  int                           pcrc_line;
#endif
};

  

#define PCR_REQ_SIZE sizeof(struct pluto_crypto_req)+10

extern void init_crypto_helpers(int nhelpers);
extern err_t send_crypto_helper_request(struct pluto_crypto_req *r
					, struct pluto_crypto_req_cont *cn
					, bool *toomuch);
extern void pluto_crypto_helper_sockets(osw_fd_set *readfds);
extern int  pluto_crypto_helper_ready(osw_fd_set *readfds);

extern void pluto_do_crypto_op(struct pluto_crypto_req *r, int helpernum);
extern void pluto_crypto_helper(int fd, int helpernum);
extern void pluto_crypto_allocchunk(wire_chunk_t *space
				    , wire_chunk_t *new
				    , size_t howbig);
extern void pluto_crypto_copychunk(wire_chunk_t *spacetrack
				   , unsigned char *space
				   , wire_chunk_t *new
				   , chunk_t data);

/* actual helper functions */
extern stf_status build_ke(struct pluto_crypto_req_cont *cn
			   , struct state *st
			   , const struct oakley_group_desc *group
			   , enum crypto_importance importance);
extern void calc_ke(struct pluto_crypto_req *r);

extern stf_status build_nonce(struct pluto_crypto_req_cont *cn
			      , struct state *st
			      , enum crypto_importance importance);
extern void calc_nonce(struct pluto_crypto_req *r);

extern void compute_dh_shared(struct state *st, const chunk_t g
			      , const struct oakley_group_desc *group);

/* no longer exists? 
extern stf_status perform_dh(struct pluto_crypto_req_cont *cn, struct state *st);
*/

extern bool generate_skeyids_iv(struct state *st);

extern stf_status start_dh_secretiv(struct pluto_crypto_req_cont *cn
				    , struct state *st
				    , enum crypto_importance importance
				    , enum phase1_role init /* TRUE=g_init,FALSE=g_r */
				    , u_int16_t oakley_group_p);

extern void finish_dh_secretiv(struct state *st,
			       struct pluto_crypto_req *r);

extern stf_status start_dh_secret(struct pluto_crypto_req_cont *cn
				  , struct state *st
				  , enum crypto_importance importance
				  , enum phase1_role init      
				  , u_int16_t oakley_group_p);

extern void finish_dh_secret(struct state *st,
			     struct pluto_crypto_req *r);

extern stf_status start_dh_v2(struct pluto_crypto_req_cont *cn
			      , struct state *st
			      , enum crypto_importance importance
			      , enum phase1_role init       /* TRUE=g_init,FALSE=g_r */
			      , u_int16_t oakley_group2);

extern void finish_dh_v2(struct state *st,
			 struct pluto_crypto_req *r);

extern void calc_dh_iv(struct pluto_crypto_req *r);
extern void calc_dh(struct pluto_crypto_req *r);
extern void calc_dh_v2(struct pluto_crypto_req *r);

extern void unpack_KE(struct state *st
		      , struct pluto_crypto_req *r
		      , chunk_t *g);
extern void unpack_nonce(chunk_t *n, struct pluto_crypto_req *r);


static inline void clonetowirechunk(wire_chunk_t  *thespace,
			     unsigned char *space,
			     wire_chunk_t *wiretarget,
			     const void   *origdat,
			     const size_t  origlen)
{
    char *gip;
    pluto_crypto_allocchunk(thespace, wiretarget, origlen);

    gip = space_chunk_ptr(space, wiretarget);
    memcpy(gip, origdat, origlen);
}

static inline void pcr_init(struct pluto_crypto_req *r
	, enum pluto_crypto_requests pcr_type
	, enum crypto_importance pcr_pcim)
{
    memset(r, 0, sizeof(*r));
    r->pcr_len  = sizeof(struct pluto_crypto_req);
    r->pcr_type = pcr_type;
    r->pcr_pcim = pcr_pcim;

    switch (r->pcr_type) {
    case pcr_build_kenonce:
    case pcr_build_nonce:
	r->pcr_d.kn.thespace.start = 0;
	r->pcr_d.kn.thespace.len   = sizeof(r->pcr_d.kn.space);
	break;
    case pcr_compute_dh_iv:
    case pcr_compute_dh:
    case pcr_compute_dh_v2:
	r->pcr_d.dhq.thespace.start = 0;
	r->pcr_d.dhq.thespace.len   = sizeof(r->pcr_d.dhq.space);
	break;
    case pcr_rsa_sign:
    case pcr_rsa_check:
    case pcr_x509cert_fetch:
    case pcr_x509crl_fetch:
	passert(0);
	break;
    }
}

#ifdef IPSEC_PLUTO_PCRC_DEBUG
#define pcrc_init(pcrc) ({ \
		(pcrc)->pcrc_file = __FILE__; \
		(pcrc)->pcrc_function = __FUNCTION__; \
		(pcrc)->pcrc_line = __LINE__; \
	})
#else
#define pcrc_init(pcrc) do { /* nothing yet */ } while (0)
#endif

#endif /* _PLUTO_CRYPT_H */


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
 
