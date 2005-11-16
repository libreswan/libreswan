/* 
 * Cryptographic helper process.
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
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
 *
 * RCSID $Id: pluto_crypt.h,v 1.8.4.1 2005/08/08 17:18:58 ken Exp $
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

typedef unsigned int pcr_req_id;

typedef struct wire_chunk {
  unsigned int start;
  size_t       len;
} wire_chunk_t;

#define KENONCE_SIZE 1280
struct pcr_kenonce {
  /* inputs */
  u_int16_t oakley_group;
  
  /* outputs */
  wire_chunk_t secret;
  wire_chunk_t gi;
  wire_chunk_t n;

  wire_chunk_t thespace;
  unsigned char space[KENONCE_SIZE];
};

#define DHCALC_SIZE 2560
struct pcr_skeyid_q {
  /* inputs */
  u_int16_t     oakley_group;
  oakley_auth_t auth;	            
  oakley_hash_t hash;               
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

  wire_chunk_t thespace;
  unsigned char space[DHCALC_SIZE];
};

struct pcr_skeyid_r {
  /* outputs */
  wire_chunk_t shared;
  wire_chunk_t skeyid;          /* output */
  wire_chunk_t skeyid_d;        /* output */
  wire_chunk_t skeyid_a;        /* output */
  wire_chunk_t skeyid_e;        /* output */
  wire_chunk_t new_iv;          
  wire_chunk_t enc_key;

  wire_chunk_t thespace;
  unsigned char space[DHCALC_SIZE];
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
    struct pcr_kenonce kn;
    struct pcr_skeyid_q  dhq;
    struct pcr_skeyid_r  dhr;
  } pcr_d;
};

struct pluto_crypto_req_cont;  /* forward reference */

typedef void (*crypto_req_func)(struct pluto_crypto_req_cont *
				, struct pluto_crypto_req *
				, err_t ugh);

struct pluto_crypto_req_cont {
  struct pluto_crypto_req_cont *pcrc_next;
  struct pluto_crypto_req      *pcrc_pcr;
  so_serial_t                   pcrc_serialno;
  pcr_req_id                    pcrc_id;
  crypto_req_func               pcrc_func;
  crypto_req_func               pcrc_free;
};

  

#define PCR_REQ_SIZE sizeof(struct pluto_crypto_req)+10

extern void init_crypto_helpers(int nhelpers);
extern err_t send_crypto_helper_request(struct pluto_crypto_req *r
					, struct pluto_crypto_req_cont *cn
					, bool *toomuch);
extern void pluto_crypto_helper_sockets(fd_set *readfds);
extern int  pluto_crypto_helper_ready(fd_set *readfds);

extern void pluto_do_crypto_op(struct pluto_crypto_req *r);
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

extern stf_status perform_dh(struct pluto_crypto_req_cont *cn, struct state *st);
extern bool generate_skeyids_iv(struct state *st);

extern stf_status perform_dh_secretiv(struct state *st
				      , enum phase1_role  init  
				      , u_int16_t oakley_group);

extern stf_status perform_dh_secret(struct state *st
				    , enum phase1_role init
				    , u_int16_t group);

extern void calc_dh_iv(struct pluto_crypto_req *r);
extern void calc_dh(struct pluto_crypto_req *r);
