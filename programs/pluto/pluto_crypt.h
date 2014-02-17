/*
 * Cryptographic helper process.
 * Copyright (C) 2004-2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008,2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 *
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

#include "lsw_select.h"
#include "crypto.h"
#include "libreswan/passert.h"

/*
 * cryptographic helper operations.
 */
enum pluto_crypto_requests {
	pcr_build_kenonce,	/* calculate g^i and nonce */
	pcr_build_nonce,	/* just fetch a new nonce */
	pcr_compute_dh_iv,	/* (g^x)(g^y) and skeyids for Phase 1 DH + prf */
	pcr_compute_dh,	/* perform (g^x)(g^y) for Phase 2 PFS */
	pcr_compute_dh_v2,	/* perform IKEv2 PARENT SA calculation, create SKEYSEED */
};


typedef unsigned int pcr_req_id;

/* wire_chunk: a chunk-like representation that is relocatable.
 *
 * This is suitable for chunks that must go over a wire and hence
 * may land at different addresses.
 * The key idea is that the start is relative to the start-of-space
 * within the struct.  This is managed within an arena.
 *
 * Because of two limitations of C typing, the actual space must
 * be created in two tranches: a fixed amount in the arena's
 * "space" field and the remaining amount in a buffer "more_space"
 * that follows the arena.  This odd arrangement allows all arenas
 * to be the same type.  A little bit of space is wasted by
 * alignment padding at the end of the arena struct; this could
 * be fixed at the cost of complexity.
 *
 * The macros with uppercase names are magic: they know
 * the field names "arena" and "space" in a way that a function
 * could not.  They may also take a bare field name as an argument
 * as a reference to that field within the parent struct.
 */
typedef struct wire_arena {
	unsigned int next;	/* index of next byte to be allocated */
	size_t roof;	/* bound of available space */
	unsigned char space[1];	/* actual space follows */
} wire_arena_t;

#define DECLARE_WIRE_ARENA(size) \
	wire_arena_t arena; \
	unsigned char more_space[(size) - 1]

#define INIT_WIRE_ARENA(parent) { \
		(parent).arena.next = 0; \
		(parent).arena.roof = sizeof((parent).arena.space) + sizeof((parent).more_space); \
	}

typedef struct wire_chunk {
	unsigned int start;
	size_t len;
} wire_chunk_t;


extern void alloc_wire_chunk(wire_arena_t *arena,
			     wire_chunk_t *new,
			     size_t size);

#define ALLOC_WIRE_CHUNK(parent, field, size) \
	alloc_wire_chunk(&(parent).arena, &(parent).field, (size))

/* create a wire_chunk that is a clone of a chunk
 * The space is allocated from the arena.
 */
extern void wire_clone_chunk(wire_arena_t *arena,
			     wire_chunk_t *new,
			     const chunk_t *chunk);

#define WIRE_CLONE_CHUNK(parent, field, chunk) \
	wire_clone_chunk(&(parent).arena, &(parent).field, &(chunk))

#define WIRE_CLONE_DATA(parent, field, ptr, len) { \
	chunk_t t; \
	setchunk(t, (ptr), (len)); \
	WIRE_CLONE_CHUNK(parent, field, t); \
    }

/* pointer to first byte of wire within arena */
#define wire_chunk_ptr(arena, wire) (&(arena)->space[(wire)->start])

#define WIRE_CHUNK_PTR(parent, field) wire_chunk_ptr(&(parent).arena, &(parent).field)

/* NOTE: setchunk_from_wire does not allocate any space for the content!
 * It is assumed that the memory for the wired_chunk will persist unchanged
 * during the life of the chunk.
 */
#define setchunk_from_wire(chunk, parent_ptr, wire) \
	setchunk(chunk, wire_chunk_ptr(&(parent_ptr)->arena, (wire)), (wire)->len)

/* end of wire_chunk definitions */

#define KENONCE_SIZE 1280

/* query and response */
struct pcr_kenonce {
	/* input, then output */
	DECLARE_WIRE_ARENA(KENONCE_SIZE);

	/* inputs */
	u_int16_t oakley_group;

	/* outputs */
	wire_chunk_t secret;
	wire_chunk_t gi;
	wire_chunk_t n;
	wire_chunk_t pubk;
};

#define DHCALC_SIZE 2560

/* query */
struct pcr_skeyid_q {
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	u_int16_t oakley_group;
	oakley_auth_t auth;
	oakley_hash_t integ_hash;
	oakley_hash_t prf_hash;
	enum phase1_role init;
	size_t keysize;	/* of encryptor */
	wire_chunk_t gi;
	wire_chunk_t gr;
	wire_chunk_t pss;
	wire_chunk_t ni;
	wire_chunk_t nr;
	wire_chunk_t icookie;
	wire_chunk_t rcookie;
	wire_chunk_t secret;
	/* u_int16_t encrypt_algo; */
	const struct encrypt_desc *encrypter;
	wire_chunk_t pubk;
};

/* response */
struct pcr_skeyid_r {
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	wire_chunk_t shared;
	wire_chunk_t skeyid;	/* output */
	wire_chunk_t skeyid_d;	/* output */
	wire_chunk_t skeyid_a;	/* output */
	wire_chunk_t skeyid_e;	/* output */
	wire_chunk_t new_iv;
	wire_chunk_t enc_key;
};

/* response */
struct pcr_skeycalc_v2_r {
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	wire_chunk_t shared;
	wire_chunk_t skeyseed;	/* output */
	wire_chunk_t skeyid_d;	/* output */
	wire_chunk_t skeyid_ai;	/* output */
	wire_chunk_t skeyid_ar;	/* output */
	wire_chunk_t skeyid_ei;	/* output */
	wire_chunk_t skeyid_er;	/* output */
	wire_chunk_t skeyid_pi;	/* output */
	wire_chunk_t skeyid_pr;	/* output */
};

struct pluto_crypto_req {
	size_t pcr_len;
	enum pluto_crypto_requests pcr_type;
	pcr_req_id pcr_id;
	enum crypto_importance pcr_pcim;

	union {
		struct pcr_kenonce kn;	/* query and result */

		struct pcr_skeyid_q dhq;	/* query v1 and v2 */
		struct pcr_skeyid_r dhr;	/* response v1 */
		struct pcr_skeycalc_v2_r dhv2;	/* response v2 */
	} pcr_d;
};

struct pluto_crypto_req_cont;	/* forward reference */

typedef void (*crypto_req_func)(struct pluto_crypto_req_cont *,
				struct pluto_crypto_req *,
				err_t ugh);

/* The crypto continuation structure
 *
 * Pluto is an event-driven transaction system.
 * Each transaction must take a very small slice of time.
 * Those that cannot, must be broken into multiple
 * transactions and the state carried between them
 * cannot be on the stack or in simple global variables.
 * A continuation is used to hold such state.
 *
 * NOTE: this struct is the used in an twisted way to implement
 * something like specialization in object-oriented languages.
 *
 * In particular, struct pluto_crypto_req_cont
 * appears as the first field in struct ke_continuation
 * and struct dh_continuation.  Thus a pointer to one of
 * those structs is also a pointer to a struct pluto_crypto_req_cont
 * (of course the types must be finessed).
 *
 * The routines that appear to deal with struct pluto_crypto_req_cont
 * objects are in fact dealing generically with either of those
 * two specializations of it.
 */
struct pluto_crypto_req_cont {
	TAILQ_ENTRY(pluto_crypto_req_cont) pcrc_list;
	struct pluto_crypto_req *pcrc_pcr;
	so_serial_t pcrc_serialno;
	pcr_req_id pcrc_id;
	crypto_req_func pcrc_func;
	pb_stream pcrc_reply_stream;
	u_int8_t *pcrc_reply_buffer;
#ifdef IPSEC_PLUTO_PCRC_DEBUG
	char *pcrc_function;
	char *pcrc_file;
	int pcrc_line;
#endif
};

/* these two structs are specializations of struct pluto_crypto_req_cont */

struct ke_continuation {
	struct pluto_crypto_req_cont ke_pcrc;	/* MUST BE THE FIRST FIELD */
	struct msg_digest *md;
};

struct dh_continuation {
	struct pluto_crypto_req_cont dh_pcrc;	/* MUST BE THE FIRST FIELD */
	struct msg_digest *md;
	so_serial_t serialno;			/* used for inter state
						 * calculations on responder */
};

#define PCR_REQ_SIZE sizeof(struct pluto_crypto_req) + 10

extern void init_crypto_helpers(int nhelpers);

extern err_t send_crypto_helper_request(struct pluto_crypto_req *r,
					struct pluto_crypto_req_cont *cn,
					bool *toomuch);

extern void enumerate_crypto_helper_response_sockets(lsw_fd_set *readfds);

extern int pluto_crypto_helper_response_ready(lsw_fd_set *readfds);

/* actual helper functions */
extern stf_status build_ke(struct pluto_crypto_req_cont *cn,
			   struct state *st,
			   const struct oakley_group_desc *group,
			   enum crypto_importance importance);
extern void calc_ke(struct pluto_crypto_req *r);

extern stf_status build_nonce(struct pluto_crypto_req_cont *cn,
			      struct state *st,
			      enum crypto_importance importance);
extern void calc_nonce(struct pluto_crypto_req *r);

extern void compute_dh_shared(struct state *st, const chunk_t g,
			      const struct oakley_group_desc *group);

/* no longer exists?
 *  extern stf_status perform_dh(struct pluto_crypto_req_cont *cn, struct state *st);
 *  extern bool generate_skeyids_iv(struct state *st);
 */


extern stf_status start_dh_secretiv(struct pluto_crypto_req_cont *cn,
				    struct state *st,
				    enum crypto_importance importance,
				    enum phase1_role init,  /* TRUE=g_init,FALSE=g_r */
				    u_int16_t oakley_group_p);

extern void finish_dh_secretiv(struct state *st,
			       struct pluto_crypto_req *r);

extern stf_status start_dh_secret(struct pluto_crypto_req_cont *cn,
				  struct state *st,
				  enum crypto_importance importance,
				  enum phase1_role init,
				  u_int16_t oakley_group_p);

extern void finish_dh_secret(struct state *st,
			     struct pluto_crypto_req *r);

extern stf_status start_dh_v2(struct pluto_crypto_req_cont *cn,
			      struct state *st,
			      enum crypto_importance importance,
			      enum phase1_role init,	/* TRUE=g_init,FALSE=g_r */
			      u_int16_t oakley_group2);

extern void finish_dh_v2(struct state *st,
			 const struct pluto_crypto_req *r);

extern void calc_dh_iv(struct pluto_crypto_req *r);
extern void calc_dh(struct pluto_crypto_req *r);
extern void calc_dh_v2(struct pluto_crypto_req *r);

extern void unpack_KE(struct state *st,
		      const struct pluto_crypto_req *r,
		      chunk_t *g);

extern void pcr_nonce_init(struct pluto_crypto_req *r,
			    enum pluto_crypto_requests pcr_type,
			    enum crypto_importance pcr_pcim);

extern void pcr_dh_init(struct pluto_crypto_req *r,
			enum pluto_crypto_requests pcr_type,
			enum crypto_importance pcr_pcim);

#ifdef IPSEC_PLUTO_PCRC_DEBUG
#define pcrc_init(pcrc, func) { \
		(pcrc)->pcrc_func = (func); \
		(pcrc)->pcrc_file = __FILE__; \
		(pcrc)->pcrc_function = __FUNCTION__; \
		(pcrc)->pcrc_line = __LINE__; \
	}
#else
#define pcrc_init(pcrc, func) { (pcrc)->pcrc_func = (func); }
#endif

#endif /* _PLUTO_CRYPT_H */
