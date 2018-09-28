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
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/*
 * This is an internal interface between a master pluto process
 * and a cryptographic helper thread.
 *
 * The helper performs the heavy lifting of cryptographic functions
 * for pluto. It does this to avoid head-of-queue problems with aggressive
 * mode, and to deal with the asynchronous nature of hardware offload.
 *
 * (Unrelated to code to compartmentalize lookups to LDAP/HTTP/FTP for CRL fetching
 * and checking.)
 */

#ifndef _PLUTO_CRYPT_H
#define _PLUTO_CRYPT_H

#include "crypto.h"
#include "chunk.h"

struct state;
struct msg_digest;

/*
 * cryptographic helper operations.
 */
enum pluto_crypto_requests {
	pcr_build_ke_and_nonce,	/* calculate g^i and generate a nonce */
	pcr_build_nonce,	/* generate a nonce */
	pcr_compute_dh_iv,	/* calculate (g^x)(g^y) and skeyids for Phase 1 DH + prf */
	pcr_compute_dh,		/* calculate (g^x)(g^y) for Phase 2 PFS */
	pcr_compute_dh_v2,	/* perform IKEv2 SA calculation, create SKEYSEED */
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

/*
 * Pluto Crypto Request: struct pluto_crypto_req
 *
 * This travels over a "wire" both ways:
 * - to a helper, specifying what it is to do
 * - from a helper, with the result.
 *
 * struct pluto_crypto_req contains a union with different
 * information for different kinds of queries and responses.
 * First we define structs for each of these.
 */

#define KENONCE_SIZE 1280

/* query and response */
struct pcr_kenonce {
	/* inputs */
	const struct oakley_group_desc *group;

	/* outputs */
	struct dh_secret *secret;
	chunk_t gi;
	chunk_t n;
};

#define DHCALC_SIZE 2560

struct pcr_v1_dh {
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	/* query */
	const struct oakley_group_desc *oakley_group;
	oakley_auth_t auth; /*IKEv1 AUTH*/
	const struct integ_desc *integ;
	const struct prf_desc *prf;
	const struct encrypt_desc *encrypter;
	enum original_role role;
	size_t key_size; /* of encryptor, in bytes */
	size_t salt_size; /* of IV salt, in bytes */
	wire_chunk_t gi;
	wire_chunk_t gr;
	wire_chunk_t pss;
	wire_chunk_t ni;
	wire_chunk_t nr;
	wire_chunk_t icookie;
	wire_chunk_t rcookie;
	struct dh_secret *secret;
	PK11SymKey *skey_d_old;
	const struct prf_desc *old_prf;

	/* response */
	PK11SymKey *shared;
	PK11SymKey *skeyid;
	PK11SymKey *skeyid_d;
	PK11SymKey *skeyid_a;
	PK11SymKey *skeyid_e;
	PK11SymKey *enc_key;
	chunk_t new_iv;
};

/* response */
struct pcr_dh_v2 {
	/* incoming */
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	const struct oakley_group_desc *dh;
	const struct integ_desc *integ;
	const struct prf_desc *prf;
	const struct encrypt_desc *encrypt;
	enum original_role role;
	size_t key_size; /* of encryptor, in bytes */
	size_t salt_size; /* of IV salt, in bytes */
	wire_chunk_t gi;
	wire_chunk_t gr;
	wire_chunk_t ni;
	wire_chunk_t nr;
	wire_chunk_t icookie;
	wire_chunk_t rcookie;
	struct dh_secret *secret;
	PK11SymKey *skey_d_old;
	const struct prf_desc *old_prf;

	/* outgoing */
	PK11SymKey *shared;
	PK11SymKey *skeyid_d;
	PK11SymKey *skeyid_ai;
	PK11SymKey *skeyid_ar;
	PK11SymKey *skeyid_ei;
	PK11SymKey *skeyid_er;
	PK11SymKey *skeyid_pi;
	PK11SymKey *skeyid_pr;
	chunk_t skey_initiator_salt;
	chunk_t skey_responder_salt;
	chunk_t skey_chunk_SK_pi;
	chunk_t skey_chunk_SK_pr;
};

struct pluto_crypto_req {
	enum pluto_crypto_requests pcr_type;

	union {
		struct pcr_kenonce kn;		/* query and result */
		struct pcr_dh_v2 dh_v2;		/* query and response v2 */
		struct pcr_v1_dh v1_dh;		/* query and response v1 */
	} pcr_d;
};

struct pluto_crypto_req_cont;	/* forward reference */


/*
 * pluto_crypto_req_cont_func:
 *
 * A function that resumes a state transition after an asynchronous
 * cryptographic calculation completes.
 *
 * It is passed:
 *
 * struct state *st:
 *
 *      The always non-NULL SA (aka state) that requested the crypto.
 *      If, on completion of the crypto, the requesting state has been
 *      deleted, this function IS NOT called.
 *
 *	Before calling, the current global state context will have
 *	been set to this state, that is, don't call set_cur_state().
 *
 * struct msg_digest *mdp:
 *
 *      If applicable, *MDP contains the incoming packet that
 *      triggered the requested crypto.  The initiator, for instance
 *      when initiating an initial connection or rekey, will not have
 *      this packet.
 *
 *      XXX: should be true now but watch out for fake_md.
 *
 *      This routine will not release_any_md(MDP).  The caller will do
 *      this.  In fact, it must zap *MDP to NULL if it thinks **MDP
 *      should not be freed.  The the caller is prepared for *MDP
 *      being set to NULL.
 *
 * struct pluto_crypto_req *r:
 *
 *	The results from the crypto operation.
 *
 *      This function is responsible for releasing or transferring the
 *      contents (and for "just knowing" the right contents in the
 *      union it should be using).
 *
 * See also the comments that prefix send_crypto_helper_request().
 */

typedef void crypto_req_cont_func(struct state *st, struct msg_digest **mdp,
				  struct pluto_crypto_req *r);

/* struct pluto_crypto_req_cont allocators */

struct state;

extern struct pluto_crypto_req_cont *new_pcrc(crypto_req_cont_func fn,
					      const char *name);

extern void init_crypto_helpers(int nhelpers);

extern void send_crypto_helper_request(struct state *st,
				       struct pluto_crypto_req_cont *cn);

/* actual helper functions */

/*
 * KE/NONCE
 */

extern void request_ke_and_nonce(const char *name,
				 struct state *st,
				 const struct oakley_group_desc *group,
				 crypto_req_cont_func *callback);

extern void request_nonce(const char *name,
			  struct state *st,
			  crypto_req_cont_func *callback);

extern void calc_ke(struct pcr_kenonce *kn);

extern void calc_nonce(struct pcr_kenonce *kn);

extern void cancelled_ke_and_nonce(struct pcr_kenonce *kn);

/*
 * IKEv1 DH
 */

extern void compute_dh_shared(struct state *st, const chunk_t g,
			      const struct oakley_group_desc *group);

extern void start_dh_v1_secretiv(crypto_req_cont_func fn, const char *name,
				 struct state *st, enum original_role role,
				 const struct oakley_group_desc *oakley_group2);

extern bool finish_dh_secretiv(struct state *st,
			       struct pluto_crypto_req *r);

extern void start_dh_v1_secret(crypto_req_cont_func fn, const char *name,
			       struct state *st, enum original_role role,
			       const struct oakley_group_desc *oakley_group2);

extern void finish_dh_secret(struct state *st,
			     struct pluto_crypto_req *r);

extern void calc_dh(struct pcr_v1_dh *dh);

extern void cancelled_v1_dh(struct pcr_v1_dh *dh);

/*
 * IKEv2 DH
 */

extern void start_dh_v2(struct state *st,
			const char *name,
			enum original_role role,
			PK11SymKey *skey_d_old,
			const struct prf_desc *old_prf,
			crypto_req_cont_func pcrc_func);

extern bool finish_dh_v2(struct state *st,
			 struct pluto_crypto_req *r, bool only_shared);

extern void cancelled_dh_v2(struct pcr_dh_v2 *dh);

/*
 * KE and NONCE
 */

extern void unpack_KE_from_helper(struct state *st,
				  struct pluto_crypto_req *r,
				  chunk_t *g);

void pcr_kenonce_init(struct pluto_crypto_req_cont *cn,
		      enum pluto_crypto_requests pcr_type,
		      const struct oakley_group_desc *dh);

struct pcr_v1_dh *pcr_v1_dh_init(struct pluto_crypto_req_cont *cn,
				 enum pluto_crypto_requests pcr_type);

struct pcr_dh_v2 *pcr_dh_v2_init(struct pluto_crypto_req_cont *cn);

#endif /* _PLUTO_CRYPT_H */
