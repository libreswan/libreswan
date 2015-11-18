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
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

#include "lsw_select.h"
#include "crypto.h"
#include "libreswan/passert.h"

/*
 * cryptographic helper operations.
 */
enum pluto_crypto_requests {
	pcr_build_ke_and_nonce,	/* calculate g^i and generate a nonce */
	pcr_build_nonce,	/* generate a nonce */
	pcr_compute_dh_iv,	/* calculate (g^x)(g^y) and skeyids for Phase 1 DH + prf */
	pcr_compute_dh,		/* calculate (g^x)(g^y) for Phase 2 PFS */
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
	/* input, then output */
	DECLARE_WIRE_ARENA(KENONCE_SIZE);

	/* inputs */
	u_int16_t oakley_group;

	/* outputs */
	SECKEYPrivateKey *secret;
	SECKEYPublicKey *pubk;
	wire_chunk_t gi;
	wire_chunk_t n;
};

#define DHCALC_SIZE 2560

/* query */
struct pcr_skeyid_q {
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	oakley_group_t oakley_group;
	oakley_auth_t auth;
	oakley_hash_t integ_hash;
	oakley_hash_t prf_hash;
	enum original_role role;
	size_t key_size; /* of encryptor, in bytes */
	size_t salt_size; /* ov IV salt, in bytes */
	wire_chunk_t gi;
	wire_chunk_t gr;
	wire_chunk_t pss;
	wire_chunk_t ni;
	wire_chunk_t nr;
	wire_chunk_t icookie;
	wire_chunk_t rcookie;
	SECKEYPrivateKey *secret;
	const struct encrypt_desc *encrypter;
	SECKEYPublicKey *pubk;
};

/* response */
struct pcr_skeyid_r {
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	PK11SymKey *shared;
	PK11SymKey *skeyid;
	PK11SymKey *skeyid_d;
	PK11SymKey *skeyid_a;
	PK11SymKey *skeyid_e;
	PK11SymKey *enc_key;

	wire_chunk_t new_iv;
};

/* response */
struct pcr_skeycalc_v2_r {
	DECLARE_WIRE_ARENA(DHCALC_SIZE);

	PK11SymKey *shared;
	PK11SymKey *skeyseed;
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
	size_t pcr_len;	/* MUST BE FIRST FIELD IN STRUCT */
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


/*
 * pluto_crypto_req_cont_func:
 *
 * A function that continues a state transition after
 * an asynchronous cryptographic calculation completes.
 *
 * See also comments prefixing send_crypto_helper_request.
 *
 * It is passed a pointer to each of the two structures.
 *
 * struct pluto_crypto_req_cont:
 *	Information back from helper process.
 *	Notionally sent across the wire.
 *
 * struct pluto_crypto_req:
 *	Bookkeeping information to resume the computation.
 *	Never sent across wire but perhaps copied.
 *	For example, it includes a struct msg_digest *
 *	in the cases where that is appropriate
 */
typedef void crypto_req_cont_func(struct pluto_crypto_req_cont *,
				struct pluto_crypto_req *);

/*
 * The crypto continuation structure
 *
 * Pluto is an event-driven transaction system.
 * Each transaction must take a very small slice of time.
 * Those that cannot, must be broken into multiple
 * transactions and the state carried between them
 * cannot be on the stack or in simple global variables.
 * A continuation is used to hold such state.
 *
 * A struct pluto_crypto_req_cont is heap-allocated
 * by code that wants to delegate cryptographic work.  It fills
 * in parts of the struct, and "fires and forgets" the work.
 * Unless the firing fails, a case that must be handled.
 * This struct stays on the master side: it isn't sent to the helper.
 * It is used to keep track of in-process work and what to do
 * when the work is complete.
 *
 * Used for:
 *	IKEv1 Quick Mode Key Exchange
 *	Other Key Exchange
 *	Diffie-Hellman computation
 */
struct pluto_crypto_req_cont {
	crypto_req_cont_func *pcrc_func;	/* function to continue with */
	/*
	 * Sponsoring state's serial number and state pointer.
	 * Currently a mish-mash but will transition
	 * to central management by send_crypto_helper_request
	 * and friends.
	 */
	so_serial_t pcrc_serialno;

	/*
	 * Sponsoring message's msg_digest.
	 * Used in most but not all continuations.
	 */
	struct msg_digest *pcrc_md;

	const char *pcrc_name;

	/*
	 * For IKEv1 Quick Mode Key Exchange:
	 * pcrc_replacing identifies the state object that
	 * the exchange will be replacing.
	 */
	so_serial_t pcrc_replacing;

	/* the rest of these fields are private to pluto_crypt.c */

	TAILQ_ENTRY(pluto_crypto_req_cont) pcrc_list;
	struct pluto_crypto_req *pcrc_pcr;	/* owner iff on backlog queue */
	pcr_req_id pcrc_id;
	pb_stream pcrc_reply_stream;	/* reply stream of suspended state transition */
	u_int8_t *pcrc_reply_buffer;	/* saved buffer contents (if any) */
#ifdef IPSEC_PLUTO_PCRC_DEBUG
	char *pcrc_function;
	char *pcrc_filep;
	int pcrc_line;
#endif
};
/* struct pluto_crypto_req_cont allocators */

extern struct pluto_crypto_req_cont *new_pcrc(
	crypto_req_cont_func fn,
	const char *name,
	struct state *st,
	struct msg_digest *md);

extern struct pluto_crypto_req_cont *new_pcrc_repl(
	crypto_req_cont_func fn,
	const char *name,
	struct state *st,
	struct msg_digest *md,
	so_serial_t replacing);


extern void init_crypto_helpers(int nhelpers);

extern stf_status send_crypto_helper_request(struct pluto_crypto_req *r,
					struct pluto_crypto_req_cont *cn);

extern void enumerate_crypto_helper_response_sockets(lsw_fd_set *readfds);

extern int pluto_crypto_helper_response_ready(lsw_fd_set *readfds);

extern void log_crypto_workers(void);

/* actual helper functions */
extern stf_status build_ke_and_nonce(struct pluto_crypto_req_cont *cn,
			   const struct oakley_group_desc *group,
			   enum crypto_importance importance);

extern void calc_ke(struct pluto_crypto_req *r);

extern stf_status build_nonce(struct pluto_crypto_req_cont *cn,
			      enum crypto_importance importance);

extern void calc_nonce(struct pluto_crypto_req *r);

extern void compute_dh_shared(struct state *st, const chunk_t g,
			      const struct oakley_group_desc *group);

extern stf_status start_dh_secretiv(struct pluto_crypto_req_cont *dh,
				    struct state *st,
				    enum crypto_importance importance,
				    enum original_role role,
				    oakley_group_t oakley_group2);

extern bool finish_dh_secretiv(struct state *st,
			       struct pluto_crypto_req *r);

extern stf_status start_dh_secret(struct pluto_crypto_req_cont *cn,
				  struct state *st,
				  enum crypto_importance importance,
				  enum original_role role,
				  oakley_group_t oakley_group2);

extern void finish_dh_secret(struct state *st,
			     struct pluto_crypto_req *r);

extern stf_status start_dh_v2(struct msg_digest *md,
			      const char *name,
			      enum original_role role,
			      crypto_req_cont_func pcrc_func);

extern bool finish_dh_v2(struct state *st,
			 const struct pluto_crypto_req *r);

extern void unpack_KE_from_helper(
	struct state *st,
	const struct pluto_crypto_req *r,
	chunk_t *g);

extern void pcr_nonce_init(struct pluto_crypto_req *r,
			    enum pluto_crypto_requests pcr_type,
			    enum crypto_importance pcr_pcim);

extern void pcr_dh_init(struct pluto_crypto_req *r,
			enum pluto_crypto_requests pcr_type,
			enum crypto_importance pcr_pcim);

#endif /* _PLUTO_CRYPT_H */
