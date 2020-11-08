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
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
 * This is an internal interface between the main and helper threads.
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
#include "ike_spi.h"
#include "crypt_mac.h"

struct state;
struct msg_digest;
struct logger;
struct prf_desc;
struct dh_local_secret;
struct dh_desc;

/*
 * Offload work to the crypto thread pool (or the event loop if there
 * are no threads).
 *
 * XXX: MDP should be just MD.  Per IKEv2, the only code squiriling
 * away MDP should be in complete_v[12]_state_transition() when
 * STF_SUSPEND is returned.  Unfortunately, IKEv1 isn't there and
 * probably never will :-(
 */

struct crypto_task; /*struct job*/

typedef void crypto_compute_fn(struct logger *logger,
			       struct crypto_task *task,
			       int my_thread);
typedef stf_status crypto_completed_cb(struct state *st,
				       struct msg_digest *md,
				       struct crypto_task **task);
typedef void crypto_cancelled_cb(struct crypto_task **task);

struct crypto_handler {
	const char *name;
	crypto_compute_fn *compute_fn;
	crypto_completed_cb *completed_cb;
	crypto_cancelled_cb *cancelled_cb;
};

extern void submit_crypto(const struct logger *logger,
			  struct state *st,
			  struct crypto_task *task,
			  const struct crypto_handler *handler,
			  const char *name);

/*
 * cryptographic helper operations.
 */
enum pluto_crypto_requests {
	pcr_crypto = 0,		/* using crypto_handler */
};

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
	chunk = chunk2(wire_chunk_ptr(&(parent_ptr)->arena, (wire)), (wire)->len)

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

struct pluto_crypto_req {
	enum pluto_crypto_requests pcr_type;
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

typedef void crypto_req_cont_func(struct state *st, struct msg_digest *md,
				  struct pluto_crypto_req *r);

/* struct pluto_crypto_req_cont allocators */

struct state;

extern struct pluto_crypto_req_cont *new_pcrc(crypto_req_cont_func fn,
					      const char *name);

extern void start_crypto_helpers(int nhelpers, struct logger *logger);
extern void send_crypto_helper_request(struct state *st,
				       struct pluto_crypto_req_cont *cn);

void stop_helper_threads(void);
void helper_threads_stopped_callback(struct state *st, void *context); /* see pluto_shutdown.c */

/* actual helper functions */

/* internal */
void calc_v1_skeyid_and_iv(struct state *st);
void calc_v2_keymat(struct state *st,
		    PK11SymKey *old_skey_d, /* SKEYSEED IKE Rekey */
		    const struct prf_desc *old_prf, /* IKE Rekey */
		    const ike_spis_t *new_ike_spis);

/*
 * KE and NONCE
 */

extern void unpack_KE_from_helper(struct state *st,
				  struct dh_local_secret *local_secret,
				  chunk_t *g);

#endif /* _PLUTO_CRYPT_H */
