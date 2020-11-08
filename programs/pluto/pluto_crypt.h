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
