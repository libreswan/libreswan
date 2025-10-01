/* IKEv2 Authentication helper, for libreswan
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include "crypt_mac.h"

#include "defs.h"
#include "ikev2_auth.h"
#include "keys.h"
#include "server_pool.h"
#include "state.h"
#include "secrets.h"
#include "log.h"
#include "connections.h"
#include "ike_alg_hash.h"
#include "crypt_hash.h"

struct task {
	/* in */
	chunk_t firstpacket;
	chunk_t nonce;
	chunk_t ia1;
	chunk_t ia2;
	struct crypt_mac idhash;
	v2_auth_signature_cb *cb;
	struct secret_pubkey_stuff *pks;
	const struct hash_desc *hasher;
	const struct pubkey_signer *signer;
	uint8_t intermediate_id[sizeof(uint32_t)];
	/* out */
	struct hash_signature signature;
};

static task_computer_fn v2_auth_signature_computer; /* type check */
static task_completed_cb v2_auth_signature_completed; /* type check */
static task_cleanup_cb v2_auth_signature_cleanup; /* type check */

struct task_handler v2_auth_signature_handler = {
	.name = "signature",
	.computer_fn = v2_auth_signature_computer,
	.completed_cb = v2_auth_signature_completed,
	.cleanup_cb = v2_auth_signature_cleanup,
};

static void pack_task(struct ike_sa *ike,
		      const struct crypt_mac *idhash,
		      enum perspective from_the_perspective_of,
		      struct task *task)
{
	enum sa_role role =
		(from_the_perspective_of == LOCAL_PERSPECTIVE ? ike->sa.st_sa_role :
		 ike->sa.st_sa_role == SA_INITIATOR ? SA_RESPONDER :
		 ike->sa.st_sa_role == SA_RESPONDER ? SA_INITIATOR :
		 0);

	chunk_t firstpacket = (from_the_perspective_of == LOCAL_PERSPECTIVE ? ike->sa.st_firstpacket_me :
			       from_the_perspective_of == REMOTE_PERSPECTIVE ? ike->sa.st_firstpacket_peer :
			       empty_chunk);

	chunk_t nonce = (role == SA_INITIATOR ? ike->sa.st_nr :
			 role == SA_RESPONDER ? ike->sa.st_ni :
			 empty_chunk);
	chunk_t ia1 = (role == SA_INITIATOR ? ike->sa.st_v2_ike_intermediate.initiator :
		       role == SA_RESPONDER ? ike->sa.st_v2_ike_intermediate.responder :
		       empty_chunk);
	chunk_t ia2 = (role == SA_INITIATOR ? ike->sa.st_v2_ike_intermediate.responder :
		       role == SA_RESPONDER ? ike->sa.st_v2_ike_intermediate.initiator :
		       empty_chunk);

	task->firstpacket = clone_hunk(firstpacket, "firstpacket");
	/* on initiator, we need to hash responders nonce */
	task->nonce = clone_hunk(nonce, "nonce");
	task->ia1 = clone_hunk(ia1, "ia1");
	task->ia2 = clone_hunk(ia2, "ia2");
	task->idhash = (*idhash);
	hton_thing(ike->sa.st_v2_ike_intermediate.id + 1, task->intermediate_id);
}

bool submit_v2_auth_signature(struct ike_sa *ike, struct msg_digest *md,
			      const struct crypt_mac *idhash,
			      const struct hash_desc *hasher,
			      enum perspective from_the_perspective_of,
			      const struct pubkey_signer *signer,
			      v2_auth_signature_cb *cb,
			      where_t where)
{
	const struct connection *c = ike->sa.st_connection;
	struct secret_pubkey_stuff *pks = get_local_private_key(c, signer->type,
								ike->sa.logger);
	if (pks == NULL) {
		/* failure: no key to use */
		return false;
	}

	struct task task = {
		.cb = cb,
		.hasher = hasher,
		.signer = signer,
		.pks = secret_pubkey_stuff_addref(pks, HERE),
		.signature = {0},
	};

	pack_task(ike, idhash, from_the_perspective_of, &task);

	submit_task(/*callback*/&ike->sa, /*task*/&ike->sa, md,
		    /*detach_whack*/false,
		    clone_thing(task, "signature task"),
		    &v2_auth_signature_handler, where);
	return true;
}

static struct hash_signature v2_auth_signature(struct logger *logger,
					       const struct crypt_mac *hash_to_sign,
					       const struct hash_desc *hash_algo,
					       const struct secret_pubkey_stuff *pks,
					       const struct pubkey_signer *signer)
{
	passert(hash_to_sign->len <= sizeof(hash_to_sign->ptr/*array*/)); /*hint to coverity*/
	logtime_t start = logtime_start(logger);

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log_hunk(logger, "hash to sign:", *hash_to_sign);
	}

	logtime_t sign_time = logtime_start(logger);
	struct hash_signature sig = signer->sign_hash(pks,
						      hash_to_sign->ptr,
						      hash_to_sign->len,
						      hash_algo,
						      logger);
	logtime_stop(&sign_time, "%s() calling sign_hash()", __func__);
	passert(sig.len <= sizeof(sig.ptr/*array*/));
	logtime_stop(&start, "%s()", __func__);
	return sig;
}

static struct crypt_mac compute_hash_to_sign(struct logger *logger, struct task *task)
{
	struct crypt_hash *ctx = crypt_hash_init("sighash", task->hasher, logger);
	crypt_hash_digest_hunk(ctx, "first packet", task->firstpacket);
	crypt_hash_digest_hunk(ctx, "nonce", task->nonce);
	/* we took the PRF(SK_d,ID[ir]'), so length is prf hash length */
	crypt_hash_digest_hunk(ctx, "IDHASH", task->idhash);
	if (task->ia1.len > 0) {
		crypt_hash_digest_hunk(ctx, "IntAuth_*_I_A", task->ia1);
		crypt_hash_digest_hunk(ctx, "IntAuth_*_R_A", task->ia2);
		/* IKE AUTH's first Message ID */
		crypt_hash_digest_thing(ctx, "IKE_AUTH_MID", task->intermediate_id);
	}
	return crypt_hash_final_mac(&ctx);
}

static void v2_auth_signature_computer(struct logger *logger, struct task *task,
				       int unused_my_thread UNUSED)
{
	struct crypt_mac hash_to_sign = compute_hash_to_sign(logger, task);
	task->signature = v2_auth_signature(logger, &hash_to_sign,
					    task->hasher,
					    task->pks, task->signer);
}

static stf_status v2_auth_signature_completed(struct state *st,
					      struct msg_digest *md,
					      struct task *task)
{
	stf_status status = task->cb(pexpect_ike_sa(st), md, &task->signature);
	return status;
}

static void v2_auth_signature_cleanup(struct task **task, struct logger *logger UNUSED)
{
	free_chunk_content(&(*task)->firstpacket);
	free_chunk_content(&(*task)->nonce);
	free_chunk_content(&(*task)->ia1);
	free_chunk_content(&(*task)->ia2);
	secret_pubkey_stuff_delref(&(*task)->pks, HERE);
	pfreeany(*task);
}
