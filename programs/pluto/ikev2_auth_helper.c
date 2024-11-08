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

struct task {
	/* in */
	const struct crypt_mac hash_to_sign;
	const struct hash_desc *hash_algo;
	v2_auth_signature_cb *cb;
	const struct secret_pubkey_stuff *pks;
	const struct pubkey_signer *signer;
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

bool submit_v2_auth_signature(struct ike_sa *ike, struct msg_digest *md,
			      const struct crypt_mac *hash_to_sign,
			      const struct hash_desc *hash_algo,
			      const struct pubkey_signer *signer,
			      v2_auth_signature_cb *cb,
			      where_t where)
{
	const struct connection *c = ike->sa.st_connection;
	struct task task = {
		.cb = cb,
		.hash_algo = hash_algo,
		.hash_to_sign = *hash_to_sign,
		.signer = signer,
		.pks = get_local_private_key(c, signer->type,
					     ike->sa.logger),
	};

	if (task.pks == NULL)
		/* failure: no key to use */
		return false;

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

	if (DBGP(DBG_BASE)) {
		DBG_dump_hunk("hash to sign", *hash_to_sign);
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

static void v2_auth_signature_computer(struct logger *logger, struct task *task,
				       int unused_my_thread UNUSED)
{
	task->signature = v2_auth_signature(logger, &task->hash_to_sign, task->hash_algo,
					    task->pks, task->signer);
}

static stf_status v2_auth_signature_completed(struct state *st,
					      struct msg_digest *md,
					      struct task *task)
{
	stf_status status = task->cb(pexpect_ike_sa(st), md, &task->signature);
	return status;
}

static void v2_auth_signature_cleanup(struct task **task)
{
	pfreeany(*task);
}
