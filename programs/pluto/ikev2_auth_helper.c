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
#include "pluto_crypt.h"
#include "state.h"
#include "secrets.h"
#include "log.h"
#include "connections.h"

struct crypto_task {
	/* in */
	const struct crypt_mac hash_to_sign;
	const struct hash_desc *hash_algo;
	enum ikev2_auth_method auth_method;
	v2_auth_signature_cb *cb;
	const struct private_key_stuff *pks;
	/* out */
	struct hash_signature signature;
};

static crypto_compute_fn v2_auth_signature_computer; /* type check */
static crypto_completed_cb v2_auth_signature_completed; /* type check */
static crypto_cancelled_cb v2_auth_signature_cancelled; /* type check */

struct crypto_handler v2_auth_signature_handler = {
	.name = "signature",
	.compute_fn = v2_auth_signature_computer,
	.completed_cb = v2_auth_signature_completed,
	.cancelled_cb = v2_auth_signature_cancelled,
};

bool submit_v2_auth_signature(struct ike_sa *ike,
			      const struct crypt_mac *hash_to_sign,
			      const struct hash_desc *hash_algo,
			      enum keyword_authby authby,
			      enum ikev2_auth_method auth_method,
			      v2_auth_signature_cb *cb)
{
	struct crypto_task task = {
		.cb = cb,
		.hash_algo = hash_algo,
		.auth_method = auth_method,
		.hash_to_sign = *hash_to_sign,
	};

	const struct connection *c = ike->sa.st_connection;
	switch (authby) {
	case AUTHBY_RSASIG:
		task.pks = get_connection_private_key(c, &pubkey_type_rsa,
						      ike->sa.st_logger);
		if (task.pks == NULL)
			/* failure: no key to use */
			return false;
		break;

	case AUTHBY_ECDSA:
		task.pks = get_connection_private_key(c, &pubkey_type_ecdsa,
						      ike->sa.st_logger);
		if (task.pks == NULL)
			/* failure: no key to use */
			return false;
		break;
	default:
		bad_case(authby);
	}
	submit_crypto(ike->sa.st_logger, &ike->sa /*state to resume*/,
		      clone_thing(task, "signature task"),
		      &v2_auth_signature_handler,
		      "computing responder signature");
	return true;
}

static void v2_auth_signature_computer(struct logger *logger, struct crypto_task *task,
				       int unused_my_thread UNUSED)
{
	task->signature = v2_auth_signature(logger, &task->hash_to_sign, task->hash_algo,
					    task->auth_method,
					    task->pks);
}

static stf_status v2_auth_signature_completed(struct state *st,
						 struct msg_digest *md,
						 struct crypto_task **task)
{
	stf_status status = (*task)->cb(pexpect_ike_sa(st), md, &(*task)->signature);
	pfreeany(*task);
	return status;
}

static void v2_auth_signature_cancelled(struct crypto_task **task)
{
	pfreeany(*task);
}
