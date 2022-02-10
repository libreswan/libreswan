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
	enum ikev2_auth_method auth_method;
	v2_auth_signature_cb *cb;
	const struct private_key_stuff *pks;
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

bool submit_v2_auth_signature(struct ike_sa *ike,
			      const struct crypt_mac *hash_to_sign,
			      const struct hash_desc *hash_algo,
			      enum keyword_authby authby,
			      enum ikev2_auth_method auth_method,
			      v2_auth_signature_cb *cb)
{
	struct task task = {
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

	submit_task(ike->sa.st_logger, &ike->sa /*state to resume*/,
		    clone_thing(task, "signature task"),
		    &v2_auth_signature_handler,
		    "computing responder signature");
	return true;
}

static const uint8_t rsa_sha1_der_header[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

static struct hash_signature v2_auth_signature(struct logger *logger,
					       const struct crypt_mac *hash_to_sign,
					       const struct hash_desc *hash_algo,
					       enum ikev2_auth_method auth_method,
					       const struct private_key_stuff *pks)
{
	passert(hash_to_sign->len <= sizeof(hash_to_sign->ptr/*array*/)); /*hint to coverity*/
	logtime_t start = logtime_start(logger);

	/*
	 * Allocate large enough space for any digest.
	 * Bound could be tightened because the signature octets are
	 * only concatenated to a SHA1 hash.
	 */
	uint8_t hash_octets[sizeof(rsa_sha1_der_header) + sizeof(hash_to_sign->ptr/*an array*/)];
	size_t hash_len;

	switch (auth_method) {

	case IKEv2_AUTH_RSA:
		/*
		 * Very old style RSA with SHA1.
		 *
		 * Both the HASH_TO_SIGN and it's DER are fed into the
		 * signature algorithm.
		 */
		passert(hash_algo == &ike_alg_hash_sha1);
		memcpy(hash_octets, &rsa_sha1_der_header,
		       sizeof(rsa_sha1_der_header));
		memcpy(hash_octets + sizeof(rsa_sha1_der_header),
		       hash_to_sign->ptr, hash_to_sign->len);
		hash_len = sizeof(rsa_sha1_der_header) + hash_to_sign->len;
		break;

	case IKEv2_AUTH_DIGSIG:
		/*
		 * New style DIGSIG.
		 *
		 * Just the hash is fed into the signature algorithm
		 * (what comes back is a full-signature).  That is
		 * then prepended with a blob to describe the
		 * full-signature.
		 */
		hash_len = hash_to_sign->len;
		passert(hash_len <= sizeof(hash_octets));
		memcpy(hash_octets, hash_to_sign->ptr, hash_to_sign->len);
		break;

	default:
		bad_case(auth_method);
	}

	if (DBGP(DBG_BASE)) {
		DBG_dump("hash to sign", hash_octets, hash_len);
	}

	logtime_t sign_time = logtime_start(logger);
	struct hash_signature sig = pks->pubkey_type->sign_hash(pks,
								hash_octets,
								hash_len,
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
					    task->auth_method,
					    task->pks);
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
