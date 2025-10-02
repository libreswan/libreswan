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
	struct {
		size_t len;
		uint8_t ptr[sizeof(msgid_t)];
	} intermediate_wire_id;
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

	task->firstpacket = clone_hunk_as_chunk(firstpacket, "firstpacket");
	/* on initiator, we need to hash responders nonce */
	task->nonce = clone_hunk_as_chunk(nonce, "nonce");
	task->idhash = (*idhash);
	task->ia1 = clone_hunk_as_chunk(ia1, "ia1");
	task->ia2 = clone_hunk_as_chunk(ia2, "ia2");
	if (ike->sa.st_v2_ike_intermediate.id != 0) {
		/*
		 * The first IKE_AUTH exchange's ID (which is
		 * presumably immediately after the last
		 * IKE_INTERMEDIATE exchange).
		 */
		task->intermediate_wire_id.len = sizeof(task->intermediate_wire_id.ptr/*array*/);
		hton_thing(ike->sa.st_v2_ike_intermediate.id + 1, task->intermediate_wire_id.ptr/*array*/);
	}
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

static void v2_auth_signature_computer(struct logger *logger, struct task *task,
				       int unused_my_thread UNUSED)
{
	logtime_t start = logtime_start(logger);

	const struct hash_hunk octets[] = {
		{ "first packet", HUNK_REF(&task->firstpacket), },
		{ "nonce", HUNK_REF(&task->nonce), },
		{ "idhash", HUNK_REF(&task->idhash), },
		/* optional intermediate, len can be 0 */
		{ "ia1", HUNK_REF(&task->ia1), },
		{ "ia2", HUNK_REF(&task->ia2), },
		{ "Intermediate ID + 1", HUNK_REF(&task->intermediate_wire_id), },
	};

	const struct hash_hunks hunks = {
		ARRAY_REF(octets),
	};

	task->signature = task->signer->sign(task->signer, task->hasher,
					     task->pks, &hunks, logger);
	logtime_stop(&start, "%s()", __func__);
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
