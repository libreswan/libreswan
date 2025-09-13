/*
 * Cryptographic helper function - calculate DH
 *
 * Copyright (C) 2007-2008 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
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
 * This code was developed with the support of IXIA communications.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>


#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "demux.h"
#include "crypto.h"
#include "crypt_kem.h"
#include "rnd.h"
#include "state.h"
#include "connections.h"
#include "server_pool.h"
#include "log.h"
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "keys.h"
#include "crypt_dh.h"
#include "ike_alg_kem_ops.h"
#include "crypt_symkey.h"
#include <pk11pub.h>
#include <keyhi.h>
#include "lswnss.h"
#include "sa_role.h"

struct dh_local_secret {
	refcnt_t refcnt;
	const struct kem_desc *kem;
	SECKEYPrivateKey *private_key;
	SECKEYPublicKey *public_key;
	PK11SymKey *shared_key;
	shunk_t ke;
	chunk_t responder_ke;
	enum sa_role role;
};

static void jam_dh_local_secret(struct jambuf *buf, struct dh_local_secret *secret)
{
	jam(buf, "DH secret %s@%p: ", secret->kem->common.fqn, secret);
}

struct dh_local_secret *calc_dh_local_secret(const struct kem_desc *kem,
					     enum sa_role role,
					     shunk_t initiator_ke,
					     struct logger *logger)
{
	SECKEYPrivateKey *private_key;
	SECKEYPublicKey *public_key;
        PK11SymKey *shared_key;
	shunk_t ke;
	chunk_t responder_ke;
	if (role == SA_RESPONDER &&
	    kem->kem_ops->kem_encapsulate != NULL) {
		ldbgf(DBG_CRYPT, logger, "responder kem_encapsulate(initator_ke.len=%zu)",
		      initiator_ke.len);
		if (PBAD(logger, initiator_ke.len == 0)) {
			return NULL;
		}
		diag_t d = kem->kem_ops->kem_encapsulate(kem,
							 initiator_ke,
							 &shared_key,
							 &responder_ke,
							 logger);
		if (d != NULL) {
			llog(RC_LOG, logger, "computing responder KE: %s",
			     str_diag(d));
			pfree_diag(&d);
			return NULL;
		}
		ke = HUNK_AS_SHUNK(responder_ke);
		private_key = NULL;
		public_key = NULL;
	} else {
		kem->kem_ops->calc_local_secret(kem, &private_key, &public_key, logger);
		shared_key = NULL;
		zero(&responder_ke);
		passert(private_key != NULL);
		passert(public_key != NULL);
		ke = kem->kem_ops->local_secret_ke(kem, public_key);
	}
	struct dh_local_secret *secret = refcnt_alloc(struct dh_local_secret, logger, HERE);
	secret->kem = kem;
	secret->private_key = private_key;
	secret->public_key = public_key;
	secret->shared_key = shared_key;
	secret->ke = ke;
	secret->responder_ke = responder_ke;
	secret->role = role;
	LDBGP_JAMBUF(DBG_CRYPT, logger, buf) {
		jam_dh_local_secret(buf, secret);
		jam_string(buf, "created");
	}
	return secret;
}

shunk_t dh_local_secret_ke(struct dh_local_secret *local_secret)
{
	return local_secret->ke;
}

const struct kem_desc *dh_local_secret_desc(struct dh_local_secret *local_secret)
{
	return local_secret->kem;
}

struct dh_local_secret *dh_local_secret_addref(struct dh_local_secret *secret, where_t where)
{
	struct logger *logger = &global_logger;
	return addref_where(secret, logger, where);
}

void dh_local_secret_delref(struct dh_local_secret **secretp, where_t where)
{
	const struct logger *logger = &global_logger;
	struct dh_local_secret *secret = delref_where(secretp, logger, where);
	if (secret == NULL) {
		return;
	}
	SECKEY_DestroyPublicKey(secret->public_key);
	SECKEY_DestroyPrivateKey(secret->private_key);
	symkey_delref(logger, "shared-key", &secret->shared_key);
	free_chunk_content(&secret->responder_ke);
	pfreeany(secret);
}

struct task {
	chunk_t remote_ke;
	struct dh_local_secret *local_secret;
	PK11SymKey *shared_secret;
	so_serial_t dh_serialno; /* where to put result */
	dh_shared_secret_cb *cb;
};

/*
 * Compute DH shared secret from our local secret and the peer's
 * public value.  We make the leap that the length should be that of
 * the group (see quoted passage at start of ACCEPT_KE).  If there is
 * something that upsets NSS (what?) we will return NULL.
 */
/* MUST BE THREAD-SAFE */

static void compute_dh_shared_secret(struct logger *logger,
				     struct task *task,
				     int thread_unused UNUSED)
{

	struct dh_local_secret *secret = task->local_secret;
	const struct kem_desc *kem = secret->kem;
	diag_t d = NULL;
	if (kem->kem_ops->calc_shared_secret != NULL) {
		d = kem->kem_ops->calc_shared_secret(kem,
						     secret->private_key,
						     secret->public_key,
						     HUNK_AS_SHUNK(task->remote_ke),
						     &task->shared_secret,
						     logger);
	} else {
		switch (secret->role) {
		case SA_RESPONDER:
		{
			PASSERT(logger, secret->shared_key != NULL);
			task->shared_secret = symkey_addref(logger, "shared_secret",
							    secret->shared_key);
			break;
		}
		case SA_INITIATOR:
		{
			PASSERT(logger, secret->private_key != NULL);
			d = kem->kem_ops->kem_decapsulate(kem,
							  secret->private_key,
							  HUNK_AS_SHUNK(task->remote_ke),
							  &task->shared_secret,
							  logger);
			break;
		}
		default:
			bad_case(secret->role);
		}
	}
	if (d != NULL) {
		llog(RC_LOG, logger, "%s", str_diag(d));
		pfree_diag(&d);
		return;
	}
	/*
	 * The IKEv2 documentation, even for ECP, refers to "g^ir".
	 */
	if (LDBGP(DBG_CRYPT, logger)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam_dh_local_secret(buf, secret);
			jam(buf, "computed shared DH secret key@%p",
			    task->shared_secret);
		}
		LDBG_symkey(logger, "dh-shared ", "g^ir", task->shared_secret);
	}
}

static void cleanup_dh_shared_secret(struct task **task, struct logger *logger)
{
	dh_local_secret_delref(&(*task)->local_secret, HERE);
	free_chunk_content(&(*task)->remote_ke);
	symkey_delref(logger, "DH secret", &(*task)->shared_secret);
	pfreeany(*task);
}

static stf_status complete_dh_shared_secret(struct state *task_st,
					    struct msg_digest *md,
					    struct task *task)
{
	struct state *dh_st = state_by_serialno(task->dh_serialno);
	ldbg(dh_st->logger, "completing DH shared secret for "PRI_SO"/"PRI_SO,
	     pri_so(task_st->st_serialno),
	     pri_so(dh_st->st_serialno));
	pexpect(dh_st->st_dh_shared_secret == NULL);
	symkey_delref(dh_st->logger, "st_dh_shared_secret", &dh_st->st_dh_shared_secret);
	/* transfer */
	dh_st->st_dh_shared_secret = task->shared_secret;
	task->shared_secret = NULL;
	stf_status status = task->cb(task_st, md);
	return status;
}

static const struct task_handler dh_shared_secret_handler = {
	.name = "dh",
	.cleanup_cb = cleanup_dh_shared_secret,
	.computer_fn = compute_dh_shared_secret,
	.completed_cb = complete_dh_shared_secret,
};

void submit_dh_shared_secret(struct state *callback_sa,
			     struct state *dh_st,
			     struct msg_digest *md,
			     chunk_t remote_ke,
			     dh_shared_secret_cb *cb, where_t where)
{
	ldbg(dh_st->logger, "submitting DH shared secret for "PRI_SO"/"PRI_SO" "PRI_WHERE,
	     pri_so(callback_sa->st_serialno),
	     pri_so(dh_st->st_serialno),
	     pri_where(where));
	if (dh_st->st_dh_shared_secret != NULL) {
		llog_pexpect(dh_st->logger, where,
			     "in %s expecting st->st_dh_shared_secret == NULL",
			     __func__);
	}
	struct task *task = alloc_thing(struct task, "dh");
	task->remote_ke = clone_hunk(remote_ke, "DH crypto");
	task->local_secret = dh_local_secret_addref(dh_st->st_dh_local_secret, HERE);
	task->dh_serialno = dh_st->st_serialno;
	task->cb = cb;
	submit_task(/*callback*/callback_sa, /*task*/dh_st, md,
		    /*detach_whack*/false,
		    task, &dh_shared_secret_handler, where);
}
