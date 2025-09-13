/*
 * Cryptographic helper function - calculate KE and nonce
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 - 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
#include "rnd.h"
#include "state.h"
#include "server_pool.h"
#include "log.h"

#include <nspr.h>
#include <prerror.h>
#include <pk11pub.h>
#include <keyhi.h>
#include "lswnss.h"
#include "test_buffer.h"
#include "ike_alg.h"
#include "crypt_dh.h"
#include "crypt_ke.h"

struct task {
	const struct kem_desc *dh;
	chunk_t nonce;
	struct dh_local_secret *local_secret;
	chunk_t initiator_ke;
	ke_and_nonce_cb *cb;
	enum sa_role role;
};

static void compute_ke_and_nonce(struct logger *logger,
				 struct task *task,
				 int thread_unused UNUSED)
{
	if (task->dh != NULL) {
		task->local_secret = calc_dh_local_secret(task->dh,
							  task->role,
							  HUNK_AS_SHUNK(task->initiator_ke),
							  logger);
		if (LDBGP(DBG_CRYPT, logger)) {
			LDBG_log(logger, "%s() %s KE (pointer): %p",
				 __func__,
				 task->dh->common.fqn,
				 task->local_secret);
		}
	}
	task->nonce = alloc_rnd_chunk(DEFAULT_NONCE_SIZE, "nonce");
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "%s() generated nonce:", __func__);
		LDBG_hunk(logger, task->nonce);
	}
}

static void cleanup_ke_and_nonce(struct task **task,
				 struct logger *logger UNUSED)
{
	dh_local_secret_delref(&(*task)->local_secret, HERE);
	free_chunk_content(&(*task)->nonce);
	free_chunk_content(&(*task)->initiator_ke);
	pfreeany(*task);
}

static stf_status complete_ke_and_nonce(struct state *st,
					struct msg_digest *md,
					struct task *task)
{
	stf_status status = task->cb(st, md,
				     task->local_secret,
				     &task->nonce);
	return status;
}

static const struct task_handler ke_and_nonce_handler = {
	.name = "dh",
	.cleanup_cb = cleanup_ke_and_nonce,
	.computer_fn = compute_ke_and_nonce,
	.completed_cb = complete_ke_and_nonce,
};

void submit_ke_and_nonce(struct state *callback_sa,
			 struct state *task_sa,
			 struct msg_digest *md,
			 const struct kem_desc *dh,
			 ke_and_nonce_cb *cb,
			 bool detach_whack,
			 where_t where)
{
	struct task task = {
		.dh = dh,
		.cb = cb,
		.role = task_sa->st_sa_role,
		.initiator_ke = clone_hunk(task_sa->st_gi, "Gi"),
	};
	submit_task(/*callback*/callback_sa, /*task*/task_sa,
		    md, detach_whack,
		    clone_thing(task, "ke-and-nonce"),
		    &ke_and_nonce_handler, where);
}

/*
 * Process KE values.
 */
void unpack_KE_from_helper(struct state *st, struct dh_local_secret *local_secret,
			   chunk_t *g)
{
	struct logger *logger = st->logger;

	/*
	 * Should the crypto helper group and the state group be in
	 * sync?
	 *
	 * Probably not, yet seemingly (IKEv2) code is assuming this.
	 *
	 * For instance, with IKEv2, the initial initiator is setting
	 * st_oakley.group to the draft KE group (and well before
	 * initial responder has had a chance to agree to any thing).
	 * Should the initial responder comes back with INVALID_KE
	 * then st_oakley.group gets changed to match the suggestion
	 * and things restart; should the initial responder come back
	 * with an accepted proposal and KE, then the st_oakley.group
	 * is set based on the accepted proposal (the two are
	 * checked).
	 *
	 * Surely, instead, st_oakley.group should be left alone.  The
	 * the initial initiator would maintain a list of KE values
	 * proposed (INVALID_KE flip-flopping can lead to more than
	 * one) and only set st_oakley.group when the initial
	 * responder comes back with a vald accepted propsal and KE.
	 */
	if (LDBGP(DBG_CRYPT, logger)) {
		const struct kem_desc *group = dh_local_secret_desc(local_secret);
		LDBG_log(logger, "wire (crypto helper) group %s and state group %s %s",
			 group->common.fqn,
			 st->st_oakley.ta_dh ? st->st_oakley.ta_dh->common.fqn : "NULL",
			 group == st->st_oakley.ta_dh ? "match" : "differ");
	}

	replace_chunk(g, dh_local_secret_ke(local_secret), "KE");
	pexpect(st->st_dh_local_secret == NULL);
	st->st_dh_local_secret = dh_local_secret_addref(local_secret, HERE);
}
