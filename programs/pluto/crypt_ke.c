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
#include "packet.h"
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
	const struct dh_desc *dh;
	chunk_t nonce;
	struct dh_local_secret *local_secret;
	ke_and_nonce_cb *cb;
};

static void compute_ke_and_nonce(struct logger *logger,
				 struct task *task,
				 int thread_unused UNUSED)
{
	if (task->dh != NULL) {
		task->local_secret = calc_dh_local_secret(task->dh, logger);
		if (DBGP(DBG_CRYPT)) {
			DBG_log("NSS: Local DH %s secret (pointer): %p",
				task->dh->common.fqn, task->local_secret);
		}
	}
	task->nonce = get_rnd_chunk(DEFAULT_NONCE_SIZE, "nonce");
	if (DBGP(DBG_CRYPT)) {
		DBG_dump_hunk("Generated nonce:", task->nonce);
	}
}

static void cleanup_ke_and_nonce(struct task **task)
{
	dh_local_secret_delref(&(*task)->local_secret, HERE);
	free_chunk_content(&(*task)->nonce);
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

void submit_ke_and_nonce(struct state *st, const struct dh_desc *dh,
			 ke_and_nonce_cb *cb, const char *name)
{
	struct task *task = alloc_thing(struct task, "dh");
	task->dh = dh;
	task->cb = cb;
	submit_task(st->st_logger, st, task, &ke_and_nonce_handler, name);
}

/*
 * Process KE values.
 */
void unpack_KE_from_helper(struct state *st, struct dh_local_secret *local_secret,
			   chunk_t *g)
{
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
	if (DBGP(DBG_CRYPT)) {
		const struct dh_desc *group = dh_local_secret_desc(local_secret);
		DBG_log("wire (crypto helper) group %s and state group %s %s",
			group->common.fqn,
			st->st_oakley.ta_dh ? st->st_oakley.ta_dh->common.fqn : "NULL",
			group == st->st_oakley.ta_dh ? "match" : "differ");
	}

	replace_chunk(g, clone_dh_local_secret_ke(local_secret));
	pexpect(st->st_dh_local_secret == NULL);
	st->st_dh_local_secret = dh_local_secret_addref(local_secret, HERE);
}
