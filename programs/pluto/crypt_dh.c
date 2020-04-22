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
#include <ctype.h>
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
#include "connections.h"
#include "pluto_crypt.h"
#include "lswlog.h"
#include "log.h"
#include "timer.h"
#include "ike_alg.h"
#include "id.h"
#include "keys.h"
#include "crypt_dh.h"
#include "ike_alg_dh_ops.h"
#include "crypt_symkey.h"
#include <nss.h>
#include <pk11pub.h>
#include <keyhi.h>
#include "lswnss.h"

struct dh_secret {
	const struct dh_desc *group;
	SECKEYPrivateKey *privk;
	SECKEYPublicKey *pubk;
};

static void lswlog_dh_secret(struct lswlog *buf, struct dh_secret *secret)
{
	lswlogf(buf, "DH secret %s@%p: ",
		secret->group->common.fqn, secret);
}

struct dh_secret *calc_dh_secret(const struct dh_desc *group,
				 chunk_t *local_ke)
{
	chunk_t ke = alloc_chunk(group->bytes, "local ke");
	SECKEYPrivateKey *privk;
	SECKEYPublicKey *pubk;
	group->dh_ops->calc_secret(group, &privk, &pubk,
				      ke.ptr, ke.len);
	passert(privk != NULL);
	passert(pubk != NULL);
	*local_ke = ke;
	struct dh_secret *secret = alloc_thing(struct dh_secret, "DH secret");
	secret->group = group;
	secret->privk = privk;
	secret->pubk = pubk;
	LSWDBGP(DBG_CRYPT, buf) {
		lswlog_dh_secret(buf, secret);
		lswlogs(buf, "created");
	}
	return secret;
}

/** Compute DH shared secret from our local secret and the peer's public value.
 * We make the leap that the length should be that of the group
 * (see quoted passage at start of ACCEPT_KE).
 * If there is something that upsets NSS (what?) we will return NULL.
 */
/* MUST BE THREAD-SAFE */
PK11SymKey *calc_dh_shared(struct dh_secret *secret,
			   chunk_t remote_ke)
{
	PK11SymKey *dhshared =
		secret->group->dh_ops->calc_shared(secret->group,
						   secret->privk,
						   secret->pubk,
						   remote_ke.ptr, remote_ke.len);
	/*
	 * The IKEv2 documentation, even for ECP, refers to "g^ir".
	 */
	LSWDBGP(DBG_CRYPT, buf) {
		lswlog_dh_secret(buf, secret);
		lswlogf(buf, "computed shared DH secret key@%p",
			dhshared);
	}
	DBG(DBG_CRYPT, DBG_symkey("dh-shared ", "g^ir", dhshared));
	return dhshared;
}

/*
 * If needed, these functions can be tweaked to; instead of moving use
 * a copy and/or a reference count.
 */

void transfer_dh_secret_to_state(const char *helper, struct dh_secret **secret,
				 struct state *st)
{
	LSWDBGP(DBG_CRYPT, buf) {
		lswlog_dh_secret(buf, *secret);
		lswlogf(buf, "transferring ownership from helper %s to state #%lu",
			helper, st->st_serialno);
	}
	pexpect(st->st_dh_secret == NULL);
	st->st_dh_secret = *secret;
	*secret = NULL;
}

void transfer_dh_secret_to_helper(struct state *st,
				  const char *helper, struct dh_secret **secret)
{
	LSWDBGP(DBG_CRYPT, buf) {
		lswlog_dh_secret(buf, st->st_dh_secret);
		lswlogf(buf, "transferring ownership from state #%lu to helper %s",
			st->st_serialno, helper);
	}
	pexpect(*secret == NULL);
	*secret = st->st_dh_secret;
	st->st_dh_secret = NULL;
}

void free_dh_secret(struct dh_secret **secret)
{
	pexpect(*secret != NULL);
	if (*secret != NULL) {
		LSWDBGP(DBG_CRYPT, buf) {
			lswlog_dh_secret(buf, *secret);
			lswlogs(buf, "destroyed");
		}
		SECKEY_DestroyPublicKey((*secret)->pubk);
		SECKEY_DestroyPrivateKey((*secret)->privk);
		pfree(*secret);
		*secret = NULL;
	}
}

struct crypto_task {
	chunk_t remote_ke;
	struct dh_secret *local_secret;
	PK11SymKey *shared_secret;
	dh_cb *cb;
};

static void compute_dh(struct logger *logger_unused UNUSED,
		       struct crypto_task *task,
		       int thread_unused UNUSED)
{
	task->shared_secret = calc_dh_shared(task->local_secret,
					     task->remote_ke);
}

static void cancel_dh(struct crypto_task **task)
{
	free_dh_secret(&(*task)->local_secret); /* must own */
	free_chunk_content(&(*task)->remote_ke);
	release_symkey("DH", "secret", &(*task)->shared_secret);
	pfreeany(*task);
}

static stf_status complete_dh(struct state *st,
			      struct msg_digest *md,
			      struct crypto_task **task)
{
	transfer_dh_secret_to_state("IKEv2 DH", &(*task)->local_secret, st);
	free_chunk_content(&(*task)->remote_ke);
	pexpect(st->st_shared_nss == NULL);
	release_symkey(__func__, "st_shared_nss", &st->st_shared_nss);
	st->st_shared_nss = (*task)->shared_secret;
	stf_status status = (*task)->cb(st, md);
	pfreeany(*task);
	return status;
}

static const struct crypto_handler dh_handler = {
	.name = "dh",
	.cancelled_cb = cancel_dh,
	.compute_fn = compute_dh,
	.completed_cb = complete_dh,
};

void submit_dh(struct state *st, chunk_t remote_ke,
	       dh_cb *cb, const char *name)
{
	struct crypto_task *task = alloc_thing(struct crypto_task, "dh");
	task->remote_ke = clone_hunk(remote_ke, "DH crypto");
	transfer_dh_secret_to_helper(st, "DH", &task->local_secret);
	task->cb = cb;
	submit_crypto(st->st_logger, st, task, &dh_handler, name);
}
