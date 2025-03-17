/* Process the IKEv2 CERT payload (offline), for libreswan
 *
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2006-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
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

#include "defs.h"

#include "demux.h"
#include "state.h"
#include "pluto_x509.h"
#include "x509_ocsp.h"
#include "server_pool.h"
#include "cert_decode_helper.h"
#include "pluto_stats.h"
#include "id.h"
#include "nss_cert_verify.h"
#include "connections.h"
#include "fetch.h"
#include "root_certs.h"
#include "x509.h"
#include "crl_queue.h"
#include "log.h"

/*
 * Just decode a cert payload.
 */

struct task {
	/* input */
	struct msg_digest *md; /* counted reference */
	struct payload_digest *cert_payloads; /* ref into md */
	cert_decode_cb *cb;
	struct id id;
	enum ike_version ike_version;
	struct root_certs *root_certs; /* counted reference */
	/* output */
	struct verified_certs verified;
};

static task_computer_fn cert_decode_computer; /* type check */
static task_completed_cb cert_decode_completed; /* type check */
static task_cleanup_cb cert_decode_cleanup; /* type check */

struct task_handler cert_decode_handler = {
	.name = "decode certificate payload",
	.computer_fn = cert_decode_computer,
	.completed_cb = cert_decode_completed,
	.cleanup_cb = cert_decode_cleanup,
};

void submit_v2_cert_decode(struct ike_sa *ike,
			   struct msg_digest *md, struct payload_digest *cert_payloads,
			   cert_decode_cb *cb, where_t where)
{
	struct task task = {
		.root_certs = root_certs_addref(&global_logger),
		.md = md_addref(md),
		.cert_payloads = cert_payloads,
		.cb = cb,
		.ike_version = ike->sa.st_ike_version,
		.id = ike->sa.st_connection->remote->host.id, /* XXX: safe? */
	};
	submit_task(/*callback*/&ike->sa, /*task*/&ike->sa, md,
		    /*detach_whack*/false,
		    clone_thing(task, "decode certificate payload task"),
		    &cert_decode_handler, where);
}

static void cert_decode_computer(struct logger *logger,
				 struct task *task,
				 int my_thread UNUSED)
{
	task->verified = find_and_verify_certs(logger, task->ike_version,
					       task->cert_payloads,
					       task->root_certs, &task->id);
}

static stf_status cert_decode_completed(struct state *st,
					struct msg_digest *md,
					struct task *task)
{
	struct ike_sa *ike = ike_sa(st, HERE);
	pexpect(!ike->sa.st_remote_certs.processed);
	ike->sa.st_remote_certs.processed = true;
	ike->sa.st_remote_certs.harmless = task->verified.harmless;

	/* if there's an error, log it */

#if defined(USE_LIBCURL) || defined(USE_LDAP)
	if (task->verified.crl_update_needed &&
	    deltasecs(crl_check_interval) > 0) {
		/*
		 * When a strict crl check fails, the certs are
		 * deleted and CRL_NEEDED is set.
		 *
		 * When a non-strict crl check fails, it is left to
		 * the crl fetch job to do a refresh (and
		 * crl_update_needed is left unset).
		 *
		 * Trigger a refresh.
		 */
		chunk_t fdn = empty_chunk;
		if (find_crl_fetch_dn(&fdn, ike->sa.st_connection)) {
			submit_crl_fetch_request(ASN1(fdn), ike->sa.logger);
		}
		pexpect(task->verified.cert_chain == NULL);
		pexpect(task->verified.pubkey_db == NULL);
	}
#endif

	/*
	 * transfer certs and db to state (might be NULL).
	 */

	pexpect(st->st_remote_certs.verified == NULL);
	ike->sa.st_remote_certs.verified = task->verified.cert_chain;
	ike->sa.st_remote_certs.groundhog = task->verified.groundhog;
	task->verified.cert_chain = NULL;

	pexpect(ike->sa.st_remote_certs.pubkey_db == NULL);
	ike->sa.st_remote_certs.pubkey_db = task->verified.pubkey_db;
	task->verified.pubkey_db = NULL;

	/*
	 * Log failure, and for the initiator possibly fail.
	 *
	 * The strange logging order is largely to keep expected test
	 * output happy.  See decode_certs().
	 */

	if (task->verified.harmless) {
		if (ike->sa.st_remote_certs.verified != NULL) {
			CERTCertificate *end_cert = ike->sa.st_remote_certs.verified->cert;
			passert(end_cert != NULL);
			dbg("certificate verified OK: %s", end_cert->subjectName);
		}
	} else {
		pexpect(ike->sa.st_remote_certs.verified == NULL);
		pexpect(ike->sa.st_remote_certs.pubkey_db == NULL);
		/* NSS: already logged details */
		llog_sa(RC_LOG, ike, "X509: certificate payload rejected for this connection");
		if (ike->sa.st_sa_role == SA_INITIATOR) {
			/*
			 * One of the certs was bad; no point switching
			 * initiator.
			 */
			pstat_sa_failed(&ike->sa, REASON_AUTH_FAILED);
			return STF_FATAL;
		}
	       /*
		* The 'end-cert' was bad so all the certs have been
		* tossed.  However, since this is the responder
		* stumble on.  There might be a connection that still
		* authenticates (after a switch?).
		*/
	}

	return task->cb(st, md);
}

static void cert_decode_cleanup(struct task **task)
{
	release_certs(&(*task)->verified.cert_chain);	/* may be NULL */
	free_public_keys(&(*task)->verified.pubkey_db);	/* may be NULL */
	md_delref(&(*task)->md);
	root_certs_delref(&(*task)->root_certs, GLOBAL_LOGGER);
	pfreeany((*task));
}
