/* Root certificates, for libreswan
 *
 * Copyright (C) 2015,2018 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2017-2018 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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

#include <cert.h>

#include "defs.h"
#include "root_certs.h"
#include "server.h"
#include "pluto_timing.h"
#include "log.h"

static struct root_certs *root_cert_db;

struct root_certs *root_certs_addref_where(where_t where, struct logger *logger)
{
	passert(in_main_thread());

	/* extend or set cert cache lifetime */
	schedule_oneshot_timer(EVENT_FREE_ROOT_CERTS, FREE_ROOT_CERTS_TIMEOUT);
	if (root_cert_db != NULL) {
		return addref_where(root_cert_db, where);
	}

	dbg("loading root certificate cache");

	/*
	 * Always allocate the ROOT_CERTS structure.  If things fail,
	 * it will contain an empty list of certificates (but avoid
	 * possibly expensive attempts to re-load).
	 */
	root_cert_db = refcnt_alloc(struct root_certs, where);

	/*
	 * Start with two references: the ROOT_CERT_DB; and the result
	 * of this function.
	 */
	struct root_certs *root_certs = addref_where(root_cert_db, where); /* function result */
	root_certs->trustcl = CERT_NewCertList();

	PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(logger);
	if (slot == NULL) {
		/* already logged */
		return root_certs; /* empty, but non-null, list */
	}

	/*
	 * This is the killer when it comes to performance.
	 */
	threadtime_t get_time = threadtime_start();
	CERTCertList *allcerts = PK11_ListCertsInSlot(slot);
	threadtime_stop(&get_time, SOS_NOBODY, "%s() calling PK11_ListCertsInSlot()", __func__);
	if (allcerts == NULL) {
		return root_certs;
	}

	/*
	 * XXX: would a better call be
	 * CERT_FilterCertListByUsage(allcerts, certUsageAnyCA,
	 * PR_TRUE)?  Timing tests suggest it makes little difference,
	 * and the result is being cached anyway.
	 */
	threadtime_t ca_time = threadtime_start();
	for (CERTCertListNode *node = CERT_LIST_HEAD(allcerts);
	     !CERT_LIST_END(node, allcerts);
	     node = CERT_LIST_NEXT(node)) {
		if (!CERT_IsCACert(node->cert, NULL)) {
			dbg("discarding non-CA cert %s", node->cert->subjectName);
			continue;
		}
		if (!node->cert->isRoot) {
			dbg("discarding non-root CA cert %s", node->cert->subjectName);
			continue;
		}
		llog(RC_LOG, logger, "adding the CA+root cert %s", node->cert->subjectName);
		CERTCertificate *dup = CERT_DupCertificate(node->cert);
		CERT_AddCertToListTail(root_certs->trustcl, dup);
	}
	CERT_DestroyCertList(allcerts);
	threadtime_stop(&ca_time, SOS_NOBODY, "%s() filtering CAs", __func__);

	return root_certs;
}

void root_certs_delref_where(struct root_certs **root_certsp,
			     struct logger *logger, where_t where)
{
	struct root_certs *root_certs = delref_where(root_certsp, logger, where);
	if (root_certs != NULL) {
		llog(RC_LOG, logger, "freeing root certificate cache");
		CERT_DestroyCertList(root_certs->trustcl);
		pfreeany(root_certs);
	}
}

bool root_certs_empty(const struct root_certs *root_certs)
{
	return (!pexpect(root_certs != NULL) ||
		root_certs->trustcl == NULL ||
		CERT_LIST_EMPTY(root_certs->trustcl));
}

void init_root_certs(void)
{
	/*
	 * Set up the timer for deleting the root certs, but don't
	 * schedule it (it gets scheduled when the root certs are
	 * allocated).
	 */
	init_oneshot_timer(EVENT_FREE_ROOT_CERTS, free_root_certs);
}

void free_root_certs(struct logger *logger)
{
	passert(in_main_thread());

	/*
	 * This function can be called during shutdown when there are
	 * no certs.
	 */
	if (root_cert_db == NULL) {
		return;
	}

	/*
	 * Deal with a helper thread being stuck (because it is being debugged?);
	 * need to peek at the refcnt.
	 *
	 * There is a race condition: the reference count may be changed between
	 * the call to refcnt_peek and the root_certs_delref's deletion.
	 * The consequence is benign: only a delay of FREE_ROOT_CERTS_TIMEOUT.
	 */
	if (refcnt_peek(root_cert_db, logger) > 1) {
		llog(RC_LOG, logger, "root certs still in use; suspect stuck thread");
		/* extend or set cert cache lifetime */
		schedule_oneshot_timer(EVENT_FREE_ROOT_CERTS, FREE_ROOT_CERTS_TIMEOUT);
	} else {
		root_certs_delref(&root_cert_db, logger);
		pexpect(root_cert_db == NULL);
	}
}
