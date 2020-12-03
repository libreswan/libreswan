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

static struct root_certs *root_certs;

struct root_certs *root_certs_addref(where_t where)
{
	passert(in_main_thread());

	/* extend or set cert cache lifetime */
	schedule_oneshot_timer(EVENT_FREE_ROOT_CERTS, FREE_ROOT_CERTS_TIMEOUT);
	if (root_certs != NULL) {
		return refcnt_addref(root_certs, where);
	}

	log_global(LOG_STREAM, null_fd, "loading root certificate cache");

	/*
	 * Always allocate the ROOT_CERTS structure.  If things fail,
	 * it will contain the empty list (but avoid possibly
	 * expensive attempts to re-load).
	 *
	 * Need to start with two references: the ROOT_CERTS; and the
	 * result of this function.
	 */
	root_certs = refcnt_alloc(struct root_certs, where);
	refcnt_addref(root_certs, where); /* function result */
	root_certs->trustcl = CERT_NewCertList();


	struct logger logger = GLOBAL_LOGGER(null_fd);
	PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(&logger);
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
		dbg("adding the CA+root cert %s", node->cert->subjectName);
		CERTCertificate *dup = CERT_DupCertificate(node->cert);
		CERT_AddCertToListTail(root_certs->trustcl, dup);
	}
	CERT_DestroyCertList(allcerts);
	threadtime_stop(&ca_time, SOS_NOBODY, "%s() filtering CAs", __func__);

	return root_certs;
}

static void root_certs_free(struct root_certs **certs, where_t unused_where UNUSED)
{
	log_global(LOG_STREAM, null_fd, "destroying root certificate cache");
	CERT_DestroyCertList(root_certs->trustcl);
	pfreeany(*certs);
}

void root_certs_delref(struct root_certs **root_certs,
			where_t where)
{
	refcnt_delref(root_certs, root_certs_free, where);
}

bool root_certs_empty(const struct root_certs *root_certs)
{
	return (!pexpect(root_certs != NULL) ||
		root_certs->trustcl == NULL ||
		CERT_LIST_EMPTY(root_certs->trustcl));
}

void init_root_certs(void)
{
	init_oneshot_timer(EVENT_FREE_ROOT_CERTS, free_root_certs);
}

void free_root_certs(struct logger *unused_logger UNUSED)
{
	passert(in_main_thread());
	root_certs_delref(&root_certs, HERE);
	pexpect(root_certs == NULL);
}
