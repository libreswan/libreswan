/* Certificate support for IKE authentication
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
 */

#include "certs.h"

#include "lswalloc.h"
#include "passert.h"

void release_certs(struct certs **head)
{
	while (*head != NULL) {
		struct certs *old = *head;
		*head = old->next;
		CERT_DestroyCertificate(old->cert);
		pfree(old);
	}
}

void add_cert(struct certs **head, CERTCertificate *cert)
{
	passert(cert != NULL);
	struct certs *new = alloc_thing(struct certs, __func__);
	new->cert = cert;
	new->next = *head;
	*head = new;
}

CERTCertificate *make_end_cert_first(struct certs **head)
{
	for (struct certs *entry = *head; entry != NULL;
	     entry = entry->next) {
		if (!CERT_IsCACert(entry->cert, NULL)) {
			/*
			 * Swap .cert values of entry and *head.
			 * This will work even if entry == *head.
			 */
			CERTCertificate *end_cert = entry->cert;
			entry->cert = (*head)->cert;
			(*head)->cert = end_cert;
			return end_cert;
		}
	}
	return NULL;
}
