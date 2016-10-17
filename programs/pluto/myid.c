/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "log.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"
#include "packet.h"
#include "whack.h"

enum myid_state myid_state = MYID_UNKNOWN;
struct id myids[MYID_SPECIFIED + 1];    /* %myid */
char *myid_str[MYID_SPECIFIED + 1];     /* string form of IDs */

const struct id *resolve_myid(const struct id *id)
{
	// char tmpid[IDTOA_BUF];

	// idtoa(id, tmpid, sizeof(tmpid));
	// loglog(RC_LOG_SERIOUS,"resolve_myid() called for id:%s",tmpid);

	if ((id)->kind == ID_MYID) {
		return &myids[myid_state];
	} else {
		return id;
	}
}

void show_myid_status(void)
{
	char idstr[IDTOA_BUF];

	(void)idtoa(&myids[myid_state], idstr, sizeof(idstr));
	whack_log(RC_COMMENT, "myid = %s", idstr);
}

/* Fills in myid from environment variable IPSECmyid or defaultrouteaddr
 */
void init_id(void)
{
	passert(empty_id.kind == ID_NONE);
	myid_state = MYID_UNKNOWN;
	{
		enum myid_state s;

		for (s = MYID_UNKNOWN; s <= MYID_SPECIFIED; s++) {
			myids[s] = empty_id;
			myid_str[s] = NULL;
		}
	}
	set_myFQDN();
}

static void calc_myid_str(enum myid_state s)
{
	/* preformat the ID name */
	char buf[IDTOA_BUF];

	idtoa(&myids[s], buf, IDTOA_BUF);
	/* replace() uses pfreeany() */
	replace(myid_str[s], clone_str(buf, "myid string"));
}

void set_myid(enum myid_state s, char *idstr)
{
	if (idstr != NULL) {
		struct id id;
		err_t ugh = atoid(idstr, &id, FALSE, FALSE);

		if (ugh != NULL) {
			loglog(RC_BADID, "myid malformed: %s \"%s\"",
			        ugh, idstr);
		} else {
			duplicate_id(&myids[s], &id);
			if (s == MYID_SPECIFIED)
				myid_state = MYID_SPECIFIED;

			calc_myid_str(s);
		}
	}
}

void set_myFQDN(void)
{
	char FQDN[HOST_NAME_MAX + 1];
	int r = gethostname(FQDN, sizeof(FQDN));

	free_id_content(&myids[MYID_HOSTNAME]);
	myids[MYID_HOSTNAME] = empty_id;
	if (r != 0) {
		log_errno((e, "gethostname() failed in set_myFQDN"));
	} else {
		FQDN[sizeof(FQDN) - 1] = '\0'; /* insurance */

		{
			size_t len = strlen(FQDN);

			if (len > 0 && FQDN[len - 1] == '.') {
				/* nuke trailing . */
				FQDN[len - 1] = '\0';
			}
		}

		if (!strcaseeq(FQDN, "localhost.localdomain")) {
			clonetochunk(myids[MYID_HOSTNAME].name, FQDN,
				     strlen(FQDN), "my FQDN");
			myids[MYID_HOSTNAME].kind = ID_FQDN;
			calc_myid_str(MYID_HOSTNAME);
		}
	}
}

void free_myFQDN(void)
{
	int i;
	free_id_content(&myids[MYID_HOSTNAME]);
	for (i = 0; i < MYID_SPECIFIED; i++) {
		pfreeany(myid_str[i]);
	}
}

/* build an ID payload
 * Note: no memory is allocated for the body of the payload (tl->ptr).
 * We assume it will end up being a pointer into a sufficiently
 * stable datastructure.  It only needs to last a short time.
 */
void build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl, struct end *end)
{
	const struct id *id = resolve_myid(&end->id);

	zero(hd);	/* OK: no pointer fields */
	*tl = empty_chunk;
	hd->isaiid_idtype = id->kind;
	switch (id->kind) {
	case ID_NONE:
		hd->isaiid_idtype =
			aftoinfo(addrtypeof(&end->host_addr))->id_addr;
		tl->len = addrbytesptr(&end->host_addr, &tl->ptr); /* sets tl->ptr too */
		break;
	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_KEY_ID:
		*tl = id->name;
		break;
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		tl->len = addrbytesptr(&id->ip_addr, &tl->ptr); /* sets tl->ptr too */
		break;
	case ID_NULL:
		tl->len = 0;
		tl->ptr = NULL;
		break;
	default:
		bad_case(id->kind);
	}
}
