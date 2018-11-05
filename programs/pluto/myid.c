/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013, 2017 Paul Wouters <pwouters@redhat.com>
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
#include "af_info.h"

/*
 * Build an ID payload
 * Note: no memory is allocated for the body of the payload (tl->ptr).
 * We assume it will end up being a pointer into a sufficiently
 * stable datastructure.  It only needs to last a short time.
 *
 * const-ness is confusing: we expect the memory pointed to by
 * the chunk will not be written, but it is awkward to paste const on it.
 */

void build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl, const struct end *end)
{
	const struct id *id = &end->id;
	const unsigned char *p;

	zero(hd);	/* OK: no pointer fields */
	/* hd->np = ISAKMP_NEXT_NONE; */
	*tl = empty_chunk;
	hd->isaiid_idtype = id->kind;

	switch (id->kind) {
	case ID_NONE:
		hd->isaiid_idtype =
			aftoinfo(addrtypeof(&end->host_addr))->id_addr;
		tl->len = addrbytesptr_read(&end->host_addr, &p);
		tl->ptr = DISCARD_CONST(unsigned char *, p);
		break;
	case ID_FROMCERT:
		hd->isaiid_idtype = ID_DER_ASN1_DN;
		/* FALLTHROUGH */
	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_KEY_ID:
		*tl = id->name;
		break;
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		tl->len = addrbytesptr_read(&id->ip_addr, &p);
		tl->ptr = DISCARD_CONST(unsigned char *, p);
		break;
	case ID_NULL:
		break;
	default:
		bad_case(id->kind);
	}
}

void v2_build_id_payload(struct ikev2_id *hd, chunk_t *tl, const struct end *end)
{
	build_id_payload((struct isakmp_ipsec_id *) hd, tl,end);
	/*
	 * note: critical bit is zero (ISAKMP_PAYLOAD_NONCRITICAL)
	 * as it must be (RFC7296 3,2)
	 */
}
