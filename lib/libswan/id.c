/*
 * identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 *
 * Copyright (C) 1999-2001,2013-2017  D. Hugh Redelmeier
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008,2012-2017  Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013-2015 Matt Rogers, <mrogers@libreswan.org>
 * Copyright (C) 2013-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2015 Valeriu Goldberger <vgoldberger@ventusnetworks.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "sysdep.h"
#include "constants.h"
#include "passert.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "sysdep.h"
#include "id.h"
#include "x509.h"
#include <cert.h>
#include "certs.h"
#include "ip_info.h"

const struct id empty_id = {
	.kind = ID_NONE,
};

/*
 * Convert textual form of id into a struct id.
 */
err_t atoid(const char *src, struct id *id)
{
	*id = empty_id;

	if (streq("%fromcert", src)) {
		*id = (struct id) {
			.kind = ID_FROMCERT,
		};
		return NULL;
	}

	if (streq("%none", src)) {
		*id = (struct id) {
			.kind = ID_NONE,
		};
		return NULL;
	}

	if (streq("%null", src)) {
		*id = (struct id) {
			.kind = ID_NULL,
		};
		return NULL;
	}

	if (strchr(src, '=') != NULL) {
		/*
		 * We interpret this as an ASCII X.501 ID_DER_ASN1_DN.
		 *
		 * convert from LDAP style or openssl x509 -subject style
		 * to ASN.1 DN
		 * discard optional @ character in front of DN
		 */
		chunk_t name = empty_chunk;
		err_t ugh = atodn((*src == '@') ? src + 1 : src, &name);
		if (ugh != NULL) {
			return ugh;
		}
		*id = (struct id) {
			.kind = ID_DER_ASN1_DN,
			.name = name,
		};
		return NULL;
	}

	if (streq(src, "%any") || streq(src, "0.0.0.0")) {
		/* any ID will be accepted */
		*id = (struct id) {
			.kind = ID_NONE,
		};
		return NULL;
	}

	if (strchr(src, '@') == NULL) {
		/*
		 * !!! this test is not sufficient for distinguishing
		 * address families.
		 *
		 * We need a notation to specify that a FQDN is to be
		 * resolved to IPv6.
		 */
		const struct ip_info *afi = strchr(src, ':') == NULL ?
			&ipv4_info :
			&ipv6_info;
		ip_address addr;
		err_t ugh = ttoaddress_dns(shunk1(src), afi, &addr);
		if (ugh != NULL) {
			return ugh;
		}
		*id = (struct id) {
			.kind = afi->id_ip_addr,
			.ip_addr = addr,
		};
		return NULL;
	}

	if (strneq(src, "@#", 2)) {
		/*
		 * if there is a second specifier (#) on the line we
		 * interpret this as ID_KEY_ID.
		 *
		 * Discard @#, convert from hex to bin.
		 */
		src += 2; /* drop "@#" */
		chunk_t name = alloc_chunk(strlen(src) / 2, "key id");
		err_t ugh = ttodata(src, 0, 16, (void*)name.ptr, name.len, &name.len);
		if (ugh != NULL) {
			free_chunk_content(&name);
			return ugh;
		}
		*id = (struct id) {
			.kind = ID_KEY_ID,
			.name = name,
		};
		return NULL;
	}

	if (strneq(src, "@~", 2)) {
		/*
		 * if there is a second specifier (~) on the line we
		 * interpret this as a binary ID_DER_ASN1_DN.
		 *
		 * discard @~, convert from hex to bin.
		 */
		src += 2; /* drop "@~" */
		chunk_t name = alloc_chunk(strlen(src) / 2, "dn id");
		err_t ugh = ttodata(src + 2, 0, 16, (void*)name.ptr, name.len, &name.len);
		if (ugh != NULL) {
			free_chunk_content(&name);
			return ugh;
		}
		*id = (struct id) {
			.kind = ID_DER_ASN1_DN,
			.name = name,
		};
		return NULL;
	}

	if (strneq(src, "@[", 2)) {
		/*
		 * if there is a second specifier ([) on the line we
		 * interpret this as a text ID_KEY_ID, and we remove a
		 * trailing "]", if there is one.
		 */
		src += 2; /* drop "@[" */
		int len = strlen(src);
		if (src[len-1] == ']') {
			len -= 1; /* drop trailing "]" */
		}
		*id = (struct id) {
			.kind = ID_KEY_ID,
			.name = clone_bytes_as_chunk(src, len, "key id"),
		};
		return NULL;
	}

	if (*src == '@') {
		*id = (struct id) {
			.kind = ID_FQDN,
			/* discard @ */
			.name = clone_bytes_as_chunk(src + 1, strlen(src)-1, "fqdn id"),
		};
		return NULL;
	}

	/*
	 * We leave in @, as per DOI 4.6.2.4 (but DNS wants
	 * . instead).
	 */
	*id = (struct id) {
		.kind = ID_USER_FQDN,
		.name = clone_bytes_as_chunk(src, strlen(src), "DOI 4.6.2.4"),
	};
	return NULL;
}

void jam_id_bytes(struct jambuf *buf, const struct id *id, jam_bytes_fn *jam_bytes)
{
	switch (id->kind) {
	case ID_FROMCERT:
		jam(buf, "%%fromcert");
		break;
	case ID_NONE:
		jam(buf, "(none)");
		break;
	case ID_NULL:
		jam(buf, "ID_NULL");
		break;
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		if (address_is_specified(id->ip_addr)) {
			jam_address(buf, &id->ip_addr);
		} else {
			jam_string(buf, "%any");
		}
		break;
	case ID_FQDN:
		jam(buf, "@");
		jam_bytes(buf, id->name.ptr, id->name.len);
		break;
	case ID_USER_FQDN:
		jam_bytes(buf, id->name.ptr, id->name.len);
		break;
	case ID_DER_ASN1_DN:
		jam_dn(buf, ASN1(id->name), jam_bytes);
		break;
	case ID_KEY_ID:
		jam(buf, "@#0x");
		jam_hex_bytes(buf, id->name.ptr, id->name.len);
		break;
	default:
		jam(buf, "unknown id kind %d", id->kind);
		break;
	}
}

const char *str_id_bytes(const struct id *id, jam_bytes_fn *jam_bytes, id_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	/* JAM_ID() only emits printable ASCII */
	jam_id_bytes(&buf, id, jam_bytes);
	return dst->buf;
}

struct id clone_id(const struct id *src, const char *name)
{
	struct id dst = {
		.kind = src->kind,
		.ip_addr = src->ip_addr,
		.name = clone_hunk(src->name, name),
	};
	return dst;
}

void free_id_content(struct id *id)
{
	switch (id->kind) {
	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_KEY_ID:
		free_chunk_content(&id->name);
		break;
	case ID_FROMCERT:
	case ID_NONE:
	case ID_NULL:
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		pexpect(id->name.ptr == NULL);
		break;
	default:
		bad_case(id->kind);
	}
}

/*
 * Is this a "match anything" id?
 */
bool id_is_any(const struct id *a)
{
	switch (a->kind) {
	case ID_NONE:
		return true; /* wildcard */

	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		return (!address_is_specified(a->ip_addr));

	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_DER_ASN1_GN:
	case ID_KEY_ID:
	case ID_NULL:
		return false;

	default:
		return false;
	}
}

/* compare two struct id values */

bool id_eq(const struct id *a, const struct id *b)
{
	if (a->kind != b->kind) {
		return false;
	}

	switch (a->kind) {
	case ID_NONE:
		return true; /* repeat of above for completeness */

	case ID_NULL:
		dbg("ID_NULL: id kind matches");
		return true;

	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		return sameaddr(&a->ip_addr, &b->ip_addr);

	case ID_FQDN:
	case ID_USER_FQDN:
	{
		/*
		 * assumptions:
		 * - case should be ignored
		 * - trailing "." should be ignored
		 *   (even if the only character?)
		 */

		/* strip trailing dots */
		size_t al = a->name.len;
		while (al > 0 && a->name.ptr[al - 1] == '.')
			al--;
		size_t bl = b->name.len;
		while (bl > 0 && b->name.ptr[bl - 1] == '.')
			bl--;

		return (al == bl /* same length */ &&
			strncaseeq((char *)a->name.ptr,
				   (char *)b->name.ptr, al));
	}

	case ID_FROMCERT:
		dbg("same_id() received ID_FROMCERT - unexpected");
		/* FALLTHROUGH */
	case ID_DER_ASN1_DN:
		return same_dn(ASN1(a->name), ASN1(b->name));

	case ID_KEY_ID:
		return hunk_eq(ASN1(a->name), ASN1(b->name));

	default:
		bad_case(a->kind);
	}
}

bool same_id(const struct id *a, const struct id *b)
{
	if (b->kind == ID_NONE || a->kind == ID_NONE) {
		dbg("id type with ID_NONE means wildcard match");
		return true; /* it's the wildcard */
	}

	return id_eq(a, b);
}

/* compare two struct id values, DNs can contain wildcards */

bool match_id(const char *prefix, const struct id *a, const struct id *b,
	      int *wildcards_out)
{
	bool match;
	int wildcards;

	if (b->kind == ID_NONE) {
		wildcards = MAX_WILDCARDS;
		match = true;
	} else if (a->kind != b->kind) {
		/* should this allow SAN match of cert with right ID_DER_ASN1_DN? */
		wildcards = MAX_WILDCARDS;
		match = false;
	} else if (a->kind == ID_DER_ASN1_DN) {
		match = match_dn_any_order_wild(prefix, ASN1(a->name), ASN1(b->name), &wildcards);
	} else if (same_id(a, b)) {
		wildcards = 0;
		match = true;
	} else {
		wildcards = MAX_WILDCARDS;
		match = false;
	}

	if (DBGP(DBG_BASE)) {
		id_buf buf;
		DBG_log("%smatch_id a=%s", prefix, str_id(a, &buf));
		DBG_log("%s         b=%s", prefix, str_id(b, &buf));
		DBG_log("%sresults  %s wildcards=%d",
			prefix, match ? "matched" : "fail", wildcards);
	}

	*wildcards_out = wildcards;
	return match;
}

/* count the number of wildcards in an id */
bool id_has_wildcards(const struct id *id)
{
	bool has_wildcards;

	switch (id->kind) {
	case ID_NONE:
		has_wildcards = true;
		break;

#if 0 /* true? */
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		has_willdcards = !address_is_specified(id->ip_addr);
		break;
#endif

	case ID_DER_ASN1_DN:
		has_wildcards = dn_has_wildcards(ASN1(id->name));
		break;

	default:
		has_wildcards = false;
		break;
	}

	id_buf b;
	dbg("id %s has wildcards: %s", str_id(id, &b), bool_str(has_wildcards));

	return has_wildcards;
}

/*
 * Build an ID payload
 * Note: no memory is allocated for the body of the payload (tl->ptr).
 * We assume it will end up being a pointer into a sufficiently
 * stable datastructure.  It only needs to last a short time.
 */

enum ike_id_type id_to_payload(const struct id *id, const ip_address *host, shunk_t *body)
{
	int type;
	shunk_t tl;
	switch (id->kind) {
	case ID_NONE:
		type = address_type(host)->id_ip_addr;
		tl = address_as_shunk(host);
		break;
	case ID_FROMCERT:
		type = ID_DER_ASN1_DN;
		tl = shunk2(id->name.ptr, id->name.len);
		break;
	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_KEY_ID:
		type = id->kind;
		tl = shunk2(id->name.ptr, id->name.len);
		break;
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		type = id->kind;
		tl = address_as_shunk(&id->ip_addr);
		break;
	case ID_NULL:
		type = id->kind;
		tl = empty_shunk;
		break;
	default:
		bad_case(id->kind);
	}
	*body = tl;
	return type;
}
