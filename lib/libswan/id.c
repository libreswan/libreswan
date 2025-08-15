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
#include "ttodata.h"
#include "lswnss.h"		/* for clone_secitem_as_chunk() */

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

	if (streq(src, "%any") || streq(src, "0.0.0.0")) {
		/* any ID will be accepted */
		*id = (struct id) {
			.kind = ID_NONE,
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
			.name = HUNK_AS_SHUNK(name),
			.scratch = name.ptr,
		};
		return NULL;
	}

	if (strchr(src, '@') == NULL) {
		/*
		 * i.e., does not contain an @ at all
		 *
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

	if (eat(src, "@#")) {
		/*
		 * @#<HEX> - convert from hex to bin as ID
		 */
		chunk_t name = NULL_HUNK;
		err_t ugh = ttochunk(shunk1(src), 16, &name);
		if (ugh != NULL) {
			return ugh;
		}
		*id = (struct id) {
			.kind = ID_KEY_ID,
			.name = ASN1(name),
			.scratch = name.ptr,
		};
		return NULL;
	}

	if (eat(src, "@~")) {
		/*
		 * @~<HEX> - convert from hex to bin as DN
		 */
		chunk_t name = NULL_HUNK;
		err_t ugh = ttochunk(shunk1(src), 16, &name);
		if (ugh != NULL) {
			return ugh;
		}
		*id = (struct id) {
			.kind = ID_DER_ASN1_DN,
			.name = ASN1(name),
			.scratch = name.ptr,
		};
		return NULL;
	}

	if (eat(src, "@[")) {
		/*
		 * @[<ID> or @[<ID>] - this is documented
		 */
		int len = strlen(src);
		if (src[len-1] == ']') {
			len -= 1; /* drop trailing "]" */
		}
		chunk_t name = clone_bytes_as_chunk(src, len, "key id");
		*id = (struct id) {
			.kind = ID_KEY_ID,
			.name = ASN1(name),
			.scratch = name.ptr,
		};
		return NULL;
	}

	if (eat(src, "@")) {
		/*
		 * @<FQDN> - reduced to <FQDN>
		 */
		chunk_t name = clone_bytes_as_chunk(src, strlen(src), "fqdn id");
		*id = (struct id) {
			.kind = ID_FQDN,
			/* discard @ */
			.name = ASN1(name),
			.scratch = name.ptr,
		};
		return NULL;
	}

	/*
	 * <DN>@<DN> unchanged per DOI 4.6.2.4 (but DNS wants
	 * . instead).
	 */
	chunk_t name = clone_bytes_as_chunk(src, strlen(src), "DOI 4.6.2.4");
	*id = (struct id) {
		.kind = ID_USER_FQDN,
		.name = ASN1(name),
		.scratch = name.ptr,
	};
	return NULL;
}

size_t jam_id_bytes(struct jambuf *buf, const struct id *id, jam_bytes_fn *jam_bytes)
{
	if (id == NULL) {
		return jam_string(buf, "<null-id>");
	}
	size_t s = 0;
	switch (id->kind) {
	case ID_FROMCERT:
		s += jam_string(buf, "%fromcert");
		break;
	case ID_NONE:
		s += jam_string(buf, "(none)");
		break;
	case ID_NULL:
		s += jam_string(buf, "ID_NULL");
		break;
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		if (address_is_specified(id->ip_addr)) {
			s += jam_address(buf, &id->ip_addr);
		} else {
			s += jam_string(buf, "%any");
		}
		break;
	case ID_FQDN:
		s += jam_string(buf, "@");
		s += jam_bytes(buf, id->name.ptr, id->name.len);
		break;
	case ID_USER_FQDN:
		s += jam_bytes(buf, id->name.ptr, id->name.len);
		break;
	case ID_DER_ASN1_DN:
		s += jam_dn(buf, id->name, jam_bytes);
		break;
	case ID_KEY_ID:
		s += jam_string(buf, "@#0x");
		s += jam_hex_bytes(buf, id->name.ptr, id->name.len);
		break;
	default:
		s += jam(buf, "unknown id kind %d", id->kind);
		break;
	}
	return s;
}

const char *str_id_bytes(const struct id *id, jam_bytes_fn *jam_bytes, id_buf *dst)
{
	struct jambuf buf = ARRAY_AS_JAMBUF(dst->buf);
	/* JAM_ID() only emits printable ASCII */
	jam_id_bytes(&buf, id, jam_bytes);
	return dst->buf;
}

size_t jam_id(struct jambuf *buf, const struct id *id)
{
	return jam_id_bytes(buf, id, jam_raw_bytes); /* see above */
}

const char *str_id(const struct id *id, id_buf *buf)
{
	struct jambuf b = ARRAY_AS_JAMBUF(buf->buf);
	jam_id(&b, id); /* see above */
	return buf->buf;
}

struct id clone_id(const struct id *src, const char *story)
{
	chunk_t name = clone_hunk(src->name, story);
	struct id dst = {
		.kind = src->kind,
		.ip_addr = src->ip_addr,
		.name = ASN1(name),
		.scratch = name.ptr,
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
		pfreeany(id->scratch);
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
	struct verbose verbose = VERBOSE(DEBUG_STREAM, &global_logger, NULL);

	if (a->kind != b->kind) {
		return false;
	}

	switch (a->kind) {
	case ID_NONE:
		return true; /* repeat of above for completeness */

	case ID_NULL:
		ldbg(&global_logger, "ID_NULL: id kind matches");
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
		while (al > 0 && ((const uint8_t*)a->name.ptr)[al - 1] == '.')
			al--;
		size_t bl = b->name.len;
		while (bl > 0 && ((const uint8_t*)b->name.ptr)[bl - 1] == '.')
			bl--;

		return (al == bl /* same length */ &&
			strncaseeq((char *)a->name.ptr,
				   (char *)b->name.ptr, al));
	}

	case ID_FROMCERT:
		vdbg("%s() received ID_FROMCERT - unexpected", __func__);
		return same_dn(a->name, b->name, verbose);

	case ID_DER_ASN1_DN:
		return same_dn(a->name, b->name, verbose);

	case ID_KEY_ID:
		return hunk_eq(a->name, b->name);

	default:
		bad_case(a->kind);
	}
}

bool same_id(const struct id *a, const struct id *b)
{
	if (b->kind == ID_NONE || a->kind == ID_NONE) {
		ldbg(&global_logger, "id type with ID_NONE means wildcard match");
		return true; /* it's the wildcard */
	}

	return id_eq(a, b);
}

/* compare two struct id values, DNs can contain wildcards */

bool match_id(const struct id *a, const struct id *b,
	      int *wildcards_out, struct verbose verbose)
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
		match = match_dn_any_order_wild(a->name, b->name, &wildcards, verbose);
	} else if (same_id(a, b)) {
		wildcards = 0;
		match = true;
	} else {
		wildcards = MAX_WILDCARDS;
		match = false;
	}

	id_buf buf;
	vdbg("match_id a=%s", str_id(a, &buf));
	vdbg("         b=%s", str_id(b, &buf));
	vdbg("  result %s wildcards=%d",
	     match ? "matched" : "fail", wildcards);

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
		has_wildcards = dn_has_wildcards(id->name);
		break;

	default:
		has_wildcards = false;
		break;
	}

	id_buf b;
	ldbg(&global_logger, "id %s has wildcards: %s", str_id(id, &b), bool_str(has_wildcards));

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


/*
 * choose either subject DN or a subjectAltName as connection end ID
 */
struct id id_from_cert(const struct cert *cert)
{
	chunk_t name = clone_secitem_as_chunk(cert->nss_cert->derSubject, "cert id");
	struct id id = {
		.name = ASN1(name),
		.scratch = name.ptr,
		.kind = ID_DER_ASN1_DN,
	};
	return id;
}
