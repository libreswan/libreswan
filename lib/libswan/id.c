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
#include <ctype.h>
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
		chunk_t name; /* shunk_t */
		err_t ugh = atodn((*src == '@') ? src + 1 : src, &name);
		if (ugh != NULL) {
			return ugh;
		}
		*id = (struct id) {
			.kind = ID_DER_ASN1_DN,
			.name = clone_hunk(name, "asn1"),
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
		err_t ugh = domain_to_address(shunk1(src), afi, &addr);
		if (ugh != NULL) {
			return ugh;
		}
		*id = (struct id) {
			.kind = afi->id_addr,
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

void jam_id(jambuf_t *buf, const struct id *id, jam_bytes_fn *jam_bytes)
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
		if (isanyaddr(&id->ip_addr)) {
			jam(buf, "%%any");
		} else {
			jam_address(buf, &id->ip_addr);
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
		jam_dn(buf, id->name, jam_bytes);
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

const char *str_id(const struct id *id, id_buf *dst)
{
	jambuf_t buf = ARRAY_AS_JAMBUF(dst->buf);
	/* JAM_ID() only emits printable ASCII */
	jam_id(&buf, id, jam_raw_bytes);
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

/* is this a "match anything" id */
bool any_id(const struct id *a)
{
	switch (a->kind) {
	case ID_NONE:
		return TRUE; /* wildcard */

	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		return isanyaddr(&a->ip_addr);

	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_KEY_ID:
	case ID_NULL:
		return FALSE;

	default:
		bad_case(a->kind);
	}
}

/* compare two struct id values */
bool same_id(const struct id *a, const struct id *b)
{
	if (b->kind == ID_NONE || a->kind == ID_NONE) {
		dbg("id type with ID_NONE means wildcard match");
		return TRUE; /* it's the wildcard */
	}

	if (a->kind != b->kind) {
		return FALSE;
	}

	switch (a->kind) {
	case ID_NONE:
		return TRUE; /* repeat of above for completeness */

	case ID_NULL:
		if (a->kind == b->kind) {
			dbg("ID_NULL: id kind matches");
			return TRUE;
		}
		return FALSE;

	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		return sameaddr(&a->ip_addr, &b->ip_addr);

	case ID_FQDN:
	case ID_USER_FQDN:
		/*
		 * assumptions:
		 * - case should be ignored
		 * - trailing "." should be ignored
		 *   (even if the only character?)
		 */
	{
		size_t al = a->name.len,
			bl = b->name.len;

		/* strip trailing dots */
		while (al > 0 && a->name.ptr[al - 1] == '.')
			al--;
		while (bl > 0 && b->name.ptr[bl - 1] == '.')
			bl--;
		return al == bl &&
			strncaseeq((char *)a->name.ptr,
				(char *)b->name.ptr, al);
	}
	case ID_FROMCERT:
		dbg("same_id() received ID_FROMCERT - unexpected");
		/* FALLTHROUGH */
	case ID_DER_ASN1_DN:
		return same_dn(a->name, b->name);

	case ID_KEY_ID:
		return hunk_eq(a->name, b->name);

	default:
		bad_case(a->kind);
	}
}

/* compare two struct id values, DNs can contain wildcards */

bool match_id(const struct id *a, const struct id *b, int *wildcards)
{
	bool match;

	*wildcards = 0;

	if (b->kind == ID_NONE) {
		*wildcards = MAX_WILDCARDS;
		match = TRUE;
	} else if (a->kind != b->kind) {
		match = FALSE;
	} else if (a->kind == ID_DER_ASN1_DN) {
		match = match_dn_any_order_wild(a->name, b->name, wildcards);
	} else {
		match = same_id(a, b);
	}

	if (DBGP(DBG_BASE)) {
		id_buf buf;
		DBG_log("   match_id a=%s", str_id(a, &buf));
		DBG_log("            b=%s", str_id(b, &buf));
		DBG_log("   results  %s", match ? "matched" : "fail");
	}

	return match;
}

/* count the number of wildcards in an id */
int id_count_wildcards(const struct id *id)
{
	int count = 0;

	switch (id->kind) {
	case ID_NONE:
		count = MAX_WILDCARDS;
		break;
	case ID_DER_ASN1_DN:
		count = dn_count_wildcards(id->name);
		break;
	default:
		break;
	}

	id_buf b;
	dbg("counting wild cards for %s is %d", str_id(id, &b), count);

	return count;
}

void duplicate_id(struct id *dst, const struct id *src)
{
	passert(dst->name.ptr == NULL || dst->name.ptr != src->name.ptr);
	free_id_content(dst);
	*dst = clone_id(src, "copy of id");
}

static bool match_rdn(const CERTRDN *const rdn_a, const CERTRDN *const rdn_b, bool *const has_wild)
{
	if (rdn_a == NULL || rdn_b == NULL)
		return FALSE;

	int matched = 0;
	int ava_num = 0;

	CERTAVA *const *avas_b;
	for (avas_b = rdn_b->avas; *avas_b != NULL; avas_b++) {
		CERTAVA *const ava_b = *avas_b;
		const SECOidTag tag_b = CERT_GetAVATag(ava_b);

		ava_num++;

		CERTAVA *const *avas_a;
		for (avas_a = rdn_a->avas; *avas_a != NULL; avas_a++) {
			CERTAVA *const ava_a = *avas_a;

			if (CERT_GetAVATag(ava_a) == tag_b) {
				SECItem *val_b = CERT_DecodeAVAValue(&ava_b->value);

				/* XXX Can CERT_DecodeAVAValue() return NULL? No man page :( */
				if (val_b != NULL) {
					if (has_wild != NULL &&
					    val_b->len == 1 &&
					    val_b->data[0] == '*') {
						*has_wild = TRUE;
						matched++;
						SECITEM_FreeItem(val_b, PR_TRUE);
						break;
					}
					SECITEM_FreeItem(val_b, PR_TRUE);
				}
				if (CERT_CompareAVA(ava_a, ava_b) == SECEqual) {
					matched++;
					break;
				}
			}
		}
	}

	return matched > 0 && matched == ava_num;
}

/*
 * match an equal number of RDNs, in any order
 * if wildcards != NULL, wildcard matches are enabled
 */
static bool match_dn_unordered(const chunk_t a, const chunk_t b, int *const wildcards)
{
	dn_buf a_dnbuf = { "", };
	dn_buf b_dnbuf = { "", };


	/*
	 * Escape the ASN.1 into RFC-1485 (actually RFC-4514 and
	 * printable ASCII) so that that it is suitable for NSS's
	 * CERT_AsciiToName().
	 */
	const char *abuf = str_dn(a, &a_dnbuf); /* RFC1485 for NSS */
	const char *bbuf = str_dn(b, &b_dnbuf); /* RFC1485 for NSS */

	/*
	 * ABUF and BBUF, set by dntoa(), contain an RFC 1485(?)
	 * encoded string and that can contain UTF-8 (i.e.,
	 * !isprint()).  Strip that out before logging.
	 */
	dbg("matching unordered DNs A: '%s' B: '%s'", abuf, bbuf);

	CERTName *const a_name = CERT_AsciiToName(abuf);
	CERTName *const b_name = CERT_AsciiToName(bbuf);

	if (a_name == NULL || b_name == NULL) {
		/* NULL is ignored; see NSS commit 206 */
		CERT_DestroyName(a_name);
		CERT_DestroyName(b_name);
		return false;
	}

	int rdn_num = 0;
	int matched = 0;
	CERTRDN *const *rdns_b;
	for (rdns_b = b_name->rdns; *rdns_b != NULL; rdns_b++) {
		CERTRDN *const rdn_b = *rdns_b;

		rdn_num++;

		CERTRDN *const *rdns_a;
		for (rdns_a = a_name->rdns; *rdns_a != NULL; rdns_a++) {
			CERTRDN *const rdn_a = *rdns_a;
			bool has_wild = FALSE;

			if (match_rdn(rdn_a, rdn_b,
				      wildcards != NULL ? &has_wild : NULL)) {
				matched++;
				if (wildcards != NULL && has_wild)
					(*wildcards)++;
				break;
			}
		}
	}

	CERT_DestroyName(a_name);
	CERT_DestroyName(b_name);
	dbg("%s matched: %d, rdn_num: %d, wc %d",
	    __func__, matched, rdn_num, wildcards ? *wildcards : 0);

	return matched > 0 && rdn_num > 0 && matched == rdn_num;
}

bool match_dn_any_order_wild(chunk_t a, chunk_t b, int *wildcards)
{
	bool ret = match_dn(a, b, wildcards);

	if (!ret) {
		dbg("%s: not an exact match, now checking any RDN order with %d wildcards",
		    __func__, *wildcards);
		/* recount wildcards */
		*wildcards = 0;
		ret = match_dn_unordered(a, b, wildcards);
	}
	return ret;
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
		type = address_type(host)->id_addr;
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
