/*
 * identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 *
 * Copyright (C) 1999-2001,2013-2017  D. Hugh Redelmeier
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2015 Matt Rogers, <mrogers@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015 Valeriu Goldberger <vgoldberger@ventusnetworks.com>
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

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "libreswan/passert.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "sysdep.h"
#include "id.h"
#include "x509.h"
#include <cert.h>
#include "certs.h"
#include "af_info.h"

/*
 * Note that there may be as many as six IDs that are temporary at
 * one time before unsharing the two ends of a connection. So we need
 * at least six temporary buffers for DER_ASN1_DN IDs.
 * We rotate them. Be careful!
 */
#define MAX_BUF 6

unsigned char *temporary_cyclic_buffer(void)
{
	/* MAX_BUF internal buffers */
	static unsigned char buf[MAX_BUF][IDTOA_BUF];
	static int counter;	/* cyclic counter */

	if (++counter == MAX_BUF)
		counter = 0;	/* next internal buffer */
	return buf[counter];	/* assign temporary buffer */
}

/*
 * Convert textual form of id into a (temporary) struct id.
 *
 * Note that if the id is to be kept, unshare_id_content will be necessary.
 * This function should be split into parts so the boolean arguments can be
 * removed -- Paul
 */
err_t atoid(char *src, struct id *id, bool oe_only)
{
	err_t ugh = NULL;

	*id = empty_id;

	if (!oe_only && streq("%fromcert", src)) {
		id->kind = ID_FROMCERT;
	} else if (!oe_only && streq("%none", src)) {
		id->kind = ID_NONE;
	} else if (!oe_only && streq("%null", src)) {
		id->kind = ID_NULL;
	} else if (!oe_only && strchr(src, '=') != NULL) {
		/* we interpret this as an ASCII X.501 ID_DER_ASN1_DN */
		id->kind = ID_DER_ASN1_DN;
		/*
		 * convert from LDAP style or openssl x509 -subject style
		 * to ASN.1 DN
		 * discard optional @ character in front of DN
		 */
		ugh = atodn((*src == '@') ? src + 1 : src, &id->name);
	} else if (strchr(src, '@') == NULL) {
		if (streq(src, "%any") || streq(src, "0.0.0.0")) {
			/* any ID will be accepted */
			id->kind = ID_NONE;
		} else {
			/*
			 * !!! this test is not sufficient for distinguishing
			 * address families.
			 * We need a notation to specify that a FQDN is to be
			 * resolved to IPv6.
			 */
			const struct af_info *afi = strchr(src, ':') == NULL ?
				&af_inet4_info : &
				af_inet6_info;

			id->kind = afi->id_addr;
			ugh = ttoaddr(src, 0, afi->af, &id->ip_addr);
		}
	} else {
		if (*src == '@') {
			if (!oe_only && *(src + 1) == '#') {
				/*
				 * if there is a second specifier (#) on the
				 * line we interprete this as ID_KEY_ID
				 */
				id->kind = ID_KEY_ID;
				id->name.ptr = (unsigned char *)src;
				/* discard @~, convert from hex to bin */
				ugh = ttodata(src + 2, 0, 16,
					(char *)id->name.ptr,
					strlen(src), &id->name.len);
			} else if (!oe_only && *(src + 1) == '~') {
				/*
				 * if there is a second specifier (~) on the
				 * line we interprete this as a binary
				 * ID_DER_ASN1_DN
				 */
				id->kind = ID_DER_ASN1_DN;
				id->name.ptr = (unsigned char *)src;
				/* discard @~, convert from hex to bin */
				ugh = ttodata(src + 2, 0, 16,
					(char *)id->name.ptr,
					strlen(src), &id->name.len);
			} else if (!oe_only && *(src + 1) == '[') {
				/*
				 * if there is a second specifier ([) on the
				 * line we interprete this as a text ID_KEY_ID,
				 * and we remove a trailing ", if there is one.
				 */
				int len = strlen(src + 2);

				id->kind = ID_KEY_ID;
				id->name.ptr = (unsigned char *)src + 2;

				/*
				 * Start of name.ptr is srv+2 so len is 2
				 * smaller than the length of src and the
				 * terminator character is at src[len+2].
				 * Therefore, the last character is src[len+1]
				 */
				if (src[len + 1] == ']') {
					src[len + 1] = '\0';
					len--;
				}
				id->name.len = len;
			} else {
				id->kind = ID_FQDN;
				/* discard @ */
				id->name.ptr = (unsigned char *)src + 1;
				id->name.len = strlen(src) - 1;
			}
		} else {
			/*
			 * We leave in @, as per DOI 4.6.2.4
			 * (but DNS wants . instead).
			 */
			id->kind = ID_USER_FQDN;
			id->name.ptr = (unsigned char *)src;
			id->name.len = strlen(src);
		}
	}
	return ugh;
}

/*
 * Converts a binary key ID into hexadecimal format
 */
static int keyidtoa(char *dst, size_t dstlen, chunk_t keyid)
{
	int n = datatot(keyid.ptr, keyid.len, 'x', dst, dstlen);

	return ((n < (int)dstlen) ? n : (int)dstlen) - 1;
}

int idtoa(const struct id *id, char *dst, size_t dstlen)
{
	int n;

	switch (id->kind) {
	case ID_FROMCERT:
		n = snprintf(dst, dstlen, "%s", "%fromcert");
		break;
	case ID_NONE:
		n = snprintf(dst, dstlen, "%s", "(none)");
		break;
	case ID_NULL:
		n = snprintf(dst, dstlen, "%s", "ID_NULL");
		break;
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		if (isanyaddr(&id->ip_addr)) {
			n = snprintf(dst, dstlen, "%s", "%any");
		} else {
			n = (int)addrtot(&id->ip_addr, 0, dst, dstlen) - 1;
		}
		break;
	case ID_FQDN:
		n = snprintf(dst, dstlen, "@%.*s", (int)id->name.len,
			id->name.ptr);
		break;
	case ID_USER_FQDN:
		n = snprintf(dst, dstlen, "%.*s", (int)id->name.len,
			id->name.ptr);
		break;
	case ID_DER_ASN1_DN:
		n = dntoa(dst, dstlen, id->name);
		break;
	case ID_KEY_ID:
		passert(dstlen > 4);
		dst[0] = '@';
		dst[1] = '#';
		dstlen -= 2;
		dst += 2;
		n = keyidtoa(dst, dstlen, id->name);
		n += 2;
		break;
	default:
		n = snprintf(dst, dstlen, "unknown id kind %d", id->kind);
		break;
	}

	/*
	 * "Sanitize" string so that log isn't endangered:
	 * replace unprintable characters with '?'.
	 */
	if (n > 0) {
		for (; *dst != '\0'; dst++)
			if (!isprint(*dst))
				*dst = '?';
	}

	return n;
}

/*
 * Replace the shell metacharacters ', \, ", `, and $ in a character string
 * by escape sequences consisting of their octal values
 */
void escape_metachar(const char *src, char *dst, size_t dstlen)
{
	while (*src != '\0' && dstlen > 5) {
		switch (*src) {
		case '\'':
		case '\\':
		case '"':
		case '`':
		case '$':
		{
			int n = snprintf(dst, dstlen, "\\03%o", *src & 0xFF);

			passert((size_t)n < dstlen);	/* no truncation! */
			dst += n;
			dstlen -= n;
			break;
		}
		default:
			passert(1 < dstlen);	/* no truncation! */
			*dst++ = *src;
			dstlen--;
		}
		src++;
	}
	passert(1 <= dstlen);	/* no truncation! */
	*dst = '\0';
}

/*
 * Make private copy of string in struct id.
 * This is needed if the result of atoid is to be kept.
 */
void unshare_id_content(struct id *id)
{
	switch (id->kind) {
	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_KEY_ID:
		id->name.ptr = clone_bytes(id->name.ptr, id->name.len,
					"keep id name");
		/* Somehow assert we have a valid id here? */
		break;
	case ID_FROMCERT:
	case ID_NONE:
	case ID_NULL:
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
		break;
	default:
		bad_case(id->kind);
	}
}

void free_id_content(struct id *id)
{
	switch (id->kind) {
	case ID_FQDN:
	case ID_USER_FQDN:
	case ID_DER_ASN1_DN:
	case ID_KEY_ID:
		freeanychunk(id->name);
		break;
	case ID_FROMCERT:
	case ID_NONE:
	case ID_NULL:
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
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
		/* NOTREACHED */
		return FALSE;
	}
}

/* compare two struct id values */
bool same_id(const struct id *a, const struct id *b)
{
	if (b->kind == ID_NONE || a->kind == ID_NONE) {
		DBG(DBG_PARSING, DBG_log("id type with ID_NONE means wildcard match"));
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
			DBG(DBG_PARSING, DBG_log("ID_NULL: id kind matches"));
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
		DBG(DBG_CONTROL,
			DBG_log("same_id() received ID_FROMCERT - unexpected"));
		/* FALLTHROUGH */
	case ID_DER_ASN1_DN:
		return same_dn(a->name, b->name);

	case ID_KEY_ID:
		return chunk_eq(a->name, b->name);

	default:
		bad_case(a->kind);
		/* NOTREACHED */
		return FALSE;
	}
}

/* compare two struct id values, DNs can contain wildcards */

static bool match_dn_any_order_wild(chunk_t a, chunk_t b, int *wildcards);	/* forward */

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

	DBG(DBG_CONTROLMORE, {
			char abuf[IDTOA_BUF];
			char bbuf[IDTOA_BUF];
			idtoa(a, abuf, IDTOA_BUF);
			idtoa(b, bbuf, IDTOA_BUF);
			DBG_log("   match_id a=%s", abuf);
			DBG_log("            b=%s", bbuf);
			DBG_log("   results  %s", match ? "matched" : "fail");
		});

	return match;
}

/* count the number of wildcards in an id */
int id_count_wildcards(const struct id *id)
{
	int count = 0;
	char idbuf[IDTOA_BUF];

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

	idtoa(id, idbuf, IDTOA_BUF);
	DBG(DBG_CONTROL,
		DBG_log("counting wild cards for %s is %d",
			idbuf,
			count);
		);

	return count;
}

void duplicate_id(struct id *dst, const struct id *src)
{
	passert(dst->name.ptr == NULL || dst->name.ptr != src->name.ptr);
	free_id_content(dst);
	dst->kind = src->kind;
	dst->ip_addr = src->ip_addr;
	clonetochunk(dst->name, src->name.ptr, src->name.len, "copy of id");
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
	char abuf[ASN1_BUF_LEN];
	char bbuf[ASN1_BUF_LEN];
	int rdn_num = 0;
	int matched = 0;

	dntoa(abuf, ASN1_BUF_LEN, a);
	dntoa(bbuf, ASN1_BUF_LEN, b);

	DBG(DBG_CONTROL,
	    DBG_log("%s A: %s, B: %s", __FUNCTION__, abuf, bbuf));

	CERTName *const a_name = CERT_AsciiToName(abuf);
	CERTName *const b_name = CERT_AsciiToName(bbuf);

	if (a_name == NULL || b_name == NULL)
		return FALSE;

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
	DBG(DBG_CONTROL,
	    DBG_log("%s matched: %d, rdn_num: %d, wc %d",
		    __FUNCTION__,
		    matched,
		    rdn_num,
		    wildcards ? *wildcards : 0));

	return matched > 0 && rdn_num > 0 && matched == rdn_num;
}

bool same_dn_any_order(chunk_t a, chunk_t b)
{
	bool ret = same_dn(a, b);

	if (!ret) {
		DBG(DBG_CONTROL, {
			DBG_log("%s: not an exact match, now checking any RDN order",
				 __FUNCTION__);
			// DBG_dump_chunk("a", a);
			// DBG_dump_chunk("b", b);
		});
		ret = match_dn_unordered(a, b, NULL);
	}

	return ret;
}

static bool match_dn_any_order_wild(chunk_t a, chunk_t b, int *wildcards)
{
	bool ret = match_dn(a, b, wildcards);

	if (!ret) {
		DBG(DBG_CONTROL,
		    DBG_log("%s: not an exact match, now checking any RDN order with %d wildcards",
				 __FUNCTION__, *wildcards));
		/* recount wildcards */
		*wildcards = 0;
		ret = match_dn_unordered(a, b, wildcards);
	}
	return ret;
}
