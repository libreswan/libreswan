/*
 * mechanisms for preshared keys (public, private, and preshared secrets)
 *
 * this is the library for reading (and later, writing!) the ipsec.secrets
 * files.
 *
 * Copyright (C) 1998-2004  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
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
 */

#include "ckaid.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswlog.h"
#include "lswnss.h"
#include "ttodata.h"

/*
 * Return true IFF CKAID starts with all of START (which is in HEX).
 */
bool ckaid_starts_with(const ckaid_t *ckaid, const char *start)
{
	if (strlen(start) > ckaid->len * 2) {
		return false;
	}

	for (int i = 0; start[i] != '\0'; i++) {
		const char *p = start + i;
		unsigned byte = ckaid->ptr[i / 2];
		/* high or low */
		unsigned nibble = (i & 1) ? (byte & 0xf) : (byte >> 4);
		char n[2] = { *p, };
		char *end;
		unsigned long ni = strtoul(n, &end, 16);
		if (*end != '\0') {
			return false;
		}
		if (ni != nibble) {
			return false;
		}
	}
	return true;
}

bool ckaid_eq_nss(const ckaid_t *l, const SECItem *r)
{
	return (l->len == r->len &&
		memeq(l->ptr, r->data, r->len));
}

size_t jam_ckaid(struct jambuf *buf, const ckaid_t *ckaid)
{
	return jam_hex_bytes(buf, ckaid->ptr, ckaid->len);
}

const char *str_ckaid(const ckaid_t *ckaid, ckaid_buf *buf)
{
	struct jambuf jam = ARRAY_AS_JAMBUF(buf->buf);
	jam_ckaid(&jam, ckaid);
	return buf->buf;
}

ckaid_t ckaid_from_secitem(const SECItem *const nss_ckaid)
{
	size_t nss_ckaid_len = nss_ckaid->len;
	/* ckaid = { .len = min(...), } barfs with gcc 11.2.1 */
	ckaid_t ckaid = {0};
	/* should not be truncated but can be */
	ckaid.len = min(nss_ckaid_len, sizeof(ckaid.ptr/*array*/));
	pexpect(ckaid.len == nss_ckaid_len);
	memmove(ckaid.ptr, nss_ckaid->data, ckaid.len);
	return ckaid;
}

SECItem same_ckaid_as_secitem(const ckaid_t *ckaid)
{
	SECItem nss_ckaid = {
		.data = (void*)ckaid->ptr, /* NSS doesn't do const */
		.len = ckaid->len,
		.type = siBuffer,
	};
	return nss_ckaid;
}

/* convert hex string ckaid to binary bin */

err_t string_to_ckaid(const char *string, ckaid_t *ckaid)
{
	if (string == NULL) {
		return "empty";
	}

	ckaid->len = (strlen(string) + 1) / 2;
	if (ckaid->len > sizeof(ckaid->ptr/*array*/)) {
		return "too long";
	}

	/* binlen will be "fixed"; ttodata doesn't take void* */
	const char *err = ttodata(string, 0, 16, ckaid->ptr, ckaid->len, &ckaid->len);
	if (err != NULL) {
		return err;
	}
	return NULL;
}
