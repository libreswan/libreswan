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
#include "secrets.h"
#include "lswlog.h"

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

size_t jam_ckaid(jambuf_t *buf, const ckaid_t *ckaid)
{
	return jam_hex_bytes(buf, ckaid->ptr, ckaid->len);
}

const char *str_ckaid(const ckaid_t *ckaid, ckaid_buf *buf)
{
	jambuf_t jam = ARRAY_AS_JAMBUF(buf->buf);
	jam_ckaid(&jam, ckaid);
	return buf->buf;
}

ckaid_t ckaid_from_secitem(const SECItem *const nss_ckaid)
{
	ckaid_t ckaid = {
		.len = nss_ckaid->len,
	};
	passert(ckaid.len <= sizeof(ckaid.ptr/*an-array*/));
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

err_t form_ckaid_rsa(chunk_t modulus, ckaid_t *ckaid)
{
	/*
	 * Compute the CKAID directly using the modulus. - keep old
	 * configurations hobbling along.
	 */
	SECItem nss_modulus = same_chunk_as_secitem(modulus, siBuffer);
	SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&nss_modulus);
	if (nss_ckaid == NULL) {
		return "unable to compute 'CKAID' from modulus";
	}
	if (DBGP(DBG_BASE)) {
		DBG_dump("computed rsa CKAID",
			 nss_ckaid->data, nss_ckaid->len);
	}
	*ckaid = ckaid_from_secitem(nss_ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);
	return NULL;
}

err_t form_ckaid_ecdsa(chunk_t pub_value, ckaid_t *ckaid)
{
	/*
	 * Compute the CKAID directly using the public value. - keep old
	 * configurations hobbling along.
	 */
	SECItem nss_pub_value = same_chunk_as_secitem(pub_value, siBuffer);
	SECItem *nss_ckaid = PK11_MakeIDFromPubKey(&nss_pub_value);
	if (nss_ckaid == NULL) {
		return "unable to compute 'CKAID' from public value";
	}
	if (DBGP(DBG_BASE)) {
		DBG_dump("computed ecdsa CKAID",
			 nss_ckaid->data, nss_ckaid->len);
	}
	*ckaid = ckaid_from_secitem(nss_ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);
	return NULL;
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
	const char *err = ttodata(string, 0, 16, (void*)ckaid->ptr, ckaid->len, &ckaid->len);
	if (err != NULL) {
		return err;
	}
	return NULL;
}
