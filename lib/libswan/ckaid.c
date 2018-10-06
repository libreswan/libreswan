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
bool ckaid_starts_with(ckaid_t ckaid, const char *start)
{
	if (strlen(start) > ckaid.nss->len * 2) {
		return false;
	}

	for (int i = 0; start[i] != '\0'; i++) {
		const char *p = start + i;
		unsigned byte = ckaid.nss->data[i / 2];
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

char *ckaid_as_string(ckaid_t ckaid)
{
	size_t string_len = ckaid.nss->len * 2 + 1;
	char *string = alloc_bytes(string_len, "ckaid-string");
	datatot(ckaid.nss->data, ckaid.nss->len, 16, string, string_len);
	return string;
}

err_t form_ckaid_nss(const SECItem *const nss_ckaid, ckaid_t *ckaid)
{
	SECItem *dup = SECITEM_DupItem(nss_ckaid);
	if (dup == NULL) {
		return "problem saving CKAID";
	}
	ckaid->nss = dup;
	return NULL;
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
	DBG(DBG_CONTROLMORE, DBG_dump("computed rsa CKAID",
				      nss_ckaid->data, nss_ckaid->len));
	err_t err = form_ckaid_nss(nss_ckaid, ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);
	return err;
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
	DBG(DBG_CONTROLMORE, DBG_dump("computed ecdsa CKAID",
					nss_ckaid->data, nss_ckaid->len));
	err_t err = form_ckaid_nss(nss_ckaid, ckaid);
	SECITEM_FreeItem(nss_ckaid, PR_TRUE);
	return err;
}

void freeanyckaid(ckaid_t *ckaid)
{
	if (ckaid != NULL && ckaid->nss) {
		SECITEM_FreeItem(ckaid->nss, PR_TRUE);
		ckaid->nss = NULL;
	}
}

void DBG_log_ckaid(const char *prefix, ckaid_t ckaid)
{
	DBG_dump(prefix, ckaid.nss->data, ckaid.nss->len);
}
