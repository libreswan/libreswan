/*
 * convert rsa pubkeys to/from RFC2537/RFC3110 resource records, for libreswan
 *
 * Copyright (C) 1998-2004  D. Hugh Redelmeier.
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

#include <nss.h>

#include "libreswan.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "secrets.h"

/*
 * Deal with RFC Resource Records as defined in rfc3110 (nee rfc2537).
 */

err_t rsa_pubkey_to_rfc_resource_record(chunk_t exponent, chunk_t modulus, chunk_t *rr)
{
	*rr = empty_chunk;

	/*
	 * Since exponent length field is either 1 or 3 bytes in size,
	 * just allocate 3 extra bytes.
	 */
	size_t rrlen = exponent.len + modulus.len + 3;
	u_char *buf = alloc_bytes(rrlen, "buffer for rfc3110");
	u_char *p = buf;

	if (exponent.len <= 255) {
		*p++ = exponent.len;
	} else if (exponent.len <= 0xffff) {
		*p++ = 0;
		*p++ = (exponent.len >> 8) & 0xff;
		*p++ = exponent.len & 0xff;
	} else {
		pfree(buf);
		return "RSA public key exponent too long for resource record";
	}

	memcpy(p, exponent.ptr, exponent.len);
	p += exponent.len;
	memcpy(p, modulus.ptr, modulus.len);
	p += modulus.len;

	*rr = (chunk_t) {
		.ptr = buf,
		.len = p - buf,
	};

	return NULL;
}

err_t rfc_resource_record_to_rsa_pubkey(chunk_t rr, chunk_t *e, chunk_t *n)
{
	*e = empty_chunk;
	*n = empty_chunk;

	/*
	 * Step 1: find the bounds of the exponent and modulus within
	 * the recource record and verify that they are sane.
	 */

	chunk_t exponent;
	if (rr.len >= 2 && rr.ptr[0] != 0x00) {
		/*
		 * Exponent length is one-byte, followed by that many
		 * exponent bytes
		 */
		exponent = (chunk_t) {
			.ptr = rr.ptr + 1,
			.len = rr.ptr[0]
		};
	} else if (rr.len >= 3 && rr.ptr[0] == 0x00) {
		/*
		 * Exponent length is 0x00 followed by 2 bytes of
		 * length (big-endian), followed by that many exponent
		 * bytes
		 */
		exponent = (chunk_t) {
			.ptr = rr.ptr + 3,
			.len = (rr.ptr[1] << BITS_PER_BYTE) + rr.ptr[2],
		};
	} else {
		/* not even room for length! */
		return "RSA public key resource record way too short";
	}

	/*
	 * Does the exponent fall off the end of the resource record?
	 */
	u_char *const exponent_end = exponent.ptr + exponent.len;
	u_char *const rr_end = rr.ptr + rr.len;
	if (exponent_end > rr_end) {
		return "truncated RSA public key resource record exponent";
	}

	/*
	 * What is left over forms the modulus.
	 */
	chunk_t modulus = (chunk_t) {
		.ptr = exponent_end,
		.len = rr_end - exponent_end,
	};

	if (modulus.len < RSA_MIN_OCTETS_RFC) {
		return "RSA public key resource record modulus too short";
	}
	if (modulus.len < RSA_MIN_OCTETS) {
		return RSA_MIN_OCTETS_UGH;
	}
	if (modulus.len > RSA_MAX_OCTETS) {
		return RSA_MAX_OCTETS_UGH;
	}

	/*
	 * Step 2: all looks good, clone the bits
	 */
	*e = chunk_clone(exponent, "e");
	*n = chunk_clone(modulus, "n");
	return NULL;
}

err_t rsa_pubkey_to_base64(chunk_t exponent, chunk_t modulus, char **base64_rr)
{
	*base64_rr = NULL;

	chunk_t rr_chunk;
	err_t err = rsa_pubkey_to_rfc_resource_record(exponent, modulus, &rr_chunk);
	if (err) {
		return err;
	}

	/*
	 * A byte is 8-bits, base64 uses 6-bits (2^6=64).  Plus some
	 * for 0s.  Plus some for \0.  Plus some extra for rounding.
	 */
	size_t rr_len = rr_chunk.len * 8 / 6 + 2 + 1 + 10;
	char *rr = alloc_bytes(rr_len, "base64 resource record");
	size_t n = datatot(rr_chunk.ptr, rr_chunk.len, 's', rr, rr_len);
	if (n >= rr_len) {
		freeanychunk(rr_chunk);
		return "base64 encoded RSA public key resource record larger than expected";
	}

	*base64_rr = rr;
	freeanychunk(rr_chunk);
	return NULL;
}

#if 0
err_t base64_to_rsa_pubkey(const char *rr, chunk_t *exponent, chunk_t *modulus)
{
	return "not implemented";
}
#endif

#if 0
err_t pack_RSA_public_key(const struct RSA_public_key *rsa, chunk_t *rr)
{
	return rsa_pubkey_to_rfc_resource_record(rsa->e, rsa->n, rr);
}
#endif

err_t unpack_RSA_public_key(struct RSA_public_key *rsa, const chunk_t *pubkey)
{
	err_t err;

	/* unpack */
	chunk_t exponent;
	chunk_t modulus;
	err = rfc_resource_record_to_rsa_pubkey(*pubkey, &exponent, &modulus);
	if (err) {
		return err;
	}

	ckaid_t ckaid;
	err = form_ckaid_rsa(modulus, &ckaid);
	if (err) {
		freeanychunk(exponent);
		freeanychunk(modulus);
		return err;
	}

	keyblobtoid(pubkey->ptr, pubkey->len, rsa->keyid, sizeof(rsa->keyid));
	rsa->k = modulus.len;
	rsa->e = exponent;
	rsa->n = modulus;
	rsa->ckaid = ckaid;

	DBG(DBG_PRIVATE, DBG_log_RSA_public_key(rsa));
	/* generate the CKAID */
	return NULL;
}
