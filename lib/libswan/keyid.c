/* printable key IDs, for libreswan
 *
 * Copyright (C) 2002  Henry Spencer.
 * Copyright (C) 2020  Andrew Cagney
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#include <string.h>

#include "keyid.h"
#include "libreswan.h"		/* for datatot() */

const keyid_t empty_keyid;

/*
 * keyblobtoid - generate a printable key ID from an RFC 2537/3110 key
 * blob
 *
 * Current algorithm is just to use first nine base64 digits.
 */

size_t keyblobtoid(const uint8_t *src, size_t srclen,
		   char *dst /* need not be valid if dstlen is 0 */,
		   size_t dstlen)
{
	char buf[KEYID_BUF];
	size_t ret;
#       define  NDIG    9

	if (srclen < (NDIG * 6 + 7) / 8) {
		strcpy(buf, "?len= ?");
		buf[5] = '0' + srclen;
		ret = 0;
	} else {
		(void) datatot(src, srclen, 64, buf, NDIG + 1);
		ret = NDIG + 1;
	}

	if (dstlen > 0) {
		if (strlen(buf) + 1 > dstlen)
			*(buf + dstlen - 1) = '\0';
		strcpy(dst, buf);
	}
	return ret;
}

 /*
  * keyblobtokeyid - generate a printable key ID from an RFC 2537/3110
  * key blob
  *
  * Current algorithm is just to use first nine base64 digits.
  */

err_t keyblob_to_keyid(const uint8_t *src, size_t srclen, keyid_t *dst)
{
	/* XXX: datatot() returns number of bytes including trailing '\0' */
	size_t ret = datatot(src, srclen, 64, dst->keyid, sizeof(dst->keyid));
	if (ret < sizeof(dst->keyid)) {
		/* how would this happen? */
		return "key blob is too small";
	} else {
		return NULL;
	}
}

/*
 * splitkeytoid - generate a printable key ID from exponent/modulus
 * pair
 *
 * Just constructs the beginnings of a key blob and calls
 * keyblobtoid().
 */

size_t splitkeytoid(const uint8_t *e, size_t elen,
		    const uint8_t *m, size_t mlen,
		    char *dst /* need not be valid if dstlen is 0 */,
		    size_t dstlen)
{
	uint8_t buf[KEYID_BUF];	/* ample room */
	uint8_t *const bufend = buf + sizeof(buf);
	uint8_t *p = buf;

	/* start with length of e; assume that it fits */
	if (elen <= 255) {
		/* one byte */
		*p++ = elen;
	} else if (elen <= 0xffff) {
		/* two bytes */
		*p++ = 0;
		*p++ = (elen >> 8) & 0xff;
		*p++ = elen & 0xff;
	} else {
		return 0;       /* unrepresentable exponent length */
	}

	/* append as much of e as fits */
	while (elen > 0 && p < bufend) {
		*p++ = *e++;
		elen--;
	}

	/* append as much of m as fits */
	while (mlen > 0 && p < bufend) {
		*p++ = *m++;
		mlen--;
	}

	return keyblobtoid(buf, p - buf, dst, dstlen);
}

 /*
  * splitkeytokeyid - generate a printable key ID from
  * exponent/modulus pair
  *
  * Just constructs the beginnings of a key blob and calls
  * keyblobtoid().
  */

err_t splitkey_to_keyid(const uint8_t *e, size_t elen,
			const uint8_t *m, size_t mlen,
			keyid_t *dst)
{
	/* form the leading few bytes of the raw keyblob */
	uint8_t keyblob[sizeof(keyid_t)];	/* ample room */
	uint8_t *const blob_end = keyblob + sizeof(keyblob);
	uint8_t *p = keyblob;

	/* start with length of e; assume that it fits */
	if (elen <= 0xff) {
		/* one byte */
		*p++ = elen;
	} else if (elen <= 0xffff) {
		/* two bytes */
		*p++ = 0;
		*p++ = (elen >> 8) & 0xff;
		*p++ = elen & 0xff;
	} else {
		*dst = empty_keyid;
		return "unrepresentable exponent length";
	}

	/* append as much of e as fits */
	while (elen > 0 && p < blob_end) {
		*p++ = *e++;
		elen--;
	}

	/* append as much of m as fits */
	while (mlen > 0 && p < blob_end) {
		*p++ = *m++;
		mlen--;
	}

	return keyblob_to_keyid(keyblob, p - keyblob, dst);
}
