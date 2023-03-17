/*
 * convert from text form of arbitrary data (e.g., keys) to binary
 *
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

#include "ttodata.h"

#include "hunk.h"		/* for char_to_lower() */
#include "passert.h"

/* converters and misc */
static int unhex(const char *, char *, size_t);
static int unb64(const char *, char *, size_t);
static int untext(const char *, char *, size_t);
static err_t badch(void);

/* internal error codes for converters */
#define SHORT (-2)	/* internal buffer too short */
#define BADPAD (-3)	/* bad base64 padding */
#define BADCH0 (-4)	/* invalid character 0 */
#define BADCH1 (-5)	/* invalid character 1 */
#define BADCH2 (-6)	/* invalid character 2 */
#define BADCH3 (-7)	/* invalid character 3 */
#define BADOFF(code) (BADCH0 - (code))

/*
 * ttodatav - convert text to data, with verbose error reports
 *
 * If some of this looks slightly odd, it's because it has changed
 * repeatedly (from the original atodata()) without a major rewrite.
 *
 * Return NULL on success, else literal or errp
 */
#define TTODATAV_IGNORE_BASE64_SPACES  (1 << 1)  /* ignore spaces in base64 encodings */

static const char *ttodatav(const char *src, size_t srclen,
			    int base,		/* 0 means figure it out */
			    char *dst,		/* need not be valid if dstlen is 0 */
			    size_t dstlen,
			    size_t *lenp,	/* where to record length (NULL is nowhere) */
			    lset_t flags	/*XXX: always LEMPTY*/)
{
	size_t ingroup;	/* number of input bytes converted at once */
	char buf[4];	/* output from conversion */
	int nbytes;	/* size of output */
	int (*decode)(const char *, char *, size_t);
	char *stop;
	int ndone;
	int i;
	int underscoreok;
	bool skipSpace = false;

	if (dstlen == 0)
		dst = buf;	/* point it somewhere valid */
	stop = dst + dstlen;

	if (base == 0) {
		if (srclen < 2)
			return "input too short to be valid";

		if (*src++ != '0')
			return "input does not begin with format prefix";

		switch (*src++) {
		case 'x':
		case 'X':
			base = 16;
			break;
		case 's':
		case 'S':
			base = 64;
			break;
		case 't':
		case 'T':
			base = 256;
			break;
		default:
			return "unknown format prefix";
		}
		srclen -= 2;
	}
	switch (base) {
	case 16:
		decode = unhex;
		underscoreok = 1;
		ingroup = 2;
		break;
	case 64:
		decode = unb64;
		underscoreok = 0;
		ingroup = 4;
		if (flags & TTODATAV_IGNORE_BASE64_SPACES)
			skipSpace = true;
		break;

	case 256:
		decode = untext;
		ingroup = 1;
		underscoreok = 0;
		break;
	default:
		return "unknown base";
	}

	/* proceed */
	ndone = 0;
	while (srclen > 0) {
		char stage[4];	/* staging area for group */
		size_t sl = 0;

		/*
		 * Grab ingroup characters into stage,
		 * squeezing out blanks if we are supposed to ignore them.
		 */
		for (sl = 0; sl < ingroup; src++, srclen--) {
			if (srclen == 0)
				return "input ends in mid-byte, perhaps truncated";
			else if (!(skipSpace && (*src == ' ' || *src == '\t')))
				stage[sl++] = *src;
		}

		nbytes = (*decode)(stage, buf, sizeof(buf));
		switch (nbytes) {
		case BADCH0:
		case BADCH1:
		case BADCH2:
		case BADCH3:
			return badch();

		case SHORT:
			return "internal buffer too short (\"can't happen\")";

		case BADPAD:
			return "bad (non-zero) padding at end of base64 input";
		}
		if (nbytes <= 0)
			return "unknown internal error";

		for (i = 0; i < nbytes; i++) {
			if (dst < stop)
				*dst++ = buf[i];
			ndone++;
		}
		while (srclen >= 1 && skipSpace &&
			(*src == ' ' || *src == '\t')) {
			src++;
			srclen--;
		}
		if (underscoreok && srclen > 1 && *src == '_') {
			/* srclen > 1 means not last character */
			src++;
			srclen--;
		}
	}

	if (ndone == 0)
		return "no data bytes specified by input";

	if (lenp != NULL)
		*lenp = ndone;
	return NULL;
}

/*
 * ttodata - convert text to data
 *
 * Return NULL on success, else literal
 */
const char *ttodata(const char *src,
		    size_t srclen,	/* 0 means apply strlen() */
		    int base,		/* 0 means figure it out */
		    char *dst,		/* need not be valid if dstlen is 0 */
		    size_t dstlen,
		    size_t *lenp)	/* where to record length (NULL is nowhere) */
{
	/* zero means apply strlen() */
	if (srclen == 0)
		srclen = strlen(src);
	return ttodatav(src, srclen, base, dst, dstlen, lenp, LEMPTY);
}

const char *ttochunk(shunk_t src,
		     int base,		/* 0 means figure it out */
		     chunk_t *dst)
{
	size_t size = 0;
	err_t err = ttodatav(src.ptr, src.len, base, NULL/*dst*/, 0/*dstlen*/, &size, LEMPTY);
	if (err != NULL) {
		return err;
	}
	passert(size > 0); /* see pdone variable above */
	*dst = alloc_chunk(size, "ttochunk");
	err = ttodatav(src.ptr, src.len, base, (char*)dst->ptr, dst->len, &size, LEMPTY);
	passert(err == NULL);
	passert(dst->len == size);
	return NULL;
}

/*
 * unhex - convert two ASCII hex digits to byte
 *
 * Return number of result bytes, or error code
 */
static int unhex(const char *src,	/* known to be full length */
		 char *dst,
		 size_t dstlen)		/* not large enough is a failure */
{
	const char *p;
	unsigned byte;
	static const char hex[] = "0123456789abcdef";

	if (dstlen < 1)
		return SHORT;

	p = strchr(hex, *src);
	if (p == NULL)
		p = strchr(hex, char_tolower(*src));
	if (p == NULL)
		return BADCH0;

	byte = (p - hex) << 4;
	src++;

	p = strchr(hex, *src);
	if (p == NULL)
		p = strchr(hex, char_tolower(*src));
	if (p == NULL)
		return BADCH1;

	byte |= (p - hex);

	*dst = byte;
	return 1;
}

/*
 * unb64 - convert four ASCII base64 digits to three bytes
 *
 * Note that a base64 digit group is padded out with '=' if it represents
 * less than three bytes:  one byte is dd==, two is ddd=, three is dddd.
 *
 * Return number of result bytes, or error code
 */
static int unb64(const char *src,	/* known to be full length */
		 char *dst,
		 size_t dstlen)
{
	const char *p;
	unsigned byte1;
	unsigned byte2;
	static const char base64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if (dstlen < 3)
		return SHORT;

	p = strchr(base64, *src++);

	if (p == NULL)
		return BADCH0;

	byte1 = (p - base64) << 2;	/* first six bits */

	p = strchr(base64, *src++);
	if (p == NULL)
		return BADCH1;

	byte2 = p - base64;	/* next six:  two plus four */
	*dst++ = byte1 | (byte2 >> 4);
	byte1 = (byte2 & 0xf) << 4;

	p = strchr(base64, *src++);
	if (p == NULL) {
		if (*(src - 1) == '=' && *src == '=') {
			if (byte1 != 0)	/* bad padding */
				return BADPAD;

			return 1;
		}
		return BADCH2;
	}

	byte2 = p - base64;	/* next six:  four plus two */
	*dst++ = byte1 | (byte2 >> 2);
	byte1 = (byte2 & 0x3) << 6;

	p = strchr(base64, *src++);
	if (p == NULL) {
		if (*(src - 1) == '=') {
			if (byte1 != 0)	/* bad padding */
				return BADPAD;

			return 2;
		}
		return BADCH3;
	}
	byte2 = p - base64;	/* last six */
	*dst++ = byte1 | byte2;

	return 3;
}

/*
 * untext - convert one ASCII character to byte
 *
 * Return number of result bytes, or error code
 */
static int untext(const char *src,	/* known to be full length */
		  char *dst,
		  size_t dstlen)	/* not large enough is a failure */
{
	if (dstlen < 1)
		return SHORT;

	*dst = *src;
	return 1;
}

/*
 * badch - produce a nice complaint about an unknown character
 *
 * If the compiler complains that the array bigenough[] has a negative
 * size, that means the TTODATAV_BUF constant has been set too small.
 *
 * Return literal or errp
 *
 * Rewrite to return diag_t.
 */
static err_t badch(void)
/*
  (const char *src,
   int errcode,
   char *errp,	// might be NULL
   size_t errlen)
*/
{
#if 1
	return "unknown character in input";
#else
	static const char pre[] = "unknown character (`";
	static const char suf[] = "') in input";
	char buf[5];
	/* it would be a VERY good idea if REQD <= TTODATAV_BUF */
#       define  REQD    (sizeof(pre) - 1 + sizeof(buf) - 1 + sizeof(suf))
	struct sizecheck {
		char bigenough[TTODATAV_BUF - REQD];	/* see above */
	};
	char ch;

	if (errp == NULL || errlen < REQD)
		return "unknown character in input";

	strcpy(errp, pre);
	/*
	 * clang 3.4 says "warning: Assigned value is garbage or undefined".
	 * This does not seem to be correct.
	 */
	ch = *(src + BADOFF(errcode));
	if (char_isprint(ch)) {
		buf[0] = ch;
		buf[1] = '\0';
	} else {
		buf[0] = '\\';
		buf[1] = ((ch & 0700) >> 6) + '0';
		buf[2] = ((ch & 0070) >> 3) + '0';
		buf[3] = ((ch & 0007) >> 0) + '0';
		buf[4] = '\0';
	}
	strcat(errp, buf);
	strcat(errp, suf);
	return (const char *)errp;
#endif
}
