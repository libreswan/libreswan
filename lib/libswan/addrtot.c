/*
 * addresses to text
 * Copyright (C) 2000  Henry Spencer.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <string.h>

#include "ip_address.h"
#include "libreswan.h"		/* for inet_addrtot() */

#define IP4BYTES        4       /* bytes in an IPv4 address */
#define PERBYTE         4       /* three digits plus a dot or NUL */
#define IP6BYTES        16      /* bytes in an IPv6 address */

/* forwards */
static size_t normal4(const unsigned char *s, size_t len, char *b, const char **dp);
static size_t normal6(const unsigned char *s, size_t len, char *b, const char **dp,
		      int squish);
static size_t reverse4(const unsigned char *s, size_t len, char *b, const char **dp);
static size_t reverse6(const unsigned char *s, size_t len, char *b, const char **dp);

/*
   - inet_addrtot - convert binary inet address to text (dotted decimal or IPv6 string)
 */
static size_t                  /* space needed for full conversion */
inet_addrtot(t, src, format, dst, dstlen)
int t;                  /* AF_INET/AF_INET6 */
const void *src;
int format;             /* character */
char *dst;              /* need not be valid if dstlen is 0 */
size_t dstlen;
{
	char buf[1 + ADDRTOT_BUF + 1];      /* :address: */

	/* initialize for cases not handled */
	const char *p = "<invalid>";
	size_t n = sizeof("<invalid>") - 1;

	switch (t) {
	case AF_INET:
		switch (format) {
		case 0:
		case 'Q':
			n = normal4(src, IP4BYTES, buf, &p);
			break;
		case 'r':
			n = reverse4(src, IP4BYTES, buf, &p);
			break;
		}
		break;

	case AF_INET6:
		switch (format) {
		case 0:
			n = normal6(src, IP6BYTES, buf, &p, 1);
			break;
		case 'Q':
			n = normal6(src, IP6BYTES, buf, &p, 0);
			break;
		case 'r':
			n = reverse6(src, IP6BYTES, buf, &p);
			break;
		}
		break;
	}

	if (dstlen > 0) {
		/* make dstlen actual result length, including NUL */
		if (dstlen > n)
			dstlen = n + 1;
		memcpy(dst, p, dstlen - 1);
		dst[dstlen - 1] = '\0';
	}
	return n;	/* strlen(untruncated result) */
}

/*
 * sin_addrtot - convert binary sockaddr_in/sockaddr_in6 address to text
 * (dotted decimal or IPv6 string)
 */
size_t                          /* space needed for full conversion */
sin_addrtot(src, format, dst, dstlen)
const void *src;
int format;                     /* character */
char *dst;                      /* need not be valid if dstlen is 0 */
size_t dstlen;
{
	const union SINSIN6 {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} *sinp = (const union SINSIN6 *) src;

	switch (sinp->sin.sin_family) {
	case AF_INET:
		return inet_addrtot(AF_INET, &sinp->sin.sin_addr, format, dst,
				    dstlen);

	case AF_INET6:
		return inet_addrtot(AF_INET6, &sinp->sin6.sin6_addr, format,
				    dst, dstlen);

	default:
		dst[0] = '\0';
		strncat(dst, "<invalid>", dstlen - 1); /* we hope possible truncation does not cause problems */
		return sizeof("<invalid>");
	}
}

/*
   - normal4 - normal IPv4 address-text conversion
 */
static size_t                   /* size of text, including NUL */
normal4(srcp, srclen, buf, dstp)
const unsigned char *srcp;
size_t srclen;
char *buf;                      /* guaranteed large enough */
const char **dstp;                    /* where to put result pointer */
{
	int i;
	char *p;

	if (srclen != IP4BYTES) /* "can't happen" */
		return 0;

	p = buf;
	for (i = 0; i < IP4BYTES; i++) {
		p += ultot(srcp[i], 10, p, PERBYTE);
		if (i != IP4BYTES - 1)
			*(p - 1) = '.'; /* overwrites the NUL */
	}
	*dstp = buf;
	return p - buf;
}

/*
   - normal6 - normal IPv6 address-text conversion
 */
static size_t                   /* size of text, including NUL */
normal6(srcp, srclen, buf, dstp, squish)
const unsigned char *srcp;
size_t srclen;
char *buf;                      /* guaranteed large enough, plus 2 */
const char **dstp;                    /* where to put result pointer */
int squish;                     /* whether to squish out 0:0 */
{
	int i;
	unsigned long piece;
	char *p;
	char *q;

	if (srclen != IP6BYTES) /* "can't happen" */
		return 0;

	p = buf;
	*p++ = ':';
	for (i = 0; i < IP6BYTES / 2; i++) {
		piece = (srcp[2 * i] << 8) + srcp[2 * i + 1];
		p += ultot(piece, 16, p, 5);    /* 5 = abcd + NUL */
		*(p - 1) = ':';                 /* overwrites the NUL */
	}
	*p = '\0';
	q = strstr(buf, ":0:0:");
	if (squish && q != NULL) {      /* zero squishing is possible */
		p = q + 1;
		while (*p == '0' && *(p + 1) == ':')
			p += 2;
		q++;
		*q++ = ':';     /* overwrite first 0 */
		while (*p != '\0')
			*q++ = *p++;
		*q = '\0';
		if (!(*(q - 1) == ':' && *(q - 2) == ':'))
			*--q = '\0';    /* strip final : unless :: */
		p = buf;
		if (!(*p == ':' && *(p + 1) == ':'))
			p++;    /* skip initial : unless :: */
	} else {
		q = p;
		*--q = '\0';    /* strip final : */
		p = buf + 1;    /* skip initial : */
	}
	*dstp = p;
	return q - p + 1;
}

/*
   - reverse4 - IPv4 reverse-lookup conversion
 */
static size_t                   /* size of text, including NUL */
reverse4(srcp, srclen, buf, dstp)
const unsigned char *srcp;
size_t srclen;
char *buf;	/* guaranteed large enough */
const char **dstp;	/* where to put result pointer */
{
	int i;
	char *p;

	if (srclen != IP4BYTES) /* "can't happen" */
		return 0;

	p = buf;
	for (i = IP4BYTES - 1; i >= 0; i--) {
		p += ultot(srcp[i], 10, p, PERBYTE);
		*(p - 1) = '.';   /* overwrites the NUL */
	}
	strcpy(p, "IN-ADDR.ARPA.");
	*dstp = buf;
	return strlen(buf) + 1;
}

/*
   - reverse6 - IPv6 reverse-lookup conversion (RFC 1886)
 * A trifle inefficient, really shouldn't use ultot...
 */
static size_t                   /* size of text, including NUL */
reverse6(srcp, srclen, buf, dstp)
const unsigned char *srcp;
size_t srclen;
char *buf;	/* guaranteed large enough */
const char **dstp;	/* where to put result pointer */
{
	int i;
	unsigned long piece;
	char *p;

	if (srclen != IP6BYTES) /* "can't happen" */
		return 0;

	p = buf;
	for (i = IP6BYTES - 1; i >= 0; i--) {
		piece = srcp[i];
		p += ultot(piece & 0xf, 16, p, 2);
		*(p - 1) = '.';
		p += ultot(piece >> 4, 16, p, 2);
		*(p - 1) = '.';
	}
	strcpy(p, "IP6.ARPA.");
	*dstp = buf;
	return strlen(buf) + 1;
}
