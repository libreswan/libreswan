/*
 * convert from binary data (e.g. key) to text form
 * Copyright (C) 2000  Henry Spencer.
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

#include <stddef.h>

#include "ttodata.h"

#include "passert.h"

static void convert(const char *src, size_t nreal, int format, char *out);

/*
 *  - datatot - convert data bytes to text
 * true length (with NUL) for success
 */
size_t datatot(const unsigned char *src, size_t srclen,
	       int format,  	  /* character indicating what format */
	       char *dst,
	       size_t dstlen) 	  /* need not be valid if dstlen is 0 */
{
	size_t inblocksize;             /* process this many bytes at a time */
	size_t outblocksize;            /* producing this many */
	size_t breakevery;              /* add a _ every this many (0 means don't) */
	size_t sincebreak;              /* output bytes since last _ */
	char breakchar;                 /* character used to break between groups */
	unsigned char inblock[10];      /* enough for any format */
	char outblock[10];              /* enough for any format */
	char fake[1];                   /* fake output area for dstlen == 0 */
	size_t needed;                  /* return value */
	char *stop;                     /* where the terminating NUL will go */
	size_t ntodo;                   /* remaining input */
	size_t nreal;
	char *out;
	char *prefix;

	breakevery = 0;
	breakchar = '_';

	switch (format) {
	case 0:
	case 'h':
		breakevery = 8;
		inblocksize = 1;
		outblocksize = 2;
		prefix = "0x";
		format = 'x';
		break;
	case 'x':
		inblocksize = 1;
		outblocksize = 2;
		prefix = "0x";
		break;
	case ':':
		breakevery = 2;
		breakchar = ':';
		inblocksize = 1;
		outblocksize = 2;
		prefix = "";
		format = 'x';
		break;
	case 16:
		inblocksize = 1;
		outblocksize = 2;
		prefix = "";
		format = 'x';
		break;
	case 's':
		inblocksize = 3;
		outblocksize = 4;
		prefix = "0s";
		break;
	case 64:                /* beware, equals ' ' */
		inblocksize = 3;
		outblocksize = 4;
		prefix = "";
		format = 's';
		break;
	default:
		return 0;
	}

	passert(inblocksize < sizeof(inblock));
	passert(outblocksize < sizeof(outblock));
	passert(breakevery % outblocksize == 0);

	if (srclen == 0)
		return 0;

	ntodo = srclen;

	if (dstlen == 0) {      /* dispose of awkward special case */
		dst = fake;
		dstlen = 1;
	}
	stop = dst + dstlen - 1;

	nreal = strlen(prefix);
	needed = nreal;                 /* for starters */
	if (dstlen <= nreal) {          /* prefix won't fit */
		/* fill_and_terminate */
		strncpy(dst, prefix, dstlen-1);
		dst[dstlen-1] = '\0';
		dst += dstlen - 1;
	} else {
		strncpy(dst, prefix, dstlen); /* make codeql happy */
		dst += nreal;
	}

	passert(dst <= stop);
	sincebreak = 0;

	while (ntodo > 0) {
		if (ntodo < inblocksize) {      /* incomplete input */
			memset(inblock, 0, sizeof(inblock));
			memcpy(inblock, src, ntodo);
			src = inblock;
			nreal = ntodo;
			ntodo = inblocksize;
		} else {
			nreal = inblocksize;
		}
		out = ((ptrdiff_t)outblocksize > stop - dst) ? outblock : dst;

		convert((const char *)src, nreal, format, out);
		needed += outblocksize;
		sincebreak += outblocksize;
		if (dst < stop) {
			if (out != dst) {
				passert(
					(ptrdiff_t)outblocksize > stop - dst);
				memcpy(dst, out, stop - dst);
				dst = stop;
			} else {
				dst += outblocksize;
			}
		}

		src += inblocksize;
		ntodo -= inblocksize;
		if (breakevery != 0 && sincebreak >= breakevery && ntodo > 0) {
			if (dst < stop)
				*dst++ = breakchar;
			needed++;
			sincebreak = 0;
		}
	}

	passert(dst <= stop);
	*dst++ = '\0';
	needed++;

	return needed;
}

/*
   - convert - convert one input block to one output block
 */
static void convert(const char *src,
		    size_t nreal,    /* how much of the input block is real */
		    int format, char *out)
{
	static char hex[] = "0123456789abcdef";
	static char base64[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			       "abcdefghijklmnopqrstuvwxyz"
			       "0123456789+/";
	unsigned char c;
	unsigned char c1, c2, c3;

	passert(nreal > 0);
	switch (format) {
	case 'x':
		passert(nreal == 1);
		c = (unsigned char)*src;
		*out++ = hex[c >> 4];
		*out++ = hex[c & 0xf];
		break;
	case 's':
		c1 = (unsigned char)*src++;
		c2 = (unsigned char)*src++;
		c3 = (unsigned char)*src++;
		*out++ = base64[c1 >> 2];       /* top 6 bits of c1 */
		c = (c1 & 0x3) << 4;            /* bottom 2 of c1... */
		c |= c2 >> 4;                   /* ...top 4 of c2 */
		*out++ = base64[c];
		if (nreal == 1) {
			*out++ = '=';
		} else {
			c = (c2 & 0xf) << 2;    /* bottom 4 of c2... */
			c |= c3 >> 6;           /* ...top 2 of c3 */
			*out++ = base64[c];
		}
		if (nreal <= 2)
			*out++ = '=';
		else
			*out++ = base64[c3 & 0x3f];     /* bottom 6 of c3 */
		break;
	default:
		passert(nreal == 0);        /* unknown format */
		break;
	}
}
