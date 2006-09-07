/*-
 * Copyright (c) 1988, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/netinet/in_cksum.c,v 1.8 2005/01/07 01:45:44 imp Exp $
 */

#include <sys/types.h>
#include <stdio.h>

/*
 * Checksum routine for Internet Protocol family headers (Portable Version).
 *
 * This routine is very heavily used in the network
 * code and should be modified for each CPU to be as fast as possible.
 */

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 : x)
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}

unsigned int csum_partial(const unsigned char *buff, int len, unsigned int start)
{
	register const u_short *w;
	register int sum = 0;
	int byte_swapped = 0;

	union {
		char	c[2];
		u_short	s;
	} s_util;
	union {
		u_short s[2];
		long	l;
	} l_util;

	sum = start;
	w = (const unsigned short *)buff;
	/*
	 * Force to even boundary.
	 */
	if ((1 & (int) w) && (len > 0)) {
	  REDUCE;
	  sum <<= 8;
	  s_util.c[0] = *(const u_char *)w;
	  w = (const u_short *)((const char *)w + 1);
	  len--;
	  byte_swapped = 1;
	}
	/*
	 * Unroll the loop to make overhead from
	 * branches &c small.
	 */
	while ((len -= 32) >= 0) {
	  sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
	  sum += w[4]; sum += w[5]; sum += w[6]; sum += w[7];
	  sum += w[8]; sum += w[9]; sum += w[10]; sum += w[11];
	  sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
	  w += 16;
	}
	len += 32;
	while ((len -= 8) >= 0) {
	  sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
	  w += 4;
	}
	len += 8;

	if (!(len == 0 && byte_swapped == 0)) {
	  REDUCE;
	  while ((len -= 2) >= 0) {
	    sum += *w++;
	  }
	  if (byte_swapped) {
	    REDUCE;
	    sum <<= 8;
	    byte_swapped = 0;
	    if (len == -1) {
	      s_util.c[1] = *(const u_char *)w;
	      sum += s_util.s;
	      len = 0;
	    } else
	      len = -1;
	  } else if (len == -1)
	    s_util.c[0] = *(const u_char *)w;
	}

	if (len)
		printf("cksum: out of data\n");

	if (len == -1) {
		/* The last mbuf has odd # of bytes. Follow the
		   standard (the odd byte may be shifted left by 8 bits
		   or not as determined by endian-ness of the machine) */
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	return (~sum & 0xffff);
}
