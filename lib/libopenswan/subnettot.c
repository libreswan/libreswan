/*
 * convert binary form of subnet description to text
 * Copyright (C) 2000  Henry Spencer.
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 * RCSID $Id: subnettot.c,v 1.6 2004/04/09 18:00:36 mcr Exp $
 */
#include "internal.h"
#include "openswan.h"
#include "constants.h"

/*
 * returns true if the subnet looks valid.
 */
bool isvalidsubnet(const ip_subnet *sub)
{
    int t=addrtypeof(&sub->addr);

    switch(t) {
    case AF_INET:
	if(sub->maskbits <= 0 && sub->maskbits > 32) {
	    return FALSE;
	}
	break;

    case AF_INET6:
	if(sub->maskbits <= 0 && sub->maskbits > 128) {
	    return FALSE;
	}
	break;

    default:
	return FALSE;
    }
    

    return TRUE;
}

/*
 - subnettot - convert subnet to text "addr/bitcount"
 */
size_t				/* space needed for full conversion */
subnettot(sub, format, dst, dstlen)
const ip_subnet *sub;
int format;			/* character */
char *dst;			/* need not be valid if dstlen is 0 */
size_t dstlen;
{
	size_t len;
	size_t rest;
	char *p;

	switch (format) {
	case 0:
		break;
	default:
		return 0;
		break;
	}

	len = addrtot(&sub->addr, format, dst, dstlen);
	if (len < dstlen) {
		dst[len - 1] = '/';
		p = dst + len;
		rest = dstlen - len;
	} else {
		p = NULL;
		rest = 0;
	}


	len += ultoa((unsigned long)sub->maskbits, 10, p, rest);

	return len;
}

size_t
subnetporttot(sub, format, dst, dstlen)
const ip_subnet *sub;
int format;
char *dst;
size_t dstlen;
{
  size_t len, alen;
  char *end;

  len = subnettot(sub, format, dst, dstlen);

  /* if port is zero, then return */
  if(portof(&sub->addr) == 0) {
    return len;
  }

  /* else, append to the format, decimal representation */
  alen = strlen(dst);
  end = dst + alen;
  if((alen + ULTOT_BUF) > dstlen) {
    /* we failed to find enough space, let caller know */
    return len + ULTOT_BUF;
  }

  /* base = 10 */
  *end++ = ':';
  len += ultoa(ntohs(portof(&sub->addr)), 10, end, dstlen-(alen+1));

  return len;
}
