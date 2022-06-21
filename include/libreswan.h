/*
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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
#ifndef _LIBRESWAN_H
#define _LIBRESWAN_H    /* seen it, no need to see it again */

#include "err.h"

#include <stdbool.h>

#include <sys/types.h>
#include <netinet/in.h>

/*
 * When using uclibc, malloc(0) returns NULL instead of success. This is
 * to make it use the inbuilt work-around.
 * See: http://osdir.com/ml/network.freeswan.devel/2003-11/msg00009.html
 */
#ifdef __UCLIBC__
# if !defined(__MALLOC_GLIBC_COMPAT__) && !defined(MALLOC_GLIBC_COMPAT)
#  warning Please compile uclibc with GLIBC_COMPATIBILITY defined
# endif
#endif

#if !defined(ESPINUDP_WITH_NON_IKE)
#define ESPINUDP_WITH_NON_IKE   1       /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define ESPINUDP_WITH_NON_ESP   2       /* draft-ietf-ipsec-nat-t-ike-02    */
#endif

/*
 * And the SA ID stuff.
 *
 * The value is in network order.
 *
 * XXX: Like IKE SPIs it should be hunk like byte array so that the
 * network ordering is enforced.
 */

typedef uint32_t ipsec_spi_t;
#define PRI_IPSEC_SPI "%08x"
#define pri_ipsec_spi(SPI) ntohl(SPI)

/*
 * new IPv6-compatible functions
 */

/* text conversions */
extern err_t ttoul(const char *src, size_t srclen, int format, unsigned long *dst);
extern err_t ttoulb(const char *src, size_t srclen, int format,
	unsigned long upb, unsigned long *dst);
extern size_t ultot(unsigned long src, int format, char *buf, size_t buflen);
#define ULTOT_BUF	((64+2)/3 + 1)  /* holds 64 bits in octal + NUL */

extern err_t ttodata(const char *src, size_t srclen, int base, char *buf,
	      size_t buflen, size_t *needed);
extern err_t ttodatav(const char *src, size_t srclen, int base,
	       char *buf,  size_t buflen, size_t *needed,
	       char *errp, size_t errlen, unsigned int flags);
#define TTODATAV_BUF    40              /* ttodatav's largest non-literal message */
#define TTODATAV_IGNORESPACE  (1 << 1)  /* ignore spaces in base64 encodings */
#define TTODATAV_SPACECOUNTS  0         /* do not ignore spaces in base64 */

extern size_t datatot(const unsigned char *src, size_t srclen, int format,
	       char *buf, size_t buflen);

/* odds and ends */
extern const char *ipsec_version_code(void);
extern const char *ipsec_version_vendorid(void);
extern const char *ipsec_version_string(void);
extern const char libreswan_vendorid[];

/* end of obsolete functions */

/* data types for SA conversion functions */

/* part extraction and special addresses */
extern struct in_addr hostof(struct in_addr addr,
		       struct in_addr mask
		       );
extern struct in_addr broadcastof(struct in_addr addr,
			   struct in_addr mask
			   );

/*
 * ENUM of klips debugging values. Not currently used in klips.
 * debug flag is actually 32 -bits, but only one bit is ever used,
 * so we can actually pack it all into a single 32-bit word.
 */
enum klips_debug_flags {
	KDF_VERBOSE     = 0,
	KDF_XMIT        = 1,
	KDF_NETLINK     = 2, /* obsolete */
	KDF_XFORM       = 3,
	KDF_EROUTE      = 4,
	KDF_SPI         = 5,
	KDF_RADIJ       = 6,
	KDF_ESP         = 7,
	KDF_AH          = 8, /* obsolete */
	KDF_RCV         = 9,
	KDF_TUNNEL      = 10,
	KDF_PFKEY       = 11,
	KDF_COMP        = 12,
	KDF_NATT        = 13,
};

/*
 * pluto and lwdnsq need to know the maximum size of the commands to,
 * and replies from lwdnsq.
 */

#define LWDNSQ_CMDBUF_LEN      1024
#define LWDNSQ_RESULT_LEN_MAX  4096

/* syntax for passthrough SA */
#ifndef PASSTHROUGHNAME
#define PASSTHROUGHNAME "%passthrough"
#define PASSTHROUGH4NAME        "%passthrough4"
#define PASSTHROUGH6NAME        "%passthrough6"
#define PASSTHROUGHIS   "tun0@0.0.0.0"
#define PASSTHROUGH4IS  "tun0@0.0.0.0"
#define PASSTHROUGH6IS  "tun0@::"
#define PASSTHROUGHTYPE "tun"
#define PASSTHROUGHSPI  0
#define PASSTHROUGHDST  0
#endif

#endif /* _LIBRESWAN_H */
