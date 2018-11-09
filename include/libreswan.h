/*
 * header file for Libreswan library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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

#include <stdint.h>
#include <stdbool.h> /* for 'bool' */

/*
 * Libreswan was written before <stdbool.h> was standardized.
 *
 * (Contradicting the kernel coding style) TRUE and FALSE continue to
 * be used because some think that it is clearer than true or false.
 */

#ifndef TRUE
# define TRUE true
#endif

#ifndef FALSE
# define FALSE false
#endif

#include <stddef.h>

/* Some constants code likes to use. Useful? */

enum {
	secs_per_minute = 60,
	secs_per_hour = 60 * secs_per_minute,
	secs_per_day = 24 * secs_per_hour
};

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

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#include <stdio.h>
#include <stdint.h>

#define DEBUG_NO_STATIC static

#ifndef IPPROTO_COMP
#  define IPPROTO_COMP 108
#endif /* !IPPROTO_COMP */

#ifndef IPPROTO_INT
#  define IPPROTO_INT 61
#endif /* !IPPROTO_INT */

#if !defined(ESPINUDP_WITH_NON_IKE)
#define ESPINUDP_WITH_NON_IKE   1       /* draft-ietf-ipsec-nat-t-ike-00/01 */
#define ESPINUDP_WITH_NON_ESP   2       /* draft-ietf-ipsec-nat-t-ike-02    */
#endif

/* and the SA ID stuff */
typedef uint32_t ipsec_spi_t;

/* misc */
struct prng {                   /* pseudo-random-number-generator guts */
	unsigned char sbox[256];
	int i, j;
	unsigned long count;
};

/*
 * definitions for user space, taken linux/include/libreswan/ipsec_sa.h
 */
typedef uint32_t IPsecSAref_t;

/* Translation to/from nfmark.
 *
 * use bits 16-31. Leave bit 32 as a indicate that IPsec processing
 * has already been done.
 */
#define IPSEC_SA_REF_TABLE_IDX_WIDTH 15
#define IPSEC_SA_REF_TABLE_OFFSET    16
#define IPSEC_SA_REF_MASK           ((1u << IPSEC_SA_REF_TABLE_IDX_WIDTH) - 1u)
#define IPSEC_NFMARK_IS_SAREF_BIT 0x80000000u

#define IPsecSAref2NFmark(x) \
	(((x) & IPSEC_SA_REF_MASK) << IPSEC_SA_REF_TABLE_OFFSET)
#define NFmark2IPsecSAref(x) \
	(((x) >> IPSEC_SA_REF_TABLE_OFFSET) & IPSEC_SA_REF_MASK)

#define IPSEC_SAREF_NULL ((IPsecSAref_t)0u)
/* Not representable as an nfmark */
#define IPSEC_SAREF_NA   ((IPsecSAref_t)0xffff0001)

#include "lswcdefs.h"

/*
 * function to log stuff from libraries that may be used in multiple
 * places.
 */
typedef int (*libreswan_keying_debug_func_t)(const char *message, ...) PRINTF_LIKE(1);

/*
 * new IPv6-compatible functions
 */

/* text conversions */
extern err_t ttoul(const char *src, size_t srclen, int format, unsigned long *dst);
extern err_t ttoulb(const char *src, size_t srclen, int format,
	unsigned long upb, unsigned long *dst);
extern size_t ultot(unsigned long src, int format, char *buf, size_t buflen);
#define ULTOT_BUF       (22 + 1)  /* holds 64 bits in octal */

extern size_t sin_addrtot(const void *sin, int format, char *dst, size_t dstlen);
#define SUBNETPROTOTOT_BUF      (SUBNETTOTO_BUF + ULTOT_BUF)
#define SAMIGTOT_BUF    (16 + SATOT_BUF + ADDRTOT_BUF)
extern err_t ttodata(const char *src, size_t srclen, int base, char *buf,
	      size_t buflen, size_t *needed);
extern err_t ttodatav(const char *src, size_t srclen, int base,
	       char *buf,  size_t buflen, size_t *needed,
	       char *errp, size_t errlen, unsigned int flags);
#define TTODATAV_BUF    40              /* ttodatav's largest non-literal message */
#define TTODATAV_IGNORESPACE  (1 << 1)  /* ignore spaces in base64 encodings */
#define TTODATAV_SPACECOUNTS  0         /* do not ignore spaces in base64   */

extern size_t datatot(const unsigned char *src, size_t srclen, int format,
	       char *buf, size_t buflen);
extern size_t keyblobtoid(const unsigned char *src, size_t srclen, char *dst,
		   size_t dstlen);
extern size_t splitkeytoid(const unsigned char *e, size_t elen,
		    const unsigned char *m,
		    size_t mlen, char *dst, size_t dstlen);
#define KEYID_BUF       10      /* up to 9 text digits plus NUL */
extern err_t ttoprotoport(char *src, size_t src_len, u_int8_t *proto, u_int16_t *port,
			  bool *has_port_wildcard);

/* PRNG */
extern void prng_init(struct prng *prng, const unsigned char *key, size_t keylen);
extern void prng_bytes(struct prng *prng, unsigned char *dst, size_t dstlen);
extern unsigned long prng_count(struct prng *prng);
extern void prng_final(struct prng *prng);

/* odds and ends */
extern const char *ipsec_version_code(void);
extern const char *ipsec_version_vendorid(void);
extern const char *ipsec_version_string(void);
extern const char libreswan_vendorid[];

/*
 * obsolete functions, to be deleted eventually
 */

/* Internet addresses */
/* obsolete (replaced by addrtot) but still in use */
extern size_t                   /* space needed for full conversion */
addrtoa(struct in_addr addr,
	int format,             /* character; 0 means default */
	char *dst,
	size_t dstlen
	);
#define ADDRTOA_BUF     ADDRTOT_BUF

/* subnets */
/* obsolete (replaced by subnettot) but still in use */
extern size_t                          /* space needed for full conversion */
subnettoa(struct in_addr addr,
	  struct in_addr mask,
	  int format,           /* character; 0 means default */
	  char *dst,
	  size_t dstlen
	  );
/* obsolete (replaced by subnettot) but still in use; no manpage */
extern size_t                          /* space needed for full conversion */
subnet6toa(struct in6_addr *addr,
	   struct in6_addr *mask,
	   int format,          /* character; 0 means default */
	   char *dst,
	   size_t dstlen
	   );
#define SUBNETTOA_BUF SUBNETTOT_BUF     /* large enough for worst case result */

/* end of obsolete functions */

/* data types for SA conversion functions */

/* part extraction and special addresses */
extern struct in_addr subnetof(struct in_addr addr,
			struct in_addr mask
			);
extern struct in_addr hostof(struct in_addr addr,
		       struct in_addr mask
		       );
extern struct in_addr broadcastof(struct in_addr addr,
			   struct in_addr mask
			   );

/* mask handling */
extern int goodmask(struct in_addr mask);
extern int masktobits(struct in_addr mask);
extern int mask6tobits(struct in6_addr *mask);
extern struct in_addr  bitstomask(int n);
extern struct in6_addr bitstomask6(int n);

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
