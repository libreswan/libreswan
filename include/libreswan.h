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

/*
 * Libreswan was written before <stdbool.h> was standardized.
 * We continue to use TRUE and FALSE because we think that they are clearer
 * than true or false.
 */

#ifndef __KERNEL__
# include <stdbool.h> /* for 'bool' */
#endif

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

/*
 * We've just got to have some datatypes defined...  And annoyingly, just
 * where we get them depends on whether we're in userland or not.
 */
/* things that need to come from one place or the other, depending */
#if defined(__KERNEL__)
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <libreswan/ipsec_kversion.h>
#include <libreswan/ipsec_param.h>
#define user_assert(foo)  { } /* nothing */

#else /* NOT in (linux) kernel */

#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#include <stdio.h>
#include <stdint.h>

#endif  /* (linux) kernel */

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

#include "ip_address.h"

#ifdef NEED_SIN_LEN
#define SET_V4(a)	{ (a).u.v4.sin_family = AF_INET; (a).u.v4.sin_len = sizeof(struct sockaddr_in); }
#define SET_V6(a)	{ (a).u.v6.sin6_family = AF_INET6; (a).u.v6.sin6_len = sizeof(struct sockaddr_in6); }
#else
#define SET_V4(a)	{ (a).u.v4.sin_family = AF_INET; }
#define SET_V6(a)	{ (a).u.v6.sin6_family = AF_INET6; }
#endif

/* then the main types */
typedef struct {
	ip_address addr;
	int maskbits;
} ip_subnet;
typedef struct {
	ip_address start;
	ip_address end;
} ip_range;

/* for use in KLIPS.  Userland should use addrtypeof() */
#define ip_address_family(a)    ((a)->u.v4.sin_family)

/*
 * ip_address_eq: test two ip_address values for equality.
 *
 * For use in KLIPS.  Userland should use sameaddr().
 */
#define ip_address_eq(a, b) \
	(ip_address_family((a)) == ip_address_family((b)) && \
	 (ip_address_family((a)) == AF_INET ? \
	  ((a)->u.v4.sin_addr.s_addr == (b)->u.v4.sin_addr.s_addr) : \
	  (0 == memcmp((a)->u.v6.sin6_addr.s6_addr32, \
		      (b)->u.v6.sin6_addr.s6_addr32, sizeof(u_int32_t) * 4)) \
	 ))

/* For use in KLIPS.  Userland should use isanyaddr() */
#define ip_address_isany(a) \
	(ip_address_family((a)) == AF_INET6 ? \
	 ((a)->u.v6.sin6_addr.s6_addr[0] == 0 && \
	  (a)->u.v6.sin6_addr.s6_addr[1] == 0 && \
	  (a)->u.v6.sin6_addr.s6_addr[2] == 0 && \
	  (a)->u.v6.sin6_addr.s6_addr[3] == 0) : \
	 ((a)->u.v4.sin_addr.s_addr == 0))

/* and the SA ID stuff */
#ifdef __KERNEL__
typedef __u32 ipsec_spi_t;
#else
typedef u_int32_t ipsec_spi_t;
#endif
typedef struct {                                /* to identify an SA, we need: */
	ip_address dst;                         /* A. destination host */
	ipsec_spi_t spi;                        /* B. 32-bit SPI, assigned by dest. host */
#               define  SPI_PASS        256     /* magic values... */
#               define  SPI_DROP        257     /* ...for use... */
#               define  SPI_REJECT      258     /* ...with SA_INT */
#               define  SPI_HOLD        259
#               define  SPI_TRAP        260
#               define  SPI_TRAPSUBNET  261
	int proto;                      /* C. protocol */
#               define  SA_ESP  50      /* IPPROTO_ESP */
#               define  SA_AH   51      /* IPPROTO_AH */
#               define  SA_IPIP 4       /* IPPROTO_IPIP */
#               define  SA_COMP 108     /* IPPROTO_COMP */
#               define  SA_INT  61      /* IANA reserved for internal use */
} ip_said;

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

/* looks up names in DNS */
extern err_t ttoaddr(const char *src, size_t srclen, int af, ip_address *dst);

/* does not look up names in DNS */
extern err_t ttoaddr_num(const char *src, size_t srclen, int af, ip_address *dst);

extern err_t tnatoaddr(const char *src, size_t srclen, int af, ip_address *dst);
extern size_t addrtot(const ip_address *src, int format, char *buf, size_t buflen);
extern size_t inet_addrtot(int type, const void *src, int format, char *buf,
		    size_t buflen);
extern size_t sin_addrtot(const void *sin, int format, char *dst, size_t dstlen);
extern err_t ttorange(const char *src, size_t srclen, int af, ip_range *dst,
		bool non_zero);
extern size_t rangetot(const ip_range *src, char format, char *dst, size_t dstlen);
#define RANGETOT_BUF     (ADDRTOT_BUF * 2 + 1)
extern err_t ttosubnet(const char *src, size_t srclen, int af, ip_subnet *dst);
extern size_t subnettot(const ip_subnet *src, int format, char *buf, size_t buflen);
#define SUBNETTOT_BUF   (ADDRTOT_BUF + 1 + 3)
extern size_t subnetporttot(const ip_subnet *src, int format, char *buf,
		     size_t buflen);
#define SUBNETPROTOTOT_BUF      (SUBNETTOTO_BUF + ULTOT_BUF)
extern err_t ttosa(const char *src, size_t srclen, ip_said *dst);
extern size_t satot(const ip_said *src, int format, char *bufptr, size_t buflen);
#define SATOT_BUF       (5 + ULTOT_BUF + 1 + ADDRTOT_BUF)
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

/* initializations */
extern void initsaid(const ip_address *addr, ipsec_spi_t spi, int proto,
	      ip_said *dst);
extern err_t loopbackaddr(int af, ip_address *dst);
extern err_t unspecaddr(int af, ip_address *dst);
extern err_t anyaddr(int af, ip_address *dst);
extern err_t initaddr(const unsigned char *src, size_t srclen, int af,
	       ip_address *dst);
extern err_t add_port(int af, ip_address *addr, unsigned short port);
extern err_t initsubnet(const ip_address *addr, int maskbits, int clash,
		 ip_subnet *dst);
extern err_t addrtosubnet(const ip_address *addr, ip_subnet *dst);

/* misc. conversions and related */
extern err_t rangetosubnet(const ip_address *from, const ip_address *to,
		    ip_subnet *dst);
extern int addrtypeof(const ip_address *src);
extern int subnettypeof(const ip_subnet *src);
extern size_t addrlenof(const ip_address *src);
extern size_t addrbytesptr_read(const ip_address *src, const unsigned char **dst);
extern size_t addrbytesptr_write(ip_address *src, unsigned char **dst);
extern size_t addrbytesof(const ip_address *src, unsigned char *dst, size_t dstlen);
extern int masktocount(const ip_address *src);
extern void networkof(const ip_subnet *src, ip_address *dst);
extern void maskof(const ip_subnet *src, ip_address *dst);

/* tests */
extern bool sameaddr(const ip_address *a, const ip_address *b);
extern int addrcmp(const ip_address *a, const ip_address *b);
extern bool samesubnet(const ip_subnet *a, const ip_subnet *b);
extern bool addrinsubnet(const ip_address *a, const ip_subnet *s);
extern bool subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
extern bool subnetishost(const ip_subnet *s);
extern bool samesaid(const ip_said *a, const ip_said *b);
extern bool sameaddrtype(const ip_address *a, const ip_address *b);
extern bool samesubnettype(const ip_subnet *a, const ip_subnet *b);
extern int isanyaddr(const ip_address *src);
extern int isunspecaddr(const ip_address *src);
extern int isloopbackaddr(const ip_address *src);

/* PRNG */
extern void prng_init(struct prng *prng, const unsigned char *key, size_t keylen);
extern void prng_bytes(struct prng *prng, unsigned char *dst, size_t dstlen);
extern unsigned long prng_count(struct prng *prng);
extern void prng_final(struct prng *prng);

/* odds and ends */
extern const char *ipsec_version_code(void);
extern const char *ipsec_version_vendorid(void);
extern const char *ipsec_version_string(void);
#ifndef __KERNEL__
extern const char libreswan_vendorid[];
#endif

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
