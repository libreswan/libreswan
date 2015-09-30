/*
 * header file for FreeS/WAN library functions
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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
 */
#ifndef _LIBRESWAN_H
#define _LIBRESWAN_H    /* seen it, no need to see it again */

/* you'd think this should be builtin to compiler... */
#ifndef TRUE
# define TRUE 1
# ifndef __KERNEL__
typedef int bool;
# endif
#endif

#ifndef FALSE
# define FALSE 0
#endif

#include <stddef.h>

/* ================ time-related declarations ================ */

enum {
	secs_per_minute = 60,
	secs_per_hour = 60 * secs_per_minute,
	secs_per_day = 24 * secs_per_hour
};

#if !defined(__KERNEL__)

#include <sys/time.h>
#include <time.h>

/*
 * UNDEFINED_TIME is meant to be an impossible exceptional time_t value.
 *
 * ??? On UNIX, 0 is a value that means 1970-01-01 00:00:00 +0000 (UTC).
 *
 * UNDEFINED_TIME is used as a real time_t value in certificate handling.
 * Perhaps this is sancioned by X.509.
 *
 * UNDEFINED_TIME is used as a mono time_t value in liveness_check().
 * 0 is PROBABLY safely distinct in this application.
 */
#define UNDEFINED_TIME  ((time_t)0)	/* ??? what a kludge! */

#define TIME_T_MAX  ((time_t) ((1ull << (sizeof(time_t) * BITS_PER_BYTE - 1)) - 1))

/*
 * Wrap time_t so that dimensional analysis will be enforced by the compiler.
 *
 * realtime_t: absolute UTC time.  Might be discontinuous due to clock adjustment.
 * monotime_t: absolute monotonic time.  No discontinuities (except for machine sleep?)
 * deltatime_t: relative time between events.  Presumed continuous.
 *
 * Try to stick to the operations implemented here.
 * A good compiler should produce identical code for these or for time_t values
 * but will catch nonsense operations through type enforcement.
 */

typedef struct { time_t delta_secs; } deltatime_t;
typedef struct { time_t real_secs; } realtime_t;
typedef struct { time_t mono_secs; } monotime_t;

/* delta time (interval) operations */

static inline deltatime_t deltatime(time_t secs) {
	deltatime_t d = { secs };
	return d;
}

static inline unsigned long deltamillisecs(deltatime_t d) {
	return d.delta_secs * 1000;
}

static inline time_t deltasecs(deltatime_t d) {
	return d.delta_secs;
}

static inline deltatime_t deltatimescale(int num, int denom, deltatime_t d) {
	/* ??? should check for overflow */
	return deltatime(deltasecs(d) * num / denom);
}

static inline bool deltaless(deltatime_t a, deltatime_t b)
{
	return deltasecs(a) < deltasecs(b);
}

static inline bool deltaless_tv_tv(const struct timeval a, const struct timeval b)
{
	return a.tv_sec < b.tv_sec ||
		( a.tv_sec == b.tv_sec && a.tv_usec < b.tv_usec);
}

static inline bool deltaless_tv_dt(const struct timeval a, const deltatime_t b)
{
	return a.tv_sec < deltasecs(b);
}

/* real time operations */

static inline realtime_t realtimesum(realtime_t t, deltatime_t d) {
	realtime_t s = { t.real_secs + d.delta_secs };
	return s;
}

static inline realtime_t undefinedrealtime(void)
{
	realtime_t u = { UNDEFINED_TIME };

	return u;
}

static inline bool isundefinedrealtime(realtime_t t)
{
	return t.real_secs == UNDEFINED_TIME;
}

static inline bool realbefore(realtime_t a, realtime_t b)
{
	return a.real_secs < b.real_secs;
}

static inline deltatime_t realtimediff(realtime_t a, realtime_t b) {
	deltatime_t d = { a.real_secs - b.real_secs };
	return d;
}

static inline realtime_t realnow(void)
{
	realtime_t t;

	time(&t.real_secs);
	return t;
}

#define REALTIMETOA_BUF     30	/* size of realtimetoa string buffer */
extern char *realtimetoa(const realtime_t rtm, bool utc, char *buf, size_t blen);

/* monotonic time operations */

static inline monotime_t monotimesum(monotime_t t, deltatime_t d) {
	monotime_t s = { t.mono_secs + d.delta_secs };
	return s;
}

static inline bool monobefore(monotime_t a, monotime_t b)
{
	return a.mono_secs < b.mono_secs;
}

static inline deltatime_t monotimediff(monotime_t a, monotime_t b) {
	deltatime_t d = { a.mono_secs - b.mono_secs };

	return d;
}

/* defs.h declares extern monotime_t mononow(void) */

#endif	/* !defined(__KERNEL__) */

/* ================ end of time-related declarations ================ */

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
#if defined(linux)
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

#else /* NOT in kernel */
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#include <stdio.h>

#  define uint8_t u_int8_t
#  define uint16_t u_int16_t
#  define uint32_t u_int32_t
#  define uint64_t u_int64_t

#endif  /* __KERNEL__ */

#endif  /* linux */

#define DEBUG_NO_STATIC static

/*
 * Yes Virginia, we have started a windows port.
 */
#if defined(__CYGWIN32__)
#if !defined(WIN32_KERNEL)
/* get windows equivalents */
#include <stdio.h>
#include <string.h>
#include <win32/types.h>
#include <netinet/in.h>
#include <cygwin/socket.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#endif  /* _KERNEL */
#endif  /* WIN32 */

/*
 * Kovacs? A macosx port?
 */
#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
#include <TargetConditionals.h>
#include <AvailabilityMacros.h>
#include <machine/types.h>
#include <machine/endian.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <tcpd.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
#define __u32  unsigned int
#define __u8  unsigned char
#define s6_addr16 __u6_addr.__u6_addr16
#define DEBUG_NO_STATIC static
#endif

/*
 * FreeBSD
 */
#if defined(__FreeBSD__)
#  define DEBUG_NO_STATIC static
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#define user_assert(foo) assert(foo)
/* apparently this way to deal with an IPv6 address is not standard. */
#define s6_addr16 __u6_addr.__u6_addr16
#endif

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

/*
 * Basic data types for the address-handling functions.
 * ip_address and ip_subnet are supposed to be opaque types; do not
 * use their definitions directly, they are subject to change!
 */

/* first, some quick fakes in case we're on an old system with no IPv6 */
#if !defined(s6_addr16) && defined(__CYGWIN32__)
extern struct in6_addr {
	union {
		u_int8_t u6_addr8[16];
		u_int16_t u6_addr16[8];
		u_int32_t u6_addr32[4];
	} in6_u;
#define s6_addr                 in6_u.u6_addr8
#define s6_addr16               in6_u.u6_addr16
#define s6_addr32               in6_u.u6_addr32
};
extern struct sockaddr_in6 {
	unsigned short int sin6_family;         /* AF_INET6 */
	__u16 sin6_port;                        /* Transport layer port # */
	__u32 sin6_flowinfo;                    /* IPv6 flow information */
	struct in6_addr sin6_addr;              /* IPv6 address */
	__u32 sin6_scope_id;                    /* scope id (new in RFC2553) */
};
#endif  /* !s6_addr16 */

/* then the main types */
typedef struct {
	union {
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} u;
} ip_address;
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
typedef const char *err_t;      /* error message, or NULL for success */
struct prng {                   /* pseudo-random-number-generator guts */
	unsigned char sbox[256];
	int i, j;
	unsigned long count;
};

/*
 * definitions for user space, taken from freeswan/ipsec_sa.h
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

/* GCC magic for use in function definitions! */
#ifdef GCC_LINT
# define PRINTF_LIKE(n) __attribute__ ((format(printf, n, n + 1)))
# define NEVER_RETURNS __attribute__ ((noreturn))
# define UNUSED __attribute__ ((unused))
# define MUST_USE_RESULT  __attribute__ ((warn_unused_result))
#else
# define PRINTF_LIKE(n) /* ignore */
# define NEVER_RETURNS  /* ignore */
# define UNUSED         /* ignore */
# define MUST_USE_RESULT	/* ignore */
#endif

#ifdef COMPILER_HAS_NO_PRINTF_LIKE
# undef PRINTF_LIKE
# define PRINTF_LIKE(n) /* ignore */
#endif

/*
 * function to log stuff from libraries that may be used in multiple
 * places.
 */
typedef int (*libreswan_keying_debug_func_t)(const char *message, ...);

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
/* RFC 1886 old IPv6 reverse-lookup format is the bulkiest */
#define ADDRTOT_BUF     (32 * 2 + 3 + 1 + 3 + 1 + 1)
typedef struct {
	char buf[ADDRTOT_BUF];
} ipstr_buf;
extern const char *ipstr(const ip_address *src, ipstr_buf *b);
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
		   int *has_port_wildcard);

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
extern size_t addrbytesptr(const ip_address *src, unsigned char **dst);
extern size_t addrbytesptr_write(ip_address *src, unsigned char **dst);
extern size_t addrbytesof(const ip_address *src, unsigned char *dst, size_t dstlen);
extern int masktocount(const ip_address *src);
extern void networkof(const ip_subnet *src, ip_address *dst);
extern void maskof(const ip_subnet *src, ip_address *dst);

/* tests */
extern int sameaddr(const ip_address *a, const ip_address *b);
extern int addrcmp(const ip_address *a, const ip_address *b);
extern int samesubnet(const ip_subnet *a, const ip_subnet *b);
extern int addrinsubnet(const ip_address *a, const ip_subnet *s);
extern int subnetinsubnet(const ip_subnet *a, const ip_subnet *b);
extern int subnetishost(const ip_subnet *s);
extern int samesaid(const ip_said *a, const ip_said *b);
extern int sameaddrtype(const ip_address *a, const ip_address *b);
extern int samesubnettype(const ip_subnet *a, const ip_subnet *b);
extern int isanyaddr(const ip_address *src);
extern int isunspecaddr(const ip_address *src);
extern int isloopbackaddr(const ip_address *src);

/* low-level grot */
extern int portof(const ip_address *src);
extern void setportof(int port, ip_address *dst);
extern struct sockaddr *sockaddrof(ip_address *src);
extern size_t sockaddrlenof(const ip_address *src);

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
extern struct in_addr hostof( struct in_addr addr,
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

/*
 * reqid definitions
 *
 * A reqid is a numerical identifier used to match IPsec SAs using
 * iptables with NETKEY/XFRM. This identifier is normally automatically
 * allocated.  It is exported to the _updown script as REQID. On Linux,
 * reqids are supported with IP Connection Tracking and NAT (iptables).
 * Automatically generated values use the range 16380 and higher.
 * Manually specified reqid values therefore must be between 1 and 16379.
 *
 * Automatically generated reqids are allocated in groups of four, one
 * for each potential SA and pseudo SA in an SA bundle.  Their number
 * will be above 16380.  The base number will be a multiple of four.
 *
 * Manually assigned reqids are all identical for a particular connection
 * and its instantiations.
 */

typedef uint32_t reqid_t;

#define IPSEC_MANUAL_REQID_MAX  0x3fff

#define reqid_ah(r)	(r)
#define reqid_esp(r)	((r) <= IPSEC_MANUAL_REQID_MAX ? (r) : (r) + 1)
#define reqid_ipcomp(r)	((r) <= IPSEC_MANUAL_REQID_MAX ? (r) : (r) + 2)

#endif /* _LIBRESWAN_H */
