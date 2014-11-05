#ifndef __IPSEC_H
#define __IPSEC_H 1

/* The definitions, required to talk to KAME racoon IKE. */

#define IPSEC_PORT_ANY          0
#define IPSEC_ULPROTO_ANY       255

enum {
	IPSEC_MODE_ANY          = 0,    /* We do not support this for SA */
	IPSEC_MODE_TRANSPORT    = 1,
	IPSEC_MODE_TUNNEL       = 2
};

enum {
	IPSEC_DIR_ANY           = 0,
	IPSEC_DIR_INBOUND       = 1,
	IPSEC_DIR_OUTBOUND      = 2,
	IPSEC_DIR_FWD           = 3,    /* It is our own */
	IPSEC_DIR_MAX           = 4,
	IPSEC_DIR_INVALID       = 5
};

enum {
	IPSEC_POLICY_DISCARD    = 0,
	IPSEC_POLICY_NONE       = 1,
	IPSEC_POLICY_IPSEC      = 2,
	IPSEC_POLICY_ENTRUST    = 3,
	IPSEC_POLICY_BYPASS     = 4
};

enum {
	IPSEC_LEVEL_DEFAULT     = 0,
	IPSEC_LEVEL_USE         = 1,
	IPSEC_LEVEL_REQUIRE     = 2,
	IPSEC_LEVEL_UNIQUE      = 3
};

#define IPSEC_REPLAYWSIZE  32

#if !(defined(__FreeBSD__) || defined(macintosh) || (defined(__MACH__) && \
	defined(__APPLE__)))
#define IP_IPSEC_POLICY 16
#define IPV6_IPSEC_POLICY 34
#endif
#endif  /* __IPSEC_H */
