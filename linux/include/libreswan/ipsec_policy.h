#ifndef _IPSEC_POLICY_H
/*
 * policy interface file between pluto and applications
 * Copyright (C) 2003              Michael Richardson <mcr@freeswan.org>
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
 */
#define _IPSEC_POLICY_H         /* seen it, no need to see it again */

/*
 * this file defines an interface between an application (or rather an
 * application library) and a key/policy daemon. It provides for inquiries
 * as to the current state of a connected socket, as well as for general
 * questions.
 *
 * In general, the interface is defined as a series of functional interfaces,
 * and the policy messages should be internal. However, because this is in
 * fact an ABI between pieces of the system that may get compiled and revised
 * seperately, this ABI must be public and revision controlled.
 *
 * It is expected that the daemon will always support previous versions.
 */

#define IPSEC_POLICY_MSG_REVISION (unsigned)200305061

enum ipsec_policy_command {
	IPSEC_CMD_QUERY_FD       = 1,
	IPSEC_CMD_QUERY_HOSTPAIR = 2,
	IPSEC_CMD_QUERY_DSTONLY  = 3,
};

struct ipsec_policy_msg_head {
	u_int32_t ipm_version;
	u_int32_t ipm_msg_len;
	u_int32_t ipm_msg_type;
	u_int32_t ipm_msg_seq;
};

enum ipsec_privacy_quality {
	IPSEC_PRIVACY_NONE     = 0,
	IPSEC_PRIVACY_INTEGRAL = 4,     /* not private at all. AH-like */
	IPSEC_PRIVACY_UNKNOWN  = 8,     /* something is claimed, but details unavail */
	IPSEC_PRIVACY_ROT13    = 12,    /* trivially breakable, i.e. 1DES */
	IPSEC_PRIVACY_GAK      = 16,    /* known eavesdroppers */
	IPSEC_PRIVACY_PRIVATE  = 32,    /* secure for at least a decade */
	IPSEC_PRIVACY_STRONG   = 64,    /* ridiculously secure */
	IPSEC_PRIVACY_TORTOISE = 192,   /* even stronger, but very slow */
	IPSEC_PRIVACY_OTP      = 224,   /* some kind of *true* one time pad */
};

enum ipsec_bandwidth_quality {
	IPSEC_QOS_UNKNOWN = 0,          /* unknown bandwidth */
	IPSEC_QOS_INTERACTIVE = 16,     /* reasonably moderate jitter, moderate fast.
	                                   Good enough for telnet/ssh. */
	IPSEC_QOS_VOIP        = 32,     /* faster crypto, predicable jitter */
	IPSEC_QOS_FTP         = 64,     /* higher throughput crypto, perhaps hardware
	                                   offloaded, but latency/jitter may be bad */
	IPSEC_QOS_WIRESPEED   = 128,    /* expect to be able to fill your pipe */
};

/* moved from programs/pluto/constants.h */
/* IPsec AH transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.3
 * http://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-9
 */
enum ipsec_authentication_algo {
	/* 0-1 RESERVED */
	AH_NONE=0,
	AH_MD5=2,
	AH_SHA=3,
	AH_DES=4,
	AH_SHA2_256=5,
	AH_SHA2_384=6,
	AH_SHA2_512=7,
	AH_RIPEMD=8,
	AH_AES_XCBC_MAC=9,
	AH_RSA=10,
	AH_AES_128_GMAC=11,     /* RFC4543 [Errata1821] */
	AH_AES_192_GMAC=12,     /* RFC4543 [Errata1821] */
	AH_AES_256_GMAC=13,     /* RFC4543 [Errata1821] */
	/* 14-248 Unassigned */
	/* 249 - 255 Reserved for private use */
	AH_NULL=251,            /* comes from kame? */
	AH_SHA2_256_TRUNC=252,  /* our own stolen value */
};

/* IPsec ESP transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.4
 * and from http://www.iana.org/assignments/isakmp-registry
 */

enum ipsec_cipher_algo {
	ESP_reserved=0,
	ESP_DES_IV64=1,
	ESP_DES=2, /* obsoleted */
	ESP_3DES=3,
	ESP_RC5=4,
	ESP_IDEA=5,
	ESP_CAST=6,
	ESP_BLOWFISH=7, /* obsoleyed */
	ESP_3IDEA=8,
	ESP_DES_IV32=9,
	ESP_RC4=10,
	ESP_NULL=11,
	ESP_AES=12,   /* CBC 128 bit AES */
	ESP_AES_CTR=13,
	ESP_AES_CCM_8=14,
	ESP_AES_CCM_12=15,
	ESP_AES_CCM_16=16,
	ESP_ID17=17, /* unassigned=17 */
	ESP_AES_GCM_8=18,
	ESP_AES_GCM_12=19,
	ESP_AES_GCM_16=20,
	ESP_SEED_CBC=21,
	ESP_CAMELLIA=22,
	ESP_NULL_AUTH_AES_GMAC=23, /* [RFC4543][Errata1821] */
	/* 249-255 reserved for private use */
	ESP_MARS=249,
	ESP_RC6=250,
	ESP_KAME_NULL=251, /* kame? */
	ESP_SERPENT=252,
	ESP_TWOFISH=253,
	ESP_ID254=254,
	ESP_ID255=255,
};

/* IPCOMP transform values
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.5
 */

enum ipsec_comp_algo {
	IPCOMP_NONE=0,
	IPCOMP_OUI=1,
	IPCOMP_DEFLATE=2,
	IPCOMP_LZS=3,
	IPCOMP_LZJH=4, /* RFC 3051 */
	/* 5-47 Reserved for approved algorithms */
	/* 48-63 Reserved for private use */
	/* 64-255 Unassigned */
};

/* Identification type values
 * RFC 2407 The Internet IP security Domain of Interpretation for
 * ISAKMP 4.6.2.1
 *
 * Also for RFC4306.
 *
 * enum ident_names;
 */

enum ipsec_id_type {
	ID_FROMCERT=         (-3),              /* taken from certificate */
	ID_IMPOSSIBLE=             (-2),        /* private to Pluto */
	ID_MYID=                   (-1),        /* private to Pluto */
	ID_NONE=                     0,         /* private to Pluto */
	ID_IPV4_ADDR=                1,
	ID_FQDN=                     2,
	ID_USER_FQDN=                3,
	ID_RFC822_ADDR = ID_USER_FQDN,  /* RFC4306 */
	ID_IPV4_ADDR_SUBNET=         4,
	ID_IPV6_ADDR=                5,
	ID_IPV6_ADDR_SUBNET=         6,
	ID_IPV4_ADDR_RANGE=          7,
	ID_IPV6_ADDR_RANGE=          8,
	ID_DER_ASN1_DN=              9,
	ID_DER_ASN1_GN=              10,
	ID_KEY_ID=                   11,
	ID_LIST=                     12, /* RFC 3554 */
	/* 13-248 Unassigned */
	/* 249-255 Reserved for private use */
};

/* Certificate type values
 * RFC 2408 ISAKMP, chapter 3.9
 */
enum ipsec_cert_type {
	CERT_NONE=                    0,        /* none, or guess from file contents */
	CERT_PKCS7_WRAPPED_X509=      1,        /* self-signed certificate from disk */
	CERT_PGP=                     2,	/* We no longer support PGP keys */
	CERT_DNS_SIGNED_KEY=          3,        /* KEY RR from DNS */
	CERT_X509_SIGNATURE=          4,
	CERT_X509_KEY_EXCHANGE=       5,
	CERT_KERBEROS_TOKENS=         6,
	CERT_CRL=                     7,
	CERT_ARL=                     8,
	CERT_SPKI=                    9,
	CERT_X509_ATTRIBUTE=          10,
	CERT_RAW_RSA=                 11, /* raw RSA from config file */
	CERT_X509_BUNDLE_URL=         12,
};

/* a SIG record in ASCII */
struct ipsec_dns_sig {
	char fqdn[256];
	char dns_sig[768]; /* empty string if not signed */
};

struct ipsec_raw_key {
	char id_name[256];
	char fs_keyid[8];
};

struct ipsec_identity {
	enum ipsec_id_type ii_type;
	enum ipsec_cert_type ii_format;
	union {
		struct ipsec_dns_sig ipsec_dns_signed;
		/* some thing for PKIX */
		struct ipsec_raw_key ipsec_raw_key;
	} ii_credential;
};

#define IPSEC_MAX_CREDENTIALS 32

struct ipsec_policy_cmd_query {
	struct ipsec_policy_msg_head head;

	/* Query section */
	ip_address query_local;         /* us   */
	ip_address query_remote;        /* them */
	u_int8_t proto;                 /* TCP, ICMP, etc. */
	u_short src_port, dst_port;

	/* Answer section */
	enum ipsec_privacy_quality strength;
	enum ipsec_bandwidth_quality bandwidth;
	enum ipsec_authentication_algo auth_detail;
	enum ipsec_cipher_algo esp_detail;
	enum ipsec_comp_algo comp_detail;

	int credential_count;

	struct ipsec_identity credentials[IPSEC_MAX_CREDENTIALS];
};

#define IPSEC_POLICY_SOCKET "/var/run/pluto/pluto.info"

/* prototypes */
extern err_t ipsec_policy_lookup(int fd,
				 struct ipsec_policy_cmd_query *result);
extern err_t ipsec_policy_init(void);
extern err_t ipsec_policy_final(void);
extern err_t ipsec_policy_readmsg(int policysock,
				  unsigned char *buf, size_t buflen);
extern err_t ipsec_policy_sendrecv(unsigned char *buf, size_t buflen);
extern err_t ipsec_policy_cgilookup(struct ipsec_policy_cmd_query *result);

extern const char *ipsec_policy_version_code(void);
extern const char *ipsec_policy_version_string(void);

#endif /* _IPSEC_POLICY_H */
