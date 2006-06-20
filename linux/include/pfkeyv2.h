/*
 * RCSID $Id: pfkeyv2.h,v 1.31 2005/04/14 01:14:54 mcr Exp $
 */

/*
RFC 2367               PF_KEY Key Management API               July 1998


Appendix D: Sample Header File

This file defines structures and symbols for the PF_KEY Version 2
key management interface. It was written at the U.S. Naval Research
Laboratory. This file is in the public domain. The authors ask that
you leave this credit intact on any copies of this file.
*/
#ifndef __PFKEY_V2_H
#define __PFKEY_V2_H 1

#define PF_KEY_V2 2
#define PFKEYV2_REVISION        199806L
#define PFKEYV2_KLIPS    200606

#define SADB_RESERVED    0
#define SADB_GETSPI      1
#define SADB_UPDATE      2
#define SADB_ADD         3
#define SADB_DELETE      4
#define SADB_GET         5
#define SADB_ACQUIRE     6
#define SADB_REGISTER    7
#define SADB_EXPIRE      8
#define SADB_FLUSH       9
#define SADB_DUMP       10
#define SADB_X_PROMISC  11
#define SADB_X_PCHANGE  12
#define SADB_X_NAT_T_NEW_MAPPING  17
#define SADB_MAX                  17

enum sadb_msg_t {
	K_SADB_RESERVED=SADB_RESERVED,
	K_SADB_GETSPI=SADB_GETSPI,
	K_SADB_UPDATE=SADB_UPDATE,
	K_SADB_ADD=SADB_ADD,
	K_SADB_DELETE=SADB_DELETE,
	K_SADB_GET=SADB_GET,
	K_SADB_ACQUIRE=SADB_ACQUIRE,
	K_SADB_REGISTER=SADB_REGISTER,
	K_SADB_EXPIRE=SADB_EXPIRE,
	K_SADB_FLUSH=SADB_FLUSH,
	K_SADB_DUMP=SADB_DUMP,
	K_SADB_X_PROMISC=SADB_X_PROMISC,
	K_SADB_X_PCHANGE=SADB_X_PCHANGE,
	K_SADB_X_GRPSA=13,
	K_SADB_X_ADDFLOW=14,
	K_SADB_X_DELFLOW=15,
	K_SADB_X_DEBUG=16,
	K_SADB_X_NAT_T_NEW_MAPPING=17,
	K_SADB_X_PLUMBIF=18,
	K_SADB_X_UNPLUMBIF=19,
	K_SADB_MAX=19
};

#define SADB_X_GRPSA	    K_SADB_X_GRPSA		    
#define SADB_X_ADDFLOW	    K_SADB_X_ADDFLOW	    
#define SADB_X_DELFLOW	    K_SADB_X_DELFLOW	    
#define SADB_X_DEBUG	    K_SADB_X_DEBUG		    
#define SADB_X_PLUMBIF	    K_SADB_X_PLUMBIF	    
#define SADB_X_UNPLUMBIF    K_SADB_X_UNPLUMBIF	    


struct sadb_msg {
  uint8_t sadb_msg_version;
  uint8_t sadb_msg_type;
  uint8_t sadb_msg_errno;
  uint8_t sadb_msg_satype;
  uint16_t sadb_msg_len;
  uint16_t sadb_msg_reserved;
  uint32_t sadb_msg_seq;
  uint32_t sadb_msg_pid;
};

struct sadb_ext {
  uint16_t sadb_ext_len;
  uint16_t sadb_ext_type;
};

struct sadb_sa {
  uint16_t sadb_sa_len;
  uint16_t sadb_sa_exttype;
  uint32_t sadb_sa_spi;
  uint8_t sadb_sa_replay;
  uint8_t sadb_sa_state;
  uint8_t sadb_sa_auth;
  uint8_t sadb_sa_encrypt;
  uint32_t sadb_sa_flags;
  uint32_t /*IPsecSAref_t*/ sadb_x_sa_ref; /* 32 bits */
  uint8_t sadb_x_reserved[4];
};

struct sadb_sa_v1 {
  uint16_t sadb_sa_len;
  uint16_t sadb_sa_exttype;
  uint32_t sadb_sa_spi;
  uint8_t sadb_sa_replay;
  uint8_t sadb_sa_state;
  uint8_t sadb_sa_auth;
  uint8_t sadb_sa_encrypt;
  uint32_t sadb_sa_flags;
};

struct sadb_lifetime {
  uint16_t sadb_lifetime_len;
  uint16_t sadb_lifetime_exttype;
  uint32_t sadb_lifetime_allocations;
  uint64_t sadb_lifetime_bytes;
  uint64_t sadb_lifetime_addtime;
  uint64_t sadb_lifetime_usetime;
  uint32_t sadb_x_lifetime_packets;
  uint32_t sadb_x_lifetime_reserved;
};

struct sadb_address {
  uint16_t sadb_address_len;
  uint16_t sadb_address_exttype;
  uint8_t sadb_address_proto;
  uint8_t sadb_address_prefixlen;
  uint16_t sadb_address_reserved;
};

struct sadb_key {
  uint16_t sadb_key_len;
  uint16_t sadb_key_exttype;
  uint16_t sadb_key_bits;
  uint16_t sadb_key_reserved;
};

struct sadb_ident {
  uint16_t sadb_ident_len;
  uint16_t sadb_ident_exttype;
  uint16_t sadb_ident_type;
  uint16_t sadb_ident_reserved;
  uint64_t sadb_ident_id;
};

struct sadb_sens {
  uint16_t sadb_sens_len;
  uint16_t sadb_sens_exttype;
  uint32_t sadb_sens_dpd;
  uint8_t sadb_sens_sens_level;
  uint8_t sadb_sens_sens_len;
  uint8_t sadb_sens_integ_level;
  uint8_t sadb_sens_integ_len;
  uint32_t sadb_sens_reserved;
};

struct sadb_prop {
  uint16_t sadb_prop_len;
  uint16_t sadb_prop_exttype;
  uint8_t sadb_prop_replay;
  uint8_t sadb_prop_reserved[3];
};

struct sadb_comb {
  uint8_t sadb_comb_auth;
  uint8_t sadb_comb_encrypt;
  uint16_t sadb_comb_flags;
  uint16_t sadb_comb_auth_minbits;
  uint16_t sadb_comb_auth_maxbits;
  uint16_t sadb_comb_encrypt_minbits;
  uint16_t sadb_comb_encrypt_maxbits;
  uint32_t sadb_comb_reserved;
  uint32_t sadb_comb_soft_allocations;
  uint32_t sadb_comb_hard_allocations;
  uint64_t sadb_comb_soft_bytes;
  uint64_t sadb_comb_hard_bytes;
  uint64_t sadb_comb_soft_addtime;
  uint64_t sadb_comb_hard_addtime;
  uint64_t sadb_comb_soft_usetime;
  uint64_t sadb_comb_hard_usetime;
  uint32_t sadb_x_comb_soft_packets;
  uint32_t sadb_x_comb_hard_packets;
};

struct sadb_supported {
  uint16_t sadb_supported_len;
  uint16_t sadb_supported_exttype;
  uint32_t sadb_supported_reserved;
};

struct sadb_alg {
  uint8_t sadb_alg_id;
  uint8_t sadb_alg_ivlen;
  uint16_t sadb_alg_minbits;
  uint16_t sadb_alg_maxbits;
  uint16_t sadb_alg_reserved;
};

struct sadb_spirange {
  uint16_t sadb_spirange_len;
  uint16_t sadb_spirange_exttype;
  uint32_t sadb_spirange_min;
  uint32_t sadb_spirange_max;
  uint32_t sadb_spirange_reserved;
};

struct sadb_x_kmprivate {
  uint16_t sadb_x_kmprivate_len;
  uint16_t sadb_x_kmprivate_exttype;
  uint32_t sadb_x_kmprivate_reserved;
};

struct sadb_x_satype {
  uint16_t sadb_x_satype_len;
  uint16_t sadb_x_satype_exttype;
  uint8_t sadb_x_satype_satype;
  uint8_t sadb_x_satype_reserved[3];
};
  
struct sadb_x_policy {
  uint16_t sadb_x_policy_len;
  uint16_t sadb_x_policy_exttype;
  uint16_t sadb_x_policy_type;
  uint8_t sadb_x_policy_dir;
  uint8_t sadb_x_policy_reserved;
  uint32_t sadb_x_policy_id;
  uint32_t sadb_x_policy_reserved2;
};
 
struct sadb_x_debug {
  uint16_t sadb_x_debug_len;
  uint16_t sadb_x_debug_exttype;
  uint32_t sadb_x_debug_tunnel;
  uint32_t sadb_x_debug_netlink;
  uint32_t sadb_x_debug_xform;
  uint32_t sadb_x_debug_eroute;
  uint32_t sadb_x_debug_spi;
  uint32_t sadb_x_debug_radij;
  uint32_t sadb_x_debug_esp;
  uint32_t sadb_x_debug_ah;
  uint32_t sadb_x_debug_rcv;
  uint32_t sadb_x_debug_pfkey;
  uint32_t sadb_x_debug_ipcomp;
  uint32_t sadb_x_debug_verbose;
  uint8_t sadb_x_debug_reserved[4];
};

struct sadb_x_nat_t_type {
  uint16_t sadb_x_nat_t_type_len;
  uint16_t sadb_x_nat_t_type_exttype;
  uint8_t sadb_x_nat_t_type_type;
  uint8_t sadb_x_nat_t_type_reserved[3];
};
struct sadb_x_nat_t_port {
  uint16_t sadb_x_nat_t_port_len;
  uint16_t sadb_x_nat_t_port_exttype;
  uint16_t sadb_x_nat_t_port_port;
  uint16_t sadb_x_nat_t_port_reserved;
};

/*
 * A protocol structure for passing through the transport level
 * protocol.  It contains more fields than are actually used/needed
 * but it is this way to be compatible with the structure used in
 * OpenBSD (http://www.openbsd.org/cgi-bin/cvsweb/src/sys/net/pfkeyv2.h)
 */
struct sadb_protocol {
  uint16_t sadb_protocol_len;
  uint16_t sadb_protocol_exttype;
  uint8_t  sadb_protocol_proto;
  uint8_t  sadb_protocol_direction;
  uint8_t  sadb_protocol_flags;
  uint8_t  sadb_protocol_reserved2;
};

#define SADB_EXT_RESERVED             0
#define SADB_EXT_SA                   1
#define SADB_EXT_LIFETIME_CURRENT     2
#define SADB_EXT_LIFETIME_HARD        3
#define SADB_EXT_LIFETIME_SOFT        4
#define SADB_EXT_ADDRESS_SRC          5
#define SADB_EXT_ADDRESS_DST          6
#define SADB_EXT_ADDRESS_PROXY        7
#define SADB_EXT_KEY_AUTH             8
#define SADB_EXT_KEY_ENCRYPT          9
#define SADB_EXT_IDENTITY_SRC         10
#define SADB_EXT_IDENTITY_DST         11
#define SADB_EXT_SENSITIVITY          12
#define SADB_EXT_PROPOSAL             13
#define SADB_EXT_SUPPORTED_AUTH       14
#define SADB_EXT_SUPPORTED_ENCRYPT    15
#define SADB_EXT_SPIRANGE             16
#define SADB_X_EXT_KMPRIVATE          17
#define SADB_X_EXT_POLICY             18
#define SADB_X_EXT_SA2                19
#define SADB_X_EXT_NAT_T_TYPE         27
#define SADB_X_EXT_NAT_T_SPORT        28
#define SADB_X_EXT_NAT_T_DPORT        29
#define SADB_X_EXT_NAT_T_OA           30
#define SADB_EXT_MAX                  30

/*
 * NOTE that there is a limit of 31 extensions due to current implementation
 * in pfkeyv2_ext_bits.c
 */
enum sadb_extension_t {
	K_SADB_EXT_RESERVED=SADB_RESERVED,
	K_SADB_EXT_SA=              SADB_EXT_SA,
	K_SADB_EXT_LIFETIME_CURRENT=SADB_EXT_LIFETIME_CURRENT,
	K_SADB_EXT_LIFETIME_HARD=   SADB_EXT_LIFETIME_HARD,
	K_SADB_EXT_LIFETIME_SOFT=   SADB_EXT_LIFETIME_SOFT,
	K_SADB_EXT_ADDRESS_SRC=     SADB_EXT_ADDRESS_SRC,
	K_SADB_EXT_ADDRESS_DST=     SADB_EXT_ADDRESS_DST,
	K_SADB_EXT_ADDRESS_PROXY=   SADB_EXT_ADDRESS_PROXY,
	K_SADB_EXT_KEY_AUTH=        SADB_EXT_KEY_AUTH,
	K_SADB_EXT_KEY_ENCRYPT=     SADB_EXT_KEY_ENCRYPT,
	K_SADB_EXT_IDENTITY_SRC=    SADB_EXT_IDENTITY_SRC,
	K_SADB_EXT_IDENTITY_DST=    SADB_EXT_IDENTITY_DST,
	K_SADB_EXT_SENSITIVITY=     SADB_EXT_SENSITIVITY,
	K_SADB_EXT_PROPOSAL=        SADB_EXT_PROPOSAL,
	K_SADB_EXT_SUPPORTED_AUTH=  SADB_EXT_SUPPORTED_AUTH,
	K_SADB_EXT_SUPPORTED_ENCRYPT=SADB_EXT_SUPPORTED_ENCRYPT,
	K_SADB_EXT_SPIRANGE=        SADB_EXT_SPIRANGE,
	K_SADB_X_EXT_KMPRIVATE=     SADB_X_EXT_KMPRIVATE,
	K_SADB_X_EXT_SATYPE2=       18,
	K_SADB_X_EXT_POLICY=        SADB_X_EXT_POLICY,
	K_SADB_X_EXT_SA2=           SADB_X_EXT_SA2,
	K_SADB_X_EXT_ADDRESS_DST2=  20,
	K_SADB_X_EXT_ADDRESS_SRC_FLOW=21,
	K_SADB_X_EXT_ADDRESS_DST_FLOW=22,
	K_SADB_X_EXT_ADDRESS_SRC_MASK=23,
	K_SADB_X_EXT_ADDRESS_DST_MASK=24,
	K_SADB_X_EXT_DEBUG=         25,
	K_SADB_X_EXT_PROTOCOL=      26,
	K_SADB_X_EXT_NAT_T_TYPE=    27,
	K_SADB_X_EXT_NAT_T_SPORT=   28,
	K_SADB_X_EXT_NAT_T_DPORT=   29,
	K_SADB_X_EXT_NAT_T_OA=      30,
	K_SADB_X_EXT_PLUMBIF=       31,
	K_SADB_X_EXT_SAREF=         32,
	K_SADB_EXT_MAX=             32,
};


#define SADB_X_EXT_SATYPE2		K_SADB_X_EXT_SATYPE2		
#define SADB_X_EXT_ADDRESS_DST2	        K_SADB_X_EXT_ADDRESS_DST2	
#define SADB_X_EXT_ADDRESS_SRC_FLOW	K_SADB_X_EXT_ADDRESS_SRC_FLOW	
#define SADB_X_EXT_ADDRESS_DST_FLOW	K_SADB_X_EXT_ADDRESS_DST_FLOW	
#define SADB_X_EXT_ADDRESS_SRC_MASK	K_SADB_X_EXT_ADDRESS_SRC_MASK	
#define SADB_X_EXT_ADDRESS_DST_MASK	K_SADB_X_EXT_ADDRESS_DST_MASK	
#define SADB_X_EXT_DEBUG		K_SADB_X_EXT_DEBUG		
#define SADB_X_EXT_PROTOCOL		K_SADB_X_EXT_PROTOCOL		
#define SADB_X_EXT_PLUMBIF		K_SADB_X_EXT_PLUMBIF		



/* K_SADB_X_DELFLOW required over and above K_SADB_X_SAFLAGS_CLEARFLOW */
#define K_SADB_X_EXT_ADDRESS_DELFLOW \
	( (1<<K_SADB_X_EXT_ADDRESS_SRC_FLOW) \
	| (1<<K_SADB_X_EXT_ADDRESS_DST_FLOW) \
	| (1<<K_SADB_X_EXT_ADDRESS_SRC_MASK) \
	| (1<<K_SADB_X_EXT_ADDRESS_DST_MASK))

#define SADB_SATYPE_UNSPEC    0
#define SADB_SATYPE_AH        2
#define SADB_SATYPE_ESP       3
#define SADB_SATYPE_RSVP      5
#define SADB_SATYPE_OSPFV2    6
#define SADB_SATYPE_RIPV2     7
#define SADB_SATYPE_MIP       8
#define SADB_X_SATYPE_IPIP    9
#ifdef KERNEL26_HAS_KAME_DUPLICATES
#define SADB_X_SATYPE_IPCOMP  9   /* ICK! */
#endif
#define SADB_X_SATYPE_COMP    10
#define SADB_X_SATYPE_INT     11
#define SADB_SATYPE_MAX       11

enum sadb_satype {
	K_SADB_SATYPE_UNSPEC=SADB_SATYPE_UNSPEC,
	K_SADB_SATYPE_AH=SADB_SATYPE_AH,
	K_SADB_SATYPE_ESP=SADB_SATYPE_ESP,
	K_SADB_SATYPE_RSVP=SADB_SATYPE_RSVP,
	K_SADB_SATYPE_OSPFV2=SADB_SATYPE_OSPFV2,
	K_SADB_SATYPE_RIPV2=SADB_SATYPE_RIPV2,
	K_SADB_SATYPE_MIP=SADB_SATYPE_MIP,
	K_SADB_X_SATYPE_IPIP=9,
	K_SADB_X_SATYPE_COMP=10,
	K_SADB_X_SATYPE_INT=11
};
#define K_SADB_SATYPE_MAX       11

enum sadb_sastate {
  K_SADB_SASTATE_LARVAL=0,
  K_SADB_SASTATE_MATURE=1,
  K_SADB_SASTATE_DYING=2,
  K_SADB_SASTATE_DEAD=3
};
#define K_SADB_SASTATE_MAX 3

#define SADB_SAFLAGS_PFS		1
#define SADB_X_SAFLAGS_REPLACEFLOW	2
#define SADB_X_SAFLAGS_CLEARFLOW	4
#define SADB_X_SAFLAGS_INFLOW		8

/* not obvious, but these are the same values as used in isakmp,
 * and in freeswan/ipsec_policy.h. If you need to add any, they
 * should be added as according to 
 *   http://www.iana.org/assignments/isakmp-registry
 * 
 * and if not, then please try to use a private-use value, and
 * consider asking IANA to assign a value.
 */
#define SADB_AALG_NONE                  0
#define SADB_AALG_MD5HMAC               2
#define SADB_AALG_SHA1HMAC              3
#define SADB_X_AALG_SHA2_256HMAC	5
#define SADB_X_AALG_SHA2_384HMAC	6
#define SADB_X_AALG_SHA2_512HMAC	7
#define SADB_X_AALG_RIPEMD160HMAC	8
#define SADB_X_AALG_NULL		251	/* kame */
#define SADB_AALG_MAX			251
enum sadb_aalg {
	K_SADB_AALG_NONE=          SADB_AALG_NONE,           	
	K_SADB_AALG_MD5HMAC=       SADB_AALG_MD5HMAC,        	
	K_SADB_AALG_SHA1HMAC=      SADB_AALG_SHA1HMAC,       	
	K_SADB_X_AALG_SHA2_256HMAC=SADB_X_AALG_SHA2_256HMAC,
	K_SADB_X_AALG_SHA2_384HMAC=SADB_X_AALG_SHA2_384HMAC,
	K_SADB_X_AALG_SHA2_512HMAC=SADB_X_AALG_SHA2_512HMAC,
	K_SADB_X_AALG_RIPEMD160HMAC=SADB_X_AALG_RIPEMD160HMAC,
};
#define K_SADB_AALG_MAX			251

#define SADB_EALG_NONE                  0
#define SADB_EALG_DESCBC                2
#define SADB_EALG_3DESCBC               3
#define SADB_X_EALG_CASTCBC		6
#define SADB_X_EALG_BLOWFISHCBC		7
#define SADB_EALG_NULL			11
#define SADB_X_EALG_AESCBC		12
#define SADB_EALG_MAX			255

enum sadb_ealg {
	K_SADB_EALG_NONE=SADB_EALG_NONE,		 
	K_SADB_EALG_DESCBC=SADB_EALG_DESCBC,	 
	K_SADB_EALG_3DESCBC=SADB_EALG_3DESCBC,	 
	K_SADB_X_EALG_CASTCBC=SADB_X_EALG_CASTCBC,	 
	K_SADB_X_EALG_BLOWFISHCBC=SADB_X_EALG_BLOWFISHCBC, 
	K_SADB_EALG_NULL=SADB_EALG_NULL,		 
	K_SADB_X_EALG_AESCBC=SADB_X_EALG_AESCBC    
};

#define K_SADB_EALG_MAX			255

#define SADB_X_CALG_NONE          0
#define SADB_X_CALG_OUI           1
#define SADB_X_CALG_DEFLATE       2
#define SADB_X_CALG_LZS           3
#define SADB_X_CALG_LZJH          4
#define SADB_X_CALG_MAX           4

enum sadb_talg {
	K_SADB_X_TALG_NONE=0,
	K_SADB_X_TALG_IPv4_in_IPv4=1,
	K_SADB_X_TALG_IPv6_in_IPv4=2,
	K_SADB_X_TALG_IPv4_in_IPv6=3,
	K_SADB_X_TALG_IPv6_in_IPv6=4,
};
#define SADB_X_TALG_MAX         4


#define SADB_IDENTTYPE_RESERVED   0
#define SADB_IDENTTYPE_PREFIX     1
#define SADB_IDENTTYPE_FQDN       2
#define SADB_IDENTTYPE_USERFQDN   3
#define SADB_X_IDENTTYPE_CONNECTION 4
#define SADB_IDENTTYPE_MAX        4

#define SADB_KEY_FLAGS_MAX     0
#endif /* __PFKEY_V2_H */

