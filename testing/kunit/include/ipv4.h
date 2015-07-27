/*

   Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

   This file is part of nfsim.

   nfsim is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   nfsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with nfsim; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __HAVE_IPV4_H
#define __HAVE_IPV4_H 1

#include <protocol.h>

/* ipv4 definitions */

/* ip.h */
#define IP_CE           0x8000          /* Flag: "Congestion"		*/
#define IP_DF           0x4000          /* Flag: "Don't Fragment"	*/
#define IP_MF           0x2000          /* Flag: "More Fragments"	*/
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part	*/

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TS  IPOPT_TIMESTAMP

#define IPTOS_TOS_MASK          0x1E
#define IPTOS_TOS(tos)          ((tos) & IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY          0x10
#define IPTOS_THROUGHPUT        0x08
#define IPTOS_RELIABILITY       0x04
#define IPTOS_MINCOST           0x02

#define IPTOS_PREC_MASK         0xE0
#define IPTOS_PREC(tos)         ((tos) & IPTOS_PREC_MASK)
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00

#define MAXTTL          255

enum {
	IPPROTO_IP = 0,         /* Dummy protocol for TCP		*/
	IPPROTO_ICMP = 1,       /* Internet Control Message Protocol	*/
	IPPROTO_IGMP = 2,       /* Internet Group Management Protocol	*/
	IPPROTO_IPIP = 4,       /* IPIP tunnels (older KA9Q tunnels use 94) */
	IPPROTO_TCP = 6,        /* Transmission Control Protocol	*/
	IPPROTO_EGP = 8,        /* Exterior Gateway Protocol		*/
	IPPROTO_PUP = 12,       /* PUP protocol				*/
	IPPROTO_UDP = 17,       /* User Datagram Protocol		*/
	IPPROTO_IDP = 22,       /* XNS IDP protocol			*/
	IPPROTO_RSVP = 46,      /* RSVP protocol			*/
	IPPROTO_GRE = 47,       /* Cisco GRE tunnels (rfc 1701,1702)	*/

	IPPROTO_IPV6   = 41,    /* IPv6-in-IPv4 tunnelling		*/

	IPPROTO_ESP = 50,       /* Encapsulation Security Payload protocol */
	IPPROTO_AH = 51,        /* Authentication Header protocol       */
	IPPROTO_PIM    = 103,   /* Protocol Independent Multicast	*/

	IPPROTO_COMP   = 108,   /* Compression Header protocol */
	IPPROTO_SCTP   = 132,   /* Stream Control Transport Protocol	*/

	IPPROTO_RAW    = 255,   /* Raw IP packets			*/
	IPPROTO_MAX
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 ihl : 4,
	     version : 4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8 version : 4,
	     ihl : 4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
	/*The options start here. */
};

struct ip_auth_hdr {
	__u8 nexthdr;
	__u8 hdrlen;            /* This one is measured in 32 bit units! */
	__u16 reserved;
	__u32 spi;
	__u32 seq_no;           /* Sequence number */
	__u8 auth_data[0];      /* Variable len but >=4. Mind the 64 bit alignment! */
};

struct ip_esp_hdr {
	__u32 spi;
	__u32 seq_no;           /* Sequence number */
	__u8 enc_data[0];       /* Variable len but >=8. Mind the 64 bit alignment! */
};

struct ip_comp_hdr {
	__u8 nexthdr;
	__u8 flags;
	__u16 cpi;
};

#define LOOPBACK(x)     (((x) & htonl(0xff000000)) == htonl(0x7f000000))
#define MULTICAST(x)    (((x) & htonl(0xf0000000)) == htonl(0xe0000000))
#define BADCLASS(x)     (((x) & htonl(0xf0000000)) == htonl(0xf0000000))
#define ZERONET(x)      (((x) & htonl(0xff000000)) == htonl(0x00000000))
#define LOCAL_MCAST(x)  (((x) & htonl(0xFFFFFF00)) == htonl(0xE0000000))

/* tcp.h */

#define TCPOPT_NOP              1       /* Padding */
#define TCPOPT_EOL              0       /* End of options */
#define TCPOPT_MSS              2       /* Segment size negotiating */
#define TCPOPT_WINDOW           3       /* Window scaling */
#define TCPOPT_SACK_PERM        4       /* SACK Permitted */
#define TCPOPT_SACK             5       /* SACK Block */
#define TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */

#define TCPOLEN_MSS            4
#define TCPOLEN_WINDOW         3
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10

/* But this is what stacks really send out. */
#define TCPOLEN_TSTAMP_ALIGNED          12
#define TCPOLEN_WSCALE_ALIGNED          4
#define TCPOLEN_SACKPERM_ALIGNED        4
#define TCPOLEN_SACK_BASE               2
#define TCPOLEN_SACK_BASE_ALIGNED       4
#define TCPOLEN_SACK_PERBLOCK           8

struct tcphdr {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 res1 : 4,
	      doff : 4,
	      fin : 1,
	      syn : 1,
	      rst : 1,
	      psh : 1,
	      ack : 1,
	      urg : 1,
	      ece : 1,
	      cwr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff : 4,
	      res1 : 4,
	      cwr : 1,
	      ece : 1,
	      urg : 1,
	      ack : 1,
	      psh : 1,
	      rst : 1,
	      syn : 1,
	      fin : 1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
};

union tcp_word_hdr {
	struct tcphdr hdr;
	__u32 words[5];
};

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3])
enum {
	TCP_FLAG_CWR = __constant_htonl(0x00800000),
	TCP_FLAG_ECE = __constant_htonl(0x00400000),
	TCP_FLAG_URG = __constant_htonl(0x00200000),
	TCP_FLAG_ACK = __constant_htonl(0x00100000),
	TCP_FLAG_PSH = __constant_htonl(0x00080000),
	TCP_FLAG_RST = __constant_htonl(0x00040000),
	TCP_FLAG_SYN = __constant_htonl(0x00020000),
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
};

struct tcp_sack_block {
	__u32 start_seq;
	__u32 end_seq;
};

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

static inline int before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1 - seq2) < 0;
}

static inline int after(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq2 - seq1) < 0;
}

/* udp */
struct udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
};

/* icmp */

#define ICMP_ECHOREPLY          0       /* Echo Reply			*/
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH      4       /* Source Quench		*/
#define ICMP_REDIRECT           5       /* Redirect (change route)	*/
#define ICMP_ECHO               8       /* Echo Request			*/
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded		*/
#define ICMP_PARAMETERPROB      12      /* Parameter Problem		*/
#define ICMP_TIMESTAMP          13      /* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply		*/
#define ICMP_INFO_REQUEST       15      /* Information Request		*/
#define ICMP_INFO_REPLY         16      /* Information Reply		*/
#define ICMP_ADDRESS            17      /* Address Mask Request		*/
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply		*/
#define NR_ICMP_TYPES           18

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH        0       /* Network Unreachable		*/
#define ICMP_HOST_UNREACH       1       /* Host Unreachable		*/
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH       3       /* Port Unreachable		*/
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED          5       /* Source Route failed		*/
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH         15      /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET          0       /* Redirect Net			*/
#define ICMP_REDIR_HOST         1       /* Redirect Host		*/
#define ICMP_REDIR_NETTOS       2       /* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL            0       /* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME       1       /* Fragment Reass time exceeded	*/

struct icmphdr {
	__u8 type;
	__u8 code;
	__u16 checksum;
	union {
		struct {
			__u16 id;
			__u16 sequence;
		} echo;
		__u32 gateway;
		struct {
			__u16 __unused;
			__u16 mtu;
		} frag;
	} un;
};

/* in_route.h */
/* IPv4 routing cache flags */

#define RTCF_DEAD       RTNH_F_DEAD
#define RTCF_ONLINK     RTNH_F_ONLINK

/* Obsolete flag. About to be deleted */
#define RTCF_NOPMTUDISC RTM_F_NOPMTUDISC

#define RTCF_NOTIFY     0x00010000
#define RTCF_DIRECTDST  0x00020000
#define RTCF_REDIRECTED 0x00040000
#define RTCF_TPROXY     0x00080000

#define RTCF_FAST       0x00200000
#define RTCF_MASQ       0x00400000
#define RTCF_SNAT       0x00800000
#define RTCF_DOREDIRECT 0x01000000
#define RTCF_DIRECTSRC  0x04000000
#define RTCF_DNAT       0x08000000
#define RTCF_BROADCAST  0x10000000
#define RTCF_MULTICAST  0x20000000
#define RTCF_REJECT     0x40000000
#define RTCF_LOCAL      0x80000000

#define RTCF_NAT        (RTCF_DNAT | RTCF_SNAT)

#define RT_TOS(tos)     ((tos) & IPTOS_TOS_MASK)

/* flow */
struct flowi {
	int oif;
	int iif;

	union {
		struct {
			__u32 daddr;
			__u32 saddr;
			__u32 fwmark;
			__u8 tos;
			__u8 scope;
		} ip4_u;

#if 0
		struct {
			struct in6_addr daddr;
			struct in6_addr saddr;
			__u32 flowlabel;
		} ip6_u;
#endif
		struct {
			__u16 daddr;
			__u16 saddr;
			__u32 fwmark;
			__u8 scope;
		} dn_u;
	} nl_u;
#define fld_dst         nl_u.dn_u.daddr
#define fld_src         nl_u.dn_u.saddr
#define fld_fwmark      nl_u.dn_u.fwmark
#define fld_scope       nl_u.dn_u.scope
#define fl6_dst         nl_u.ip6_u.daddr
#define fl6_src         nl_u.ip6_u.saddr
#define fl6_flowlabel   nl_u.ip6_u.flowlabel
#define fl4_dst         nl_u.ip4_u.daddr
#define fl4_src         nl_u.ip4_u.saddr
#define fl4_fwmark      nl_u.ip4_u.fwmark
#define fl4_tos         nl_u.ip4_u.tos
#define fl4_scope       nl_u.ip4_u.scope

	__u8 proto;
	__u8 flags;
	union {
		struct {
			__u16 sport;
			__u16 dport;
		} ports;

		struct {
			__u8 type;
			__u8 code;
		} icmpt;

		struct {
			__u16 sport;
			__u16 dport;
			__u8 objnum;
			__u8 objnamel;          /* Not 16 bits since max val is 16 */
			__u8 objname[16];       /* Not zero terminated */
		} dnports;

		__u32 spi;
	} uli_u;
#define fl_ip_sport     uli_u.ports.sport
#define fl_ip_dport     uli_u.ports.dport
#define fl_icmp_type    uli_u.icmpt.type
#define fl_icmp_code    uli_u.icmpt.code
#define fl_ipsec_spi    uli_u.spi
} __attribute__((__aligned__(BITS_PER_LONG / 8)));

#define FLOW_DIR_IN     0
#define FLOW_DIR_OUT    1
#define FLOW_DIR_FWD    2

/* rtable.h */
struct rtable {
	union {
		struct dst_entry dst;
		struct rtable           *rt_next;
	} u;

	unsigned rt_flags;
	unsigned rt_type;

	__u32 rt_dst;                   /* Path destination	*/
	__u32 rt_src;                   /* Path source		*/
	int rt_iif;

	/* Info on neighbour */
	__u32 rt_gateway;

	/* Cache lookup keys */
	struct flowi fl;

#ifdef CONFIG_IP_ROUTE_NAT
	__u32 rt_src_map;
	__u32 rt_dst_map;
#endif
};

void ip_select_ident(struct iphdr *iph, struct dst_entry *dst,
		     struct sock *sk);

/* fib */
enum {
	RTN_UNSPEC,
	RTN_UNICAST,            /* Gateway or direct route	*/
	RTN_LOCAL,              /* Accept locally		*/
	RTN_BROADCAST,          /* Accept locally as broadcast,
				   send as broadcast */
	RTN_ANYCAST,            /* Accept locally as broadcast,
				   but send as unicast */
	RTN_MULTICAST,          /* Multicast route		*/
	RTN_BLACKHOLE,          /* Drop				*/
	RTN_UNREACHABLE,        /* Destination is unreachable   */
	RTN_PROHIBIT,           /* Administratively prohibited	*/
	RTN_THROW,              /* Not in this table		*/
	RTN_NAT,                /* Translate this address	*/
	RTN_XRESOLVE,           /* Use external resolver	*/
};

unsigned inet_addr_type(u32 addr);

/**
 * entry in a routing table
 * TODO: gateway.
 */
struct ipv4_route {
	struct list_head entry;
	u32 network;
	u32 netmask;
	struct net_device       *interface;
	u32 gateway;
};

/* the routing table */
extern struct list_head routes;

/* routing cache - dst_entries for each skb */
extern struct rtable *rcache;

/* address data attached to a device */
struct in_ifaddr {
	struct in_ifaddr        *ifa_next;

	struct in_device        *ifa_dev;

	u32 ifa_local;
	u32 ifa_address;
	u32 ifa_mask;
	u32 ifa_broadcast;
};

/* ipv4-specific extension for an interface */
/* struct ipv4_if_ext { */
struct in_device {
	struct net_device       *dev;
	struct in_ifaddr        *ifa_list;

	/*
	   struct in_addr		addr;
	   unsigned char		netmask;
	   struct in_addr		broadcast;
	 */
};

static inline unsigned int netmask_bits(uint32_t netmask)
{
	int maskbits = 32;
	int bit = 0;

	while (!((netmask << (bit++)) & 0x80000000))
		maskbits--;
	return maskbits;
}

extern const char *inet_ntoa(struct in_addr);
extern int inet_aton(const char *cp, struct in_addr *inp);

static inline int inet_atou32(const char *cp, uint32_t *addr)
{
	return inet_aton(cp, (struct in_addr *)addr);
}

static inline const char *inet_u32toa(uint32_t addr)
{
	struct in_addr inaddr;

	inaddr.s_addr = addr;
	return inet_ntoa(inaddr);
}

int register_inetaddr_notifier(struct notifier_block *nb);
int unregister_inetaddr_notifier(struct notifier_block *nb);
int __call_inetaddr_notifier(unsigned long, struct in_ifaddr *ifa);

static inline int register_netdevice_notifier(struct notifier_block *nb)
{
	return 0;
}
#define unregister_netdevice_notifier(notifier)

u32 inet_select_addr(const struct net_device *dev, u32 dst, int scope);

int ip_route_me_harder(struct sk_buff **pskb);

int ip_route(struct sk_buff *skb);

int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff*));

enum ip_defrag_users {
	IP_DEFRAG_LOCAL_DELIVER,
	IP_DEFRAG_CALL_RA_CHAIN,
	IP_DEFRAG_CONNTRACK_IN,
	IP_DEFRAG_CONNTRACK_OUT,
	IP_DEFRAG_NAT_OUT,
	IP_DEFRAG_VS_IN,
	IP_DEFRAG_VS_OUT,
	IP_DEFRAG_VS_FWD
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 11)
struct sk_buff *ip_defrag(struct sk_buff *skb);
#else
struct sk_buff *ip_defrag(struct sk_buff *skb, u32 user);
#endif

void ipfrag_flush(void);

void icmp_send(struct sk_buff *skb_in, int type, int code, u32 info);

int ip_finish_output(struct sk_buff *skb);

void ip_send_check(struct iphdr *iph);

unsigned short ip_fast_csum(void * iph, unsigned int ihl);
/* unsigned short ip_fast_csum(unsigned char * iph, unsigned int ihl); */

unsigned int csum_fold(unsigned int sum);

unsigned int csum_partial(const void * buff, int len, unsigned int sum);
/* unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum); */

unsigned short csum_tcpudp_magic(unsigned long saddr,
				 unsigned long daddr,
				 unsigned short len,
				 unsigned short proto,
				 unsigned int sum);
u32 csum_tcpudp_nofold(unsigned long saddr,
		       unsigned long daddr,
		       unsigned short len,
		       unsigned short proto,
		       unsigned int sum);
uint16_t tcp_v4_check(struct tcphdr *th, int len,
		      unsigned long saddr, unsigned long daddr,
		      unsigned long base);

static inline int xrlim_allow(struct dst_entry *dst, int timeout)
{
	return 1;
}

/* routing */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 5, 0)
struct rt_key {
	__u32 src, dst;
	__u8 tos;
	__u32 oif;
};
int ip_route_output_key(struct rtable **rp, struct rt_key *key);

/* Deprecated: use ip_route_output_key directly */
static inline int ip_route_output(struct rtable **rp,
				  u32 daddr, u32 saddr, u32 tos, int oif)
{
	struct rt_key key = { dst:daddr, src:saddr, oif:oif, tos:tos };

	return ip_route_output_key(rp, &key);
}
#else
int ip_route_output_key(struct rtable **rp, struct flowi *flp);
#endif

int xfrm_lookup(struct dst_entry **dst_p, struct flowi *fl,
		struct sock *sk, int flags);

int ip_route_input(struct sk_buff *skb, u32 daddr, u32 saddr,
		   u8 tos, struct net_device *dev);

char *ipv4_describe_packet(struct sk_buff *skb);

void add_route_for_device(struct in_device *indev);

inline unsigned short ip_compute_csum(unsigned char * buff, int len);

#define IPT_DSCP_MASK   0xfc
#define IPT_DSCP_SHIFT  2
#define IPT_DSCP_MAX    0x3f

#endif /* __HAVE_IPV4_H */
