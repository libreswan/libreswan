/*
 * declarations relevant to encapsulation-like operations
 * Copyright (C) 1996, 1997  John Ioannidis.
 * Copyright (C) 1998, 1999, 2000, 2001  Richard Guy Briggs.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef _IPSEC_ENCAP_H_

#define SENT_IP4        0x01    /* match OpenBSD for what it's worth */
#define SENT_IP6        0x02    /* match OpenBSD for what it's worth */

struct sockaddr_encap {
	__u8 sen_len;                   /* length */
	__u8 sen_family;                /* AF_ENCAP */
	__u16 sen_type;                 /* see SENT_* */
	union {
		struct                  /* SENT_IP4 */
		{
			struct in_addr Src;
			struct in_addr Dst;
			__u8 Proto;
			__u16 Sport;
			__u16 Dport;
		} Sip4;
		struct                  /* SENT_IP6 */
		{
			struct in6_addr Src;
			struct in6_addr Dst;
			__u8 Proto;
			__u16 Sport;
			__u16 Dport;
		} Sip6;
	} Sen;
} __attribute__((packed));

#define sen_ip_src      Sen.Sip4.Src
#define sen_ip_dst      Sen.Sip4.Dst
#define sen_proto       Sen.Sip4.Proto
#define sen_sport       Sen.Sip4.Sport
#define sen_dport       Sen.Sip4.Dport

#define sen_ip6_src     Sen.Sip6.Src
#define sen_ip6_dst     Sen.Sip6.Dst
#define sen_proto6      Sen.Sip6.Proto
#define sen_sport6      Sen.Sip6.Sport
#define sen_dport6      Sen.Sip6.Dport

#ifndef AF_ENCAP
#define AF_ENCAP 26
#endif /* AF_ENCAP */

#define _IPSEC_ENCAP_H_
#endif /* _IPSEC_ENCAP_H_ */
