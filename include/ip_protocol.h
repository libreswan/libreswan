/* ip-protocols, for libreswan
 *
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

#ifndef IP_PROTOCOL_H
#define IP_PROTOCOL_H

/*
 * What's being encapsulated using DST IP packets.
 *
 * See:
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 *
 * Also see ip(7) and socket(IF_INET, SOCK_RAW, protocol).
 */

typedef struct ip_protocol {
	const char *description;
	const char *prefix;
	const char *name;
	unsigned ikev1;
	/*
	 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	 *
	 * IPPROTO_*
	 */
	unsigned ipproto;
	/*
	 * Using this to encapsulate.
	 */
	const struct ip_encap *encap_esp;
} ip_protocol;

extern const struct ip_protocol ip_protocol_unset;
extern const struct ip_protocol ip_protocol_icmp;	/* Internet Control Message */
extern const struct ip_protocol ip_protocol_ipip;	/* IPv4 encapsulation */
extern const struct ip_protocol ip_protocol_tcp;	/* any host internal protocol */
extern const struct ip_protocol ip_protocol_udp;	/* any host internal protocol */
extern const struct ip_protocol ip_protocol_esp;	/* Encapsulated Security Payload */
extern const struct ip_protocol ip_protocol_ah;		/* Authentication Header */
extern const struct ip_protocol ip_protocol_comp;	/* IP Payload Compression Protocol */
extern const struct ip_protocol ip_protocol_internal;	/* any host internal protocol */

#if 0
enum eroute_type {
	ET_UNSPEC = 0,
	ET_AH    = SA_AH,       /* (51)  authentication */
	ET_ESP   = SA_ESP,      /* (50)  encryption/auth */
	ET_IPCOMP= SA_COMP,     /* (108) compression */
	ET_INT   = SA_INT,      /* (61)  internal type */
	ET_IPIP  = SA_IPIP,     /* (4)   turn on tunnel type */
};
#endif

const struct ip_protocol *protocol_by_prefix(const char  *prefix);
const struct ip_protocol *protocol_by_ipproto(unsigned protoid);

#endif
