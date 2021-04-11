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

#include <stdbool.h>

#include <netinet/in.h>		/* for IPPROTO_* */

#include "shunk.h"
#include "err.h"

struct jambuf;

/*
 * What's being encapsulated using DST IP packets.
 *
 * See:
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 *
 * Also see ip(7) and socket(IF_INET, SOCK_RAW, protocol).
 */

typedef struct ip_protocol {
	/*
	 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	 *
	 * IPPROTO_*
	 */
	unsigned ipproto;
	const char *description;
	const char *prefix;
	const char *name;
	bool ipv6_extension_header;
	const char *reference;
	/*
	 * IKEv1's Protocol ID
	 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.1
	 */
	unsigned ikev1_protocol_id;
	/*
	 * Using this to encapsulate.
	 */
	const struct ip_encap *encap_esp;
	/* is a port required? */
	bool endpoint_requires_non_zero_port;
} ip_protocol;

#ifdef IPPROTO_COMP
#define COMP_IPPROTO IPPROTO_COMP /*linux*/
#endif
#ifdef IPPROTO_IPCOMP
#define COMP_IPPROTO IPPROTO_IPCOMP
#endif
#define INTERNAL_IPPROTO 61

extern const struct ip_protocol ip_protocols[];

#define ip_protocol_unset ip_protocols[0]
#define ip_protocol_icmp ip_protocols[IPPROTO_ICMP]		/* Internet Control Message */
#define ip_protocol_ipip ip_protocols[IPPROTO_IPIP]		/* IPv4 encapsulation */
#define ip_protocol_tcp ip_protocols[IPPROTO_TCP]		/* any host internal protocol */
#define ip_protocol_udp ip_protocols[IPPROTO_UDP]		/* any host internal protocol */
#define ip_protocol_esp ip_protocols[IPPROTO_ESP]		/* Encapsulated Security Payload */
#define ip_protocol_ah ip_protocols[IPPROTO_AH]			/* Authentication Header */
#define ip_protocol_comp ip_protocols[COMP_IPPROTO]		/* IP Payload Compression Protocol */
#define ip_protocol_internal ip_protocols[INTERNAL_IPPROTO]	/* any host internal protocol */

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

const struct ip_protocol *protocol_by_prefix(const char *prefix);
const struct ip_protocol *protocol_by_ipproto(unsigned protoid);
const struct ip_protocol *protocol_by_shunk(shunk_t protocol);

err_t ttoipproto(const char *text, unsigned *ipproto);

/* ex: '=TCP=>' */
size_t jam_protocols(struct jambuf *buf, const ip_protocol *src, char sep,
		     const ip_protocol *dst);

#endif
