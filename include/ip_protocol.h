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

struct ip_protocol {
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
	/*
	 * When showing a selector or packet, the zero port denotes
	 * any port (0-65535) and should be omitted from the output.
	 *
	 * When parsing an endpoint, zero aka wild ports, aren't
	 * allowed.
	 */
	bool zero_port_is_any;
};

#define PRI_IP_PROTOCOL "%s"
#define pri_ip_protocol(PROTOCOL) ((PROTOCOL) > 255 ? "PROTO>255" :	\
				   protocol_from_ipproto(PROTOCOL)->name)

#if 0
typedef const struct ip_protocol *ip_protocol; /* good idea? */
#endif

#ifdef IPPROTO_COMP
#define IPCOMP_IPPROTO IPPROTO_COMP /*linux*/
#endif
#ifdef IPPROTO_IPCOMP
#define IPCOMP_IPPROTO IPPROTO_IPCOMP /*everything else*/
#endif

extern const struct ip_protocol ip_protocols[256];

#define ip_protocol_all ip_protocols[0]				/* "the SA can carry all protocols" */
#define ip_protocol_icmp ip_protocols[IPPROTO_ICMP]		/* Internet Control Message */
#define ip_protocol_icmpv6 ip_protocols[IPPROTO_ICMPV6]		/* Internet Control Message */
#define ip_protocol_ipip ip_protocols[IPPROTO_IPIP]		/* IPv4 encapsulation */
#define ip_protocol_tcp ip_protocols[IPPROTO_TCP]		/* any host internal protocol */
#define ip_protocol_udp ip_protocols[IPPROTO_UDP]		/* any host internal protocol */
#define ip_protocol_esp ip_protocols[IPPROTO_ESP]		/* Encapsulated Security Payload */
#define ip_protocol_ah ip_protocols[IPPROTO_AH]			/* Authentication Header */
#define ip_protocol_ipcomp ip_protocols[IPCOMP_IPPROTO]		/* IP Payload Compression Protocol */

/* match then eat the start of prefix */
const struct ip_protocol *protocol_from_caseeat_prefix(shunk_t *prefix);

const struct ip_protocol *protocol_from_ipproto(unsigned protoid);
const struct ip_protocol *protocol_from_shunk(shunk_t protocol);

err_t ttoprotocol(shunk_t text, const struct ip_protocol **ipproto);

/* these are kind of pointless */

typedef struct {
	char buf[19];
} protocol_buf;

size_t jam_protocol(struct jambuf *, const struct ip_protocol *);
const char *str_protocol(const struct ip_protocol *);

/* ex: sep='=' gives '=TCP=>' */
size_t jam_protocol_pair(struct jambuf *buf,
			 const struct ip_protocol *src,
			 char sep,
			 const struct ip_protocol *dst);

/* used to size other buffers */

#endif
