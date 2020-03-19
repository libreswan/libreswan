/* ip_protocol, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "ip_protocol.h"
#include "ietf_constants.h"
#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for strncaseeq() */

#include "libreswan/pfkeyv2.h"

#if 0
const struct ip_protocol ip_protocol_unspec = {
	.prefix = "unk",
	.description = "unknown",
	.name = "UNKNOWN",
};
#endif

const struct ip_protocol ip_protocol_icmp = {
	.description = "Internet Control Message",
	.prefix = "icmp",
	.name = "ICMP",
	.ipproto = IPPROTO_ICMP,
};

const struct ip_protocol ip_protocol_ipip = {
	.description = "IPv4 encapsulation",
	.prefix = "tun",
	.name = "IPIP",
	.ipproto = IPPROTO_IPIP,
};

const struct ip_protocol ip_protocol_tcp = {
	.description = "Transmission Control",
	.prefix = "tcp",
	.name = "TCP",
	.ipproto = IPPROTO_TCP,
};

const struct ip_protocol ip_protocol_udp = {
	.description = "User Datagram",
	.prefix = "udp",
	.name = "UDP",
	.ipproto = IPPROTO_UDP,
};

const struct ip_protocol ip_protocol_esp = {
	.description = "Encapsulated Security Payload",
	.prefix = "esp",
	.name = "ESP",
	.ipproto = IPPROTO_ESP,
	.ikev1 = PROTO_IPSEC_ESP,
};

const struct ip_protocol ip_protocol_ah = {
	.description = "Authentication Header",
	.prefix = "ah",
	.name = "AH",
	.ipproto = IPPROTO_AH,
	.ikev1 = PROTO_IPSEC_AH,
};

const struct ip_protocol ip_protocol_comp = {
	.description = "IP Payload Compression Protocol",
	.prefix = "comp",
	.name = "COMP",
#ifdef IPPROTO_IPCOMP
	.ipproto = IPPROTO_IPCOMP,
#endif
#ifdef IPPROTO_COMP
	.ipproto = IPPROTO_COMP,
#endif
	.ikev1 = PROTO_IPCOMP,
};

const struct ip_protocol ip_protocol_internal = {
	.description = "any host internal protocol",
	.prefix = "int",
	.name = "INT",
	.ipproto = 61,
};

static const struct ip_protocol *ip_protocols[] = {
	&ip_protocol_icmp,
	&ip_protocol_ipip,
	&ip_protocol_tcp,
	&ip_protocol_udp,
	&ip_protocol_esp,
	&ip_protocol_ah,
	&ip_protocol_comp,
	&ip_protocol_internal,
};

const struct ip_protocol *protocol_by_prefix(const char *prefix)
{
	for (unsigned u = 0; u < elemsof(ip_protocols); u++) {
		const struct ip_protocol *p = ip_protocols[u];
		if (strncaseeq(prefix, p->prefix, strlen(p->prefix))) {
			return p;
		}
	}
	return NULL;
}

const struct ip_protocol *protocol_by_ipproto(unsigned ipproto)
{
	for (unsigned u = 0; u < elemsof(ip_protocols); u++) {
		const struct ip_protocol *p = ip_protocols[u];
		if (p->ipproto == ipproto) {
			return p;
		}
	}
	return NULL;
}
