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

#include <netinet/in.h>		/* for IPPROTO_* */

#include "lswcdefs.h"		/* for elemsof() */
#include "constants.h"		/* for strncaseeq() */
#include "enum_names.h"

#include "ip_protocol.h"
#include "ip_encap.h"

const struct ip_protocol ip_protocol_unset = {
	.prefix = "unk",
	.description = "unknown",
	.name = "UNKNOWN",
	.ipproto = 0,
};

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
	.encap_esp = &ip_encap_esp_in_tcp,
};

const struct ip_protocol ip_protocol_udp = {
	.description = "User Datagram",
	.prefix = "udp",
	.name = "UDP",
	.ipproto = IPPROTO_UDP,
	.encap_esp = &ip_encap_esp_in_udp,
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
#define INTERNAL 61
	.ipproto = INTERNAL,
};

const struct ip_protocol *protocol_by_prefix(const char *prefix)
{
	static const struct ip_protocol *ip_protocols[] = {
		&ip_protocol_unset,
		&ip_protocol_icmp,
		&ip_protocol_ipip,
		&ip_protocol_tcp,
		&ip_protocol_udp,
		&ip_protocol_esp,
		&ip_protocol_ah,
		&ip_protocol_comp,
		&ip_protocol_internal,
	};
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
	/* perhaps a little sparse */
	static const struct ip_protocol *ip_protocols[] = {
		[0] = &ip_protocol_unset,
		[IPPROTO_ICMP] = &ip_protocol_icmp,
		[IPPROTO_IPIP] = &ip_protocol_ipip,
		[IPPROTO_TCP] = &ip_protocol_tcp,
		[IPPROTO_UDP] = &ip_protocol_udp,
		[IPPROTO_ESP] = &ip_protocol_esp,
		[IPPROTO_AH] = &ip_protocol_ah,
#ifdef IPPROTO_IPCOMP
		[IPPROTO_IPCOMP] = &ip_protocol_comp,

#endif
#ifdef IPPROTO_COMP
		[IPPROTO_COMP] = &ip_protocol_comp,
#endif
		[INTERNAL] = &ip_protocol_internal,
	};
	if (ipproto < elemsof(ip_protocols)) {
		return ip_protocols[ipproto];
	} else {
		return NULL;
	}
}

static const char *const ip_protocol_id_name[] = {
	[0] = "ALL",
#define A(P) [IPPROTO_##P] = #P
	A(UDP),
	A(TCP),
	A(ICMP),
#undef A
};

enum_names ip_protocol_id_names = {
	0, elemsof(ip_protocol_id_name) - 1,
	ARRAY_REF(ip_protocol_id_name),
	NULL, /* prefix */
	NULL, /* next */
};
