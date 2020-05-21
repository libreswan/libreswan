/* IP encapsulation, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

/*
 * Should the the ESP/AH packet be encapsulated using some other
 * transport?  For UDP this is called NAT.  For TCP this is called
 * IKETCP.
 *
 * XXX: Confusingly mode (TUNNEL, TRANSPORT) is also (understandably)
 * refered to as encapsulation :-(
 */

#ifndef IP_ENCAP_H
#define IP_ENCAP_H

struct ip_encap {
	const char *name;
	const struct ip_protocol *outer;
	const struct ip_protocol *inner;
	/*
	 * Passed into the kernel to flag that this transform is
	 * encapsulated.
	 *
	 * TCP Encap of IKE and IPsec Packets
	 * https://tools.ietf.org/html/rfc8229
	 */
	unsigned encap_type;
};

extern const struct ip_encap ip_encap_esp_in_tcp;
extern const struct ip_encap ip_encap_esp_in_udp;

#define PRI_IP_ENCAP "%u(%s)"
#define pri_ip_encap(E) (E) == NULL ? 0 : (E)->encap_type, (E) == NULL ? "none" : (E)->name

#endif
