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

/*
 * XXX: linux can't include both headers.
 */
#ifdef linux
#  include <linux/udp.h>		/* for TCP_ENCAP_ESPINTCP and UDP_ENCAP_ESPINUDP */
#else
#  include <netinet/udp.h>		/* for UDP_ENCAP_ESPINUDP aka NAT */
#endif

#include "ip_protocol.h"
#include "ip_encap.h"

const struct ip_encap ip_encap_esp_in_tcp = {
	.name = "espintcp",
	.outer = &ip_protocol_tcp,
	.inner = &ip_protocol_esp,
#ifdef TCP_ENCAP_ESPINTCP
	.encap_type = TCP_ENCAP_ESPINTCP,
#endif
};

const struct ip_encap ip_encap_esp_in_udp = {
	.name = "espinudp",
	.outer = &ip_protocol_udp,
	.inner = &ip_protocol_esp,
#ifdef UDP_ENCAP_ESPINUDP
	.encap_type = UDP_ENCAP_ESPINUDP,
#endif
};
