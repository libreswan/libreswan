/* Libreswan interfaces management (interfaces.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "lsw_socket.h"

#include "constants.h"
#include "ip_endpoint.h"
#include "ip_address.h"
#include "passert.h"
#include "ipsecconf/interfaces.h"
#include "lswlog.h"	/* for pexpect() */
#include "ip_info.h"
#include "ip_protocol.h"
#include "ip_sockaddr.h"

bool starter_iface_find(const char *iface, const struct ip_info *family,
			ip_address *dst, ip_address *nh)
{
	/* XXX: danger REQ is recycled by ioctl() calls */
	struct ifreq req;

	if (iface == NULL)
		return false;	/* ??? can this ever happen? */

	int sock = cloexec_socket(family->af, SOCK_DGRAM, 0);
	if (sock < 0)
		return false;

	fill_and_terminate(req.ifr_name, iface, IFNAMSIZ);

	/* UP? */
	if (ioctl(sock, SIOCGIFFLAGS, &req) != 0 ||
	    (req.ifr_flags & IFF_UP) == 0x0) {
		close(sock);
		return false;
	}

	/*
	 * convert the sockaddr to an endpoint (ADDRESS:PORT, but
	 * expect PORT==0)) and then extract just the address
	 */

	/* get NH */
	if (nh != NULL &&
	    (req.ifr_flags & IFF_POINTOPOINT) != 0x0 &&
	    (ioctl(sock, SIOCGIFDSTADDR, &req) == 0)) {
		if (req.ifr_addr.sa_family == family->af) {
			ip_address nh_address;
			ip_port nh_port;
			happy(sockaddr_to_address_port(&req.ifr_addr, family->sockaddr_size,
						       &nh_address, &nh_port));
			pexpect(hport(nh_port) == 0);
			*nh = nh_address;
		}
	}

	/* get DST */
	if (dst != NULL &&
	    ioctl(sock, SIOCGIFADDR, &req) == 0) {
		if (req.ifr_addr.sa_family == family->af) {
			ip_address dst_address;
			ip_port dst_port;
			happy(sockaddr_to_address_port(&req.ifr_addr, family->sockaddr_size,
						       &dst_address, &dst_port));
			pexpect(hport(dst_port) == 0);
			*dst = dst_address;
		}
	}

	close(sock);
	return true;
}

