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

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "ip_endpoint.h"
#include "ip_address.h"
#include "socketwrapper.h"
#include "libreswan/ipsec_tunnel.h"
#include "libreswan/passert.h"
#include "ipsecconf/interfaces.h"
#include "ipsecconf/exec.h"
#include "ipsecconf/starterlog.h"
#include "lswlog.h"	/* for pexpect() */

bool starter_iface_find(const char *iface, int af, ip_address *dst, ip_address *nh)
{
	/* XXX: danger REQ is recycled by ioctl() callss */
	struct ifreq req;

	if (iface == NULL)
		return false;	/* ??? can this ever happen? */

	int sock = safe_socket(af, SOCK_DGRAM, 0);
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
	if ((req.ifr_flags & IFF_POINTOPOINT) != 0x0 && nh != NULL &&
	    (ioctl(sock, SIOCGIFDSTADDR, &req) == 0)) {
		const ip_sockaddr *sa = (const ip_sockaddr *)&req.ifr_addr;
		passert(&sa->sa == &req.ifr_addr);
		if (sa->sa.sa_family == af) {
			/* XXX: sizeof right? */
			ip_endpoint nhe;
			happy(sockaddr_to_endpoint(sa, sizeof(*sa), &nhe));
			pexpect(endpoint_port(&nhe) == 0);
			*nh = endpoint_address(&nhe);
		}
	}

	/* get DST */
	if (dst != NULL && ioctl(sock, SIOCGIFADDR, &req) == 0) {
		const ip_sockaddr *sa = (const ip_sockaddr *)&req.ifr_addr;
		passert(&sa->sa == &req.ifr_addr);
		if (sa->sa.sa_family == af) {
			/* XXX: sizeof right? */
			ip_endpoint dste;
			happy(sockaddr_to_endpoint(sa, sizeof(*sa), &dste));
			pexpect(endpoint_port(&dste) == 0);
			*dst = endpoint_address(&dste);
		}
	}

	close(sock);
	return true;
}

