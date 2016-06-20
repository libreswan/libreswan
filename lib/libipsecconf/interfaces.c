/* FreeS/WAN interfaces management (interfaces.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include "socketwrapper.h"
#include "libreswan/ipsec_tunnel.h"

#include "ipsecconf/interfaces.h"
#include "ipsecconf/exec.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterlog.h"

#ifndef MIN
# define MIN(a, b) ( ((a) <= (b)) ? (a) : (b) )
#endif

bool starter_iface_find(const char *iface, int af, ip_address *dst, ip_address *nh)
{
	struct ifreq req;
	struct sockaddr_in *sa = (struct sockaddr_in *)(&req.ifr_addr);
	int sock;

	if (iface == NULL)
		return FALSE;	/* ??? can this ever happen? */

	sock = safe_socket(af, SOCK_DGRAM, 0);
	if (sock < 0)
		return FALSE;

	strncpy(req.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFFLAGS, &req) != 0 ||
	    (req.ifr_flags & IFF_UP) == 0x0) {
		close(sock);
		return FALSE;
	}

	if ((req.ifr_flags & IFF_POINTOPOINT) != 0x0 && nh != NULL &&
	    (ioctl(sock, SIOCGIFDSTADDR, &req) == 0)) {
		/* ??? what should happen for IPv6? */
		if (sa->sin_family == af) {
			initaddr((const void *)&sa->sin_addr,
				 sizeof(struct in_addr), af, nh);
		}
	}
	if (dst != NULL && ioctl(sock, SIOCGIFADDR, &req) == 0) {
		/* ??? what should happen for IPv6? */
		if (sa->sin_family == af) {
			initaddr((const void *)&sa->sin_addr,
				 sizeof(struct in_addr), af, dst);
		}
	}
	close(sock);
	return TRUE;
}

