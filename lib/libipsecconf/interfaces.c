/* FreeS/WAN interfaces management (interfaces.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
# define MIN(a, b) ( ((a) > (b)) ? (b) : (a) )
#endif

char *starter_find_physical_iface(int sock, char *iface)
{
	static char ifs[IFNAMSIZ + 1];
	struct ifreq req;

	strncpy(req.ifr_name, iface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req) == 0) {
		if (req.ifr_flags & IFF_UP) {
			memcpy(ifs, iface, IFNAMSIZ);
			ifs[IFNAMSIZ] = '\0';	/* ensure NUL termination */
			return ifs;
		}
	}
	return NULL;
}

int starter_iface_find(char *iface, int af, ip_address *dst, ip_address *nh)
{
	char *phys;
	struct ifreq req;
	struct sockaddr_in *sa = (struct sockaddr_in *)(&req.ifr_addr);
	int sock;

	if (!iface)
		return -1;

	sock = safe_socket(af, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	phys = starter_find_physical_iface(sock, iface);
	if (!phys)
		goto failed;

	strncpy(req.ifr_name, phys, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req) != 0)
		goto failed;
	if (!(req.ifr_flags & IFF_UP))
		goto failed;

	if ((req.ifr_flags & IFF_POINTOPOINT) && (nh) &&
	    (ioctl(sock, SIOCGIFDSTADDR, &req) == 0)) {
		if (sa->sin_family == af) {
			initaddr((const void *)&sa->sin_addr,
				 sizeof(struct in_addr), af, nh);
		}
	}
	if ((dst) && (ioctl(sock, SIOCGIFADDR, &req) == 0)) {
		if (sa->sin_family == af) {
			initaddr((const void *)&sa->sin_addr,
				 sizeof(struct in_addr), af, dst);
		}
	}
	close(sock);
	return 0;

failed:
	close(sock);
	return -1;
}

