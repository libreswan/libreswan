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
 *
 * RCSID $Id: interfaces.c,v 1.5 2005/01/11 17:52:51 ken Exp $
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openswan.h>

#include "sysdep.h"
#include "openswan/ipsec_tunnel.h"

#include "ipsecconf/interfaces.h"
#include "ipsecconf/exec.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterlog.h"

#define MIN(a,b) ( ((a)>(b)) ? (b) : (a) )

char *starter_find_physical_iface(int sock, char *iface)
{
	static char _if[IFNAMSIZ+1];
	char *b;
	struct ifreq req;
	FILE *f;
	char line[256];

	strncpy(req.ifr_name, iface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
		if (req.ifr_flags & IFF_UP) {
			strncpy(_if, iface, IFNAMSIZ);
			return _if;
		}
	}
	else {
		/**
		 * If there is a file named /var/run/pluto/dynip/<iface>, look if we
		 * can get interface name from there (IP_PHYS)
		 */
		b = (char *)malloc(strlen(DYNIP_DIR)+strlen(iface)+10);
		if (b) {
			sprintf(b, "%s/%s", DYNIP_DIR, iface);
			f = fopen(b, "r");
			free(b);
			if (f) {
				memset(_if, 0, sizeof(_if));
				memset(line, 0, sizeof(line));
				while (fgets(line, sizeof(line)-1, f)!=0) {
					if ((strncmp(line,"IP_PHYS=\"", 9)==0) &&
						(line[strlen(line)-2]=='"') &&
						(line[strlen(line)-1]=='\n')) {
						strncpy(_if, line+9, MIN(strlen(line)-11,IFNAMSIZ));
						break;
					}
					else if ((strncmp(line,"IP_PHYS=", 8)==0) &&
						(line[8]!='"') &&
						(line[strlen(line)-1]=='\n')) {
						strncpy(_if, line+8, MIN(strlen(line)-9,IFNAMSIZ));
						break;
					}
				}
				fclose(f);
				if (*_if) {
					strncpy(req.ifr_name, _if, IFNAMSIZ);
					if (ioctl(sock, SIOCGIFFLAGS, &req)==0) {
						if (req.ifr_flags & IFF_UP) {
							return _if;
						}
					}
				}
			}
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

	if (!iface) return -1;

	sock = socket(af, SOCK_DGRAM, 0);
	if (sock < 0) return -1;

	phys = starter_find_physical_iface(sock, iface);
	if (!phys) goto failed;

	strncpy(req.ifr_name, phys, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFFLAGS, &req)!=0) goto failed;
	if (!(req.ifr_flags & IFF_UP)) goto failed;

	if ((req.ifr_flags & IFF_POINTOPOINT) && (nh) &&
		(ioctl(sock, SIOCGIFDSTADDR, &req)==0)) {
		if (sa->sin_family == af) {
			initaddr((const void *)&sa->sin_addr,
				sizeof(struct in_addr), af, nh);
		}
	}
	if ((dst) && (ioctl(sock, SIOCGIFADDR, &req)==0)) {
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

