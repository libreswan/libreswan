/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 *  Helper functions to get/set addresses of UDP packets
 *  based on recvfromto by Miquel van Smoorenburg
 * (Imported from freeradius by mcr@xelerance.com on 2005-01-23)
 *
 * recvfromto	Like recvfrom, but also stores the destination
 *		IP address. Useful on multihomed hosts.
 *
 *		Should work on Linux and BSD.
 *
 *		Copyright (C) 2002 Miquel van Smoorenburg.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU Lesser General Public
 *		License as published by the Free Software Foundation; either
 *		version 2 of the License, or (at your option) any later version.
 *
 * sendfromto	added 18/08/2003, Jan Berkel <jan@sitadelle.com>
 *		Works on Linux and FreeBSD (5.x)
 */
#include <sys/types.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "udpfromto.h"
#include "libreswan.h"
#include "lswlog.h"
#include "socketwrapper.h"

#include "sysdep.h"

int udpfromto_init(int s)
{
	int err = -1, opt = 1;

	errno = ENOSYS;
#ifdef HAVE_IP_PKTINFO
	/* Set the IP_PKTINFO option (Linux). */
	err = setsockopt(s, SOL_IP, IP_PKTINFO, &opt, sizeof(opt));
#endif

#ifdef HAVE_IP_RECVDSTADDR
	/*
	 * Set the IP_RECVDSTADDR option (BSD).
	 * Note: IP_RECVDSTADDR == IP_SENDSRCADDR
	 */
	err = setsockopt(s, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt));
#endif

#if !defined(HAVE_IP_PKTINFO) && !defined(HAVE_IP_RECVDSTADDR)
#error "Must have either HAVE_IP_PKTINFO or HAVE_IP_RECVDSTADDR"
#endif
	return err;
}

int recvfromto(int s, void *buf, size_t len, int flags,
	struct sockaddr *from, socklen_t *fromlen,
	struct sockaddr *to, socklen_t *tolen)
{
#if defined(HAVE_IP_PKTINFO) || defined(HAVE_IP_RECVDSTADDR)
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char cbuf[256];
	int err;

	/*
	 * If from or to are set, they must be big enough
	 * to store a struct sockaddr_in.
	 */
	if ((from && (!fromlen || *fromlen < sizeof(struct sockaddr_in))) ||
		(to && (!tolen || *tolen < sizeof(struct sockaddr_in)))) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * IP_PKTINFO / IP_RECVDSTADDR don't provide sin_port so we have to
	 * retrieve it using getsockname().
	 */
	if (to != NULL) {
		struct sockaddr_in si;
		socklen_t l = sizeof(si);

		((struct sockaddr_in *)to)->sin_family = AF_INET;
#ifdef NEED_SIN_LEN
		((struct sockaddr_in *)to)->sin_len =
			sizeof(struct sockaddr_in);
#endif	/* NEED_SIN_LEN */

		((struct sockaddr_in *)to)->sin_port = 0;
		l = sizeof(si);
		if (getsockname(s, (struct sockaddr *)&si, &l) == 0) {
			((struct sockaddr_in *)to)->sin_port = si.sin_port;
			((struct sockaddr_in *)to)->sin_addr = si.sin_addr;
		}
		if (tolen != NULL)
			*tolen = sizeof(struct sockaddr_in);
	}

	/* Set up iov and msgh structures. */
	zero(&msgh);
	iov.iov_base = buf;
	iov.iov_len = len;
	msgh.msg_control = cbuf;
	msgh.msg_controllen = sizeof(cbuf);
	msgh.msg_name = from;
	msgh.msg_namelen = fromlen ? *fromlen : 0;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	/* Receive one packet. */
	if ((err = recvmsg(s, &msgh, flags)) < 0)
		return err;

	if (fromlen != NULL)
		*fromlen = msgh.msg_namelen;

	/* Process auxiliary received data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&msgh);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
#ifdef HAVE_IP_PKTINFO
		if (cmsg->cmsg_level == SOL_IP &&
			cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *i =
				(struct in_pktinfo *)CMSG_DATA(cmsg);
			if (to != NULL) {
				((struct sockaddr_in *)to)->sin_addr =
					i->ipi_addr;
				if (tolen != NULL)
					*tolen = sizeof(struct sockaddr_in);
			}
			break;
		}
#endif	/* HAVE_IP_PKTINFO */

#ifdef HAVE_IP_RECVDSTADDR
		if (cmsg->cmsg_level == IPPROTO_IP &&
			cmsg->cmsg_type == IP_RECVDSTADDR) {
			struct in_addr *i = (struct in_addr *)CMSG_DATA(cmsg);
			if (to) {
				((struct sockaddr_in *)to)->sin_addr = *i;
				if (tolen)
					*tolen = sizeof(struct sockaddr_in);
			}
			break;
		}
#endif	/* HAVE_IP_RECVDSTADDR */
	}
	return err;

#else
	/* fallback: call recvfrom */
	return recvfrom(s, buf, len, flags, from, fromlen);

#endif	/* defined(HAVE_IP_PKTINFO) || defined(HAVE_IP_RECVDSTADDR) */
}
