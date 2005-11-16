/* decode incoming IKE echo request messages
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: ikeping.c,v 1.1 2005/04/21 02:14:30 mcr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>	/* only used for belt-and-suspenders select call */
#include <sys/poll.h>	/* only used for forensic poll call */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#if defined(IP_RECVERR) && defined(MSG_ERRQUEUE)
#  include <asm/types.h>	/* for __u8, __u32 */
#  include <linux/errqueue.h>
#  include <sys/uio.h>	/* struct iovec */
#endif

#include <openswan.h>

#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "log.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */

/*
 * receive and decode reply packet
 *
 */
void receive_ike_echo_request(struct msg_digest *md)
{
    char b1[ADDRTOT_BUF];

    addrtot(&md->sender, 0, b1, sizeof(b1));

    openswan_log("received ike-echo-request-%d packet from %s/%d\n",
		 md->hdr.isa_xchg, b1, md->sender_port);

#if 0
	op->isa_np    = NOTHING_WRONG;
	op->isa_version = (1 << ISA_MAJ_SHIFT) | 0;
	op->isa_xchg  = ISAKMP_XCHG_ECHOREPLY;
	op->isa_flags =0;
	op->isa_msgid =rand();
	op->isa_length=0;
#endif
}

void receive_ike_echo_reply(struct msg_digest *md)
{
    char b1[ADDRTOT_BUF];

    addrtot(&md->sender, 0, b1, sizeof(b1));

    openswan_log("received ike-echo-reply-%d packet from %s/%d\n",
		 md->hdr.isa_xchg, b1, md->sender_port);

#if 0
	op->isa_np    = NOTHING_WRONG;
	op->isa_version = (1 << ISA_MAJ_SHIFT) | 0;
	op->isa_xchg  = ISAKMP_XCHG_ECHOREPLY;
	op->isa_flags =0;
	op->isa_msgid =rand();
	op->isa_length=0;
#endif
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 *
 */
