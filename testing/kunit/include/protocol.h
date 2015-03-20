/*

   Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

   This file is part of nfsim.

   nfsim is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   nfsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with nfsim; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * functions provided by a protocol module
 */

#ifndef __HAVE_PROTOCOL_H
#define __HAVE_PROTOCOL_H 1

#include <core.h>

/**
 * called when a packet arrives for the protocol to handle. If the packet is
 * from the local network stack, if_in will be null.
 */
int ip_rcv(struct sk_buff *skb);

int ip_rcv_local(struct sk_buff *skb);

#endif /* __HAVE_PROTOCOL_H */
