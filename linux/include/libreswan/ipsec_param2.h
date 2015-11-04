/*
 * header file for Libreswan kernel compat
 * Copyright (C) 2009 Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 *
 */

#ifndef _IPSEC_PARAM2_H_
#define _IPSEC_PARAM2_H_

/* nicely, latest netdevice.h includes this define */
#ifndef HAVE_NETDEV_PRIV
#define netdev_priv(dev) ((dev)->priv)
#endif

#if defined(IP_SELECT_IDENT_NEW)
# if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0))
#  define KLIPS_IP_SELECT_IDENT(iph, skb) __ip_select_ident(iph, 1)
# else
#  define KLIPS_IP_SELECT_IDENT(iph, skb) __ip_select_ident(dev_net(skb->dev), iph, 1)
# endif
#else
# define KLIPS_IP_SELECT_IDENT(iph, skb) __ip_select_ident(iph, skb_dst(skb), 0)
#endif

#if !defined(HAVE_CURRENT_UID)
#define current_uid() (current->uid)
#endif

#endif /* _LIBRESWAN_PARAM2_H */

