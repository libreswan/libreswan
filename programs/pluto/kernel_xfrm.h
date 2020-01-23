/* declarations of routines that interface with the kernel's pfkey mechanism
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003  Herbert Xu
 * Copyright (C) 2014 Paul Wouters <pwouters@redhat.com>
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

#if defined(linux) && defined(NETKEY_SUPPORT)
extern const struct kernel_ops netkey_kernel_ops;
/*
 * The socket buffer is used to queue netlink messages between sender and
 * receiver. The size of these buffers specifies the maximum size you will be
 * able to write() to a netlink socket, i.e. it will indirectly define the
 * maximum message size. The default is 32KiB. For now we picked a somewhat
 * arbitrary maximum of 8192 for the data portion to accommodate large selinux
 * IPsec labels (see rhbz#1154784)
 */
#define MAX_NETLINK_DATA_SIZE 8192
#endif
