/* reqid definitions, for libreswan
 *
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#ifndef REQID_H
#define REQID_H

/*
 * reqid definitions
 *
 * A reqid is a numerical identifier used to match IPsec SAs using
 * iptables with NETKEY/XFRM. This identifier is normally automatically
 * allocated.  It is exported to the _updown script as REQID. On Linux,
 * reqids are supported with IP Connection Tracking and NAT (iptables).
 * Automatically generated values use the range 16380 and higher.
 * Manually specified reqid values therefore must be between 1 and 16379.
 *
 * Automatically generated reqids are allocated in groups of four, one
 * for each potential SA and pseudo SA in an SA bundle.  Their number
 * will be above 16380.  The base number will be a multiple of four.
 *
 * Manually assigned reqids are all identical for a particular connection
 * and its instantiations.
 */

#include <stdint.h>		/* for uint32_t */

typedef uint32_t reqid_t;

#define IPSEC_MANUAL_REQID_MAX  0x3fff

#define reqid_ah(r)	(r)
#define reqid_esp(r)	((r) <= IPSEC_MANUAL_REQID_MAX ? (r) : (r) + 1)
#define reqid_ipcomp(r)	((r) <= IPSEC_MANUAL_REQID_MAX ? (r) : (r) + 2)

#endif
