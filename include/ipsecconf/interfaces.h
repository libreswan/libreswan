/* Libreswan interfaces management (interfaces.h)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005 Michael Richardson <mcr@marajade.sandelman.ca>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#ifndef _STARTER_INTERFACES_H_
#define _STARTER_INTERFACES_H_

#include "ip_address.h"

bool starter_iface_find(const char *iface, int af, ip_address *dst, ip_address *nh);

#endif /* _STARTER_INTERFACES_H_ */

