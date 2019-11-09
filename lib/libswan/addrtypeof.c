/*
 * extract parts of an ip_address
 * Copyright (C) 2000  Henry Spencer.
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

#include <string.h>

#include "ip_address.h"
#include "ip_info.h"

/*
   - addrtypeof - get the type of an ip_address
 */
int addrtypeof(const ip_address *src)
{
	const struct ip_info *t = address_type(src);
	return t == NULL ? AF_UNSPEC : t->af;
}
