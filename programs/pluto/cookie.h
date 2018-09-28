/* cookie generation/verification routines.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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

#include <libreswan.h>

extern const u_char zero_cookie[COOKIE_SIZE];   /* guaranteed 0 */

extern void get_cookie(bool initiator, uint8_t cookie[COOKIE_SIZE],
		       const ip_address *addr);

#define is_zero_cookie(cookie) all_zero((cookie), COOKIE_SIZE)
