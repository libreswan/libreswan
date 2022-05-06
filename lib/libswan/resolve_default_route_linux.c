/* linux route resolution, for libreswan
 *
 * Copyright (C) 2017 Antony Antony
 * Copyright (C) 2018 Paul Wouters
 * Copyright (C) 2022 Andrew Cagney
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

#include "addr_lookup.h"

bool resolve_default_route(struct starter_end *host,
			   struct starter_end *peer,
			   lset_t verbose_rc_flags,
			   struct logger *logger)
{
	switch (resolve_defaultroute_one(host, peer, verbose_rc_flags, logger)) {
	case RESOLVE_FAILURE:
		return false;
	case RESOLVE_SUCCESS:
		return true;
	case RESOLVE_PLEASE_CALL_AGAIN:
		break;
	}

	switch (resolve_defaultroute_one(host, peer, verbose_rc_flags, logger)) {
	case RESOLVE_FAILURE:
		return false;
	case RESOLVE_SUCCESS:
		return true;
	case RESOLVE_PLEASE_CALL_AGAIN:
		return false;
	}

	return false;
}
