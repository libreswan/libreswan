/* IPsec DOI and Oakley resolution routines
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright 2005 Michael C. Richardson <mcr@xelerance.com>
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

#include "fd.h"

struct child_sa *quick_outI1(struct ike_sa *isakmp,
			     struct connection *c,
			     const struct child_policy *policy,
			     so_serial_t replacing);
