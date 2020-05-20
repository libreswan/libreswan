/* reqids, for libreswan
 *
 * Copyright (C) 2019 Andrew Cagney
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

#include "reqid.h"
#include "passert.h"

/*
 * generate a base reqid for automatic keying
 *
 * We are actually allocating a group of four contiguous
 * numbers: one is used for each SA in an SA bundle.
 *
 * - must not be in range 0 to IPSEC_MANUAL_REQID_MAX
 *
 * - is a multiple of 4 (we are actually allocating four requids: see
 *   requid_ah, reqid_esp, reqid_ipcomp)
 *
 * - does not duplicate any currently in use (its assumed that pluto
 *   will crash before the 24-bit integer - one million connections -
 *   rolls over).
 *
 * NOTE: comments seems to lie, we use same reqid for the
 *       ESP inbound and outbound.
 *
 * XXX: Could just as easily return:
 *
 *     IPSEC_MANUAL_REQID_ROOF + connection.nr * 4
 */

reqid_t gen_reqid(void)
{
	/* 0x3fff+1==16384 is the first reqid we will use when not specified manually */
	static reqid_t global_reqids = IPSEC_MANUAL_REQID_MAX+1;
	global_reqids += 4;
	passert(global_reqids != 0); /* 16 000 000 roll over */
	passert(global_reqids % 4 == 0); /* allocate 4 at a time */
	return global_reqids;
}

reqid_t reqid_ah(reqid_t r)
{
	return r;
}

reqid_t reqid_esp(reqid_t r)
{
	return r <= IPSEC_MANUAL_REQID_MAX ? r : (r + 1);
}

reqid_t reqid_ipcomp(reqid_t r)
{
	return r <= IPSEC_MANUAL_REQID_MAX ? r : (r + 2);
}
