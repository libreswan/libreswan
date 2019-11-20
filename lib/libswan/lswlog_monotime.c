/* log monotime, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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

#include <inttypes.h>

#include "constants.h"
#include "monotime.h"
#include "lswlog.h"

size_t lswlog_monotime(struct lswlog *buf, monotime_t m)
{
	/* convert it to time-since-epoch and log that */
	return lswlog_deltatime(buf, monotimediff(m, monotime_epoch));
}
