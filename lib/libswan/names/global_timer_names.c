/* global_timer names, for libreswan
 *
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 1998-2002,2015  D. Hugh Redelmeier.
 * Copyright (C) 2016-2026 Andrew Cagney
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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

#include "pluto_constants.h"
#include "enum_names.h"
#include "names.h"

/*
 * enum global_timers
 */

static const char *global_timer_name[] = {
#define S(E) [E - EVENT_REINIT_SECRET] = #E
	S(EVENT_REINIT_SECRET),
	S(EVENT_SHUNT_SCAN),
	S(EVENT_SD_WATCHDOG),
	S(EVENT_CHECK_CRLS),
	S(EVENT_FREE_ROOT_CERTS),
	S(EVENT_RESET_LOG_LIMITER),
#undef S
};

const struct enum_names global_timer_enum_names = {
	GLOBAL_TIMER_FLOOR, GLOBAL_TIMER_ROOF-1,
	ARRAY_PTR(global_timer_name),
	"EVENT_",
	NULL,
};

const struct names global_timer_names = {
	.enum_names = &global_timer_enum_names,
};
