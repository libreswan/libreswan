/* pluto_sd.c
 * Status notifications for systemd
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "constants.h"

#include "defs.h"		/* for so_serial_t */
#include "log.h"
#include "timer.h"
#include "pluto_sd.h"

static global_timer_cb sd_watchdog_event;

void pluto_sd_init(struct logger *logger)
{
	uint64_t sd_usecs;
	int ret = sd_watchdog_enabled(0, &sd_usecs);

	if (ret == 0) {
		llog(RC_LOG, logger, "systemd watchdog not enabled - not sending watchdog keepalives");
		return;
	}
	if (ret < 0) {
		llog(RC_LOG, logger, "systemd watchdog returned error %d - not sending watchdog keepalives", ret);
		return;
	}

	llog(RC_LOG, logger, "systemd watchdog for ipsec service configured with timeout of %"PRIu64" usecs", sd_usecs);
	uintmax_t sd_secs = sd_usecs / 2 / 1000000; /* suggestion from sd_watchdog_enabled(3) */
	llog(RC_LOG, logger, "watchdog: sending probes every %ju secs", sd_secs);
	/* tell systemd that we have finished starting up */
	pluto_sd(PLUTO_SD_START, SD_REPORT_NO_STATUS);
	/* start the keepalive events */
	enable_periodic_timer(EVENT_SD_WATCHDOG, sd_watchdog_event,
			      deltatime(sd_secs));
}

/*
 * Interface for sd_notify(3) calls.
 */
void pluto_sd(int action, int status)
{
	dbg("pluto_sd: executing action %s(%d), status %d",
	    enum_name(&sd_action_names, action), action, status);

	switch (action) {
	case PLUTO_SD_WATCHDOG:
		sd_notify(0, "WATCHDOG=1");
		break;
	case PLUTO_SD_RELOADING:
		sd_notify(0, "RELOADING=1");
		break;
	case PLUTO_SD_READY:
		sd_notify(0, "READY=1");
		break;
	case PLUTO_SD_STOPPING:
		sd_notifyf(0, "STOPPING=1\nSTATUS=PLUTO_EXIT=%d", status);
		break;
	case PLUTO_SD_START:
		sd_notifyf(0, "READY=1\nSTATUS=Startup completed.\nMAINPID=%lu",
			(unsigned long) getpid());
		break;
	case PLUTO_SD_EXIT:
		sd_notifyf(0, "STATUS=Exited.\nERRNO=%i", status);
		break;
	default:
		bad_case(action);
		break;
	}
}

void sd_watchdog_event(struct logger *unused_logger UNUSED)
{
	pluto_sd(PLUTO_SD_WATCHDOG, SD_REPORT_NO_STATUS);
}
