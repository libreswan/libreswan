/* pluto_sd.c
 * Status notifications for systemd
 * Copyright (c) 2013 Matt Rogers <mrogers@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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
#include "timer.h"
#include "pluto_sd.h"
#include "lswlog.h"

unsigned long sd_pid;

/*
 * Interface for sd_notify calls. The status for watchdog and start cases
 * can be passed NO_STATUS as it's only useful for exit at the moment.
 * man sd_notify(3)
 */

static void pluto_sd(int action, int status)
{
	DBG(DBG_CONTROL, DBG_log("pluto_sd: executing action %s(%d), status %d",
		enum_name(&sd_action_names, action), action, status));

	switch(action) {
	case PLUTO_SD_WATCHDOG:
		sd_notify(0, "WATCHDOG=1");
		break;
	case PLUTO_SD_START:
		sd_notifyf(0, "READY=1\nSTATUS=Startup completed.\nMAINPID=%lu",
			(unsigned long) getpid());
		break;
	case PLUTO_SD_EXIT:
		sd_notifyf(0, "STATUS=Exited.\nERRNO=%i", status);
		break;
	default:
		bad_case(action); /* we don't ever generate PLUTO_SD_ERROR ? */
		break;
	}
}

void pluto_sd_watchdog_start(void) 
{
	pluto_sd(PLUTO_SD_START, SD_REPORT_NO_STATUS);
}

void pluto_sd_watchdog_exit(int status)
{
	pluto_sd(PLUTO_SD_EXIT, status);
}

void sd_watchdog_event(void)
{
	pluto_sd(PLUTO_SD_WATCHDOG, SD_REPORT_NO_STATUS);
	event_schedule(EVENT_SD_WATCHDOG, SD_WATCHDOG_INTERVAL, NULL);
	return;
}
