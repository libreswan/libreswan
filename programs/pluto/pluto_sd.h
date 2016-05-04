/* pluto_sd.h
 * Status notifications for systemd
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
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

#ifndef _PLUTO_SD_H
#define _PLUTO_SD_H

#include <systemd/sd-daemon.h>

#define SD_WATCHDOG_INTERVAL 15

#define SD_REPORT_NO_STATUS 0

extern void sd_watchdog_event(void);
extern void pluto_sd_watchdog_start(void);
extern void pluto_sd_watchdog_exit(int status);

#endif /* _PLUTO_SD_H */
