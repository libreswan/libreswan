/* pluto_sd.h
 * Status notifications for systemd
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2016 Paul Wouters <pwouters@redhat.com>
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

#ifdef USE_SYSTEMD_WATCHDOG

#include <systemd/sd-daemon.h>

#define SD_REPORT_NO_STATUS 0

extern void pluto_sd_init(void);
extern void pluto_sd(int action, int status);
extern void sd_watchdog_event(void);

#endif /* USE_SYSTEMD_WATCHDOG */

#endif /* _PLUTO_SD_H */
