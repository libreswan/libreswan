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

/* SPDX-License-Identifier: MIT-0 */

/* Implement the systemd notify protocol without external dependencies.
 * Supports both readiness notification on startup and on reloading,
 * according to the protocol defined at:
 * https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
 * This protocol is guaranteed to be stable as per:
 * https://systemd.io/PORTABILITY_AND_STABILITY/ */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "constants.h"

#include "defs.h"		/* for so_serial_t */
#include "log.h"
#include "timer.h"
#include "pluto_sd.h"

#define _cleanup_(f) __attribute__((cleanup(f)))

static global_timer_cb sd_watchdog_event;

static void closep(int *fd) {
	if (!fd || *fd < 0)
		return;

	close(*fd);
	*fd = -1;
}

static int notify(const char *message) {
	union sockaddr_union {
		struct sockaddr sa;
		struct sockaddr_un sun;
	} socket_addr = {
		.sun.sun_family = AF_UNIX,
	};
	size_t path_length, message_length;
	_cleanup_(closep) int fd = -1;
	const char *socket_path;

	socket_path = getenv("NOTIFY_SOCKET");
	if (!socket_path)
		return 0; /* Not running under systemd? Nothing to do */

	if (!message)
		return -EINVAL;

	message_length = strlen(message);
	if (message_length == 0)
		return -EINVAL;

	/* Only AF_UNIX is supported, with path or abstract sockets */
	if (socket_path[0] != '/' && socket_path[0] != '@')
		return -EAFNOSUPPORT;

	path_length = strlen(socket_path);
	/* Ensure there is room for NUL byte */
	if (path_length >= sizeof(socket_addr.sun.sun_path))
		return -E2BIG;

	memcpy(socket_addr.sun.sun_path, socket_path, path_length);

	/* Support for abstract socket */
	if (socket_addr.sun.sun_path[0] == '@')
		socket_addr.sun.sun_path[0] = 0;

	fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, &socket_addr.sa, offsetof(struct sockaddr_un, sun_path) + path_length) != 0)
		return -errno;

	ssize_t written = write(fd, message, message_length);
	if (written != (ssize_t) message_length)
		return written < 0 ? -errno : -EPROTO;

	return 1; /* Notified! */
}

static int notifyf(const char *format, ...) {
	_cleanup_(free) char *p = NULL;
        int r;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0 || !p)
                        return -ENOMEM;
        }

        return notify(p);
}

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
		notify("WATCHDOG=1");
		break;
	case PLUTO_SD_RELOADING:
		notify("RELOADING=1");
		break;
	case PLUTO_SD_READY:
		notify("READY=1");
		break;
	case PLUTO_SD_STOPPING:
		notifyf("STOPPING=1\nSTATUS=PLUTO_EXIT=%d", status);
		break;
	case PLUTO_SD_START:
		notifyf("READY=1\nSTATUS=Startup completed.\nMAINPID=%lu",
			(unsigned long) getpid());
		break;
	case PLUTO_SD_EXIT:
		notifyf("STATUS=Exited.\nERRNO=%i", status);
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
