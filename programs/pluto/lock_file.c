/* Pluto main program
 *
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2016 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2016 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2016-2025 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include <errno.h>
#include <sys/stat.h>		/* for mkdir()!?! */
#include <fcntl.h>		/* for open() */
#include <unistd.h>		/* for unlink() */

#include "lock_file.h"
#include "lswalloc.h"
#include "config_setup.h"
#include "ipsecconf/keywords.h"		/* for KSF_RUNDIR; ulgh */

#include "defs.h"		/* for so_serial_t */
#include "log.h"
#include "server.h"		/* for delete_ctl_socket() */

static char *pluto_lock_filename;

int create_lock_file(const struct config_setup *oco, bool fork_desired, struct logger *logger)
{
	const char *rundir = config_setup_string(oco, KSF_RUNDIR);
	if (mkdir(rundir, 0755) != 0) {
		if (errno != EEXIST) {
			fatal_errno(PLUTO_EXIT_LOCK_FAIL, logger, errno,
				    "unable to create lock dir: \"%s\"", rundir);
		}
	}

	pluto_lock_filename = alloc_printf("%s/pluto.pid", rundir);

	unsigned attempt;
	for (attempt = 0; attempt < 2; attempt++) {
		int fd = open(pluto_lock_filename, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC,
			      S_IRUSR | S_IRGRP | S_IROTH);
		if (fd >= 0) {
			return fd;
		}
		if (errno != EEXIST) {
			fatal_errno(PLUTO_EXIT_LOCK_FAIL, logger, errno,
				    "unable to create lock file \"%s\"", pluto_lock_filename);
		}
		if (fork_desired) {
			fatal(PLUTO_EXIT_LOCK_FAIL, logger,
			      "lock file \"%s\" already exists", pluto_lock_filename);
		}
		/*
		 * if we did not fork, then we don't really need the pid to
		 * control, so wipe it
		 */
		if (unlink(pluto_lock_filename) == -1) {
			fatal_errno(PLUTO_EXIT_LOCK_FAIL, logger, errno,
				    "lock file \"%s\" already exists and could not be removed",
				    pluto_lock_filename);
		}
		/*
		 * lock file removed, try creating it
		 * again ...
		 */
	}
	fatal(PLUTO_EXIT_LOCK_FAIL, logger, "lock file \"%s\" could not be created after %u attempts",
	      pluto_lock_filename, attempt);
}

/*
 * fill_lock - Populate the lock file with pluto's PID
 *
 * @param lockfd File Descriptor for the lock file
 * @param pid PID (pid_t struct) to be put into the lock file
 * @return bool True if successful
 */
bool fill_and_close_lock_file(int *lockfdp, pid_t pid)
{
	int lockfd = (*lockfdp);
	(*lockfdp) = -1; /* no going back */

	char buf[30];	/* holds "<pid>\n" */
	int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
	bool ok = len > 0 && write(lockfd, buf, len) == len;

	close(lockfd);
	return ok;
}

/*
 * delete_lock - Delete the lock file
 */

void delete_lock_file(void)
{
	if (pluto_lock_filename != NULL) {
		delete_ctl_socket();
		unlink(pluto_lock_filename);	/* is noting failure useful? */
		pfreeany(pluto_lock_filename);
	}
}
