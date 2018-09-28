/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2012 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013,2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2017 Andrew Cagney <cagney@gnu.org>
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
 *
 */

#include <pthread.h>    /* Must be the first include file */
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <sys/stat.h>

#include <libreswan.h>

#include "sysdep.h"
#include "connections.h"
#include "peerlog.h"
#include "log.h"	 /* for cur_connection*/

/* maximum number of files to keep open for per-peer log files */
#define MAX_PEERLOG_COUNT 16

/*
 * Since peerlog() can be called from a helper thread (for instance
 * when debug logging) while the main thread is updating these static
 * structures, lock all operations.
 */
static pthread_mutex_t peerlog_mutex = PTHREAD_MUTEX_INITIALIZER;

/* close one per-peer log */
static void unlocked_perpeer_logclose(struct connection *c);     /* forward */

bool log_to_perpeer = false;		/* should log go to per-IP file? */
char *peerlog_basedir = NULL;
static int perpeer_count = 0;

/* from sys/queue.h -> NOW private sysdep.h. */
static CIRCLEQ_HEAD(, connection) perpeer_list;

void peerlog_init(void)
{
	pthread_mutex_lock(&peerlog_mutex);
	CIRCLEQ_INIT(&perpeer_list);
	pthread_mutex_unlock(&peerlog_mutex);
}

static void unlocked_peerlog_close(void)
{
	/* exit if the circular queue has not been initialized */
	if (perpeer_list.cqh_first == NULL)
		return;

	/* end of circular queue is given by pointer to "HEAD" */
	while (perpeer_list.cqh_first != (void *)&perpeer_list)
		unlocked_perpeer_logclose(perpeer_list.cqh_first);
}

void peerlog_close(void)
{
	pthread_mutex_lock(&peerlog_mutex);
	unlocked_peerlog_close();
	pthread_mutex_unlock(&peerlog_mutex);
}

static void unlocked_perpeer_logclose(struct connection *c)
{
	/* only free/close things if we had used them! */
	if (c->log_file != NULL) {
		passert(perpeer_count > 0);

		CIRCLEQ_REMOVE(&perpeer_list, c, log_link);
		perpeer_count--;
		fclose(c->log_file);
		c->log_file = NULL;
	}
}

static void unlocked_perpeer_logfree(struct connection *c)
{
	unlocked_perpeer_logclose(c);
	if (c->log_file_name != NULL) {
		pfree(c->log_file_name);
		c->log_file_name = NULL;
		c->log_file_err = FALSE;
	}
}

void perpeer_logfree(struct connection *c)
{
	pthread_mutex_lock(&peerlog_mutex);
	unlocked_perpeer_logfree(c);
	pthread_mutex_unlock(&peerlog_mutex);
}

/* attempt to arrange a writeable parent directory for <path>
 * Result indicates success.  Failure will be logged.
 *
 * NOTE: this routine must not call our own logging facilities to report
 * an error since those routines are not re-entrant and such a call
 * would be recursive.
 */
static bool unlocked_ensure_writeable_parent_directory(char *path)
{
	/* NOTE: a / in the first char of a path is not like any other.
	 * That is why the strchr starts at path + 1.
	 */
	char *e = strrchr(path + 1, '/'); /* end of directory prefix */
	bool happy = TRUE;

	if (e != NULL) {
		/* path has an explicit directory prefix: deal with it */

		/* Treat a run of slashes as one.
		 * Remember that a / in the first char is different.
		 */
		while (e > path + 1 && e[-1] == '/')
			e--;

		*e = '\0'; /* carve off dirname part of path */

		if (access(path, W_OK) == 0) {
			/* mission accomplished, with no work */
		} else if (errno != ENOENT) {
			/* cannot write to this directory for some reason
			 * other than a missing directory
			 */
			syslog(LOG_CRIT, "cannot write to %s: %s", path, strerror(
				       errno));
			happy = FALSE;
		} else {
			/* missing directory: try to create one */
			happy = unlocked_ensure_writeable_parent_directory(path);
			if (happy) {
				if (mkdir(path, 0750) != 0) {
					syslog(LOG_CRIT,
					       "cannot create dir %s: %s",
					       path, strerror(errno));
					happy = FALSE;
				}
			}
		}

		*e = '/'; /* restore path to original form */
	}
	return happy;
}

/* open the per-peer log
 *
 * NOTE: this routine must not call our own logging facilities to report
 * an error since those routines are not re-entrant and such a call
 * would be recursive.
 */
static void unlocked_open_peerlog(struct connection *c)
{
	/* syslog(LOG_INFO, "opening log file for conn %s", c->name); */

	if (c->log_file_name == NULL) {
		char peername[ADDRTOT_BUF], dname[ADDRTOT_BUF];
		size_t peernamelen = addrtot(&c->spd.that.host_addr, 'Q', peername,
			sizeof(peername)) - 1;
		int lf_len;


		/* copy IP address, turning : and . into / */
		{
			char ch, *p, *q;

			p = peername;
			q = dname;
			do {
				ch = *p++;
				if (ch == '.' || ch == ':')
					ch = '/';
				*q++ = ch;
			} while (ch != '\0');
		}

		lf_len = peernamelen * 2 +
			 strlen(peerlog_basedir) +
			 sizeof("//.log") +
			 1;
		c->log_file_name =
			alloc_bytes(lf_len, "per-peer log file name");

		snprintf(c->log_file_name, lf_len, "%s/%s/%s.log",
			 peerlog_basedir, dname, peername);

		/* syslog(LOG_DEBUG, "conn %s logfile is %s", c->name, c->log_file_name); */
	}

	/* now open the file, creating directories if necessary */

	c->log_file_err = !unlocked_ensure_writeable_parent_directory(c->log_file_name);
	if (c->log_file_err)
		return;

	c->log_file = fopen(c->log_file_name, "w");
	if (c->log_file == NULL) {
		if (c->log_file_err) {
			syslog(LOG_CRIT, "logging system cannot open %s: %s",
			       c->log_file_name, strerror(errno));
			c->log_file_err = TRUE;
		}
		return;
	}

	/* look for a connection to close! */
	while (perpeer_count >= MAX_PEERLOG_COUNT) {
		/* cannot be NULL because perpeer_count > 0 */
		passert(perpeer_list.cqh_last != (void *)&perpeer_list);

		unlocked_perpeer_logclose(perpeer_list.cqh_last);
	}

	/* insert this into the list */
	CIRCLEQ_INSERT_HEAD(&perpeer_list, c, log_link);
	passert(c->log_file != NULL);
	perpeer_count++;
}

/* log a line to cur_connection's log */
static void unlocked_peerlog(struct connection *cur_connection,
			     const char *m)
{
	if (cur_connection == NULL) {
		/* we cannot log it in this case. Oh well. */
		return;
	}

	if (cur_connection->log_file == NULL)
		unlocked_open_peerlog(cur_connection);

	/* despite our attempts above, we may not be able to open the file. */
	if (cur_connection->log_file != NULL) {
		char datebuf[32];

		struct realtm now = local_realtime(realnow());
		strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %T", &now.tm);
		fprintf(cur_connection->log_file, "%s %s\n",
			datebuf, m);

		/* now move it to the front of the list */
		CIRCLEQ_REMOVE(&perpeer_list, cur_connection, log_link);
		CIRCLEQ_INSERT_HEAD(&perpeer_list, cur_connection, log_link);
	}
}

/* log a line to cur_connection's log */
void peerlog(struct connection *cur_connection, const char *m)
{
	pthread_mutex_lock(&peerlog_mutex);
	unlocked_peerlog(cur_connection, m);
	pthread_mutex_unlock(&peerlog_mutex);
}
