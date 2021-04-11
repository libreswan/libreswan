/* event-loop fork, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002, 2013,2016 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 Wolfgang Nothdurft <wolfgang@linogate.de>
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 D. Hugh Redelmeier <hugh@mimosa.com>
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
 *
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "monotime.h"

#include "defs.h"		/* for so_serial_t */
#include "server_fork.h"
#include "hash_table.h"
#include "log.h"
#include "state_db.h"
#include "state.h"		/* for unsuspend_md() */
#include "demux.h"		/* for release_any_md() */
#include "pluto_timing.h"
#include "show.h"

#define PID_MAGIC 0x000f000cUL

struct pid_entry {
	unsigned long magic;
	struct list_entry hash_entry;
	pid_t pid;
	void *context;
	server_fork_cb *callback;
	so_serial_t serialno;
	const char *name;
	monotime_t start_time;
	struct logger *logger;
};

static void jam_pid_entry(struct jambuf *buf, const void *data)
{
	if (data == NULL) {
		jam(buf, "NULL pid");
	} else {
		const struct pid_entry *entry = data;
		passert(entry->magic == PID_MAGIC);
		if (entry->serialno != SOS_NOBODY) {
			jam(buf, "#%lu ", entry->serialno);
		}
		jam(buf, "%s pid %d", entry->name, entry->pid);
	}
}

static hash_t pid_hasher(const pid_t *pid)
{
	return hash_table_hasher(shunk2(pid, sizeof(*pid)), zero_hash);
}

static hash_t pid_entry_hasher(const void *data)
{
	const struct pid_entry *entry = data;
	passert(entry->magic == PID_MAGIC);
	return pid_hasher(&entry->pid);
}

static struct list_entry *pid_entry_entry(void *data)
{
	struct pid_entry *entry = data;
	passert(entry->magic == PID_MAGIC);
	return &entry->hash_entry;
}

static struct list_head pid_entry_slots[23];

static struct hash_table pids_hash_table = {
	.info = {
		.name = "pid table",
		.jam = jam_pid_entry,
	},
	.hasher = pid_entry_hasher,
	.entry = pid_entry_entry,
	.nr_slots = elemsof(pid_entry_slots),
	.slots = pid_entry_slots,
};

void show_process_status(struct show *s)
{
	show_separator(s);
	/* XXX: don't sort for now */
	show_comment(s, "  PID  Process");
	for (unsigned i = 0; i < elemsof(pid_entry_slots); i++) {
		const struct list_head *h = &pid_entry_slots[i];
		const struct pid_entry *e;
		FOR_EACH_LIST_ENTRY_NEW2OLD(h, e) {
			/*
			 * XXX: Danger! The test script
			 * wait-until-pluto-started greps to see if
			 * the "addconn" line has disappeared.
			 */
			show_comment(s, "%5d  %s", e->pid, e->name);
		}
	}
}

static void add_pid(const char *name, so_serial_t serialno, pid_t pid,
		    server_fork_cb *callback, void *context, struct logger *logger)
{
	dbg("forked child %d", pid);
	struct pid_entry *new_pid = alloc_thing(struct pid_entry, "(ignore) fork pid");
	new_pid->magic = PID_MAGIC;
	new_pid->pid = pid;
	new_pid->callback = callback;
	new_pid->context = context;
	new_pid->serialno = serialno;
	new_pid->name = name;
	new_pid->start_time = mononow();
	new_pid->logger = clone_logger(logger, HERE);
	add_hash_table_entry(&pids_hash_table, new_pid);
}

static void free_pid_entry(struct pid_entry **p)
{
	free_logger(&(*p)->logger, HERE);
	pfree(*p);
	*p = NULL;
}

int server_fork(const char *name, so_serial_t serialno, server_fork_op *op,
		server_fork_cb *callback, void *context,
		struct logger *logger)
{
	pid_t pid = fork();
	switch (pid) {
	case -1:
		log_errno(logger, errno, "fork failed");
		return -1;
	case 0: /* child */
		exit(op(context, logger));
		break;
	default: /* parent */
		add_pid(name, serialno, pid, callback, context, logger);
		return pid;
	}
}

static void jam_status(struct jambuf *buf, int status)
{
	jam(buf, " (");
	if (WIFEXITED(status)) {
		jam(buf, "exited with status %u",
			WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		jam(buf, "terminated with signal %s (%d)",
			strsignal(WTERMSIG(status)),
			WTERMSIG(status));
	} else if (WIFSTOPPED(status)) {
		/* should not happen */
		jam(buf, "stopped with signal %s (%d) but WUNTRACED not specified",
			strsignal(WSTOPSIG(status)),
			WSTOPSIG(status));
	} else if (WIFCONTINUED(status)) {
		jam(buf, "continued");
	} else {
		jam(buf, "wait status %x not recognized!", status);
	}
#ifdef WCOREDUMP
	if (WCOREDUMP(status)) {
		jam_string(buf, ", core dumped");
	}
#endif
	jam_string(buf, ")");
}

void server_fork_sigchld_handler(struct logger *logger)
{
	while (true) {
		int status;
		errno = 0;
		pid_t child = waitpid(-1, &status, WNOHANG);
		switch (child) {
		case -1: /* error? */
			if (errno == ECHILD) {
				dbg("waitpid returned ECHILD (no child processes left)");
			} else {
				log_errno(logger, errno, "waitpid unexpectedly failed");
			}
			return;
		case 0: /* nothing to do */
			dbg("waitpid returned nothing left to do (all child processes are busy)");
			return;
		default:
			LSWDBGP(DBG_BASE, buf) {
				jam(buf, "waitpid returned pid %d",
					child);
				jam_status(buf, status);
			}
			struct pid_entry *pid_entry = NULL;
			hash_t hash = pid_hasher(&child);
			struct list_head *bucket = hash_table_bucket(&pids_hash_table, hash);
			FOR_EACH_LIST_ENTRY_OLD2NEW(bucket, pid_entry) {
				passert(pid_entry->magic == PID_MAGIC);
				if (pid_entry->pid == child) {
					break;
				}
			}
			if (pid_entry == NULL) {
				LLOG_JAMBUF(RC_LOG, logger, buf) {
					jam(buf, "waitpid return unknown child pid %d",
						child);
					jam_status(buf, status);
				}
				continue;
			}
			/* log against pid_entry->logger; must cleanup */
			struct state *st = state_by_serialno(pid_entry->serialno);
			if (pid_entry->serialno == SOS_NOBODY) {
				pid_entry->callback(NULL, NULL, status,
						    pid_entry->context,
						    pid_entry->logger);
			} else if (st == NULL) {
				LSWDBGP(DBG_BASE, buf) {
					jam_pid_entry(buf, pid_entry);
					jam_string(buf, " disappeared");
				}
				pid_entry->callback(NULL, NULL, status,
						    pid_entry->context,
						    pid_entry->logger);
			} else {
				struct msg_digest *md = unsuspend_md(st);
				if (DBGP(DBG_CPU_USAGE)) {
					deltatime_t took = monotimediff(mononow(), pid_entry->start_time);
					deltatime_buf dtb;
					DBG_log("#%lu waited %s for '%s' fork()",
						st->st_serialno, str_deltatime(took, &dtb),
						pid_entry->name);
				}
				statetime_t start = statetime_start(st);
				pid_entry->callback(st, md, status,
						    pid_entry->context,
						    pid_entry->logger);
				statetime_stop(&start, "callback for %s",
					       pid_entry->name);
				release_any_md(&md);
			}
			/* clean it up */
			del_hash_table_entry(&pids_hash_table, pid_entry);
			free_pid_entry(&pid_entry);
			continue;
		}
	}
}

/*
 * fork()+exec().
 */

void server_fork_exec(const char *what, const char *path,
		      char *argv[], char *envp[],
		      server_fork_cb *callback, void *callback_context,
		      struct logger *logger)
{
#if USE_VFORK
	int pid = vfork(); /* for better, for worse, in sickness and health..... */
#elif USE_FORK
	int pid = fork();
#else
#error "server_fork_exec() requires USE_VFORK or USE_FORK"
#endif
	switch (pid) {
	case -1: /* oops */
		log_errno(logger, errno, "fork failed");
		break;
	case 0: /* child */
		execve(path, argv, envp);
		/* really can't printf() */
		_exit(42);
	default: /* parent */
		dbg("created %s helper (pid:%d) using %s+execve",
		    what, pid, USE_VFORK ? "vfork" : "fork");
		add_pid(what, SOS_NOBODY, pid, callback, callback_context, logger);
	}
}

void init_server_fork(void)
{
	init_hash_table(&pids_hash_table);
}
