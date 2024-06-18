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

#ifdef __linux__
#define _GNU_SOURCE		/* for pipe2() */
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "monotime.h"

#include "defs.h"		/* for so_serial_t */
#include "server_fork.h"
#include "hash_table.h"
#include "log.h"
#include "state.h"		/* for unsuspend_md() */
#include "demux.h"		/* for md_delref() */
#include "pluto_timing.h"
#include "show.h"
#include "connections.h"

#define PID_MAGIC 0x000f000cUL

struct pid_entry {
	unsigned long magic;
	struct {
		struct list_entry list;
		struct list_entry pid;
	} pid_entry_db_entries;
	pid_t pid;
	void *context;
	server_fork_cb *callback;
	so_serial_t serialno;
	struct msg_digest *md;
	const char *name;
	monotime_t start_time;
	int fd; /* valid when fdl != NULL */
	struct fd_read_listener *fdl; /* stdout+stderr; may be NULL */
	struct logger *logger;
};

static size_t jam_pid_entry(struct jambuf *buf, const struct pid_entry *entry)
{
	if (entry == NULL) {
		return jam(buf, "NULL pid");
	}

	size_t s = 0;
	passert(entry->magic == PID_MAGIC);
	if (entry->serialno != SOS_NOBODY) {
		s += jam(buf, "#%lu ", entry->serialno);
	}
	s += jam(buf, "%s pid %d", entry->name, entry->pid);
	return s;
}

static hash_t hash_pid_entry_pid(const pid_t *pid)
{
	return hash_thing(*pid, zero_hash);
}

HASH_TABLE(pid_entry, pid, .pid, 23);

static struct pid_entry *pid_entry_by_pid(const pid_t pid)
{
	hash_t hash = hash_pid_entry_pid(&pid);
	struct list_head *bucket = hash_table_bucket(&pid_entry_pid_hash_table, hash);
	struct pid_entry *pid_entry;
	FOR_EACH_LIST_ENTRY_OLD2NEW(pid_entry, bucket) {
		passert(pid_entry->magic == PID_MAGIC);
		if (thingeq(pid_entry->pid, pid)) {
			return pid_entry;
		}
	}
	return NULL;
}

static void pid_entry_db_init(struct logger *logger);
static void pid_entry_db_check(struct logger *logger);
static void pid_entry_db_init_pid_entry(struct pid_entry *);
static void pid_entry_db_add(struct pid_entry *);
static void pid_entry_db_del(struct pid_entry *);

HASH_DB(pid_entry, &pid_entry_pid_hash_table);

void show_process_status(struct show *s)
{
	show_separator(s);
	/* XXX: don't sort for now */
	show(s, "  PID  Process");
	const struct pid_entry *e;
	FOR_EACH_LIST_ENTRY_OLD2NEW(e, &pid_entry_db_list_head) {
		/*
		 * XXX: Danger! The test script
		 * wait-until-pluto-started greps to see if
		 * the "addconn" line has disappeared.
		 */
		show(s, "%5d  %s", e->pid, e->name);
	}
}

static struct pid_entry *add_pid(const char *name,
				 so_serial_t serialno,
				 struct msg_digest *md,
				 pid_t pid,
				 server_fork_cb *callback, void *context,
				 struct logger *logger)
{
	ldbg(logger, "forked child %s %d", name, pid);
	struct pid_entry *new_pid = alloc_thing(struct pid_entry, "(ignore) fork pid");
	dbg_alloc("pid", new_pid, HERE);
	new_pid->magic = PID_MAGIC;
	new_pid->pid = pid;
	new_pid->callback = callback;
	new_pid->context = context;
	new_pid->serialno = serialno;
	new_pid->name = name;
	new_pid->start_time = mononow();
	new_pid->logger = clone_logger(logger, HERE);
	new_pid->md = md_addref(md);
	pid_entry_db_init_pid_entry(new_pid);
	pid_entry_db_add(new_pid);
	return new_pid;
}

static void free_pid_entry(struct pid_entry **p)
{
	free_logger(&(*p)->logger, HERE);
	md_delref(&(*p)->md);
	dbg_free("pid", *p, HERE);
	pfree(*p);
	*p = NULL;
}

static bool dump_fd(struct pid_entry *pid_entry)
{
	if (pid_entry->fdl == NULL) {
		ldbg(pid_entry->logger, "%s: fd %d is closed",
		     pid_entry->name, pid_entry->fd);
		return false;
	}

	char buf[LOG_WIDTH/2];
	ssize_t len = read(pid_entry->fd, buf, sizeof(buf));
	if (len < 0) {
		llog_error(pid_entry->logger, errno, "%s: reading fd %d failed: ",
			   pid_entry->name, pid_entry->fd);
		return false;
	}

	if (len == 0) {
		ldbg(pid_entry->logger, "%s: reading fd %d returned EOF",
		     pid_entry->name, pid_entry->fd);
		detach_fd_read_listener(&pid_entry->fdl);
		close(pid_entry->fd);
		return false;
	}

	/*
	 * Split the output into lines and then send it to the log
	 * file only.
	 *
	 * Don't write it to whack/addconn as they will copy it to
	 * stdout causing it to end up back here!
	 */

	char sep;
	shunk_t output = shunk2(buf, len);
	while (true) {
		shunk_t line = shunk_token(&output, &sep, "\n");
		if (line.ptr == NULL) {
			break;
		}
		LLOG_JAMBUF(LOG_STREAM/*not-whack*/, pid_entry->logger, buf) {
			jam_string(buf, pid_entry->name);
			jam_string(buf, ": ");
			jam_sanitized_hunk(buf, line);
		}
	}

	return true; /* try again */
}

int server_fork(const char *name,
		so_serial_t serialno,
		struct msg_digest *md,
		server_fork_op *op,
		server_fork_cb *callback, void *context,
		struct logger *logger)
{
	pid_t pid = fork();
	switch (pid) {
	case -1:
		llog_error(logger, errno, "fork failed");
		return -1;
	case 0: /* child */
		exit(op(context, logger));
		break;
	default: /* parent */
		add_pid(name, serialno, md, pid, callback, context, logger);
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
				llog_error(logger, errno, "waitpid unexpectedly failed");
			}
			return;
		case 0: /* nothing to do */
			dbg("waitpid returned nothing left to do (all child processes are busy)");
			return;
		default:
			LDBGP_JAMBUF(DBG_BASE, logger, buf) {
				jam(buf, "waitpid returned pid %d",
					child);
				jam_status(buf, status);
			}
			struct pid_entry *pid_entry = pid_entry_by_pid(child);
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
				LDBGP_JAMBUF(DBG_BASE, logger, buf) {
					jam_pid_entry(buf, pid_entry);
					jam_string(buf, " disappeared");
				}
				pid_entry->callback(NULL, NULL, status,
						    pid_entry->context,
						    pid_entry->logger);
			} else {
				if (DBGP(DBG_CPU_USAGE)) {
					deltatime_t took = monotimediff(mononow(), pid_entry->start_time);
					deltatime_buf dtb;
					DBG_log("#%lu waited %s for '%s' fork()",
						st->st_serialno, str_deltatime(took, &dtb),
						pid_entry->name);
				}
				statetime_t start = statetime_start(st);
				const enum ike_version ike_version = st->st_ike_version;
				stf_status ret = pid_entry->callback(st, pid_entry->md, status,
								     pid_entry->context,
								     pid_entry->logger);
				if (ret == STF_SKIP_COMPLETE_STATE_TRANSITION) {
					/* MD.ST may have been freed! */
					dbg("resume %s for #%lu skipped complete_v%d_state_transition()",
					    pid_entry->name, pid_entry->serialno, ike_version);
				} else {
					complete_state_transition(st, pid_entry->md, ret);
				}
				statetime_stop(&start, "callback for %s",
					       pid_entry->name);
			}
			/* drain output using blocking read */
			if (pid_entry->fdl != NULL) {
				int flags = fcntl(pid_entry->fd, F_GETFL);
				fcntl(pid_entry->fd, F_SETFL, flags & ~O_NONBLOCK);
				while (dump_fd(pid_entry));
			}
			/* clean it up */
			pid_entry_db_del(pid_entry);
			free_pid_entry(&pid_entry);
			continue;
		}
	}
}

/*
 * fork()+exec().
 */

static void child_output_listener(int fd, void *arg, struct logger *logger)
{
	struct pid_entry *pid_entry = arg;
	PASSERT(logger, pid_entry->fdl != NULL);
	PASSERT(logger, pid_entry->fd == fd);
	dump_fd(pid_entry);
}

void server_fork_exec(const char *path,
		      char *argv[], char *envp[],
		      server_fork_cb *callback, void *callback_context,
		      struct logger *logger)
{
	const char *what = argv[0];
	/*
	 * Create a pipe so that child can feed us its output.  After
	 * the fork O_CLOEXEC will need to be stripped (which dup2()
	 * does automatically).
	 */
	int fds[2]; /*0=read,1=write*/
	if (pipe2(fds, O_CLOEXEC) < 0) {
		llog_error(logger, errno, "pipe2() failed");
		return;
	}

#if USE_VFORK
	int pid = vfork(); /* for better, for worse, in sickness and health..... */
#elif USE_FORK
	int pid = fork();
#else
#error "server_fork_exec() requires USE_VFORK or USE_FORK"
#endif
	if (pid < 0) {
		llog_error(logger, errno, "fork failed");
		return;
	}

	if (pid == 0) {
		/*
		 * child
		 *
		 * close input; dup2() the write end of the pipe
		 * stdout/stderr, the act of dup2()ing strips
		 * O_CLOEXEC.
		 */
		close(fds[0/*read-fd*/]);
		int write_fd = fds[1];
		PASSERT(logger, write_fd != STDOUT_FILENO);
		PASSERT(logger, write_fd != STDERR_FILENO);
		close(STDIN_FILENO);
		dup2(write_fd, STDOUT_FILENO);
		dup2(write_fd, STDERR_FILENO);
		close(write_fd);
		/* go */
		execve(path, argv, envp);
		/* really can't printf() */
		_exit(42);
	}

	/* parent */
	ldbg(logger, "created %s helper (pid:%d) using %s+execve",
	     what, pid, USE_VFORK ? "vfork" : "fork");
	close(fds[1/*write-fd*/]);
	struct pid_entry *entry = add_pid(what, SOS_NOBODY, /*md*/NULL,
					  pid, callback, callback_context, logger);
	/* save the FD */
	entry->fd = fds[0/*read-fd*/];
	/* enable nonblock */
	int flags = fcntl(entry->fd, F_GETFL);
	fcntl(entry->fd, F_SETFL, flags|O_NONBLOCK);
	/* listen */
	attach_fd_read_listener(&entry->fdl, entry->fd, "fork-exec",
				child_output_listener, entry);
}

void init_server_fork(struct logger *logger)
{
	pid_entry_db_init(logger);
}

void check_server_fork(struct logger *logger)
{
	pid_entry_db_check(logger);
}
