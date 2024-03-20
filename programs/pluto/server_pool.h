/* Server thread pool, for libreswan
 *
 * Copyright (C) 2004-2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2008,2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
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

/*
 * This is an internal interface between the main thread and the
 * helper threads (thread pool).
 *
 * The helper threads performs the heavy lifting, such as
 * cryptographic functions, for pluto.  It does this to avoid bogging
 * down the main thread with cryptography, increasing throughput.
 *
 * (Unrelated to code to compartmentalize lookups to LDAP/HTTP/FTP for CRL fetching
 * and checking.)
 */

#ifndef SERVER_POOL_H
#define SERVER_POOL_H

struct state;
struct msg_digest;
struct logger;

struct task; /*struct job*/

typedef void task_computer_fn(struct logger *logger,
			       struct task *task,
			       int my_thread);
/* might be called */
typedef stf_status task_completed_cb(struct state *st,
				     struct msg_digest *md,
				     struct task *task);
/* always called */
typedef void task_cleanup_cb(struct task **task);

struct task_handler {
	const char *name;
	task_computer_fn *computer_fn;
	task_completed_cb *completed_cb;
	task_cleanup_cb *cleanup_cb;
};

extern void submit_task(struct state *callback_sa,
			struct state *task_sa,
			struct msg_digest *md,
			bool detach_whack,
			struct task *task,
			const struct task_handler *handler,
			where_t where);

extern void start_server_helpers(int nhelpers, struct logger *logger);
void stop_server_helpers(void (*all_server_helpers_stopped)(void));
void free_server_helper_jobs(struct logger *logger);

#endif
