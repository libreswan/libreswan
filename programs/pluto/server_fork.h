/* pluto_fork, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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

#ifndef PLUTO_FORK_H
#define PLUTO_FORK_H

struct logger;
struct msg_digest;
struct state;

/*
 * Create a child process using fork()
 *
 * Typically used to perform a thread unfriendly operation, such as
 * calling PAM.
 *
 * On callback:
 *
 * ST either points at the state matching SERIALNO, or NULL (SERIALNO
 * is either SOS_NOBODY or the state doesn't exist).  A CB expecting a
 * state back MUST check ST before processing.  Caller sets CUR_STATE
 * so don't play with that.
 *
 * MDP either points at the unsuspended contents of .st_suspended_md,
 * or NULL.  On return, if *MDP is non-NULL, then it will be released.
 *
 * STATUS is the child processes exit code as returned by things like
 * waitpid().
 */

typedef void server_fork_cb(struct state *st, struct msg_digest *md,
			    int status, void *context, struct logger *logger);
typedef int server_fork_op(void *context, struct logger *logger);

extern int server_fork(const char *name, so_serial_t serialno, server_fork_op *op,
		       server_fork_cb *callback, void *callback_context,
		       struct logger *logger);
void server_fork_exec(const char *what, const char *path,
		      char *argv[], char *envp[],
		      server_fork_cb *callback, void *callback_context,
		      struct logger *logger);

void server_fork_sigchld_handler(struct logger *logger);
void init_server_fork(void);

#endif /* _SERVER_H */
