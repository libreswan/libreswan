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

#ifndef SERVER_FORK_H
#define SERVER_FORK_H

#include "chunk.h"

struct logger;
struct msg_digest;
struct state;
struct show;
enum stream;
struct whack_message;

/*
 * Create a child process using fork()
 *
 * server_fork() is 
 *
 * server_fork_exec(), with a more traditional subprocess, is used as
 * an alternative to popen() et.al.
 *
 * On callback:
 *
 * ST either points at the state matching SERIALNO, or NULL (SERIALNO
 * is either SOS_NOBODY or the state doesn't exist).  A CB expecting a
 * state back MUST check ST before processing.
 *
 * STATUS is the child processes exit code as returned by things like
 * waitpid().
 */

typedef stf_status server_fork_cb(struct state *st,
				  struct msg_digest *md,
				  int wstatus, shunk_t output,
				  void *context,
				  struct logger *logger);

/*
 * Call OP() within a child process.
 *
 * Used to perform a thread unfriendly operation, such as calling PAM.
 */

typedef int server_fork_op(void *context, struct logger *logger);
extern int server_fork(const char *name,
		       so_serial_t serialno,
		       struct msg_digest *md,
		       server_fork_op *op,
		       server_fork_cb *callback,
		       void *callback_context,
		       struct logger *logger);

/*
 * Run a program as a child process in the background.
 *
 * INPUT is written to the child process after it has been created.
 *
 * LOG_OUTPUT, when non-zero, is where to send subprocess output.
 *
 * On exit CALLBACK(wstatus, output, context, ...) is called.  WSTATUS
 * was returned by waitpid(); OUTPUT contains all the accumulated
 * output from the process.
 */

void server_fork_exec(const char *path,
		      char *argv[], char *envp[],
		      shunk_t input,
		      enum stream log_output,
		      server_fork_cb *callback,
		      void *callback_context,
		      struct logger *logger);

void server_fork_sigchld_handler(struct logger *logger);
void init_server_fork(struct logger *logger);
void check_server_fork(struct logger *logger);
void whack_processstatus(const struct whack_message *wm, struct show *s);

#endif
