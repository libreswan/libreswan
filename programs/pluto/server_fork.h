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
 * Run code as a child process in the background.
 *
 * SERVER_FORK(): calls the function FORK_OP() within the child
 * process (the value returned is passed to exit()).  This is used to
 * perform a thread unfriendly operation, such as calling PAM.
 *
 * SERVER_FORK_EXEC(): runs PROGRAM passing ARGV[].

 * On exit CALLBACK(ST, MD, WSTATUS, OUTPUT, CALLBACK_CONTEXT, ...) is
 * called where WSTATUS was returned by waitpid() and OUTPUT contains
 * all the accumulated output from the process.
 *
 * When INPUT is non-empty, it is written to the Child's STDIN.
 *
 * When OUTPUT_STREAM is not NO_STREAM, the child processes output is
 * logged as it is captured (as a special case, output is only logged
 * to DEBUG_STREAM, when debugging is enabled).
 */

typedef stf_status server_fork_cb(struct state *st,
				  struct msg_digest *md,
				  int wstatus, shunk_t output,
				  void *callback_context,
				  struct logger *logger);

typedef int server_fork_op(void *callback_context, struct logger *logger);
pid_t server_fork(const char *name,
		  server_fork_op *fork_op,
		  so_serial_t serialno,
		  struct msg_digest *md,
		  shunk_t input,
		  enum stream output_stream,
		  server_fork_cb *callback,
		  void *callback_context,
		  struct logger *logger);

pid_t server_fork_exec(const char *path,
		       char *argv[], char *envp[], /*op*/
#if 0
		       so_serial_t serialno,
		       struct msg_digest *md,
#endif
		       shunk_t input,
		       enum stream output_stream,
		       server_fork_cb *callback,
		       void *callback_context,
		       struct logger *logger);

void server_fork_sigchld_handler(struct logger *logger);
void init_server_fork(struct logger *logger);
void check_server_fork(struct logger *logger);
void whack_processstatus(const struct whack_message *wm, struct show *s);

#endif
