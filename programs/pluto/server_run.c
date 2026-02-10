/* routines that interface with the kernel's IPsec mechanism, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#define _GNU_SOURCE	/* expose execvpe() on Linux */

#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include "lswalloc.h"
#include "server_run.h"

#include "verbose.h"
#include "log.h"

bool server_run(const char *verb, const char *verb_suffix,
		const char *cmd,
		struct verbose verbose)
{
#	define CHUNK_WIDTH	80	/* units for cmd logging */
	if (verbose.debug) {
		int slen = strlen(cmd);
		int i;

		VDBG_log("executing %s%s: %s",
			 verb, verb_suffix, cmd);
		VDBG_log("popen cmd is %d chars long", slen);
		for (i = 0; i < slen; i += CHUNK_WIDTH)
			VDBG_log("cmd(%4d):%.*s:", i,
				 slen-i < CHUNK_WIDTH? slen-i : CHUNK_WIDTH,
				 &cmd[i]);
	}
#	undef CHUNK_WIDTH


	{
		/*
		 * invoke the script, catching stderr and stdout
		 * It may be of concern that some file descriptors will
		 * be inherited.  For the ones under our control, we
		 * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
		 * Any used by library routines (perhaps the resolver or
		 * syslog) will remain.
		 */
		FILE *f = popen(cmd, "r");

		if (f == NULL) {
			vlog("unable to popen %s%s command",
			     verb, verb_suffix);
			return false;
		}

		/* log any output */
		for (;; ) {
			/*
			 * if response doesn't fit in this buffer, it will
			 * be folded
			 */
			char resp[256];

			if (fgets(resp, sizeof(resp), f) == NULL) {
				if (ferror(f)) {
					llog_errno(ERROR_STREAM, verbose.logger, errno,
						   "fgets failed on output of %s%s command: ",
						   verb, verb_suffix);
					pclose(f);
					return false;
				} else {
					passert(feof(f));
					break;
				}
			} else {
				char *e = resp + strlen(resp);

				if (e > resp && e[-1] == '\n') {
					e[-1] = '\0'; /* trim trailing '\n' */
				}

				LLOG_JAMBUF(RC_LOG, verbose.logger, buf) {
					jam_string(buf, verb);
					jam_string(buf, verb_suffix);
					jam_string(buf, " output: ");
					jam_sanitized_hunk(buf, shunk1(resp));
				}
			}
		}

		/* report on and react to return code */
		{
			int r = pclose(f);

			if (r == -1) {
				llog_errno(ERROR_STREAM, verbose.logger, errno,
					   "pclose failed for %s%s command: ",
					   verb, verb_suffix);
				return false;
			} else if (WIFEXITED(r)) {
				if (WEXITSTATUS(r) != 0) {
					vlog("%s%s command exited with status %d",
					     verb, verb_suffix,
					     WEXITSTATUS(r));
					return false;
				}
			} else if (WIFSIGNALED(r)) {
				vlog("%s%s command exited with signal %d",
				     verb, verb_suffix, WTERMSIG(r));
				return false;
			} else {
				vlog("%s%s command exited with unknown status %d",
				     verb, verb_suffix, r);
				return false;
			}
		}
	}
	return true;
}

bool server_runv(const char *argv[], struct verbose verbose)
{
	int status = server_runve_io(argv, NULL/*envp*/,
				     /*input*/empty_shunk,
				     /*output*/NULL,
				     /*send-output-to*/ALL_STREAMS,
				     verbose);
	return (status == 0);
}

NEVER_RETURNS
static void child_process(const char *story,
			  int fd[],
			  const char *argv[],
			  const char *envp[],
			  struct verbose verbose)
{
	/*
	 * In child, connect child's STDIN to fd[0] -
	 * parent->child.
	 */

	if (dup2(fd[0], STDIN_FILENO) < 0) {
		llog_errno(ERROR_STREAM, verbose.logger, errno,
			   "\"%s\" dup2(fd[0], STDIN) failed: ", story);
		exit(127);
	}

	/*
	 * In child, connect fd[1] - child->parent - to
	 * child's STDOUT and STDERR.
	 */

	if (dup2(fd[1], STDOUT_FILENO) < 0) {
		llog_errno(ERROR_STREAM, verbose.logger, errno,
			   "\"%s\" dup2(fd[1], STDOUT) failed: ", story);
		exit(127);
	}

	if (dup2(fd[1], STDOUT_FILENO) < 0) {
		llog_errno(ERROR_STREAM, verbose.logger, errno,
			   "\"%s\" dup2(fd[1], STDERR) failed: ", story);
		exit(127);
	}

	/*
	 * In child, close fd[0,1], but only when they are not
	 * STDIN, STDOUT, or STDERR.
	 */

	if (fd[0] != STDIN_FILENO) {
		if (close(fd[0]) < 0) {
			llog_errno(ERROR_STREAM, verbose.logger, errno,
				   "\"%s\" close(fd[0]) failed: ", story);
			exit(127);
		}
	}

	if (fd[1] != STDOUT_FILENO && fd[1] != STDERR_FILENO) {
		if (close(fd[1]) < 0) {
			llog_errno(ERROR_STREAM, verbose.logger, errno,
				   "\"%s\" close(fd[1]) failed: ", story);
			exit(127);
		}
	}

	/*
	 * In child, with redirection done, exec new command.
	 *
	 * execvpe(), always available on BSD, is available on
	 * Linux when #define _GNU_SOURCE.
	 */

	if (envp == NULL) {
		execvp(argv[0], (char**)argv);
	} else {
		/* definition requires _GNU_SOURCE on Linux */
		execvpe(argv[0], (char**)argv, (char**)envp);
	}
	llog_errno(ERROR_STREAM, verbose.logger, errno,
		   "\"%s\" execve() failed: ", story);
	exit(127);
}

int server_runve_io(const char *argv[],
		    const char *envp[],
		    shunk_t input, chunk_t *output,
		    enum stream output_stream,
		    const struct verbose verbose)
{
	if (output_stream != 0) {
		LLOG_JAMBUF(output_stream, verbose.logger, buf) {
			jam_string(buf, "command: ");
			const char *sep = "";
			for (const char **c = argv; *c != NULL; c++) {
				jam_string(buf, sep); sep = " ";
				jam_string(buf, "'");
				jam_shell_quoted_hunk(buf, shunk1(*c));
				jam_string(buf, "'");
			}
		}
	}

	if (output != NULL) {
		zero(output);
	}

	/*
	 * fd[0] will be parent->child
	 * fd[1] will be child->parent
	 */
	int fd[2];
	if (pipe(fd) == -1) {
		llog_errno(ERROR_STREAM, verbose.logger, errno, "pipe(): ");
		return -1;
	}

	pid_t child = fork();
	if (child < 0) {
		llog_errno(ERROR_STREAM, verbose.logger, errno, "fork(): ");
		return -1;
	}

	if (child == 0) {
		child_process(argv[0], fd, argv, envp, verbose);
	}

	/*
	 * PARENT
	 */

	if (input.len > 0 &&
	    write(fd[1], input.ptr, input.len) != (ssize_t)input.len) {
		llog_errno(ERROR_STREAM, verbose.logger, errno, "partial write: ");
		/* stumble on to waitpid() */
	}

	if (close(fd[1]) < 0) {
		llog_errno(ERROR_STREAM, verbose.logger, errno, "close(fd[1]): ");
		/* stumble on to waitpid() */
	}

	while (true) {
		char inp[100];
		ssize_t n = read(fd[0], inp, sizeof(inp));
		if (n > 0) {
			if (output_stream != 0) {
				LLOG_JAMBUF(output_stream, verbose.logger, buf) {
					jam_string(buf, "output: ");
					jam_sanitized_hunk(buf, shunk2(inp, n));
				}
			}
			if (output != NULL) {
				append_chunk_hunk("output", output, shunk2(inp, n));
			}
			continue;
		}

		int status;
		const char *why = (n == 0 ? "EOF" : strerror(errno));
		waitpid(child, &status, 0);
		if (output_stream != 0) {
			llog(output_stream, verbose.logger,
			     "wstatus: %d; exited %s(%d); signaled: %s(%d); stopped: %s(%d); core: %s; %s",
			     status,
			     bool_str(WIFEXITED(status)), WEXITSTATUS(status),
			     bool_str(WIFSIGNALED(status)), WTERMSIG(status),
			     bool_str(WIFSTOPPED(status)), WSTOPSIG(status),
			     bool_str(WCOREDUMP(status)),
			     why);
		}
		return status;
	}
}
