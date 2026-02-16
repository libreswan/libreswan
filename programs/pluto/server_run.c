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

bool server_rune(const char *story,
		 const char *cmd,
		 const char *envp[],
		 struct verbose verbose)
{
	vdbg("executing %s: %s", story, cmd);
#if 0
#	define CHUNK_WIDTH	80	/* units for cmd logging */
	if (verbose.debug) {
		int slen = strlen(cmd);
		int i;

		VDBG_log("popen cmd is %d chars long", slen);
		for (i = 0; i < slen; i += CHUNK_WIDTH)
			VDBG_log("cmd(%4d):%.*s:", i,
				 slen-i < CHUNK_WIDTH? slen-i : CHUNK_WIDTH,
				 &cmd[i]);
	}
#	undef CHUNK_WIDTH
#endif

	/*
	 * Both BSD and Linux document popen() as invoking /bin/sh -c
	 * '...'.
	 */
	const char *argv[] = {
		"/bin/sh",
		"-c",
		cmd,
		NULL,
	};

	int status = server_runve_io(story, argv, envp,
				     /*input*/empty_shunk,
				     /*output*/NULL,
				     verbose,
				     (verbose.debug ? DEBUG_STREAM : 0));
	return (status == 0);
}

bool server_runv(const char *story, const char *argv[], struct verbose verbose)
{
	int status = server_runve_io(story, argv,
				     /*envp*/NULL,
				     /*input*/empty_shunk,
				     /*save_output*/NULL,
				     verbose,
				     /*command_stream*/ALL_STREAMS);
	return (status == 0);
}

bool server_runve(const char *story,
		  const char *argv[],
		  const char *envp[],
		  struct verbose verbose)
{
	int status = server_runve_io(story, argv, envp,
				     /*input*/empty_shunk,
				     /*save_output*/NULL,
				     verbose,
				     /*command_stream*/ALL_STREAMS);
	return (status == 0);
}

NEVER_RETURNS
static void child_process(const char *story,
			  int fd[],
			  shunk_t input,
			  const char *argv[],
			  const char *envp[],
			  struct verbose verbose)
{
	/*
	 * In child, connect child's STDIN to fd[0] - parent->child;
	 * but only when it needs to remain open.
	 */

	if (input.len == 0) {
		close(fd[0]);
	} else if (fd[0] != STDIN_FILENO) {
		if (dup2(fd[0], STDIN_FILENO) < 0) {
			verror(errno, "command \"%s\": dup2(fd[0], STDIN) failed: ", story);
			exit(127);
		}
		if (close(fd[0]) < 0) {
			verror(errno, "command \"%s\": close(fd[0]) failed: ", story);
			exit(127);
		}
	}

	/*
	 * In child, connect fd[1] - child->parent - to
	 * child's STDOUT and STDERR.
	 */

	if (fd[1] != STDOUT_FILENO) {
		if (dup2(fd[1], STDOUT_FILENO) < 0) {
			verror(errno, "command \"%s\": dup2(fd[1], STDOUT) failed: ", story);
			exit(127);
		}
	}

	if (fd[1] != STDERR_FILENO) {
		if (dup2(fd[1], STDERR_FILENO) < 0) {
			verror(errno, "command \"%s\": dup2(fd[1], STDERR) failed: ", story);
			exit(127);
		}
	}

	if (fd[1] != STDOUT_FILENO && fd[1] != STDERR_FILENO) {
		if (close(fd[1]) < 0) {
			verror(errno, "command\"%s\": close(fd[1]) failed: ", story);
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

	/* should never reach here */
	verror(errno, "command \"%s\": execve() failed: ", story);
	exit(127);
}

int server_runve_io(const char *story,
		    const char *argv[],
		    const char *envp[],
		    shunk_t input,
		    chunk_t *save_output,
		    const struct verbose verbose,
		    enum stream command_stream)
{
	if (command_stream != 0) {
		LLOG_JAMBUF(command_stream, verbose.logger, buf) {
			jam_string(buf, "command \"");
			jam_string(buf, story);
			jam_string(buf, "\":");
			for (const char **c = argv; *c != NULL; c++) {
				jam_string(buf, " ");
				/*
				 * XXX: jam_sanitized_hunk doesn't
				 * excape single quotes.
				 *
				 * XXX: should split long arguments.
				 * Currently they are truncated.
				 */
				jam_string(buf, "'");
				jam_shell_quoted_hunk(buf, shunk1(*c));
				jam_string(buf, "'");
			}
		}
	}

	for (const char **p = envp; p != NULL && *p != NULL; p++) {
		vdbg("%s", *p);
	}

	if (save_output != NULL) {
		zero(save_output);
	}

	/*
	 * fd[0] will be parent->child
	 * fd[1] will be child->parent
	 */
	int fd[2];
	if (pipe(fd) == -1) {
		verror(errno, "command\"%s\": pipe() failed: ", story);
		return -1;
	}

	pid_t child = fork();
	if (child < 0) {
		verror(errno, "command \"%s\": fork() failed: ", story);
		return -1;
	}

	if (child == 0) {
		child_process(story, fd, input, argv, envp, verbose);
	}

	/*
	 * PARENT: Send input to child; always close.
	 */

	if (input.len > 0) {
		if (write(fd[1], input.ptr, input.len) != (ssize_t)input.len) {
			verror(errno, "command \"%s\": partial write(): ", story);
			/* stumble on to waitpid() */
		}
	}

	if (close(fd[1]) < 0) {
		verror(errno, "command \"%s\": close(fd[1]) failed: ", story);
		/* stumble on to waitpid() */
	}

	/*
	 * Drain the child's stdout; use FILE so that things break on
	 * lines.
	 */
	FILE *output_file = fdopen(fd[0], "r");
	fd[0] = -1; /* ownership transfered to OUTPUT_FILE */
	enum stream output_stream = (save_output == NULL ? ALL_STREAMS :
				     verbose.debug ? DEBUG_STREAM :
				     0);
	while (true) {

		/*
		 * If response doesn't fit in this buffer, it will be
		 * folded.
		 */
		char resp[256];
		if (fgets(resp, sizeof(resp), output_file) == NULL) {
			if (ferror(output_file)) {
				verror(errno,
				       "command \"%s\": fgets() failed reading output: ",
				       story);
				break;
			}

			passert(feof(output_file));
			break;
		}

		shunk_t output = shunk1(resp); /* contains '\n' */

		if (output_stream != 0) {
			/* drop '\n' */
			unsigned len = output.len;
			if (output.len > 0 && resp[output.len-1] == '\n') {
				len--;
			}

			LLOG_JAMBUF(output_stream, verbose.logger, buf) {
				jam_string(buf, "command \"");
				jam_string(buf, story);
				jam_string(buf, "\" output: ");
				jam_sanitized_bytes(buf, resp, len);
			}
		}

		if (save_output != NULL) {
			append_chunk_hunk("output", save_output, output);
		}
	}
	fclose(output_file);

	/*
	 * Now reap the child.
	 */

	while (true) {

		int status;
		waitpid(child, &status, 0);

		if (WIFCONTINUED(status)) {
			vwarning("command \"%s\": continued", story);
			continue;
		}

		if (WIFSIGNALED(status)) {
			vwarning("command \"%s\": terminated with signal %s (%d)",
				 story,
				 strsignal(WTERMSIG(status)),
				 WTERMSIG(status));
			return -1;
		}

		if (WIFEXITED(status)) {
			unsigned code = WEXITSTATUS(status);
			if (code != 0) {
				vwarning("command \"%s\": exited with status %u",
					 story, code);
			} else if (command_stream != 0) {
				llog(command_stream, verbose.logger,
				     "command \"%s\": exited normally", story);
			} else {
				vdbg("command \"%s\": exited normally", story);
			}
			return code;
		}

		if (WIFSTOPPED(status)) {
			/* should not happen */
			vwarning("command \"%s\": stopped with signal %s (%d) but WUNTRACED not specified",
				 story,
				 strsignal(WSTOPSIG(status)),
				 WSTOPSIG(status));
			continue;
		}

		return -1;
	}
}
