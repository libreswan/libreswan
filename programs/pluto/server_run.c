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

#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>

#include "lswalloc.h"
#include "server_run.h"

#include "verbose.h"
#include "log.h"

bool server_run(const char *verb, const char *verb_suffix,
		const char *cmd,
		struct verbose verbose)
{
#	define CHUNK_WIDTH	80	/* units for cmd logging */
	if (DBGP(DBG_BASE)) {
		int slen = strlen(cmd);
		int i;

		DBG_log("executing %s%s: %s",
			verb, verb_suffix, cmd);
		DBG_log("popen cmd is %d chars long", slen);
		for (i = 0; i < slen; i += CHUNK_WIDTH)
			DBG_log("cmd(%4d):%.*s:", i,
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
#ifdef HAVE_BROKEN_POPEN
			/*
			 * See bug #1067  Angstrom Linux on a arm7 has no
			 * popen()
			 */
			if (errno == ENOSYS) {
				/*
				 * Try system(), though it will not give us
				 * output
				 */
				vlog("unable to popen(), falling back to system()");
				system(cmd);
				return true;
			}
#endif
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
					llog_error(verbose.logger, errno,
						   "fgets failed on output of %s%s command",
						   verb, verb_suffix);
					pclose(f);
					return false;
				} else {
					passert(feof(f));
					break;
				}
			} else {
				char *e = resp + strlen(resp);

				if (e > resp && e[-1] == '\n')
					e[-1] = '\0'; /* trim trailing '\n' */
				vlog("%s%s output: %s", verb, verb_suffix, resp);
			}
		}

		/* report on and react to return code */
		{
			int r = pclose(f);

			if (r == -1) {
				llog_error(verbose.logger, errno,
					   "pclose failed for %s%s command",
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

bool server_runv(const char *argv[], const struct verbose verbose)
{
	char command[LOG_WIDTH];
	struct jambuf buf[] = { ARRAY_AS_JAMBUF(command), };
	const char *sep = "";
	for (const char **c = argv; *c != NULL; c++) {
		jam_string(buf, sep); sep = " ";
		jam_string(buf, "'");
		jam_shell_quoted_hunk(buf, shunk1(*c));
		jam_string(buf, "'");
	}
	if (!vexpect(jambuf_ok(buf))) {
		return false;
	}
	vlog("command: %s", command);

	FILE *out = popen(command, "re");	/*'e' is an extension
						 * for close on
						 * exec */
	if (out == NULL) {
		llog_error(verbose.logger, errno, "command '%s' failed: ", command);
		return false;
	}

	while (true) {
		char inp[100];
		int n = fread(inp, 1, sizeof(inp), out);
		if (n > 0) {
			LLOG_JAMBUF(RC_LOG, verbose.logger, buf) {
				jam_string(buf, "output: ");
				jam_sanitized_hunk(buf, shunk2(inp, n));
			}
			continue;
		}
		if (feof(out) || ferror(out)) {
			const char *why = (feof(out) ? "eof" :
					   ferror(out) ? "error" :
					   "???");
			int wstatus = pclose(out);
			llog(RC_LOG, verbose.logger,
			     "%s: %d; exited %s(%d); signaled: %s(%d); stopped: %s(%d); core: %s",
			     why, wstatus,
			     bool_str(WIFEXITED(wstatus)), WEXITSTATUS(wstatus),
			     bool_str(WIFSIGNALED(wstatus)), WTERMSIG(wstatus),
			     bool_str(WIFSTOPPED(wstatus)), WSTOPSIG(wstatus),
			     bool_str(WCOREDUMP(wstatus)));
			break;
		}
	}
	return true;
}

chunk_t server_runv_chunk(const char *argv[], const struct verbose verbose)
{
	char command[LOG_WIDTH];
	struct jambuf buf[] = { ARRAY_AS_JAMBUF(command), };
	const char *sep = "";
	for (const char **c = argv; *c != NULL; c++) {
		jam_string(buf, sep); sep = " ";
		jam_string(buf, "'");
		jam_shell_quoted_hunk(buf, shunk1(*c));
		jam_string(buf, "'");
	}
	if (!vexpect(jambuf_ok(buf))) {
		return (chunk_t) NULL_HUNK;
	}
	vlog("command: %s", command);

	FILE *out = popen(command, "re");	/*'e' is an extension
						 * for close on
						 * exec */
	if (out == NULL) {
		llog_error(verbose.logger, errno, "command '%s' failed: ", command);
		return (chunk_t) NULL_HUNK;
	}

	chunk_t output = NULL_HUNK;
	while (true) {
		char inp[100];
		int n = fread(inp, 1, sizeof(inp), out);
		if (n > 0) {
			LLOG_JAMBUF(RC_LOG, verbose.logger, buf) {
				jam_string(buf, "output: ");
				jam_sanitized_hunk(buf, shunk2(inp, n));
			}
			append_chunk_hunk("output", &output, shunk2(inp, n));
			continue;
		}
		if (feof(out) || ferror(out)) {
			const char *why = (feof(out) ? "eof" :
					   ferror(out) ? "error" :
					   "???");
			int wstatus = pclose(out);
			llog(RC_LOG, verbose.logger,
			     "%s: %d; exited %s(%d); signaled: %s(%d); stopped: %s(%d); core: %s",
			     why, wstatus,
			     bool_str(WIFEXITED(wstatus)), WEXITSTATUS(wstatus),
			     bool_str(WIFSIGNALED(wstatus)), WTERMSIG(wstatus),
			     bool_str(WIFSTOPPED(wstatus)), WSTOPSIG(wstatus),
			     bool_str(WCOREDUMP(wstatus)));
			break;
		}
	}
	return output;
}
