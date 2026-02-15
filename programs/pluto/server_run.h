/* run a subprogram, for libreswan
 *
 * Copyright (C) 1998-2001,2013  D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2019 Andrew Cagney
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

#ifndef SERVER_RUN_H
#define SERVER_RUN_H

#include <stdbool.h>

#include "chunk.h"

struct verbose;
struct logger;

bool server_rune(const char *story,
		 const char *cmd,
		 const char *envp[],
		 struct verbose verbose);

bool server_runv(const char *story, const char *argv[],
		 struct verbose verbose);

/*
 * When INPUT is non-empty it is written to the child.
 *
 * When SAVE_OUTPUT is non-NULL, output from the child is captured;
 * else output is logged.
 *
 * When envp is non-NULL, use execve(argv,envp).
 *
 * Write command being executed to COMMAND_STREAM (when non-zero).
 *
 * Returns -1, 0, exit code.
 */

int server_runve_io(const char *story,
		    const char *argv[],
		    const char *envp[],
		    shunk_t input,
		    chunk_t *save_output,
		    struct verbose verbose,
		    enum stream command_stream);

#endif
