/* show (whack-only) output functions, for libreswan
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

#ifndef SHOW_H
#define SHOW_H

#include "lswcdefs.h"		/* for PRINTF_LIKE() */

struct show;
enum rc_type;
struct logger;

/*
 * Try to deal with the separator (i.e., don't output duplicate blank
 * / spacer lines when combining functions that send output to whack)
 * in show (whack-only) output.
 */

struct show *alloc_show(struct logger *logger);
void free_show(struct show **s);
/* underlying global logger formed by alloc_show() */
struct logger *show_logger(struct show *s);

/*
 * output primitives: access the internal jambuf; show the contents of
 * a jambuf.
 */

struct jambuf *show_jambuf(struct show *s, enum rc_type rc);
void show_to_logger(struct show *s);
#define SHOW_JAMBUF(S, BUF)					\
	for (struct jambuf *BUF = show_jambuf(S, RC_COMMENT);	\
	     BUF != NULL;					\
	     show_to_logger(S), BUF = NULL)

/*
 * Flag that the next line needs to be preceded by a separator (aka
 * blank line).  For instance:
 *
 * Example 1:
 *
 *    show_separator(s);
 *    show(s, "heading 1");
 *    show_separator(s);
 *    show_separator(s);
 *    show(s, "heading 2");
 *    show_separator(s);
 *
 *    heading 1
 *    <blank>
 *    heading 2
 *    <blank>
 *
 * Example 2:
 *
 *    show_blank(s);
 *    show_separator(s);
 *    show_blank(s);
 *    show(s, "heading 1");
 *
 * will output:
 *
 *    <blank>
 *    line 1
 *
 */
void show_separator(struct show *s);
void show_blank(struct show *s);

/*
 * If necessary show the separator (aka blank line), and then show the
 * message.  Suppress further separation.
 *
 * "comment" comes from RC_COMMENT, better name?
 */

void show(struct show *s, const char *message, ...) PRINTF_LIKE(2);

/*
 * Whack only logging.
 *
 * None of these functions add a context prefix (such as connection
 * name).  If that's really really needed then use
 * log_*(WHACK_STREAM,...) above.
 *
 * also requires a valid whackfd.  It should only be used by show
 * commands.
 */

void whack_log(enum rc_type rc, struct show *s, const char *message, ...) PRINTF_LIKE(3);

#endif
