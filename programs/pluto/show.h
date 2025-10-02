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
struct show_ops;

/*
 * Try to deal with the separator (i.e., don't output duplicate blank
 * / spacer lines when combining functions that send output to whack)
 * in show (whack-only) output.
 */

extern const struct show_ops show_text_ops;
extern const struct show_ops show_json_ops;

struct show *alloc_show(struct logger *logger, const struct show_ops *ops);
void free_show(struct show **s);
/* underlying global logger formed by alloc_show() */
struct logger *show_logger(struct show *s);

/*
 * output primitives: access the internal jambuf; show the contents of
 * a jambuf.
 */

struct jambuf *show_jambuf(struct show *s);
void show_to_logger(struct show *s);
#define SHOW_JAMBUF(S, BUF)				\
	for (struct jambuf *BUF = show_jambuf(S);	\
	     BUF != NULL;				\
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
 * Line based output functions. If necessary show the separator (aka
 * blank line), and then show the message.  Suppress further
 * separation.
 */

void show(struct show *s, const char *message, ...) PRINTF_LIKE(2);
void show_rc(enum rc_type rc, struct show *s, const char *message, ...) PRINTF_LIKE(3);

/*
 * Structured output functions.
 */
void show_structured_start(struct show *s);
void show_structured_end(struct show *s);

#define SHOW_STRUCTURED(S, F)				\
	for (bool F = (show_structured_start(S), true); \
	     F; show_structured_end(S), F = false)

void show_raw(struct show *s, const char *message, ...) PRINTF_LIKE(2);
void show_string(struct show *s, const char *message, ...) PRINTF_LIKE(2);

void show_member_start(struct show *s, const char *name);
void show_member_end(struct show *s);

#define SHOW_MEMBER(S, F, FMT, ...)					\
	for (bool F = (show_member_start(S, FMT, ##__VA_ARGS__), true); \
	     F;	show_member_end(S), F = false)

void show_array_start(struct show *s);
void show_array_end(struct show *s);

#define SHOW_ARRAY(S, F)				\
	for (bool F = (show_array_start(S), true);	\
	     F;	show_array_end(S), F = false)

void show_object_start(struct show *s);
void show_object_end(struct show *s);

#define SHOW_OBJECT(S, F)				\
	for (bool F = (show_object_start(S), true);	\
	     F; show_object_end(S), F = false)

#endif
