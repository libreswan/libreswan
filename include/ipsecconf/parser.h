/* Libreswan config file parser
 * This header is only for use by code within libipsecconf.
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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

#ifndef IPSECCONF_PARSER_H
#define IPSECCONF_PARSER_H

#include <sys/queue.h>		/* for TAILQ_* */

#include "shunk.h"
#include "deltatime.h"
#include "lswlog.h"		/* for enum stream */

struct jambuf;
struct logger;
struct parser;
enum end;

struct keyword {
	const struct keyword_def *keydef;
	bool keyleft;
	bool keyright;
	char *string;
};

/* note: these lists are dynamic */
struct kw_list {
	struct kw_list *next;
	struct keyword keyword;
	char *string;
	uintmax_t number;
	deltatime_t deltatime;
};

struct section_list {
	TAILQ_ENTRY(section_list) link;

	char *name;
	struct kw_list *kw;
	bool beenhere;
};

struct config_parsed {
	struct kw_list *config_setup;

	TAILQ_HEAD(sectionhead, section_list) sections;
	int ipsec_conf_version;

	struct section_list conn_default;
};

struct parser {
	struct config_parsed *cfg;
	struct kw_list **kw;
	enum section { SECTION_CONFIG_SETUP, SECTION_CONN_DEFAULT, SECTION_CONN, } section;
	struct starter_comments_list *comments;
	struct logger *logger;
	enum stream error_stream;
	unsigned verbosity;
	struct input_source *input;
};

#include "parser.tab.h"	/* generated by bison */

/* defined in parser.y */

void parser_warning(struct parser *parser, int eerror/*can be 0*/,
		    const char *s, ...) PRINTF_LIKE(3);

void parser_fatal(struct parser *parser, int eerror/*can be 0*/,
		  const char *s, ...) PRINTF_LIKE(3) NEVER_RETURNS;

void parser_find_keyword(shunk_t s, enum end default_end, struct keyword *kw, struct parser *parser);

struct config_parsed *parser_load_conf(const char *file, struct logger *logger,
				       unsigned verbosity);
struct config_parsed *parser_argv_conf(const char *name, char *argv[], int start, struct logger *logger);

void parser_freeany_config_parsed(struct config_parsed **cfg);

#define THIS_IPSEC_CONF_VERSION 2

#endif /* _IPSEC_PARSER_H_ */
