/* Libreswan config file parser (parserlast.h)
 * Copyright (C) 2004 Michael Richardson <mcr@sandelman.ottawa.on.ca>
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

#ifndef _IPSEC_PARSERLAST_H_
#define _IPSEC_PARSERLAST_H_

/* this file depends upon YYSTYPE from parser.tab.h, which
 * means that it can't go into parser.h, which gets includes
 * before that file.
 */

extern int parser_find_keyword(const char *s, YYSTYPE *lval);

#endif /* _IPSEC_PARSERLAST_H_ */
