/* keywords, for libreswan
 *
 * Copyright (C) 2018 Andrew Cagney
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

#include "keywords.h"
#include "lswlog.h"

const struct keyword *keyword_by_name(const struct keywords *keywords,
				      shunk_t name)
{
	for (unsigned ki = 0; ki < keywords->nr_values; ki++) {
		const struct keyword *kv = &keywords->values[ki];
		if (kv->name != NULL && shunk_strcaseeq(name, kv->name)) {
			return kv;
		}
	}
	return NULL;
}

const struct keyword *keyword_by_sname(const struct keywords *keywords,
				       shunk_t name)
{
	for (unsigned ki = 0; ki < keywords->nr_values; ki++) {
		const struct keyword *kv = &keywords->values[ki];
		if (kv->sname != NULL && shunk_strcaseeq(name, kv->sname)) {
			return kv;
		}
	}
	return NULL;
}

const struct keyword *keyword_by_value_direct(const struct keywords *keywords,
					      unsigned value)
{
	if (value >= keywords->nr_values) {
		return NULL;
	}
	const struct keyword *kw = &keywords->values[value];
	if (kw->name == NULL) {
		return NULL;
	}
	passert(kw->value == value);
	return kw;
}

#if 0
const struct keyword *keyword_by_value_binary(const struct keywords *keywords,
					      unsigned value)
{
}
#endif

const struct keyword *keyword_by_value_linear(const struct keywords *keywords,
					      unsigned value)
{
	for (unsigned ki = 0; ki < keywords->nr_values; ki++) {
		const struct keyword *kv = &keywords->values[ki];
		if (kv->value == value) {
			return kv;
		}
	}
	return NULL;
}

const struct keyword *keyword_by_value(const struct keywords *keywords,
				       unsigned value)
{
	return keywords->by_value(keywords, value);
}

size_t lswlog_keyname(struct lswlog *buf, const struct keywords *keywords, unsigned value)
{
	const struct keyword *keyword = keyword_by_value(keywords, value);
	if (keyword == NULL) {
		return lswlogf(buf, "'%s %u'", keywords->name, value);
	} else {
		return lswlogs(buf, keyword->name);
	}
}

size_t lswlog_keysname(struct lswlog *buf, const struct keywords *keywords, unsigned value)
{
	const struct keyword *keyword = keyword_by_value(keywords, value);
	if (keyword == NULL) {
		return lswlogf(buf, "'%s %u'", keywords->name, value);
	} else {
		return lswlogs(buf, keyword->sname);
	}
}
