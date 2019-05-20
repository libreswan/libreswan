/* State lists and hash tables, for libreswan
 *
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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

#include <stdint.h>

#include "lswlog.h"
#include "libreswan/passert.h"
#include "defs.h"
#include "hash_table.h"

static void log_entry(const char *op, struct list_entry *entry)
{
	passert(entry != NULL);
	if (DBGP(DBG_TMI)) {
		LSWLOG_DEBUG(buf) {
			lswlogf(buf, "%s: %s ", entry->info->name, op);
			if (entry->data == NULL) {
				lswlogf(buf, "entry %p is HEAD (older %p newer %p)",
					entry, entry->older, entry->newer);
			} else {
				lswlogf(buf, " object %p (", entry->data);
				entry->info->log(buf, entry->data);
				lswlogf(buf, ") entry %p (older %p newer %p)",
					entry, entry->older, entry->newer);
			}
		}
	}
	if (entry->newer != NULL || entry->older != NULL) {
		passert(entry->newer != NULL);
		passert(entry->newer->older == entry);
		passert(entry->older != NULL);
		passert(entry->older->newer == entry);
	}
}

void init_list(const struct list_info *info,
	       struct list_head *list)
{
	if (list->head.older == NULL) {
		passert(list->head.newer == NULL);
		list->head.older = &list->head;
		list->head.newer = &list->head;
		list->head.info = info;
		list->head.data = NULL;	/* sign of being head */
	} else {
		/* already initialized */
		/* ??? does this ever happen? */
		passert(list->head.newer != NULL);
		passert(list->head.info == info);
		passert(list->head.data == NULL);
	}
}

struct list_entry list_entry(const struct list_info *info,
			     void *data)
{
	passert(info != NULL);
	passert(data != NULL);

	return (struct list_entry) {
		.older = NULL,
		.newer = NULL,
		.data = data,
		.info = info,
	};
}

bool detached_list_entry(const struct list_entry *entry)
{
	passert(entry->data != NULL);	/* entry is not a list head */
	passert((entry->newer == NULL) == (entry->newer == NULL));
	return entry->newer == NULL;
}

void insert_list_entry(struct list_head *list,
		       struct list_entry *entry)
{
	passert(entry->info != NULL);
	passert(entry->data != NULL);
	if (DBGP(DBG_TMI)) {
		LSWLOG_DEBUG(buf) {
			lswlogf(buf, "%s: inserting object %p (",
				entry->info->name, entry->data);
			entry->info->log(buf, entry->data);
			lswlogf(buf, ") entry %p into list %p (older %p newer %p)",
				entry, list, list->head.older, list->head.newer);
		}
	}
	passert(list->head.info == entry->info);
	passert(entry->data != NULL);
	passert(entry->older == NULL && entry->newer == NULL);
	passert(list->head.newer != NULL && list->head.older != NULL);
	/* insert at the front */
	entry->newer = &list->head;
	entry->older = list->head.older;
	entry->older->newer = entry;
	entry->newer->older = entry;
	/* list->newer = list->newer; */
	log_entry("inserted", entry);
	log_entry("list", &list->head);
}

void remove_list_entry(struct list_entry *entry)
{
	passert(entry->data != NULL);	/* entry is not a list head */

	/* unlink: older - entry - newer */
	struct list_entry *newer = entry->newer;
	struct list_entry *older = entry->older;

	passert(older != NULL && newer != NULL);

	log_entry("removing", entry);
	entry->older = NULL;	/* detach from list */
	entry->newer = NULL;

	newer->older = older;	/* seal the rift */
	older->newer = newer;

	if (older == newer) {
		DBGF(DBG_TMI, "%s: empty", entry->info->name);
	} else {
		log_entry("updated older", older);
		log_entry("updated newer ", newer);
	}
}
