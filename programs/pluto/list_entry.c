/* State lists and hash tables, for libreswan
 *
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
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

#include "defs.h"
#include "hash_table.h"

static void log_entry(const char *op, struct list_entry *entry)
{
	passert(entry != NULL);
	LSWDBGP(entry->info->debug, buf) {
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
	if (list->head.older == NULL || list->head.newer == NULL) {
		list->head.older = &list->head;
		list->head.newer = &list->head;
		list->head.info = info;
	}
}

struct list_entry list_entry(const struct list_info *info,
			     void *data)
{
	return (struct list_entry) {
		.older = NULL,
		.newer = NULL,
		.data = data,
		.info = info,
	};
}

void insert_list_entry(struct list_head *list,
		       struct list_entry *entry)
{
	passert(entry->info != NULL);
	LSWDBGP(entry->info->debug, buf) {
		lswlogf(buf, "%s: inserting object %p (",
			entry->info->name, entry->data);
		entry->info->log(buf, entry->data);
		lswlogf(buf, ") entry %p into list %p (older %p newer %p)",
			entry, list, list->head.older, list->head.newer);
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

bool remove_list_entry(struct list_entry *entry)
{
	/* unlink: older - entry - newer */
	struct list_entry *newer = entry->newer;
	struct list_entry *older = entry->older;
	if (older == NULL && newer == NULL) {
		log_entry("can't remove", entry);
		return false;
	} else {
		log_entry("removing", entry);
		entry->older = NULL;
		entry->newer = NULL;
		newer->older = older;
		/*
		 * ??? static analysis suggests either older or newer might be NULL.
		 * (But not both.)
		 * Perhaps an undocumented invariant saves us.
		 */
		older->newer = newer;
		if (older == newer) {
			DBG(entry->info->debug, DBG_log("%s: empty", entry->info->name));
		} else {
			log_entry("updated older", older);
			log_entry("updated newer ", newer);
		}
		return true;
	}
}
