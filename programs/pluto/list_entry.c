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
#include "passert.h"
#include "defs.h"
#include "hash_table.h"

#define passert_entry(ENTRY, ASSERTION)					\
	{								\
		bool a_ = ASSERTION;					\
		if (!a_) {						\
			LSWLOG_PEXPECT(buf) {				\
				jam(buf, "%s: ",			\
				    (ENTRY)->info->name);		\
				jam_list_entry(buf, (ENTRY));		\
				jam(buf, ": %s", #ASSERTION);		\
			}						\
		}							\
	}

#define passert_info(INFO, ASSERTION)					\
	{								\
		bool a_ = ASSERTION;					\
		if (!a_) {						\
			LSWLOG_PEXPECT(buf) {				\
				jam(buf, "%s: %s",			\
				    (INFO)->name,			\
				    #ASSERTION);			\
			}						\
		}							\
	}

void jam_list_entry(struct lswlog *buf, const struct list_entry *entry)
{
	if (entry == NULL) {
		jam(buf, "(null)");
	} else {
		if (entry->data == NULL) {
			lswlogf(buf, "HEAD");
		} else {
			entry->info->jam(buf, entry->data);
		}
		jam(buf, " %p<-%p->%p", entry->older, entry, entry->newer);
	}
}

static void log_entry(const char *op, struct list_entry *entry)
{
	passert(entry != NULL);
	if (DBGP(DBG_TMI)) {
		LSWLOG_DEBUG(buf) {
			lswlogf(buf, "%s: %s ", entry->info->name, op);
			jam_list_entry(buf, entry);
		}
	}
	if (entry->newer != NULL || entry->older != NULL) {
		passert_entry(entry, entry->newer != NULL);
		passert_entry(entry, entry->newer->older == entry);
		passert_entry(entry, entry->older != NULL);
		passert_entry(entry, entry->older->newer == entry);
	}
}

struct list_entry list_entry(const struct list_info *info,
			     void *data)
{
	passert_info(info, info != NULL);
	passert_info(info, data != NULL);

	return (struct list_entry) {
		.older = NULL,
		.newer = NULL,
		.data = data,
		.info = info,
	};
}

bool detached_list_entry(const struct list_entry *entry)
{
	passert_entry(entry, entry->data != NULL);	/* entry is not a list head */
	passert_entry(entry, (entry->newer == NULL) == (entry->newer == NULL));
	return entry->newer == NULL;
}

void insert_list_entry(struct list_head *list,
		       struct list_entry *entry)
{
	passert_entry(entry, entry->info != NULL);
	passert_entry(entry, entry->data != NULL);
	if (DBGP(DBG_TMI)) {
		LSWLOG_DEBUG(buf) {
			lswlogf(buf, "%s: inserting ",
				entry->info->name);
			jam_list_entry(buf, entry);
			lswlogf(buf, " into list ");
			jam_list_entry(buf, &list->head);
		}
	}
	passert_entry(entry, list->head.info == entry->info);
	passert_entry(entry, entry->data != NULL);
	passert_entry(entry, entry->older == NULL && entry->newer == NULL);
	passert_entry(entry, list->head.newer != NULL && list->head.older != NULL);
	/* insert at the front */
	entry->newer = &list->head;
	entry->older = list->head.older;
	entry->older->newer = entry;
	entry->newer->older = entry;
	/* list->newer = list->newer; */
	if (DBGP(DBG_TMI)) {
		LSWLOG_DEBUG(buf) {
			lswlogf(buf, "%s: inserted  ",
				entry->info->name);
			jam_list_entry(buf, entry);
			lswlogf(buf, " into list ");
			jam_list_entry(buf, &list->head);
		}
	}
}

void remove_list_entry(struct list_entry *entry)
{
	log_entry("removing", entry);

	/* entry is not a list head */
	passert_entry(entry, entry->data != NULL);

	/* unlink: older - entry - newer */
	struct list_entry *newer = entry->newer;
	struct list_entry *older = entry->older;
	passert_entry(entry, older != NULL && newer != NULL);

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
