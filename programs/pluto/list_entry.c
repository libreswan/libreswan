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

#include "passert.h"
#include "defs.h"
#include "log.h"
#include "hash_table.h"

#define passert_entry(ENTRY, ASSERTION)					\
	{								\
		bool a_ = ASSERTION; /* evaluate once */		\
		if (!a_) {						\
			LLOG_PASSERT_JAMBUF(&global_logger, HERE, buf) { \
				jam_string(buf, (ENTRY)->info->name);	\
				jam_string(buf, ": ");			\
				jam_list_entry(buf, (ENTRY));		\
				jam_string(buf, ": ");			\
				jam_string(buf, #ASSERTION);		\
			}						\
		}							\
	}

#define passert_info(INFO, ASSERTION)					\
	{								\
		bool a_ = ASSERTION; /* evaluate once */		\
		if (!a_) {						\
			LLOG_PASSERT_JAMBUF(&global_logger, HERE, buf) { \
				jam_string(buf, (INFO)->name);		\
				jam_string(buf, ": ");			\
				jam_string(buf, #ASSERTION);		\
			}						\
		}							\
	}

void jam_list_entry(struct jambuf *buf, const struct list_entry *entry)
{
	if (entry == NULL) {
		jam(buf, "(null)");
	} else {
		if (entry->data == NULL) {
			jam(buf, "HEAD");
		} else {
			entry->info->jam(buf, entry->data);
		}
		jam(buf, " %p<-%p->%p", entry->next[NEW2OLD], entry, entry->next[OLD2NEW]);
	}
}

static void log_entry(const char *op, struct list_entry *entry)
{
	passert(entry != NULL);
	LDBGP_JAMBUF(DBG_TMI, &global_logger, buf) {
		jam(buf, "%s: %s ", entry->info->name, op);
		jam_list_entry(buf, entry);
	}
	if (entry->next[OLD2NEW] != NULL || entry->next[NEW2OLD] != NULL) {
		passert_entry(entry, entry->next[OLD2NEW] != NULL);
		passert_entry(entry, entry->next[OLD2NEW]->next[NEW2OLD] == entry);
		passert_entry(entry, entry->next[NEW2OLD] != NULL);
		passert_entry(entry, entry->next[NEW2OLD]->next[OLD2NEW] == entry);
	}
}

void init_list_entry(const struct list_info *info, void *data, struct list_entry *entry)
{
	/* something to do? */
	passert_info(info, data != NULL);
	passert_info(info, entry != NULL);
	/* not initialized */
	passert_info(info, entry->info == NULL);
	passert_info(info, entry->data == NULL);
	passert_info(info, entry->next[OLD2NEW] == NULL);
	passert_info(info, entry->next[NEW2OLD] == NULL);
#if 0
	/* cross-check */
	passert_info(info, entry == data_list_entry(info, data));
#endif
	/* initialize */
	*entry = (struct list_entry) {
		.info = info,
		.data = data,
	};
}

#if 0
struct list_entry *data_list_entry(const struct list_info *info, void *data)
{
	uint8_t *ptr = data;
	struct list_entry *entry = (void *)(ptr + info->offset);
	return entry;
}
#endif

#if 0
void *list_entry_data(const struct list_entry *entry)
{
	passert(entry->info != NULL);
	uint8_t *offptr = (void*)entry;
	return offptr - entry->info->offset;
}
#endif

bool detached_list_entry(const struct list_entry *entry)
{
	passert_entry(entry, entry->data != NULL);	/* entry is not a list head */
	passert_entry(entry, (entry->next[OLD2NEW] == NULL) == (entry->next[OLD2NEW] == NULL));
	return entry->next[OLD2NEW] == NULL;
}

void insert_list_entry(struct list_head *list,
		       struct list_entry *entry)
{
	passert_entry(entry, entry->info != NULL);
	passert_entry(entry, entry->data != NULL);
	LDBGP_JAMBUF(DBG_TMI, &global_logger, buf) {
		jam(buf, "%s: inserting ",
		    entry->info->name);
		jam_list_entry(buf, entry);
		jam(buf, " into list ");
		jam_list_entry(buf, &list->head);
	}
	passert_entry(entry, list->head.info == entry->info);
	passert_entry(entry, entry->data != NULL);
	passert_entry(entry, entry->next[NEW2OLD] == NULL && entry->next[OLD2NEW] == NULL);
	passert_entry(entry, list->head.next[NEW2OLD] != NULL && list->head.next[OLD2NEW] != NULL);
	/* insert at the front */
	entry->next[OLD2NEW] = &list->head;
	entry->next[NEW2OLD] = list->head.next[NEW2OLD];
	entry->next[NEW2OLD]->next[OLD2NEW] = entry;
	entry->next[OLD2NEW]->next[NEW2OLD] = entry;
	/* list->next[OLD2NEW] = list->next[OLD2NEW]; */
	LDBGP_JAMBUF(DBG_TMI, &global_logger, buf) {
		jam(buf, "%s: inserted  ",
		    entry->info->name);
		jam_list_entry(buf, entry);
		jam(buf, " into list ");
		jam_list_entry(buf, &list->head);
	}
}

void remove_list_entry(struct list_entry *entry)
{
	log_entry("removing", entry);

	/* entry is not a list head */
	passert_entry(entry, entry->data != NULL);

	/* unlink: older - entry - newer */
	struct list_entry *newer = entry->next[OLD2NEW];
	struct list_entry *older = entry->next[NEW2OLD];
	passert_entry(entry, older != NULL && newer != NULL);

	entry->next[NEW2OLD] = NULL;	/* detach from list */
	entry->next[OLD2NEW] = NULL;

	newer->next[NEW2OLD] = older;	/* seal the rift */
	older->next[OLD2NEW] = newer;

	if (older == newer) {
		ldbgf(DBG_TMI, &global_logger, "%s: empty", entry->info->name);
	} else {
		log_entry("updated older", older);
		log_entry("updated newer ", newer);
	}
}
