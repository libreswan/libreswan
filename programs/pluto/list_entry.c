/* State lists and hash tables, for libreswan
 *
 * Copyright (C) 2015 Andrew Cagney <andrew.cagney@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
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

static void log_entry(const struct list_info *info,
		      const char *op, struct list_entry *entry)
{
	LSWDBGP(DBG_CONTROLMORE, buf) {
		lswlogf(buf, "%s: %s ", info->name, op);
		if (entry == NULL) {
			lswlogs(buf, "entry is NULL");
		} else if (entry->data == NULL) {
			lswlogs(buf, "entry is HEAD");
		} else {
			lswlogf(buf, " object %p (", entry->data);
			info->log(buf, entry->data);
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

void insert_list_entry(const struct list_info *info,
		       struct list_entry *slot,
		       struct list_entry *entry)
{
	LSWDBGP(DBG_CONTROLMORE, buf) {
		lswlogf(buf, "%s: inserting object %p (",
			info->name, entry->data);
		info->log(buf, entry->data);
		lswlogf(buf, ") entry %p into slot %p (older %p newer %p)",
			entry, slot, slot->older, slot->newer);
	}
	passert(entry->older == NULL && entry->newer == NULL);
	if (slot->newer == NULL && slot->older == NULL) {
		entry->newer = slot;
		entry->older = slot;
		slot->newer = entry;
		slot->older = entry;
	} else {
		/* insert at the front */
		entry->older = slot->older;
		entry->older->newer = entry;
		entry->newer = slot;
		slot->older = entry;
		/* slot->newer = slot->newer; */
	}
	log_entry(info, "inserted", entry);
	log_entry(info, "slot", slot);
}

void remove_list_entry(const struct list_info *info,
		       struct list_entry *entry)
{
	log_entry(info, "removing", entry);
	/* unlink: older - entry - newer */
	struct list_entry *newer = entry->newer;
	struct list_entry *older = entry->older;
	entry->older = NULL;
	entry->newer = NULL;
	/* kill loop if empty.  */
	if (older == newer) {
		/* the head */
		newer->older = NULL;
		older->newer = NULL;
		DBG(DBG_CONTROL, DBG_log("%s: empty", info->name));
	} else {
		newer->older = older;
		older->newer = newer;
		log_entry(info, "updated older", older);
		log_entry(info, "updated newer ", newer);
	}
}
