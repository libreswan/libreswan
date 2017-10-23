/* double linked list, for libreswan
 *
 * Copyright (C) 2015, 2017 Andrew Cagney
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

#ifndef _list_entry_h_
#define _list_entry_h_

/*
 * Description of a list entry, used for logging.
 */

struct list_info {
	const char *name;
	size_t (*log)(struct lswlog *buf, void *data);
};

/*
 * Double linked list entry.
 *
 * Since these are stored directly in the list object there is less
 * memory management overhead.
 *
 * The list head is an empty list_entry (data is NULL) where .older is
 * in new-to-old order and .newer is in old-to-new order.  Since the
 * lists link back to head .data == NULL acts as a sentinel.
 *
 * When the list is empty, head's .newer and .older are both forced to
 * NULL.
 */

struct list_entry {
	struct list_entry *older;
	struct list_entry *newer;
	void *data;
};

/*
 * Insert (at front) or remove the object from the linked list.
 *
 * These operations are O(1).
 */

void insert_list_entry(const struct list_info *info,
		       struct list_entry *head,
		       struct list_entry *entry);

void remove_list_entry(const struct list_info *info,
		       struct list_entry *entry);

/*
 * Iterate through all the entries in the list in old-to-new order.
 *
 * When the list is empty, HEAD's .newer and .older are both NULL and
 * the loop is skipped.  E is not modified (XXX: should it be
 * explicitly set to NULL?).
 *
 * So that the current entry can be deleted, the E##entry pointer is
 * kept one step ahead.
 *
 * Since a non-empty list loops back to HEAD, HEAD's .data==NULL acts
 * as the seintinel; and E is left with that NULL value.
 */

#define FOR_EACH_LIST_ENTRY(HEAD, E)					\
	/* at least one entry? */					\
	for (struct list_entry *E##entry = (HEAD)->newer;		\
	     E##entry != NULL; E##entry = NULL)				\
		/* E=curr, step entry */				\
		for (E = (typeof(E))E##entry->data,			\
			     E##entry = E##entry->newer;		\
		     E != NULL;						\
		     E = (typeof(E))E##entry->data,			\
			     E##entry = E##entry->newer)

#endif
