/* double linked list, for libreswan
 *
 * Copyright (C) 2015, 2017 Andrew Cagney
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

#ifndef _list_entry_h_
#define _list_entry_h_

/*
 * Description of a list entry, used for logging.
 */

struct list_info {
	lset_t debug;
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
 * NULL.  It makes debugging easier.
 */

struct list_entry {
	struct list_entry *older;
	struct list_entry *newer;
	void *data;
	const struct list_info *info;
};

/*
 * Double linked list HEAD.
 */

struct list_head {
	struct list_entry head;
};

void init_list(const struct list_info *info, struct list_head *list);
struct list_entry list_entry(const struct list_info *info, void *data);

/*
 * Insert (at front) or remove the object from the linked list.  The
 * macros *OLD2NEW() and *NEW2OLD(), below, determine the apparent
 * ordering.
 *
 * These operations are O(1).
 */

void insert_list_entry(struct list_head *list,
		       struct list_entry *entry);
bool remove_list_entry(struct list_entry *entry);

/*
 * Iterate through all the entries in the list in either old-to-new or
 * new-to-old order.
 *
 * So that the current entry can be deleted, the E##entry pointer is
 * always on the next entry.
 *
 * Since a non-empty list loops back to HEAD, HEAD's .data==NULL acts
 * as the sentinel; and DATA is left with that NULL value.
 */

#define FOR_EACH_LIST_ENTRY_(HEAD, DATA, NEXT)				\
	/* head.NEXT is never NULL */					\
	for (struct list_entry *DATA##entry = (HEAD)->head.NEXT;	\
	     DATA##entry != &(HEAD)->head;				\
	     DATA##entry = &(HEAD)->head)				\
		/* DATA = ENTRY->data; ENTRY = ENTRY->NEXT */		\
		for (DATA = (typeof(DATA))DATA##entry->data,		\
			     DATA##entry = DATA##entry->NEXT;		\
		     DATA != NULL;					\
		     DATA = (typeof(DATA))DATA##entry->data,		\
			     DATA##entry = DATA##entry->NEXT)

#define FOR_EACH_LIST_ENTRY_OLD2NEW(HEAD, DATA)		\
	FOR_EACH_LIST_ENTRY_(HEAD, DATA, newer)

#define FOR_EACH_LIST_ENTRY_NEW2OLD(HEAD, DATA)		\
	FOR_EACH_LIST_ENTRY_(HEAD, DATA, older)

#endif
