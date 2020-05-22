/* double linked list, for libreswan
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

#ifndef LIST_ENTRY_H
#define LIST_ENTRY_H

/*
 * Description of a list entry, used for logging.
 */

struct list_info {
	const char *name;
	void (*jam)(struct lswlog *buf, const void *data);
};

/*
 * Double linked list entry.
 *
 * Since these are stored directly in the list object there is less
 * memory management overhead.

 * Each list is represented as a doubly-linked cycle, with a
 * distinguished element we call the head.  The head is the
 * only element with .data == NULL.  This acts as a sentinel.
 *
 * For a list_head.head, before initialization, the list head's .newer and
 * .older must be NULL.  After initialization .newer points to the oldest
 * list_entry (list_head.head, if the list is empty) and .older points
 * to the newest.  This seems contradictory, but it serves to bend time
 * into a cycle.
 *
 * For a regular list_entry, .newer and .older are NULL when the the entry
 * is detached from any list.  Otherwise both must be non-NULL.
 *
 * Currently all elements of a list must have identical .info values.
 * This could easily be changed if we needed heterogeneous lists.
 */

struct list_entry {
	struct list_entry *older;
	struct list_entry *newer;
	void *data;
	const struct list_info *info;
};

void jam_list_entry(struct lswlog *buf, const struct list_entry *entry);

/*
 * Double linked list HEAD.
 *
 * INIT_LIST_HEAD() is intended for static structures.  To use it at
 * runtime, prefix the macro with (struct list_head).
 */

struct list_head {
	struct list_entry head;
};

struct list_entry list_entry(const struct list_info *info, void *data);
#define INIT_LIST_HEAD(LIST_HEAD_PTR, LIST_INFO_PTR)		\
	{							\
		.head = {					\
			.info = (LIST_INFO_PTR),		\
			.older = &(LIST_HEAD_PTR)->head,	\
			.newer = &(LIST_HEAD_PTR)->head,	\
		},						\
	}

/*
 * detached_list_entry: test whether an entry is on any list.
 * insert_list_entry: Insert an entry at the front of the list.
 * remove_list_entry: remove the entry from anywhere in the list.
 * The macros *OLD2NEW() and *NEW2OLD(), below, expose the ordering.
 *
 * These operations are O(1).
 */

bool detached_list_entry(const struct list_entry *entry);

void insert_list_entry(struct list_head *list,
		       struct list_entry *entry);
void remove_list_entry(struct list_entry *entry);

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
									\
	/* entry = either first entry or back at head */		\
	for (struct list_entry *entry_ = (HEAD)->head.NEXT;		\
	     entry_ != NULL; entry_ = NULL)				\
									\
		/* DATA = ENTRY->data; ENTRY = ENTRY->NEXT */		\
		for (DATA = (typeof(DATA))entry_->data,			\
			     entry_ = entry_->NEXT;			\
		     DATA != NULL;					\
		     DATA = (typeof(DATA))entry_->data,			\
			     entry_ = entry_->NEXT)

#define FOR_EACH_LIST_ENTRY_OLD2NEW(HEAD, DATA)		\
	FOR_EACH_LIST_ENTRY_(HEAD, DATA, newer)

#define FOR_EACH_LIST_ENTRY_NEW2OLD(HEAD, DATA)		\
	FOR_EACH_LIST_ENTRY_(HEAD, DATA, older)

#endif
