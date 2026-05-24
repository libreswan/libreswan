/* Open array structure, for libreswan
 *
 * Copyright (C) 2025-2026  Andrew Cagney <cagney@gnu.org>
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

#ifndef TABLE_H
#define TABLE_H

#include "lswalloc.h"

/*
 * Tables:
 *
 * Use C's feature of open ended array:
 *
 *   struct whatever_table {
 *     other stuff;
 *     unsigned len;
 *     <TYPE> table[] COUNTED_BY(len);
 *   }
 *
 */

#define table_alloc(TABLE, COUNT)					\
	({								\
		TABLE *table_ = NULL;					\
		size_t size_ = 0;					\
		size_ += sizeof(*table_);				\
		size_ += sizeof(table_->table[0]) * (COUNT);		\
		table_ = alloc_bytes(size_, "alloc-"#TABLE"-table");	\
		table_->len = (COUNT);					\
		table_;							\
	})

#define table_valloc(TABLE, ...)					\
	({								\
		TABLE *table_ = NULL;					\
		typeof(table_->table[0]) values_[] = { __VA_ARGS__ };	\
		size_t size_ = 0;					\
		size_ += sizeof(*table_);				\
		size_ += sizeof(values_);				\
		table_ = alloc_bytes(size_, "alloc-"#TABLE"-vtable");	\
		table_->len = elemsof(values_);				\
		memmove(table_->table, values_, sizeof(values_));	\
		table_;							\
	})

#define table_grow(TABLE, ...)						\
	({								\
		passert(TABLE != NULL);					\
		typeof((TABLE)->table[0]) values_[] = { __VA_ARGS__ };	\
		unsigned old_len_ = (TABLE)->len;			\
		size_t old_size_ = 0;					\
		old_size_ += sizeof(*(TABLE));				\
		old_size_ += old_len_ * sizeof(values_[0]);		\
		size_t new_size_ = old_size_ + sizeof(values_);		\
		void *table_ = (TABLE);					\
		realloc_bytes(&table_, old_size_, new_size_, "grow-"#TABLE"-table"); \
		(TABLE) = table_;					\
		(TABLE)->len = old_len_ + elemsof(values_);		\
		memmove(&(TABLE)->table[old_len_], values_, sizeof(values_)); \
		(TABLE);						\
	})

/* unfortunately SORTER takes VOID parameters */
#define table_sort(TABLE, SORTER)			\
	({						\
		qsort((TABLE)->table, (TABLE)->len,	\
		      sizeof((TABLE)->table[0]),	\
		      SORTER);				\
	})

#define TABLE_FOR_EACH(ITEM, TABLE)					\
	for (typeof((TABLE)->table[0]) *ITEM = ((TABLE) != NULL ? &(TABLE)->table[0] : NULL); \
	     ITEM != NULL && ITEM < &(TABLE)->table[(TABLE)->len];	\
	     ITEM++)


#define table_len(TABLE) ((TABLE) == NULL ? 0 :	\
			  (TABLE)->len)

#define table_end(TABLE) ((TABLE) == NULL ? NULL :		\
			  ((TABLE)->table + (TABLE)->len));


#endif
