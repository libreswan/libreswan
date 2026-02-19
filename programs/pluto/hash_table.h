/* hash table and linked lists, for libreswan
 *
 * Copyright (C) 2015, 2017, 2019 Andrew Cagney
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

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include "list_entry.h"
#include "shunk.h"		/* has constant ptr */
#include "where.h"

/*
 * Generic hash table.
 */

typedef struct { unsigned hash; } hash_t;
extern const hash_t zero_hash;

struct hash_table {
	const struct list_info *const info;
	hash_t (*hasher)(const void *data);
	struct list_entry *(*entry)(void *data);
	long nr_entries; /* approx? */
	unsigned long nr_slots;
	struct list_head *slots;
};

#define HASH_TABLE(STRUCT, NAME, FIELD, NR_BUCKETS)			\
									\
	LIST_INFO(STRUCT, STRUCT##_db_entries.NAME,			\
		  STRUCT##_##NAME##_hash_info, jam_##STRUCT);		\
									\
	static hash_t hash_table_hash_##STRUCT##_##NAME(const void *data) \
	{								\
		const struct STRUCT *s = data;				\
		return hash_##STRUCT##_##NAME(&(*s)FIELD);		\
	}								\
									\
	static struct list_head STRUCT##_##NAME##_buckets[NR_BUCKETS];	\
									\
	static struct list_entry *hash_table_entry_##STRUCT##_##NAME(void *data) \
	{								\
		struct STRUCT *s = data;				\
		return &s->STRUCT##_db_entries.NAME;			\
	}								\
									\
	struct hash_table STRUCT##_##NAME##_hash_table = {		\
		.hasher = hash_table_hash_##STRUCT##_##NAME,		\
		.entry = hash_table_entry_##STRUCT##_##NAME,		\
		.nr_slots = NR_BUCKETS,					\
		.slots = STRUCT##_##NAME##_buckets,			\
		.info = &STRUCT##_##NAME##_hash_info,			\
	}

void init_hash_table(struct hash_table *table, struct logger *logger);
void check_hash_table(struct hash_table *table,
		      const struct logger *logger,
		      where_t where);

hash_t hash_bytes(const void *ptr, size_t len, hash_t hash);
#define hash_hunk(HUNK, HASH)						\
	({								\
		typeof(HUNK) h_ = HUNK; /* evaluate once */		\
		hash_bytes(h_.ptr, h_.len, HASH);			\
	})
#define hash_thing(THING, HASH)						\
	({								\
		shunk_t h_ = THING_AS_SHUNK(THING); /* evaluate once */	\
		hash_bytes(h_.ptr, h_.len, HASH);			\
	})

/*
 * Maintain the table.
 *
 * Use the terms "add" and "del" as this table has no true ordering
 * beyond new being the most recent insertion - rehash does "del" then
 * "add" which re-orders things.
 */

void init_hash_table_entry(struct hash_table *table, void *data);
void add_hash_table_entry(struct hash_table *table, void *data);
void del_hash_table_entry(struct hash_table *table, void *data);

#define HASH_DB(STRUCT, TABLE, ...)					\
									\
	/* backup list for when there is no accelerator */		\
									\
	LIST_INFO(STRUCT, STRUCT##_db_entries.list,			\
		  STRUCT##_db_list_info, jam_##STRUCT);			\
									\
	static struct list_head STRUCT##_db_list_head =			\
		INIT_LIST_HEAD(&STRUCT##_db_list_head,			\
			       &STRUCT##_db_list_info);			\
									\
	struct hash_table *const STRUCT##_db_hash_tables[] = {		\
		TABLE, ##__VA_ARGS__,					\
	};								\
									\
	void STRUCT##_db_init(struct logger *logger)			\
	{								\
		FOR_EACH_ELEMENT(h, STRUCT##_db_hash_tables) {		\
			init_hash_table(*h, logger);			\
		}							\
	}								\
									\
	void STRUCT##_db_check(const struct logger *logger,		\
			       where_t where)				\
	{								\
		FOR_EACH_ELEMENT(h, STRUCT##_db_hash_tables) {		\
			check_hash_table(*h, logger, where);		\
		}							\
	}								\
									\
	void STRUCT##_db_init_##STRUCT(struct STRUCT *s)		\
	{								\
		init_list_entry(&STRUCT##_db_list_info, s,		\
				&s->STRUCT##_db_entries.list);		\
		FOR_EACH_ELEMENT(H, STRUCT##_db_hash_tables) {		\
			init_hash_table_entry(*H, s);			\
		}							\
	}								\
									\
	void STRUCT##_db_add(struct STRUCT *s)				\
	{								\
		insert_list_entry(&STRUCT##_db_list_head,		\
				  &s->STRUCT##_db_entries.list);	\
		FOR_EACH_ELEMENT(H, STRUCT##_db_hash_tables) {		\
			add_hash_table_entry(*H, s);			\
		}							\
	}								\
									\
	void STRUCT##_db_del(struct STRUCT *s)				\
	{								\
		remove_list_entry(&s->STRUCT##_db_entries.list);	\
		FOR_EACH_ELEMENT(h, STRUCT##_db_hash_tables) {		\
			del_hash_table_entry(*h, s);			\
		}							\
	}

/* not all code requires rehashing */

#define REHASH_DB(STRUCT)					\
	void STRUCT##_db_rehash(struct STRUCT *s)		\
	{							\
		FOR_EACH_ELEMENT(h, STRUCT##_db_hash_tables) {	\
			del_hash_table_entry(*h, s);		\
			add_hash_table_entry(*h, s);		\
		}						\
	}

#define REHASH_DB_ENTRY(STRUCT, NAME, FIELD)				\
	void STRUCT##_db_rehash_##NAME(struct STRUCT *s)		\
	{								\
		del_hash_table_entry(&STRUCT##_##NAME##_hash_table, s);	\
		add_hash_table_entry(&STRUCT##_##NAME##_hash_table, s);	\
	}

/*
 * Return the head of the list entries that match HASH.
 *
 * Use this, in conjunction with FOR_EACH_LIST_ENTRY, when searching.
 *
 * Don't forget to also check that the object itself matches - more
 * than one hash can map to the same list of entries.
 */

struct list_head *hash_table_bucket(struct hash_table *table, hash_t hash);

#endif
