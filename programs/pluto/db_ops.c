/*
 * Dynamic db (proposal, transforms, attributes) handling.
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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

/*
 * The strategy is to have (full contained) struct db_prop in db_context
 * pointing to ONE dynamically sizable transform vector (trans0).
 * Each transform stores attrib. in ONE dyn. sizable attribute vector (attrs0)
 * in a "serialized" way (attributes storage is used in linear sequence for
 * subsequent transforms).
 *
 * Resizing for both trans0 and attrs0 is supported:
 * - For trans0: quite simple, just allocate and copy trans. vector content
 *               also update trans_cur (by offset)
 * - For attrs0: after allocating and copying attrs, I must rewrite each
 *               trans->attrs present in trans0; to achieve this, calculate
 *               attrs pointer offset (new minus old) and iterate over
 *               each transform "adding" this difference.
 *               also update attrs_cur (by offset)
 *
 * db_context structure:
 *      +---------------------+
 *	|  prop               |
 *	|    .protoid         |
 *	|    .trans           | --+
 *	|    .trans_cnt       |   |
 *	+---------------------+ <-+
 *	|  trans0             | ----> { trans#1 | ... | trans#i | ...   }
 *	+---------------------+                       ^
 *	|  trans_cur          | ----------------------' current transf.
 *	+---------------------+
 *	|  attrs0             | ----> { attr#1 | ... | attr#j | ...  }
 *	+---------------------+                      ^
 *	|  attrs_cur          | ---------------------' current attr.
 *	+---------------------+
 *	| max_trans,max_attrs |  max_trans/attrs: number of elem. of each vector
 *	+---------------------+
 *
 * See testing examples at end for interface usage.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "packet.h"
#include "spdb.h"
#include "db_ops.h"
#include "log.h"
#include "whack.h"

#include <assert.h>

/*
 * stats: do accounting for allocations displayed in db_ops_show_status()
 */
struct db_ops_stats {
	int st_curr_cnt;        /* current number of allocations */
	int st_total_cnt;       /* total allocations so far */
	size_t st_maxsz;        /* max. size requested */
};
#define DB_OPS_ZERO { 0, 0, 0 };
#define DB_OPS_STATS_DESC   "{curr_cnt, total_cnt, maxsz}"
#define DB_OPS_STATS_STR(name)  name "={%d,%d,%d} "
#define DB_OPS_STATS_F(st) (st).st_curr_cnt, (st).st_total_cnt, \
	(int)(st).st_maxsz
static struct db_ops_stats db_context_st = DB_OPS_ZERO;
static struct db_ops_stats db_trans_st = DB_OPS_ZERO;
static struct db_ops_stats db_attrs_st = DB_OPS_ZERO;
static __inline__ void * alloc_bytes_st(size_t size, const char *str,
					struct db_ops_stats *st)
{
	void *ptr = alloc_bytes(size, str);

	st->st_curr_cnt++;
	st->st_total_cnt++;
	if (size > st->st_maxsz)
		st->st_maxsz = size;
	return ptr;
}
#define ALLOC_BYTES_ST(z, s, st) alloc_bytes_st(z, s, &(st));
#define PFREE_ST(p, st)         { st.st_curr_cnt--; pfree(p);  }

/*
 * Initialize db object
 *
 * max_trans and max_attrs can be 0, will be dynamically expanded
 * as a result of "add" operations
 */
static void db_prop_init(struct db_context *ctx, uint8_t protoid, int max_trans,
		 int max_attrs)
{
	ctx->trans0 = NULL;
	ctx->attrs0 = NULL;

	if (max_trans > 0) {
		ctx->trans0 = ALLOC_BYTES_ST(
			sizeof(struct db_trans) * max_trans,
			"db_context->trans",
			db_trans_st);
	}

	if (max_attrs > 0) {
		ctx->attrs0 = ALLOC_BYTES_ST(
			sizeof(struct db_attr) * max_attrs,
			"db_context->attrs", db_attrs_st);
	}

	ctx->max_trans = max_trans;
	ctx->max_attrs = max_attrs;
	ctx->trans_cur = ctx->trans0;
	ctx->attrs_cur = ctx->attrs0;
	ctx->prop.protoid = protoid;
	ctx->prop.trans = ctx->trans0;
	ctx->prop.trans_cnt = 0;
}

/* Expand storage for transforms by number delta_trans */
static void db_trans_expand(struct db_context *ctx, int delta_trans)
{
	int max_trans = ctx->max_trans + delta_trans;
	struct db_trans *const old_trans = ctx->trans0;
	struct db_trans *const new_trans = ALLOC_BYTES_ST(sizeof(struct db_trans) * max_trans,
				    "db_context->trans (expand)", db_trans_st);

	memcpy(new_trans, old_trans, ctx->max_trans * sizeof(struct db_trans));

	/* update trans0 (obviously) */
	ctx->trans0 = ctx->prop.trans = new_trans;

	/* update trans_cur (by offset) */
	ctx->trans_cur = ctx->trans_cur - old_trans + new_trans;

	/* update elem count */
	ctx->max_trans = max_trans;

	if (old_trans != NULL)
		PFREE_ST(old_trans, db_trans_st);
}

/*
 * Expand storage for attributes by delta_attrs number AND
 * adjust pointers into trans->attr
 */
static void db_attrs_expand(struct db_context *ctx, int delta_attrs)
{
	unsigned int ti;
	int max_attrs = ctx->max_attrs + delta_attrs;
	struct db_attr *const old_attrs = ctx->attrs0;
	struct db_attr *const new_attrs = ALLOC_BYTES_ST(sizeof(struct db_attr) * max_attrs,
				    "db_context->attrs (expand)", db_attrs_st);

	memcpy(new_attrs, old_attrs, ctx->max_attrs * sizeof(struct db_attr));

	/*
	 * Relocate pointers into ctx->attrs.
	 * Note: C addition is NOT associative (due to scaling)
	 */
	ctx->attrs0 = ctx->attrs0 - old_attrs + new_attrs;
	ctx->attrs_cur = ctx->attrs_cur - old_attrs + new_attrs;

	for (ti = 0; ti < ctx->prop.trans_cnt; ti++)
		ctx->prop.trans[ti].attrs = ctx->prop.trans[ti].attrs - old_attrs + new_attrs;

	/* update elem count */
	ctx->max_attrs = max_attrs;

	if (old_attrs != NULL)
		PFREE_ST(old_attrs, db_attrs_st);
}

/* Allocate a new db object */
struct db_context *db_prop_new(uint8_t protoid, int max_trans, int max_attrs)
{
	struct db_context *ctx = ALLOC_BYTES_ST(sizeof(struct db_context), "db_context",
			      db_context_st);

	db_prop_init(ctx, protoid, max_trans, max_attrs);
	return ctx;
}

/* Free a db object */
void db_destroy(struct db_context *ctx)
{
	if (ctx->trans0 != NULL)
		PFREE_ST(ctx->trans0, db_trans_st);
	if (ctx->attrs0 != NULL)
		PFREE_ST(ctx->attrs0, db_attrs_st);
	PFREE_ST(ctx, db_context_st);
}

/* Start a new transform, expand trans0 is needed */
void db_trans_add(struct db_context *ctx, uint8_t transid)
{
	passert(ctx->trans_cur != NULL);
	/*	skip incrementing current trans pointer the 1st time*/
	if (ctx->trans_cur->attr_cnt != 0)
		ctx->trans_cur++;
	/*
	 *	Strategy: if more space is needed, expand by
	 *	          <current_size>/2 + 1
	 *
	 *	This happens to produce a "reasonable" sequence
	 *	after few allocations, eg.:
	 *	0,1,2,4,8,13,20,31,47
	 */
	if ((ctx->trans_cur - ctx->trans0) >= ctx->max_trans) {
		db_trans_expand(ctx, ctx->max_trans / 2 + 1);
	}
	ctx->trans_cur->transid = transid;
	ctx->trans_cur->attrs = ctx->attrs_cur;
	ctx->trans_cur->attr_cnt = 0;
	ctx->prop.trans_cnt++;
}

/* Add attr copy to current transform, expanding attrs0 if needed */
static void db_attr_add(struct db_context *ctx, const struct db_attr *a)
{
	/*
	 *	Strategy: if more space is needed, expand by
	 *	          <current_size>/2 + 1
	 */
	if ((ctx->attrs_cur - ctx->attrs0) >= ctx->max_attrs) {
		db_attrs_expand(ctx, ctx->max_attrs / 2 + 1);
	}
	*ctx->attrs_cur++ = *a;
	ctx->trans_cur->attr_cnt++;
}

/*
 * Add attr copy (by value) to current transform,
 * expanding attrs0 if needed, just calls db_attr_add().
 */
void db_attr_add_values(struct db_context *ctx,  enum ikev1_oakley_attr type, uint16_t val)
{
	struct db_attr attr;

	/* ??? is this always an Oakley (IKEv1 Phase 1) attribute? */
	attr.type.oakley = type;
	attr.val = val;
	db_attr_add(ctx, &attr);
}

void db_ops_show_status(void)
{
	whack_log(RC_COMMENT, "stats db_ops: "
		  DB_OPS_STATS_DESC " :"
		  DB_OPS_STATS_STR("context")
		  DB_OPS_STATS_STR("trans")
		  DB_OPS_STATS_STR("attrs"),
		  DB_OPS_STATS_F(db_context_st),
		  DB_OPS_STATS_F(db_trans_st),
		  DB_OPS_STATS_F(db_attrs_st));
}
