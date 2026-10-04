/* Flags primitive, for libreswan
 *
 * Copyright (C) 2026 Andrew Cagney
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

#ifndef FLAGS_H
#define FLAGS_H

#include <stdlib.h>
#include <stdbool.h>

#include "lswcdefs.h"
#include "diag.h"

struct names;
struct jambuf;

#define FLAGS(FLAG) { ARRAY_PTR(FLAG), }

struct ro_flags {
	unsigned len;
	const bool *flag COUNTED_BY_PTR(len);
};

#define RO_FLAGS(FLAGS)			\
	(struct ro_flags) {		\
		.len = (FLAGS).len,	\
		.flag = (FLAGS).flag,	\
	}

struct rw_flags {
	unsigned len;
	bool *flag COUNTED_BY_PTR(len);
};

#define RW_FLAGS(FLAGS)			\
	(struct rw_flags) {		\
		.len = (FLAGS).len,	\
		.flag = (FLAGS).flag,	\
	}

diag_t tto_rw_flags(const char *value,
		    struct rw_flags flags,
		    const struct names *names);
#define ttoflags(VALUE, FLAG, NAMES)			\
	tto_rw_flags(VALUE, (struct rw_flags) FLAGS(FLAG), NAMES)

void jam_ro_flags(struct jambuf *buf,
		  struct ro_flags flags,
		  const struct names *names);
#define jam_flags(BUF, FLAG, NAMES)				\
	jam_ro_flags(BUF, (struct ro_flags) FLAGS(FLAG), NAMES)

void jam_ro_flags_human(struct jambuf *buf,
			struct ro_flags flags,
			const struct names *names);
#define jam_flags_human(BUF, FLAG, NAMES)				\
	jam_ro_flags_human(BUF, (struct ro_flags) FLAGS(FLAG), NAMES)

bool ro_flags_set(struct ro_flags flags);

#define flags_op_in2_out1(OP, TYPE, LHS, RHS, ...)			\
	({								\
		struct TYPE result_ = {0};				\
		/* type check */					\
		const struct TYPE *lhs_ = &(LHS);			\
		const struct TYPE *rhs_ = &(RHS);			\
		flags_##OP##_op((struct rw_flags) FLAGS(result_.TYPE),	\
				(struct ro_flags) FLAGS(lhs_->TYPE),	\
				(struct ro_flags) FLAGS(rhs_->TYPE),	\
				##__VA_ARGS__);				\
		result_;						\
	})

#define flags_op_in2_out0(OP, TYPE, LHS, RHS, ...)			\
	({								\
		/* type check */					\
		const struct TYPE *lhs_ = &(LHS);			\
		const struct TYPE *rhs_ = &(RHS);			\
		flags_##OP##_op((struct ro_flags) FLAGS(lhs_->TYPE),	\
				(struct ro_flags) FLAGS(rhs_->TYPE),	\
				##__VA_ARGS__);				\
	})

#define flags_op_in1_out1(OP, TYPE, RHS, ...)				\
	({								\
		struct TYPE result_ = {0};				\
		/* type check */					\
		const struct TYPE *rhs_ = &(RHS);			\
		flags_##OP##_op((struct rw_flags) FLAGS(result_.TYPE),	\
				(struct ro_flags) FLAGS(rhs_->TYPE),	\
				##__VA_ARGS__);				\
		result_;						\
	})

#define flags_op_in1_out0(OP, TYPE, RHS, ...)				\
	({								\
		/* type check */					\
		const struct TYPE *rhs_ = &(RHS);			\
		flags_##OP##_op((struct ro_flags) FLAGS(rhs_->TYPE),	\
				##__VA_ARGS__);				\
	})

void flags_and_op(struct rw_flags and, struct ro_flags lhs, struct ro_flags rhs);
void flags_or_op(struct rw_flags or, struct ro_flags lhs, struct ro_flags rhs);

#define flags_and(TYPE, LHS, RHS) flags_op_in2_out1(and, TYPE, LHS, RHS)
#define flags_or(TYPE, LHS, RHS) flags_op_in2_out1(or, TYPE, LHS, RHS)

void flags_not_op(struct rw_flags not, struct ro_flags rhs);
#define flags_not(TYPE, RHS) flags_op_in1_out1(not, TYPE, RHS)

unsigned flags_count_op(struct ro_flags rhs);
#define flags_count(TYPE, RHS) flags_op_in1_out0(count, TYPE, RHS)

bool flags_eq_op(struct ro_flags lhs, struct ro_flags rhs);
#define flags_eq(TYPE, LHS, RHS) flags_op_in2_out0(eq, TYPE, LHS, RHS)

bool flags_has_all_op(struct ro_flags lhs, struct ro_flags rhs);
bool flags_has_any_op(struct ro_flags lhs, struct ro_flags rhs);
bool flags_has_none_op(struct ro_flags lhs, struct ro_flags rhs);

#define flags_has_all(TYPE, LHS, RHS) flags_op_in2_out0(has_all, TYPE, LHS, RHS)
#define flags_has_any(TYPE, LHS, RHS) flags_op_in2_out0(has_any, TYPE, LHS, RHS)
#define flags_has_none(TYPE, LHS, RHS) flags_op_in2_out0(has_none, TYPE, LHS, RHS)
#define flags_has_flag(TYPE, RHS, FLAG) ((RHS).TYPE[FLAG])

void flags_and_flag_op(struct rw_flags and, struct ro_flags lhs, unsigned rhs);
void flags_or_flag_op(struct rw_flags or, struct ro_flags lhs, unsigned rhs);
#define flags_and_flag(TYPE, LHS, RHS) flags_op_in1_out1(and_flag, TYPE, LHS, RHS)
#define flags_or_flag(TYPE, LHS, RHS) flags_op_in1_out1(or_flag, TYPE, LHS, RHS)

#define flags_from_flag(TYPE, FLAG)					\
	({								\
		struct TYPE flags_ = {0};				\
		flags_.TYPE[FLAG] = true;				\
		flags_;							\
	})

#endif
