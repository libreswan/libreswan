/*	db_ops.h,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp	*/
#ifndef _DB_OPS_H
#define _DB_OPS_H

#include "spdb.h"

/*
 * 	Main db object, (quite proposal "oriented")
 */
struct db_context {
	struct db_prop prop;		/* proposal buffer (not pointer) */
	struct db_trans *trans0;	/* transf. list, dynamically sized */
	struct db_trans *trans_cur;	/* current transform ptr */
	struct db_attr *attrs0;		/* attr. list, dynamically sized */
	struct db_attr *attrs_cur;	/* current attribute ptr */
	int max_trans;			/* size of trans list */
	int max_attrs;			/* size of attrs list */
};

/*
 * 	Allocate a new db object
 */
struct db_context * db_prop_new(u_int8_t protoid, int max_trans, int max_attrs);

/*	Initialize object for proposal building  */
int db_prop_init(struct db_context *ctx, u_int8_t protoid, int max_trans, int max_attrs);

/*	Free all resourses for this db */
void db_destroy(struct db_context *ctx);

/*	Start a new transform */
int db_trans_add(struct db_context *ctx, u_int8_t transid);
/*	Add a new attribute by copying db_attr content */
int db_attr_add(struct db_context *db_ctx, const struct db_attr *attr);
/*	Add a new attribute by value */
int db_attr_add_values(struct db_context *ctx,  u_int16_t type, u_int16_t val);

/*	Get proposal from db object */
static __inline__ struct db_prop *db_prop_get(struct db_context *ctx) {
	return &ctx->prop;
}
/*	Show stats (allocation, etc) */
int db_ops_show_status(void);

extern void db_print(struct db_context *ctx);

#endif /* _DB_OPS_H */
