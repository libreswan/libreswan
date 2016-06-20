/* table structure used by enum_name() and friends.
 *
 * Note: this structure is opaque to all files that don't
 * define tables for enum_name() and friends.
 */
struct enum_names {
	unsigned long en_first;                 /* first value in range */
	unsigned long en_last;                  /* last value in range (inclusive) */
	const char *const *en_names;
	size_t en_checklen;	/* for checking: elemsof(en_names) == en_last-enfirst+1 */
	const struct enum_names *en_next_range; /* descriptor of next range */
};

struct enum_enum_names {
	unsigned long een_first;		/* first value in range */
	unsigned long een_last;			/* last value in range (inclusive) */
	const struct enum_names *const *const een_enum_name;	/* actual table to use, subscripted by previous enum */
	size_t een_checklen;	/* for checking: elemsof(een_names) == een_last-enfirst+1 */
};

/*
 * To simplify initializing
 *	en_names, en_checklen
 *	een_enum_names, een_checklen
 *
 * NOTE: this is by nature a scary macro because it
 * is used to initialized two fields.
 * This has a hacky advantage:
 * if you don't wish to count the last element of
 * the array (say, because it is a NULL there for
 * bitnamesof), just use ARRAY_REF()-1!
 */
#define ARRAY_REF(p) (p), elemsof(p)

/* to check that enum_names are consistent */
extern void check_enum_names(enum_names *checklist[], size_t tl);
