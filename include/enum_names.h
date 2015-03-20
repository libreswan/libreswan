/* structure for use by constant->name array. This is private. */
struct enum_names {
	unsigned long en_first;                 /* first value in range */
	unsigned long en_last;                  /* last value in range (inclusive) */
	const char *const *en_names;
	const struct enum_names *en_next_range; /* descriptor of next range */
};
