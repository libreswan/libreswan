
/*
 * For stand-alone tools.
 *
 * XXX: can "progname" be made private to lswlog.c?
 */
extern const char *progname;
extern void tool_init_log(const char *progname);
extern void tool_close_log(void);
