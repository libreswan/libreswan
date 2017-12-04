
/*
 * For stand-alone tools.
 *
 * XXX: can "progname" be made private to lswlog.c?
 */
extern char *progname;
extern void tool_init_log(char *progname);
extern void tool_close_log(void);
