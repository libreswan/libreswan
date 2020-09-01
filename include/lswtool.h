
/*
 * For stand-alone tools.
 *
 * XXX: can "progname" be made private to lswlog.c?
 */
struct logger;
extern const char *progname;
struct logger *tool_init_log(const char *progname);
