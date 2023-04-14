
/*
 * For stand-alone tools.
 *
 * XXX: can "progname" be made private to lswlog.c?
 */
struct logger;
extern const char *progname;
struct logger *tool_logger(int argc, char *argv[]);
