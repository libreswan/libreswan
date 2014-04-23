#include <stdarg.h>

void whack_log(int rc, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	fprintf(stderr, "RC=%u ", rc);
	vfprintf(stderr, msg, args);
	putc('\n', stderr);
	va_end(args);
}

struct state;

void release_pending_whacks(struct state *st, err_t story)
{
}

