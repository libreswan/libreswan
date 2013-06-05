#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* no rate limiting for test cases */
int printk_ratelimit(void)
{
	return 1;
}

int printk(char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int r = 0;

	va_start(ap, fmt);
	if (fmt != NULL) {
		r = vsnprintf(buf, sizeof(buf), fmt, ap);
		fputs(buf, stdout);
	}
	va_end(ap);

	fflush(stdout);

	return r;
}

void barf(const char *msg)
{
	printf("barf: %s\n", msg);
	lsw_abort();
}

