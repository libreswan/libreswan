#include <stdbool.h>

struct starter_end;
struct logger;

enum resolve_status {
	RESOLVE_FAILURE = -1,
	RESOLVE_SUCCESS = 0,
	RESOLVE_PLEASE_CALL_AGAIN = 1,
};

enum resolve_status resolve_defaultroute_one(struct starter_end *host,
					     struct starter_end *peer,
					     lset_t verbose_rc_flags,
					     struct logger *logger);
