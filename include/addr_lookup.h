#include <stdbool.h>

struct starter_end;
struct logger;

int resolve_defaultroute_one(struct starter_end *host,
			     struct starter_end *peer, bool verbose,
			     struct logger *logger);
