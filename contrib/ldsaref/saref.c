#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <ipsec_saref.h>

typedef int (*socket_fn)(int, int, int);
static socket_fn real_socket = NULL;
static int saref = 0;
#define UNASSIGNED_SAREF 0
#define INVALID_SAREF (-1)

int socket(int domain, int type, int protocol)
{
	int sk, rc;

	if (real_socket == NULL)
		real_socket = (socket_fn)dlsym(RTLD_NEXT, "socket");

	sk = real_socket(domain, type, protocol);

	if (saref == UNASSIGNED_SAREF) {
		const char *str;

		saref = INVALID_SAREF;
		str = getenv("IPSEC_SAREF");
		if (str != NULL) {
			char tmp = 0;

			rc = sscanf(str, "%u%c", &saref, &tmp);
			if (rc != 1)
				saref = INVALID_SAREF;
		}
	}

	if (saref != UNASSIGNED_SAREF && saref != INVALID_SAREF)
		(void) setsockopt(sk, IPPROTO_IP, IP_IPSEC_BINDREF, &saref,
				  sizeof(saref));

	return sk;
}
