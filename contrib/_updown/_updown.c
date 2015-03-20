/* $Id: _updown.c,v 1.1 2005/07/21 20:42:57 ken Exp $
 *
 * THIS IS OBSOLETE - It is no longer functionally identical to the scripts
 *
 *
 * This program is replacement for /usr/local/lib/ipsec/_updown script
 * and its functionality is identical.
 *
 * Installation:
 * 1. Compile with "gcc -O2 -o updown updown.c"
 * 2. Install "cp -f updown /usr/local/lib/ipsec"
 * 3. Update your configs so that they include leftupdown and rightupdown
 * keywords, e.g.:
 *
 * conn test
 *   ...
 *   leftupdown=/usr/local/lib/ipsec/updown
 *   rightupdown=/usr/local/lib/ipsec/updown
 *   ...
 *
 * Characteristics:
 * - written in C, thus faster and less resource intensive than shell script
 * - uses iptables
 * - doesn't yet support opportunistic encryption
 *
 * Written by Pawel Krawczyk <kravietz at aba.krakow.pl>
 *
 * License: GPLv2.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char *load(const char *what);
int my_system(char *bin, char **argv);

int main(void)
{
	char *pluto_verb;
	char *pluto_peer_client;
	char *pluto_interface;
	char *pluto_me;
	char *pluto_my_client;
	char *argv[20];
	int status;
	int testing = 0;

	if ( load("UPDOWN_TESTING") == NULL)
		chdir("/etc");
	else
		testing = 1;

	/* Wczytujemy zmienne przekazane nam przez Pluto */
	pluto_verb = load("PLUTO_VERB");
	if (pluto_verb == NULL) {
		fprintf(stderr, "PLUTO_VERB not set\n");
		return 1;
	}
	pluto_peer_client = load("PLUTO_PEER_CLIENT");
	if (pluto_peer_client == NULL) {
		fprintf(stderr, "PLUTO_PEER_CLIENT not set\n");
		return 1;
	}
	pluto_interface = load("PLUTO_INTERFACE");
	if (pluto_interface == NULL) {
		fprintf(stderr, "PLUTO_INTERFACE not set\n");
		return 1;
	}
	pluto_me = load("PLUTO_ME");
	if (pluto_me == NULL) {
		fprintf(stderr, "PLUTO_ME not set\n");
		return 1;
	}
	pluto_my_client = load("PLUTO_MY_CLIENT");
	if (pluto_my_client == NULL) {
		fprintf(stderr, "PLUTO_MY_CLIENT not set\n");
		return 1;
	}

	/* Dodajemy lub usuwamy routing w zaleznosci od
	 * polecenia przekazanego w PLUTO_VERB
	 */
	if (strncmp(pluto_verb, "route-", 6) == 0 ||
	    strncmp(pluto_verb, "up-", 3) == 0) {

		argv[0] = "/bin/ip";
		argv[1] = "route";
		argv[2] = "add";
		argv[3] = pluto_peer_client;
		argv[4] = "dev";
		argv[5] = pluto_interface;
		argv[6] = "via";
		argv[7] = pluto_me;
		argv[8] = 0;
		if (!testing) {
			status = my_system("/bin/ip", argv);
			if (status != 0)
				return status;
		} else {
			printf("route add %s\n", pluto_peer_client);
		}
	}

	if (strncmp(pluto_verb, "unroute-", 8) == 0 ||
	    strncmp(pluto_verb, "down-", 5) == 0) {

		argv[0] = "/bin/ip";
		argv[1] = "route";
		argv[2] = "del";
		argv[3] = pluto_peer_client;
		argv[4] = "dev";
		argv[5] = pluto_interface;
		argv[6] = "via";
		argv[7] = pluto_me;
		argv[8] = 0;
		if (!testing) {
			status = my_system("/bin/ip", argv);
			if (status != 0)
				return status;
		} else {
			printf("route del %s\n", pluto_peer_client);
		}

	}

	if (strncmp(pluto_verb, "prepare-", 8) == 0) {

		argv[0] = "/bin/ip";
		argv[1] = "route";
		argv[2] = "del";
		argv[3] = pluto_peer_client;
		argv[4] = 0;
		if (!testing) {
			/* We ignore any errors from this command,
			 * as it's used to clear up any routes that
			 * may or may not be present.
			 */
			int null = open("/dev/null", O_WRONLY);
			dup2(null, 1);
			dup2(null, 2);
			status = my_system("/bin/ip", argv);
		} else {
			printf("prepare del %s\n", pluto_my_client);
		}

	}

	return 0;
}

char *load(const char *what)
{
	char *tmp, *tmp1;

	tmp1 = getenv(what);
	if (tmp1 == NULL)
		return NULL;

	tmp = strchr(tmp1, '=');
	if (tmp != NULL) {
		tmp++;
		tmp1 = tmp;
	}

	return tmp1;
}

int my_system(char *bin, char **argv)
{
	int status, pid;

	pid = vfork();
	if (pid == -1)
		return 1;

	if (pid == 0) {
		execv(bin, argv);
		return 127;
	}
	do {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR)
				return 1;
		} else {
			return status;
		}
	} while (1);
}

