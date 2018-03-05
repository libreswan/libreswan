#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "swan.h"

/* Parse args and call is_encrypted() from swan.c */
int main(int argc, char *argv[])
{
	char source_ip[IPLEN + 1], dest_ip[IPLEN + 1];
	int debug = 0, port = 0;

	*source_ip = 0;
	*dest_ip = 0;
	for (;;) {
		static struct option long_options[] = {
			{"debug",  no_argument,       0, 1},
			{"source", required_argument, 0, 2},
			{"port",   required_argument, 0, 3},
			{0, 0, 0, 0}
		};
		int option_index = 0, opt;

		opt = getopt_long(argc, argv, "", long_options, &option_index);
		if (opt == -1)
			break;

		switch (opt) {
		case 1:
			debug = 1;
			break;

		case 2:
			strncpy(source_ip, optarg, IPLEN);
			source_ip[IPLEN] = 0;
			break;

		case 3:
			port = atoi(optarg);
			break;

		default:
			exit(1);
		}
	}

	if (optind != argc - 1) {
		printf("No destination IP address specified\n");
		exit(1);
	}
	strncpy(dest_ip, argv[optind], IPLEN);
	dest_ip[IPLEN] = 0;

	int ret = is_encrypted(dest_ip, port, source_ip, 2, debug);
	printf("%s\n", ret ? "True" : "False");
	return ret;
}
