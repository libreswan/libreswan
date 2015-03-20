#define main eroute01main
#define getpid eroute01getpid

#include "../../../programs/eroute/eroute.c"

#undef main

int main(int argc, char **argv)
{
	debug = 1;
	eroute01main(argc, argv);
}

int eroute01getpid()
{
	return 9999;
}

int pfkey_open_sock_with_error(void)
{
	int pfkey_sock = -1;

	pfkey_sock = open("pfkey.out", O_RDWR | O_CREAT, 0644);

	if (pfkey_sock == -1) {
		perror("pfkey.out");
		exit(1);
	}

	return pfkey_sock;
}

