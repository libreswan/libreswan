#define main   spi01main
#define getpid spi01getpid

#include "../../../programs/spigrp/spigrp.c"

#undef main

int main(int argc, char **argv)
{
	debug = 1;
	spi01main(argc, argv);
}

int spi01getpid()
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

	if (lseek(pfkey_sock, 0, SEEK_END) == -1) {
		perror("lseek end");
		exit(2);
	}

	return pfkey_sock;
}

