#define IPLEN		100	/* Max length for IP address/mask string */

int is_encrypted(char *destination, int port, char *source, int timeout,
		int debug);
