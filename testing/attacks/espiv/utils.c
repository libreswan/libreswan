#include "ipsec_hack.h"

static int read_hex_int(char *c)
{
	unsigned int result = 0;

	while (*c != '\0') {

		if (*c >= '0' && *c <= '9')
			result = (result << 4) | (*c - '0');
		else if (*c >= 'a' && *c <= 'f')
			result = (result << 4) | (*c - 'a' + 10);
		/* else silently ignore *c */

		c++;
	}
	return result;
}

static u8 read_byte(u8 *c, u8 endmark)
{
	u8 result = 0;

	while (*c != endmark && *c != '\0') {

		if (*c >= '0' && *c <= '9')
			result = (result << 4) | (*c - '0');
		else if (*c >= 'a' && *c <= 'f')
			result = (result << 4) | (*c - 'a' + 10);
		/* else silently ignore *c */

		c++;
	}
	return result;
}

static void read_mac(u8 *c, u8 *mac)
{
	/* This function assumes that mac is format xx:xx:xx:xx:xx:xx */
	int i;

	for (i = 0; i < 6; i++)
		mac[i] = read_byte(c + (i * 3), ':');
}

static void read_block(u8 *c, u8 *block)
{
	/* This function assumes that block is format xx:xx:xx:xx:xx:xx:xx:xx */
	int i;

	for (i = 0; i < 8; i++)
		block[i] = read_byte(c + (i * 3), ':');
}

static u32 read_dotted_ipv4_address(u8 *str)
{
	u32 result = 0;
	u8 temp = 0;

	while (*str != '\0') {
		if (*str >= '0' && *str <= '9') {
			temp *= 10;
			temp += *str - '0';
		} else if (*str == '.') {
			result = (result << 8) | temp;
			temp = 0;
		}

		str++;
	}
	result = (result << 8) | temp;
	return result;
}

u16 ipheader_checksum(u16 *buffer, u16 len)
{
	u32 check = 0;

	while (len-- > 0)
		check += (u32)(*buffer++);
	while (check >> 16)
		check = (check & 0x0000ffff) + (check >> 16);
	return (u16)(check == 0 ? 0 : ~check);
}

void ipv4_print_address(u32 address)
{
	printf("%ld.%ld.%ld.%ld",
	       ((address & 0x000000ff) >> 0),
	       ((address & 0x0000ff00) >> 8),
	       ((address & 0x00ff0000) >> 16),
	       ((address & 0xff000000) >> 24));
}

static int read_arguments_from_file(char *fname, option_data *opt);	/* forward */

static void parse_option(char *arg, option_data *opt)
{
	if (strncmp("file=", arg, 5) == 0)
		read_arguments_from_file((arg + 5), opt);
	if (strncmp("src=", arg, 4) == 0)
		opt->src_address = read_dotted_ipv4_address(arg + 4);
	if (strncmp("dst=", arg, 4) == 0)
		opt->dst_address = read_dotted_ipv4_address(arg + 4);
	if (strncmp("fake_src=", arg, 9) == 0)
		opt->fake_src_address = read_dotted_ipv4_address(arg + 9);
	if (strncmp("gw=", arg, 3) == 0)
		opt->gw = read_dotted_ipv4_address(arg + 3);
	if (strncmp("fake_dst=", arg, 9) == 0)
		opt->fake_dst_address = read_dotted_ipv4_address(arg + 9);
	if (strncmp("spi=", arg, 4) == 0)
		opt->spi = read_hex_int(arg + 4);
	if (strncmp("lif=", arg, 4) == 0)
		strcpy(opt->listen_if, (arg + 4));
	if (strncmp("sif=", arg, 4) == 0)
		strcpy(opt->send_if, (arg + 4));
	if (strncmp("guess=", arg, 6) == 0)
		read_block((arg + 6), opt->guess);
	if (strncmp("block=", arg, 6) == 0)
		read_block((arg + 6), opt->block_to_crack);
	if (strncmp("oiv=", arg, 4) == 0)
		read_block((arg + 4), opt->original_iv);
	if (strncmp("dmac=", arg, 5) == 0)
		read_mac((arg + 5), opt->dmac);
	if (strncmp("-h", arg, 2) == 0) {
		printf("Usage: ipsec_hack [options]\n");
		printf("Options:\n");
		printf("\tfile={filename}\t\t\t read options from file\n");
		printf("\tsrc={dotted IPv4 address}\t source address of the IPsec connection\n");
		printf("\tdst={dotted IPv4 address}\t destination address of the IPsec connection\n");
		printf("\tfake_src={dotted IPv4 address}\t source address of the attack packet\n");
		printf("\tfake_dst={dotted IPv4 address}\t destination address of the attack packet\n");
		printf("\tspi={hex int}\t\t\t SPI of the IPsec connection\n");
		printf("\tlif={interface name}\t\t name of the listening interface\n");
		printf("\tsif={interface name}\t\t name of the interface where the attack packets are sent\n");
		printf("\tguess={xx:xx:xx:xx:xx:xx:xx:xx}\t first guess of the plaintext block\n");
		printf("\tblock={xx:xx:xx:xx:xx:xx:xx:xx}\t block to crack\n");
		printf("\toiv={xx:xx:xx:xx:xx:xx:xx:xx}\t IV used to enrypt the block\n");
		printf("\tdmac={xx:xx:xx:xx:xx:xx}\t MAC address of the gateway\n");
		printf("\t\t\t\t\t used to send attack packets\n");
		printf("\t-v\t\t\t\t verbose mode\n");
		printf("\t-vv\t\t\t\t more verbose mode\n");
		printf("\t-s\t\t\t\t exit if SPI between src and dst not seen for n seconds\n");
		printf("\t-i{int}\t\t\t\t packet counter reporting interval (default is 1000)\n");
		printf("\t-w{int}\t\t\t\t seconds to wait before existing if SPI not seen\n");
		printf("\t-cd\t\t\t\t allow random reserved bit in IP header (default is NO)\n");
		exit(1);
	}
	if (strncmp("-v", arg, 2) == 0)
		opt->verbose = 1;
	if (strncmp("-vv", arg, 3) == 0)
		opt->verbose = 2;
	if (strncmp("-s", arg, 2) == 0)
		opt->spi_change_detection = 1;
	if (strncmp("-i", arg, 2) == 0)
		opt->packet_print_intervall = atoi(arg + 2);
	if (strncmp("-w", arg, 2) == 0)
		opt->spi_wait_time = atoi(arg + 2);
	if (strncmp("-ch", arg, 3) == 0)
		opt->rsv_bit = 0;
}

static int read_arguments_from_file(char *fname, option_data *opt)
{
	char line_buf[100];
	char *bp;
	int c;
	FILE *fp;

	fp = fopen(fname, "r");
	if (fp == NULL) {
		printf("Error opening file %s\n", fname);
		return -1;
	}

	bp = line_buf;
	while ((c = fgetc(fp)) != EOF) {
		if (c == '\n') {
			*bp = '\0';
			parse_option(line_buf, opt);
			bp = line_buf;
			continue;
		}
		*bp = c;
		bp++;
	}

	fclose(fp);
	return 1;
}

int read_arguments(int argc, char *argv[], option_data *opt)
{
	for (; argc > 1; argc--)
		parse_option(argv[argc - 1], opt);
}
