/*
 * this program converts a pcap file to a C source file for use
 * by testing code.
 */

#include <pcap.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int packnum = 0;

static void pcap_skbuff(uint8_t *user,
		 const struct pcap_pkthdr *h,
		 const uint8_t *bytes)
{
	FILE *out = (FILE *)user;

	packnum++;
	fprintf(out, "const unsigned int packet%d_len=%d;\n", packnum,
		h->caplen);
	fprintf(out, "const unsigned char packet%d[]={\n", packnum);

	/*
	 * line looks like:
	 *  0xXX, 0xYY, 0xZZ, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,  /+ ........ +/
	 *        1         2         3         4         5         6
	 * 3456789012345678901234567890123456789012345678901234567890123456789
	 */

	/* for each line of output ... */
	for (unsigned i = 0; i < h->caplen; ) {
		char line[81];
		memset(line, ' ', sizeof(line));
		line[53] = '/';
		line[54] = '*';
		line[65] = '*';
		line[66] = '/';
		line[67] = '\n';
		line[68] = '\0';

		/* for each byte of input that fits in this line ... */
		for (unsigned pos = 0; i < h->caplen && pos < 8; pos++) {
			snprintf(line + (pos * 6) + 4, 6, "0x%02x,", bytes[i]);
			line[(pos * 6) + 4 + 5] = ' ';
			line[pos + 56] = isprint(bytes[i]) ? bytes[i] : '.';
			i++;
		}
		fputs(line, out);
	}
	fprintf(out, "    0};\n\n");
}

int main(int argc, char *argv[])
{
	while (--argc > 0) {
		const char *f = *++argv;

		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *pc = pcap_open_offline(f, errbuf);
		if (pc == NULL) {
			fprintf(stderr, "pcap_open_offline(%s): %s\n",
				f, errbuf);
			exit(10);
		}

		pcap_dispatch(pc, -1, pcap_skbuff, (uint8_t *)stdout);
		pcap_close(pc);
	}

	exit(0);
}
