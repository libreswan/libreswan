/*
 * this program converts a pcap file to a C source file for use
 * by testing code.
 *
 */

#include <pcap.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int packnum = 0;

void pcap_skbuff(u_char *user,
		 const struct pcap_pkthdr *h,
		 const u_char *bytes)
{
	FILE *out = (FILE *)user;
	char line[81];
	int pos;
	int i;

	packnum++;
	fprintf(out, "const unsigned int packet%d_len=%d;\n", packnum,
		h->caplen);
	fprintf(out, "const unsigned char packet%d[]={\n", packnum);

	memset(line, ' ', sizeof(line));
	line[53] = '/';
	line[54] = '*';
	line[65] = '*';
	line[66] = '/';
	line[67] = '\n';
	line[68] = '\0';
	pos = 0;

	for (i = 0; i < h->caplen; i++) {
		if (pos == 8) {
			fputs(line, out);
			memset(line, ' ', sizeof(line));
			line[53] = '/';
			line[54] = '*';
			line[65] = '*';
			line[66] = '/';
			line[67] = '\n';
			line[68] = '\0';
			pos = 0;
		}

		/* line looks like:
		 *  0xXX, 0xYY, 0xZZ, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,  /+ ........ +/
		 *        1         2         3         4         5         6
		 * 3456789012345678901234567890123456789012345678901234567890123456789
		 */
		snprintf(line + (pos * 6) + 4, 6, "0x%02x,", bytes[i]);
		line[(pos * 6) + 4 + 5] = ' ';
		if (isprint(bytes[i]))
			line[pos + 56] = bytes[i];
		else
			line[pos + 56] = '.';
		pos++;
	}

	fputs(line, out);
	fprintf(out, "    0};\n\n");
}

int main(int argc, char *argv[])
{
	char *f;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pc;
	FILE *out = stdout;

	while (--argc > 0) {
		f = *++argv;

		pc = pcap_open_offline(f, errbuf);
		if (pc == NULL) {
			fprintf(stderr, "pcap_open_offline(%s): %s\n",
				f, errbuf);
			exit(10);
		}

		pcap_dispatch(pc, -1, pcap_skbuff, (u_char *)out);
		pcap_close(pc);
	}

	exit(0);
}
