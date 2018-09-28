/*
 * RSA signature key generation, for libreswan
 *
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2016 Tuomo Soini <tis@foobar.fi>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * NOTE: This should probably be rewritten to use NSS RSA_NewKey()
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <libreswan.h>
#include "lswalloc.h"
#include "secrets.h"

#include <prerror.h>
#include <prinit.h>
#include <prmem.h>
#include <plstr.h>
#include <key.h>
#include <keyt.h>
#include <nss.h>
#include <pk11pub.h>
#include <seccomon.h>
#include <secerr.h>
#include <secport.h>

#include <time.h>

#include <arpa/nameser.h> /* for NS_MAXDNAME */
#include "constants.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "lswtool.h"
#include "lswconf.h"
#include "lswnss.h"

#ifdef FIPS_CHECK
#  include <fipscheck.h>
#endif

/*
 * We allow 2192 as a minimum, but default to a random value between 3072 and
 * 4096. The range is used to avoid a mono-culture of key sizes.
 */
#define MIN_KEYBIT 2192

#ifndef DEVICE
# define DEVICE  "/dev/random"
#endif
#ifndef MAXBITS
# define MAXBITS 20000
#endif

#define DEFAULT_SEED_BITS 60 /* 480 bits of random seed */

/* No longer use E=3 to comply to FIPS 186-4, section B.3.1 */
#define F4	65537

char usage[] =
	"rsasigkey [--verbose] [--seeddev <device>] [--nssdir <dir>]\n"
	"        [--password <password>] [--hostname host] [--seedbits bits] [<keybits>]";
struct option opts[] = {
	{ "rounds",     1,      NULL,   'p', },	/* obsoleted */
	{ "noopt",      0,      NULL,   'n', }, /* obsoleted */
	{ "configdir",  1,      NULL,   'c', }, /* obsoleted */
	{ "verbose",    0,      NULL,   'v', },
	{ "seeddev",    1,      NULL,   'S', },
	{ "random",     1,      NULL,   'r', }, /* compat alias for seeddev */
	{ "hostname",   1,      NULL,   'H', },
	{ "help",       0,      NULL,   'h', },
	{ "version",    0,      NULL,   'V', },
	{ "nssdir",     1,      NULL,   'd', }, /* nss-tools use -d */
	{ "password",   1,      NULL,   'P', },
	{ "seedbits",   1,      NULL,   's', },
	{ 0,            0,      NULL,   0, }
};
char *device = DEVICE;          /* where to get randomness */
int nrounds = 30;               /* rounds of prime checking; 25 is good */
char outputhostname[NS_MAXDNAME];  /* hostname for output */

/* forwards */
void rsasigkey(int nbits, int seedbits, const struct lsw_conf_options *oco);
void lsw_random(size_t nbytes, unsigned char *buf);
static const char *conv(const unsigned char *bits, size_t nbytes, int format);

/*
 * UpdateRNG - Updates NSS's PRNG with user generated entropy
 *
 * pluto and rsasigkey use the NSS crypto library as its random source.
 * Some government Three Letter Agencies require that pluto reads additional
 * bits from /dev/random and feed these into the NSS RNG before drawing random
 * from the NSS library, despite the NSS library itself already seeding its
 * internal state. This process can block pluto or rsasigkey for an extended
 * time during startup, depending on the entropy of the system. Therefore
 * the default is to not perform this redundant seeding. If specifying a
 * value, it is recommended to specify at least 460 bits (for FIPS) or 440
 * bits (for BSI).
 */
static void UpdateNSS_RNG(int seedbits)
{
	SECStatus rv;
	int seedbytes = BYTES_FOR_BITS(seedbits);
	unsigned char *buf = alloc_bytes(seedbytes, "TLA seedmix");

	lsw_random(seedbytes, buf);
	rv = PK11_RandomUpdate(buf, seedbytes);
	assert(rv == SECSuccess);
	messupn(buf, seedbytes);
	pfree(buf);
}

/*
   - main - mostly argument parsing
 */
int main(int argc, char *argv[])
{
	log_to_stderr = FALSE;
	tool_init_log("ipsec rsasigkey");

	int opt;
	int nbits = 0;
	int seedbits = DEFAULT_SEED_BITS;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'n':
		case 'p':
			fprintf(stderr, "%s: --noopt and --rounds options have been obsoleted - ignored\n",
				progname);
			break;
		case 'v':       /* verbose description */
			log_to_stderr = TRUE;
			break;

		case 'r':
			fprintf(stderr, "%s: Warning: --random is obsoleted for --seeddev. It no longer specifies the random device used for obtaining random key material",
				progname);
			/* FALLTHROUGH */
		case 'S':       /* nonstandard random device for seed */
			device = optarg;
			break;

		case 'H':       /* set hostname for output */
			{
				size_t full_len = strlen(optarg);
				bool oflow = sizeof(outputhostname) - 1 < full_len;
				size_t copy_len = oflow ? sizeof(outputhostname) - 1 : full_len;

				memcpy(outputhostname, optarg, copy_len);
				outputhostname[copy_len] = '\0';
			}
			break;
		case 'h':       /* help */
			printf("Usage:\t%s\n", usage);
			exit(0);
			break;
		case 'V':       /* version */
			printf("%s %s\n", progname, ipsec_version_code());
			exit(0);
			break;
		case 'c':       /* obsoleted by --nssdir|-d */
		case 'd':       /* -d is used for nssdirdir with nss tools */
			lsw_conf_nssdir(optarg);
			break;
		case 'P':       /* token authentication password */
			lsw_conf_nsspassword(optarg);
			break;
		case 's': /* seed bits */
			seedbits = atoi(optarg);
			if (PK11_IsFIPS()) {
				if (seedbits < DEFAULT_SEED_BITS) {
					fprintf(stderr, "%s: FIPS mode does not allow < %d seed bits\n",
						progname, DEFAULT_SEED_BITS);
					exit(1);
				}
			}
			break;
		case '?':
		default:
			printf("Usage:\t%s\n", usage);
			exit(2);
		}

	if (outputhostname[0] == '\0') {
		if (gethostname(outputhostname, sizeof(outputhostname)) < 0) {
			fprintf(stderr, "%s: gethostname failed (%s)\n",
				progname,
				strerror(errno));
			exit(1);
		}
	}

	/*
	 * RSA-PSS requires keysize to be a multiple of 8 bits
	 * (see PCS#1 v2.1).
	 * We require a multiple of 16.  (??? why?)
	 */
	if (argv[optind] == NULL) {
		/* default keysize: a multiple of 16 in [3072,4096) */
		srand(time(NULL));
		nbits = 3072 + 16 * (rand() % (1024 / 16));
	} else {
		unsigned long u;
		err_t ugh = ttoulb(argv[optind], 0, 10, INT_MAX, &u);

		if (ugh != NULL) {
			fprintf(stderr,
				"%s: keysize specification is malformed: %s\n",
				progname, ugh);
			exit(1);
		}
		nbits = u;
	}

	if (nbits < MIN_KEYBIT ) {
		fprintf(stderr,
			"%s: requested RSA key size (%d) is too small - use %d or more\n",
			progname, nbits, MIN_KEYBIT);
		exit(1);
	} else if (nbits > MAXBITS) {
		fprintf(stderr,
			"%s: requested RSA key size (%d) is too large - (max %d)\n",
			progname, nbits, MAXBITS);
		exit(1);
	} else if (nbits % (BITS_PER_BYTE * 2) != 0) {
		fprintf(stderr,
			"%s: requested RSA key size (%d) is not a multiple of %d\n",
			progname, nbits, (int)BITS_PER_BYTE * 2);
		exit(1);
	}

	/*
	 * Don't fetch the config options until after they have been
	 * processed, and really are "constant".
	 */
	const struct lsw_conf_options *oco = lsw_init_options();
	rsasigkey(nbits, seedbits, oco);
	exit(0);
}

/*
 * generate an RSA signature key
 *
 * e is fixed at F4.
 */
void rsasigkey(int nbits, int seedbits, const struct lsw_conf_options *oco)
{
	PK11RSAGenParams rsaparams = { nbits, (long) F4 };
	PK11SlotInfo *slot = NULL;
	SECKEYPrivateKey *privkey = NULL;
	SECKEYPublicKey *pubkey = NULL;
	realtime_t now = realnow();

	lsw_nss_buf_t err;
	if (!lsw_nss_setup(oco->nssdir, 0, lsw_nss_get_password, err)) {
		fprintf(stderr, "%s: %s\n", progname, err);
		exit(1);
	}

	slot = lsw_nss_get_authenticated_slot(err);
	if (slot == NULL) {
		fprintf(stderr, "%s: %s\n", progname, err);
		lsw_nss_shutdown();
		exit(1);
	}

	/* Do some random-number initialization. */
	UpdateNSS_RNG(seedbits);
	privkey = PK11_GenerateKeyPair(slot,
				       CKM_RSA_PKCS_KEY_PAIR_GEN,
				       &rsaparams, &pubkey,
				       PR_TRUE,
				       PK11_IsFIPS() ? PR_TRUE : PR_FALSE,
				       lsw_return_nss_password_file_info());
	/* inTheToken, isSensitive, passwordCallbackFunction */
	if (privkey == NULL) {
		fprintf(stderr,
			"%s: key pair generation failed: \"%d\"\n", progname,
			PORT_GetError());
		return;
	}

	chunk_t public_modulus = {
		.ptr = pubkey->u.rsa.modulus.data,
		.len = pubkey->u.rsa.modulus.len,
	};
	chunk_t public_exponent = {
		.ptr = pubkey->u.rsa.publicExponent.data,
		.len = pubkey->u.rsa.publicExponent.len,
	};

	char *hex_ckaid;
	{
		SECItem *ckaid = PK11_GetLowLevelKeyIDForPrivateKey(privkey);
		if (ckaid == NULL) {
			fprintf(stderr, "%s: 'CKAID' calculation failed\n", progname);
			exit(1);
		}
		hex_ckaid = strdup(conv(ckaid->data, ckaid->len, 16));
		SECITEM_FreeItem(ckaid, PR_TRUE);
	}

	/*privkey->wincx = &pwdata;*/
	PORT_Assert(pubkey != NULL);
	fprintf(stderr, "Generated RSA key pair with CKAID %s was stored in the NSS database\n",
		hex_ckaid);

	/* and the output */
	libreswan_log("output...\n");  /* deliberate extra newline */
	printf("\t# RSA %d bits   %s   %s", nbits, outputhostname,
		ctime(&now.rt.tv_sec));
	/* ctime provides \n */
	printf("\t# for signatures only, UNSAFE FOR ENCRYPTION\n");

	printf("\t#ckaid=%s\n", hex_ckaid);

	/* RFC2537/RFC3110-ish format */
	{
		char *base64 = NULL;
		err_t err = rsa_pubkey_to_base64(public_exponent, public_modulus, &base64);
		if (err) {
			fprintf(stderr, "%s: unexpected error encoding RSA public key '%s'\n",
				progname, err);
			exit(1);
		}
		printf("\t#pubkey=%s\n", base64);
		pfree(base64);
	}

	printf("\tModulus: 0x%s\n", conv(public_modulus.ptr, public_modulus.len, 16));
	printf("\tPublicExponent: 0x%s\n", conv(public_exponent.ptr, public_exponent.len, 16));

	if (hex_ckaid != NULL)
		free(hex_ckaid);
	if (privkey != NULL)
		SECKEY_DestroyPrivateKey(privkey);
	if (pubkey != NULL)
		SECKEY_DestroyPublicKey(pubkey);

	lsw_nss_shutdown();
}

/*
 * lsw_random - get some random bytes from /dev/random (or wherever)
 * NOTE: This is only used for additional seeding of the NSS RNG
 */
void lsw_random(size_t nbytes, unsigned char *buf)
{
	size_t ndone;
	int dev;
	ssize_t got;

	dev = open(device, 0);
	if (dev < 0) {
		fprintf(stderr, "%s: could not open %s (%s)\n", progname,
			device, strerror(errno));
		exit(1);
	}

	ndone = 0;
	libreswan_log("getting %d random seed bytes for NSS from %s...\n",
		      (int) nbytes * BITS_PER_BYTE, device);
	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			fprintf(stderr, "%s: read error on %s (%s)\n", progname,
				device, strerror(errno));
			exit(1);
		}
		if (got == 0) {
			fprintf(stderr, "%s: eof on %s!?!\n", progname, device);
			exit(1);
		}
		ndone += got;
	}

	close(dev);
}

/*
   - conv - convert bits to output in specified datatot format
 * NOTE: result points into a STATIC buffer
 */
static const char *conv(const unsigned char *bits, size_t nbytes, int format)
{
	static char convbuf[MAXBITS / 4 + 50];  /* enough for hex */
	size_t n;

	n = datatot(bits, nbytes, format, convbuf, sizeof(convbuf));
	if (n == 0) {
		fprintf(stderr, "%s: can't-happen convert error\n", progname);
		exit(1);
	}
	if (n > sizeof(convbuf)) {
		fprintf(stderr,
			"%s: can't-happen convert overflow (need %d)\n",
			progname, (int) n);
		exit(1);
	}
	return convbuf;
}
