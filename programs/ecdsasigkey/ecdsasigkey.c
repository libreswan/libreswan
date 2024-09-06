/*
 * ECDSA signature key generation, for libreswan
 *
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2016 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2019-2020 Paul Wouters <pwouters@redhat.com>
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
#include <getopt.h>

#include <prerror.h>
#include <prinit.h>
#include <prmem.h>
#include <plstr.h>
#include <keyhi.h>
#include <keythi.h>
#include <pk11pub.h>
#include <seccomon.h>
#include <secerr.h>
#include <secport.h>

#include <time.h>

#include <arpa/nameser.h> /* for NS_MAXDNAME */

#include "ttodata.h"
#include "constants.h"
#include "lswversion.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "lswtool.h"
#include "lswconf.h"
#include "lswnss.h"

#ifndef DEVICE
# define DEVICE  "/dev/random"
#endif
#ifndef MAXBITS
# define MAXBITS 521
#endif

#define DEFAULT_SEED_BITS 60 /* 480 bits of random seed */

struct curve {
	const char *name;
	SECOidTag tag;
};

static const struct curve curves[] = {
	{ "secp256r1", SEC_OID_SECG_EC_SECP256R1 },
	{ "secp384r1", SEC_OID_SECG_EC_SECP384R1 },
	{ "secp521r1", SEC_OID_SECG_EC_SECP521R1 }
};

char usage[] =
	"ecdsasigkey [--verbose] [ --debug ] [--seeddev <device>] [--nssdir <dir>]\n"
	"        [--password <password>] [--seedbits bits] [<curve-name>]";

enum opt {
	OPT_DEBUG = 256,
};

struct option opts[] = {
	{ "debug",      0,      NULL,   OPT_DEBUG, },
	{ "verbose",    0,      NULL,   'v', },
	{ "seeddev",    1,      NULL,   'S', },
	{ "help",       0,      NULL,   'h', },
	{ "version",    0,      NULL,   'V', },
	{ "nssdir",     1,      NULL,   'd', }, /* nss-tools use -d */
	{ "password",   1,      NULL,   'P', },
	{ "seedbits",   1,      NULL,   's', },
	{ 0,            0,      NULL,   0, }
};
char *device = DEVICE;          /* where to get randomness */
int nrounds = 30;               /* rounds of prime checking; 25 is good */

/* forwards */
static void ecdsasigkey(SECOidTag curve, int seedbits,
		 const struct lsw_conf_options *oco, struct logger *logger);
static void lsw_random(size_t nbytes, unsigned char *buf, struct logger *logger);
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
static void UpdateNSS_RNG(int seedbits, struct logger *logger)
{
	SECStatus rv;
	int seedbytes = BYTES_FOR_BITS(seedbits);
	unsigned char *buf = alloc_bytes(seedbytes, "TLA seedmix");

	lsw_random(seedbytes, buf, logger);
	rv = PK11_RandomUpdate(buf, seedbytes);
	passert(rv == SECSuccess);
	messupn(buf, seedbytes);
	pfree(buf);
}

int main(int argc, char *argv[])
{
	log_to_stderr = false;
	struct logger *logger = tool_logger(argc, argv);

	int opt;
	int seedbits = DEFAULT_SEED_BITS;
	SECOidTag curve = SEC_OID_UNKNOWN;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'v':       /* verbose description */
			log_to_stderr = true;
			break;

		case OPT_DEBUG:
			cur_debugging = -1;
			break;

		case 'S':       /* nonstandard random device for seed */
			device = optarg;
			break;

		case 'h':       /* help */
			printf("Usage:\t%s\n", usage);
			exit(0);
			break;
		case 'V':       /* version */
			printf("%s %s\n", progname, ipsec_version_code());
			exit(0);
			break;
		case 'd':       /* -d is used for nssdirdir with nss tools */
			lsw_conf_nssdir(optarg, logger);
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

	if (argv[optind] == NULL) {
		curve = SEC_OID_SECG_EC_SECP256R1;
	} else {
		for (size_t i = 0; i < elemsof(curves); i++) {
			if (streq(argv[optind], curves[i].name)) {
				curve = curves[i].tag;
				break;
			}
		}
		if (curve == SEC_OID_UNKNOWN) {
			fprintf(stderr,
				"%s: curve specification is malformed: %s\n",
				progname, argv[optind]);
			exit(1);
		}
	}

	/*
	 * Don't fetch the config options until after they have been
	 * processed, and really are "constant".
	 */
	const struct lsw_conf_options *oco = lsw_init_options();

	ecdsasigkey(curve, seedbits, oco, logger);
	exit(0);
}

/*
 * generate an ECDSA signature key
 */
static void ecdsasigkey(SECOidTag curve, int seedbits,
			const struct lsw_conf_options *oco, struct logger *logger)
{
	PK11SlotInfo *slot = NULL;
	SECKEYPrivateKey *privkey = NULL;
	SECKEYPublicKey *pubkey = NULL;


	/*
	 * Wrap the raw OID in ASN.1.  Must double free ecdsaparams.
	 */
	SECOidData *oiddata = SECOID_FindOIDByTag(curve);
	SECItem *ecdsaparams = SEC_ASN1EncodeItem(NULL, NULL, &oiddata->oid,
						  SEC_ObjectIDTemplate);

	init_nss(oco->nssdir, (struct nss_flags){0}, logger);

	slot = lsw_nss_get_authenticated_slot(logger);
	if (slot == NULL) {
		/* already logged */
		shutdown_nss();
		exit(1);
	}

	/* Do some random-number initialization. */
	UpdateNSS_RNG(seedbits, logger);
	privkey = PK11_GenerateKeyPair(slot,
				       CKM_EC_KEY_PAIR_GEN,
				       ecdsaparams, &pubkey,
				       PR_TRUE,
				       PK11_IsFIPS() ? PR_TRUE : PR_FALSE,
				       lsw_nss_get_password_context(logger));

	SECITEM_FreeItem(ecdsaparams, PR_TRUE/*also-free-item*/);

	/* inTheToken, isSensitive, passwordCallbackFunction */
	if (privkey == NULL) {
		fprintf(stderr,
			"%s: key pair generation failed: \"%d\"\n", progname,
			PORT_GetError());
		return;
	}

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

	PORT_Assert(pubkey != NULL);
	fprintf(stderr, "Generated ECDSA key pair with CKAID %s was stored in the NSS database\n",
		hex_ckaid);
	fprintf(stderr, "The public key can be displayed using: ipsec showhostkey --left --ckaid %s\n",
		hex_ckaid);

	if (hex_ckaid != NULL)
		free(hex_ckaid);
	if (privkey != NULL)
		SECKEY_DestroyPrivateKey(privkey);
	if (pubkey != NULL)
		SECKEY_DestroyPublicKey(pubkey);

	shutdown_nss();
}

/*
 * lsw_random - get some random bytes from /dev/random (or wherever)
 * NOTE: This is only used for additional seeding of the NSS RNG
 */
static void lsw_random(size_t nbytes, unsigned char *buf, struct logger *logger)
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
	llog(RC_LOG, logger, "getting %d random seed bytes for NSS from %s...\n",
		    (int) nbytes * BITS_IN_BYTE, device);
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
 * conv - convert bits to output in specified datatot format
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
