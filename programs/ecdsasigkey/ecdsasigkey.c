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

#include "optarg.h"
#include "ttodata.h"
#include "constants.h"
#include "lswversion.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "lswtool.h"
#include "lswnss.h"
#include "ipsecconf/keywords.h"		/* for KSF_NSSDIR */
#include "ipsecconf/setup.h"

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

enum opt {
	OPT_DEBUG = 256,
	OPT_VERSION,
	OPT_VERBOSE,
	OPT_NSSDIR,
	OPT_PASSWORD,
	OPT_SEEDDEV,
	OPT_SEEDBITS,
	OPT_HELP,
};

const struct option optarg_options[] = {
	{ OPT("debug", "help|<debug-flags>"), optional_argument, NULL, OPT_DEBUG, },
	{ "verbose\0",            no_argument,        NULL,   OPT_VERBOSE, },
	{ "help\0",               no_argument,        NULL,   OPT_HELP, },
	{ "version\0",            no_argument,        NULL,   OPT_VERSION, },
	NSSDIR_OPTS,
	{ 0,            0,      NULL,   0, }
};
int nrounds = 30;               /* rounds of prime checking; 25 is good */

/* forwards */
static void ecdsasigkey(SECOidTag curve, int seedbits, struct logger *logger);
static const char *conv(const unsigned char *bits, size_t nbytes, int format);

int main(int argc, char *argv[])
{
	log_to_stderr = false;
	struct logger *logger = tool_logger(argc, argv);

	int seedbits = DEFAULT_SEED_BITS;
	SECOidTag curve = SEC_OID_UNKNOWN;
	struct nss_flags nss = {0};

	while (true) {

		int c = optarg_getopt(logger, argc, argv);
		if (c < 0) {
			break;
		}

		switch ((enum opt)c) {
		case OPT_VERBOSE:       /* verbose description */
			log_to_stderr = true;
			continue;

		case OPT_DEBUG:
			optarg_debug(OPTARG_DEBUG_YES);
			continue;

		case OPT_SEEDDEV:       /* nonstandard random device for seed */
			optarg_seeddev(logger);
			continue;

		case OPT_HELP:       /* help */
			optarg_usage("ipsec ecdsasigkey", "[<curve-name>]", "");

		case OPT_VERSION:       /* version */
			optarg_version("");

		case OPT_NSSDIR:       /* -d is used for nssdirdir with nss tools */
			optarg_nssdir(logger);
			continue;
		case OPT_PASSWORD:       /* token authentication password */
			optarg_nss_password(logger, &nss);
			continue;

		case OPT_SEEDBITS: /* seed bits */
			seedbits = atoi(optarg);
			if (PK11_IsFIPS()) {
				if (seedbits < DEFAULT_SEED_BITS) {
					fprintf(stderr, "%s: FIPS mode does not allow < %d seed bits\n",
						progname, DEFAULT_SEED_BITS);
					exit(1);
				}
			}
			continue;
		}

		bad_case(c);
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
	init_nss(config_setup_nssdir(), nss, logger);

	ecdsasigkey(curve, seedbits, logger);
	exit(0);
}

/*
 * generate an ECDSA signature key
 */
static void ecdsasigkey(SECOidTag curve, int seedbits, struct logger *logger)
{
	SECKEYPrivateKey *privkey = NULL;
	SECKEYPublicKey *pubkey = NULL;

	/*
	 * Wrap the raw OID in ASN.1.  Must double free ecdsaparams.
	 */
	SECOidData *oiddata = SECOID_FindOIDByTag(curve);
	SECItem *ecdsaparams = SEC_ASN1EncodeItem(NULL, NULL, &oiddata->oid,
						  SEC_ObjectIDTemplate);

	PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(logger);
	if (slot == NULL) {
		/* already logged */
		shutdown_nss();
		exit(1);
	}

	/* Do some random-number initialization. */
	lsw_nss_seed_rng(seedbits, logger);
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
