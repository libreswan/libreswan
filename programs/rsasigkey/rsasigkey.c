/*
 * RSA signature key generation
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com> 
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com> 
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
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
#include <gmp.h>

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

#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswconf.h"

#ifdef FIPS_CHECK
#  include <fipscheck.h>
#endif

#ifndef DEVICE
/* To the openwrt people: Do not change /dev/random to /dev/urandom. The
 * /dev/random device is ONLY used for generating long term keys, which
 * should NEVER be done with /dev/urandom. If people use X.509, PSK or
 * even raw RSA keys generated on other systems, changing this will have
 * 0 effect. It's better to fail or bail out of generating a key, then
 * generate a bad one.
 */
#define	DEVICE	"/dev/random"
#endif
#ifndef MAXBITS
#define	MAXBITS	20000
#endif

/* the code in getoldkey() knows about this */
#define	E	3		/* standard public exponent */

/*#define F4	65537*/	/* preferred public exponent, Fermat's 4th number */
char usage[] = "rsasigkey [--verbose] [--random device] [--configdir dir] [--password password] nbits [--hostname host] [--noopt] [--rounds num]";
struct option opts[] = {
  {"verbose",	0,	NULL,	'v',},
  {"random",	1,	NULL,	'r',},
  {"rounds",	1,	NULL,	'p',},
  {"oldkey",	1,	NULL,	'o',},
  {"hostname",	1,	NULL,	'H',},
  {"noopt",	0,	NULL,	'n',},
  {"help",		0,	NULL,	'h',},
  {"version",	0,	NULL,	'V',},
  {"configdir",        1,      NULL,   'c' },
  {"password", 1,      NULL,   'P' },
  {0,		0,	NULL,	0,}
};
int verbose = 0;		/* narrate the action? */
char *device = DEVICE;		/* where to get randomness */
int nrounds = 30;		/* rounds of prime checking; 25 is good */
mpz_t prime1;			/* old key's prime1 */
mpz_t prime2;			/* old key's prime2 */
char outputhostname[1024];	/* hostname for output */
int do_lcm = 1;			/* use lcm(p-1, q-1), not (p-1)*(q-1) */

char me[] = "ipsec rsasigkey";	/* for messages */

/* forwards */
int getoldkey(char *filename);
void rsasigkey(int nbits, char *configdir, char *password);
void initprime(mpz_t var, int nbits, int eval);
void initrandom(mpz_t var, int nbits);
void getrandom(size_t nbytes, unsigned char *buf);
unsigned char *bundle(int e, mpz_t n, size_t *sizep);
char *conv(unsigned char *bits, size_t nbytes, int format);
char *hexout(mpz_t var);
void report(char *msg);


/*#define NUM_KEYSTROKES 120*/
#define RAND_BUF_SIZE 60

#define GEN_BREAK(e) rv=e; break;

/* getModulus - returns modulus of the RSA public key */
SECItem *getModulus(SECKEYPublicKey *pk) { return &pk->u.rsa.modulus; }

/* getPublicExponent - returns public exponent of the RSA public key */
SECItem *getPublicExponent(SECKEYPublicKey *pk) { return &pk->u.rsa.publicExponent; }

/* Caller must ensure that dst is at least item->len*2+1 bytes long */
void SECItemToHex(const SECItem * item, char * dst)
{
    if (dst && item && item->data) {
	unsigned char * src = item->data;
	unsigned int    len = item->len;
	for (; len > 0; --len, dst += 2) {
		sprintf(dst, "%02x", *src++);
	}
	*dst = '\0';
    }
}

/*
 * hexOut - prepare hex output, guaranteeing even number of digits
 * The current Libreswan conversion routines expect an even digit count,
 * but the is no guarantee the data will have such length.
 * hexOut is like hexout but takes a SECItem *.
 */
char *hexOut(SECItem *data)
{
    unsigned i;
    static char hexbuf[3 + MAXBITS/4 + 1];
    char *hexp;

    memset(hexbuf, 0, 3 + MAXBITS/4 + 1);
    for (i = 0, hexp = hexbuf+3; i < data->len; i++, hexp += 2) {
	sprintf(hexp, "%02x", data->data[i]);
    }
    *hexp='\0';     

    hexp = hexbuf+1;
    hexp[0] = '0';
    hexp[1] = 'x';

    return hexp;
}

/* UpdateRNG - Updates NSS's PRNG with user generated entropy. */
void UpdateNSS_RNG(void)
{
    SECStatus rv;
    unsigned char buf[RAND_BUF_SIZE];
    getrandom(RAND_BUF_SIZE, buf);
    rv = PK11_RandomUpdate(buf, sizeof buf);
    assert(rv == SECSuccess);
    memset(buf, 0, sizeof buf);
}

/*  Returns the password passed in in the text file.
 *  Uses the password once and nulls it out the prevent
 *  PKCS11 from calling us forever.
 */
char *GetFilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char* phrases, *phrase;
    PRFileDesc *fd;
    PRInt32 nb;
    const char *pwFile = (const char *)arg;
    int i;
    const long maxPwdFileSize = 4096;
    char* tokenName = NULL;
    int tokenLen = 0;

    if (!pwFile) {
	return 0;
    }

    if (retry) {
	return 0;  /* no good retrying - the files contents will be the same */
    }

    phrases = PORT_ZAlloc(maxPwdFileSize);

    if (!phrases) {
	return 0; /* out of memory */
    }

    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) {
	fprintf(stderr, "No password file \"%s\" exists.\n", pwFile);
	PORT_Free(phrases);
	return NULL;
    }
    nb = PR_Read(fd, phrases, maxPwdFileSize);

    PR_Close(fd);

    if (nb == 0) {
	fprintf(stderr,"password file contains no data\n");
	PORT_Free(phrases);
	return NULL;
    }

    if (slot) {
	tokenName = PK11_GetTokenName(slot);
	if (tokenName) {
	    tokenLen = PORT_Strlen(tokenName);
	}
    }
    i = 0;
    do {
	int startphrase = i;
	int phraseLen;
	/* handle the Windows EOL case */
	while (phrases[i] != '\r' && phrases[i] != '\n' && i < nb) i++;
	/* terminate passphrase */
	phrases[i++] = '\0';
	/* clean up any EOL before the start of the next passphrase */
	while ( (i<nb) && (phrases[i] == '\r' || phrases[i] == '\n')) {
		phrases[i++] = '\0';
	}
	/* now analyze the current passphrase */
	phrase = &phrases[startphrase];
	if (!tokenName)
		break;
	if (PORT_Strncmp(phrase, tokenName, tokenLen)) continue;
	phraseLen = PORT_Strlen(phrase);
	if (phraseLen < (tokenLen+1)) continue;
	if (phrase[tokenLen] != ':') continue;
	phrase = &phrase[tokenLen+1];
	break;
    } while (i<nb);

    phrase = PORT_Strdup((char*)phrase);
    PORT_Free(phrases);
    return phrase;
}

char *GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    secuPWData *pwdata = (secuPWData *)arg;
    secuPWData pwnull = { PW_NONE, 0 };
    secuPWData pwxtrn = { PW_EXTERNAL, "external" };
    char *pw;

    if (pwdata == NULL) {
	pwdata = &pwnull;
    }

    if (PK11_ProtectedAuthenticationPath(slot)) {
	pwdata = &pwxtrn;
    }
    if (retry && pwdata->source != PW_NONE) {
	fprintf(stderr, "%s: Incorrect password/PIN entered.\n", me);
	return NULL;
    }

    switch (pwdata->source) {
	case PW_FROMFILE:
		/* Instead of opening and closing the file every time, get the pw
		* once, then keep it in memory (duh).
		*/
		pw = GetFilePasswd(slot, retry, pwdata->data);
		pwdata->source = PW_PLAINTEXT;
		pwdata->data = strdup(pw);
		/* it's already been dup'ed */
		return pw;
	case PW_PLAINTEXT:
		return strdup(pwdata->data);
	default: /* cases PW_NONE and PW_EXTERNAL not supported */
		fprintf(stderr, "Unknown or unsupported case in GetModulePassword");
		break;
    }

    fprintf(stderr, "%s: Password check failed:  No password found.\n", me);
    return NULL;
}

/*
 - main - mostly argument parsing
 */
int main(int argc, char *argv[])
{
	int opt;
	extern int optind;
	extern char *optarg;
	int errflg = 0;
	int i;
	int nbits;
	char *oldkeyfile = NULL;
	char *configdir = NULL; /* where the NSS databases reside */
	char *password = NULL;  /* password for token authentication */

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'v':	/* verbose description */
			verbose = 1;
			break;
		case 'r':	/* nonstandard /dev/random */
			device = optarg;
			break;
		case 'p':	/* number of prime-check rounds */
			nrounds = atoi(optarg);
			if (nrounds <= 0) {
				fprintf(stderr, "%s: rounds must be > 0\n", me);
				exit(2);
			}
			break;
		case 'o':	/* reformat old key */
			oldkeyfile = optarg;
			break;
		case 'H':	/* set hostname for output */
			strcpy(outputhostname, optarg);
			break;
		case 'n':	/* don't optimize the private key */
			do_lcm = 0;
			break;
		case 'h':	/* help */
			printf("Usage:\t%s\n", usage);
			exit(0);
			break;
		case 'V':	/* version */
			printf("%s %s\n", me, ipsec_version_code());
			exit(0);
			break;
		case 'c':       /* nss configuration directory */
			configdir = optarg;
			break;
		case 'P':       /* token authentication password */
			password = optarg;
			break;
		case '?':
		default:
			errflg = 1;
			break;
		}
	if (errflg || optind != argc-1) {
		printf("Usage:\t%s\n", usage);
		exit(2);
	}

	if (outputhostname[0] == '\0') {
		i = gethostname(outputhostname, sizeof(outputhostname));
		if (i < 0) {
			fprintf(stderr, "%s: gethostname failed (%s)\n",
				me,
				strerror(errno));
			exit(1);
		}
	}

	if (oldkeyfile == NULL) {
		assert(argv[optind] != NULL);
		nbits = atoi(argv[optind]);
	} else
		nbits = getoldkey(oldkeyfile);

	if (nbits <= 0) {
		fprintf(stderr, "%s: invalid bit count (%d)\n", me, nbits);
		exit(1);
	} else if (nbits > MAXBITS) {
		fprintf(stderr, "%s: overlarge bit count (max %d)\n", me,
								MAXBITS);
		exit(1);
	} else if (nbits % (CHAR_BIT*2) != 0) {	/* *2 for nbits/2-bit primes */
		fprintf(stderr, "%s: bit count (%d) not multiple of %d\n", me,
						nbits, (int)CHAR_BIT*2);
		exit(1);
	}

	rsasigkey(nbits, configdir, password);
	exit(0);
}

/*
 - getoldkey - fetch an old key's primes
 */
int				/* nbits */
getoldkey(filename)
char *filename;
{
#ifdef OLD_GCC
	fprintf(stderr, "%s: getoldkey is broken\n", me);
	exit(1);
#else
	FILE *f;
	char line[MAXBITS/2];
	char *p;
	char *value;
	static char pube[] = "PublicExponent:";
	static char pubevalue[] = "0x03";
	static char pr1[] = "Prime1:";
	static char pr2[] = "Prime2:";
#	define	STREQ(a, b)	(strcmp(a, b) == 0)
	int sawpube = 0;
	int sawpr1 = 0;
	int sawpr2 = 0;
	int nbits;
	char fsin[2];
	fsin[0]='-'; /*file stdin*/
	fsin[1]='\0';

	nbits = 0;
 
	if (STREQ(filename, fsin))
		f = stdin;
	else
		f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "%s: unable to open file `%s' (%s)\n", me,
						filename, strerror(errno));
		exit(1);
	}
	if (verbose)
		fprintf(stderr, "getting old key from %s...\n", filename);

	while (fgets(line, sizeof(line), f) != NULL) {
		p = line + strlen(line) - 1;
		if (*p != '\n') {
			fprintf(stderr, "%s: over-long line in file `%s'\n",
							me, filename);
			exit(1);
		}
		*p = '\0';

		p = line + strspn(line, " \t");		/* p -> first word */
		value = strpbrk(p, " \t");		/* value -> after it */
		if (value != NULL) {
			*value++ = '\0';
			value += strspn(value, " \t");
			/* value -> second word if any */
		}

		if (value == NULL || *value == '\0') {
			/* wrong format */
		} else if (STREQ(p, pube)) {
			sawpube = 1;
			if (!STREQ(value, pubevalue)) {
				fprintf(stderr, "%s: wrong public exponent (`%s') in old key\n",
					me, value);
				exit(1);
			}
		} else if (STREQ(p, pr1)) {
			if (sawpr1) {
				fprintf(stderr, "%s: duplicate `%s' lines in `%s'\n",
					me, pr1, filename);
				exit(1);
			}
			sawpr1 = 1;
			nbits = (strlen(value) - 2) * 4 * 2;
			if (mpz_init_set_str(prime1, value, 0) < 0) {
				fprintf(stderr, "%s: conversion error in reading old prime1\n",
					me);
				exit(1);
			}
		} else if (STREQ(p, pr2)) {
			if (sawpr2) {
				fprintf(stderr, "%s: duplicate `%s' lines in `%s'\n",
					me, pr2, filename);
				exit(1);
			}
			sawpr2 = 1;
			if (mpz_init_set_str(prime2, value, 0) < 0) {
				fprintf(stderr, "%s: conversion error in reading old prime2\n",
					me);
				exit(1);
			}
		}
	}
	
	if (f != stdin)
		fclose(f);

	if (!sawpube || !sawpr1 || !sawpr2) {
		fprintf(stderr, "%s: old key missing or incomplete\n", me);
		exit(1);
	}

	assert(sawpr1);		/* and thus nbits is known */
	return(nbits);
#endif
}

/*
 - rsasigkey - generate an RSA signature key
 * e is fixed at 3, without discussion.  That would not be wise if these
 * keys were to be used for encryption, but for signatures there are some
 * real speed advantages.
 */

/* Generates an RSA signature key using nss.
 * Curretly e is fixed at 3, but we may change that.  We may
 * use F4 if preformance doesn't degrade much realative to 3.
 * Notice that useoldkey is not yet supported.
 */
void
rsasigkey(int nbits, char *configdir, char *password)
{
    SECStatus rv;
    PRBool nss_initialized          = PR_FALSE;
    PK11RSAGenParams rsaparams      = { nbits, (long) E };
    secuPWData  pwdata              = { PW_NONE, NULL };
    PK11SlotInfo *slot              = NULL;
    SECKEYPrivateKey *privkey       = NULL;
    SECKEYPublicKey *pubkey         = NULL;
    unsigned char *bundp            = NULL;
    mpz_t n;
    mpz_t e;
    size_t bs;
    char n_str[3 + MAXBITS/4 + 1];
    char buf[100];
    time_t now = time((time_t *)NULL);

    mpz_init(n);
    mpz_init(e);

    do {
	if (!configdir) {
		fprintf(stderr, "%s: configdir is required\n", me);
		return;
	}

	snprintf(buf, sizeof(buf), "%s/nsspassword",configdir);
	pwdata.source = password ? (strcmp(password, buf)? PW_PLAINTEXT: PW_FROMFILE) : PW_NONE;
	pwdata.data = password ? password : NULL;

	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	snprintf(buf, sizeof(buf), "%s",configdir);
	if ((rv = NSS_InitReadWrite(buf)) != SECSuccess) {
		fprintf(stderr, "%s: NSS_InitReadWrite returned %d\n", me, PR_GetError());
		break;
	}
#ifdef FIPS_CHECK
	if (PK11_IsFIPS() && !FIPSCHECK_verify(NULL, NULL)) {
		printf("FIPS integrity verification test failed.\n");
		exit(1);
	}
#endif 

	if (PK11_IsFIPS() && !password) {
		fprintf(stderr, "%s: On FIPS mode a password is required\n", me);
		break;
	}

	PK11_SetPasswordFunc(GetModulePassword);
	nss_initialized = PR_TRUE;

	/* Good for now but someone may want to use a hardware token */
	slot = PK11_GetInternalKeySlot();
	/* In which case this may be better */
	/* slot = PK11_GetBestSlot(CKM_RSA_PKCS_KEY_PAIR_GEN, password ? &pwdata : NULL); */
	/* or the user may specify the name of a token. */

	/*if (PK11_IsFIPS() || !PK11_IsInternal(slot)) {
		rv = PK11_Authenticate(slot, PR_FALSE, &pwdata);
		if (rv != SECSuccess) {
			fprintf(stderr, "%s: could not authenticate to token '%s'\n",
				me, PK11_GetTokenName(slot));
			GEN_BREAK(SECFailure);
		}
	}*/

	/* Do some random-number initialization. */
	UpdateNSS_RNG();
	/* Log in to the token */
	if (password) {
	    rv = PK11_Authenticate(slot, PR_FALSE, &pwdata);
	    if (rv != SECSuccess) {
		fprintf(stderr, "%s: could not authenticate to token '%s'\n",
			me, PK11_GetTokenName(slot));
		GEN_BREAK(SECFailure);
	    }
	}
	privkey = PK11_GenerateKeyPair(slot
		, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaparams, &pubkey
		, PR_TRUE, password ? PR_TRUE : PR_FALSE, &pwdata);
	/* inTheToken, isSensitive, passwordCallbackFunction */
	if (!privkey) {
		fprintf(stderr, "%s: key pair generation failed: \"%d\"\n", me, PORT_GetError());
		GEN_BREAK(SECFailure);
	}

	/*privkey->wincx = &pwdata;*/
	PORT_Assert(pubkey != NULL);
	fprintf(stderr, "Generated RSA key pair using the NSS database\n");
       
	SECItemToHex(getModulus(pubkey), n_str);
	assert(!mpz_set_str(n, n_str, 16));

	/* and the output */
	/* note, getoldkey() knows about some of this */
	report("output...\n");          /* deliberate extra newline */
	printf("\t# RSA %d bits   %s   %s", nbits, outputhostname, ctime(&now));
                                                       /* ctime provides \n */
	printf("\t# for signatures only, UNSAFE FOR ENCRYPTION\n");
	bundp = bundle(E, n, &bs);
	printf("\t#pubkey=%s\n", conv(bundp, bs, 's')); /* RFC2537ish format */
	printf("\tModulus: %s\n", hexOut(getModulus(pubkey)));
	printf("\tPublicExponent: %s\n", hexOut(getPublicExponent(pubkey)));

	SECItem *ckaID=PK11_MakeIDFromPubKey(getModulus(pubkey));
	if(ckaID!=NULL) {
		printf("\t# everything after this point is CKA_ID in hex format when using NSS\n");
		printf("\tPrivateExponent: %s\n", hexOut(ckaID));
		printf("\tPrime1: %s\n", hexOut(ckaID));
		printf("\tPrime2: %s\n", hexOut(ckaID));
		printf("\tExponent1: %s\n", hexOut(ckaID));
		printf("\tExponent2: %s\n", hexOut(ckaID));
		printf("\tCoefficient: %s\n", hexOut(ckaID));
		printf("\tCKAIDNSS: %s\n", hexOut(ckaID));
		SECITEM_FreeItem(ckaID, PR_TRUE);
	}

	} while(0);

    if (privkey) SECKEY_DestroyPrivateKey(privkey);
    if (pubkey) SECKEY_DestroyPublicKey(pubkey);    

    if (nss_initialized) {
	(void) NSS_Shutdown();
    }
    (void) PR_Cleanup();
}


/*
 - getrandom - get some random bytes from /dev/random (or wherever)
 */
void
getrandom(nbytes, buf)
size_t nbytes;
unsigned char *buf;			/* known to be big enough */
{
	size_t ndone;
	int dev;
	ssize_t got;

	dev = open(device, 0);
	if (dev < 0) {
		fprintf(stderr, "%s: could not open %s (%s)\n", me,
						device, strerror(errno));
		exit(1);
	}

	ndone = 0;
	if (verbose)
		fprintf(stderr, "getting %d random bytes from %s...\n", (int) nbytes,
							device);
	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			fprintf(stderr, "%s: read error on %s (%s)\n", me,
						device, strerror(errno));
			exit(1);
		}
		if (got == 0) {
			fprintf(stderr, "%s: eof on %s!?!\n", me, device);
			exit(1);
		}
		ndone += got;
	}

	close(dev);
}

/*
 - hexout - prepare hex output, guaranteeing even number of digits
 * (The current FreeS/WAN conversion routines want an even digit count,
 * but mpz_get_str doesn't promise one.)
 */
char *				/* pointer to static buffer (ick) */
hexout(var)
mpz_t var;
{
	static char hexbuf[3 + MAXBITS/4 + 1];
	char *hexp;

	mpz_get_str(hexbuf+3, 16, var);
	if (strlen(hexbuf+3)%2 == 0)	/* even number of hex digits */
		hexp = hexbuf+1;
	else {				/* odd, must pad */
		hexp = hexbuf;
		hexp[2] = '0';
	}
	hexp[0] = '0';
	hexp[1] = 'x';

	return hexp;
}

/*
 - bundle - bundle e and n into an RFC2537-format lump
 * Note, calls hexout.
 */
unsigned char *				/* pointer to static buffer (ick) */
bundle(e, n, sizep)
int e;
mpz_t n;
size_t *sizep;
{
	char *hexp = hexout(n);
	static unsigned char bundbuf[2 + MAXBITS/8];
	const char *er;
	size_t size;

	assert(e <= 255);
	bundbuf[0] = 1;
	bundbuf[1] = e;
	er = ttodata(hexp, 0, 0, (char *)bundbuf+2, sizeof(bundbuf)-2, &size);
	if (er != NULL) {
		fprintf(stderr, "%s: can't-happen bundle convert error `%s'\n",
								me, er);
		exit(1);
	}
	if (size > sizeof(bundbuf)-2) {
		fprintf(stderr, "%s: can't-happen bundle overflow (need %d)\n",
								me, (int) size);
		exit(1);
	}
	if (sizep != NULL)
		*sizep = size + 2;
	return bundbuf;
}

/*
 - conv - convert bits to output in specified format
 */
char *				/* pointer to static buffer (ick) */
conv(bits, nbytes, format)
unsigned char *bits;
size_t nbytes;
int format;			/* datatot() code */
{
	static char convbuf[MAXBITS/4 + 50];	/* enough for hex */
	size_t n;

	n = datatot(bits, nbytes, format, convbuf, sizeof(convbuf));
	if (n == 0) {
		fprintf(stderr, "%s: can't-happen convert error\n", me);
		exit(1);
	}
	if (n > sizeof(convbuf)) {
		fprintf(stderr, "%s: can't-happen convert overflow (need %d)\n",
								me, (int) n);
		exit(1);
	}
	return convbuf;
}

/*
 - report - report progress, if indicated
 */
void
report(msg)
char *msg;
{
	if (!verbose)
		return;
	fprintf(stderr, "%s\n", msg);
}
