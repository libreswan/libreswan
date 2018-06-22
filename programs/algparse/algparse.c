#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswfips.h"
#include "lswconf.h"

#include "ike_alg.h"
#include "alg_info.h"

static bool test_proposals = false;
static bool test_algs = false;
static bool verbose = false;
static bool debug = false;
static bool impair = false;
static bool ikev1 = false;
static bool ikev2 = false;
static bool fips = false;
static bool pfs = false;
static int failures = 0;

enum expect { FAIL = false, PASS = true, IGNORE, };

#define CHECK(TYPE,PARSE,OK) {						\
		struct proposal_policy policy = {			\
			.ikev1 = ikev1,					\
			.ikev2 = ikev2,					\
			.alg_is_ok = OK,				\
			.pfs = pfs,					\
		};							\
		printf("algparse ");					\
		if (fips) {						\
			printf("-fips ");				\
		}							\
		if (ikev1) {						\
			printf("-v1 ");					\
		}							\
		if (ikev2) {						\
			printf("-v2 ");					\
		}							\
		if (pfs) {						\
			printf("-pfs ");				\
		}							\
		if (algstr == NULL) {					\
			printf("'%s'\n", #PARSE);			\
		} else {						\
			printf("'%s=%s'\n", #PARSE, algstr);		\
		}							\
		fflush(NULL);						\
		char err_buf[512] = "";	/* ??? big enough? */		\
		struct alg_info_##TYPE *e =				\
			alg_info_##PARSE##_create_from_str(&policy,	\
							   algstr,	\
							   err_buf,	\
							   sizeof(err_buf)); \
		if (e != NULL) {					\
			passert(err_buf[0] == '\0');			\
			FOR_EACH_PROPOSAL_INFO(&e->ai, proposal) {	\
				LSWLOG_FILE(stdout, log) {		\
					lswlogf(log, "\t");		\
					lswlog_proposal_info(log, proposal); \
				}					\
			}						\
			alg_info_free(&e->ai);				\
			if (expected == FAIL) {				\
				failures++;				\
				fprintf(stderr,				\
					"UNEXPECTED PASS: %s%s%s\n",	\
					#PARSE,				\
					algstr == NULL ? "" : "=",	\
					algstr == NULL ? "" : algstr);	\
			}						\
		} else {						\
			passert(err_buf[0]);				\
			printf("\tERROR: %s\n", err_buf);		\
			if (expected == PASS) {				\
				failures++;				\
				fprintf(stderr,				\
					"UNEXPECTED FAIL: %s%s%s\n",	\
					#PARSE,				\
					algstr == NULL ? "" : "=",	\
					algstr == NULL ? "" : algstr);	\
			}						\
		}							\
		fflush(NULL);						\
	}

/*
 * Kernel not available so fake it.
 */
static bool kernel_alg_is_ok(const struct ike_alg *alg)
{
	if (alg->algo_type == &ike_alg_dh) {
		/* require an in-process/ike implementation of DH */
		return ike_alg_is_ike(alg);
	} else {
		/* no kernel to ask! */
		return TRUE;
	}
}

static void esp(enum expect expected, const char *algstr)
{
	CHECK(esp, esp, kernel_alg_is_ok);
}

static void ah(enum expect expected, const char *algstr)
{
	CHECK(esp, ah, kernel_alg_is_ok);
}

static void ike(enum expect expected, const char *algstr)
{
	CHECK(ike, ike, ike_alg_is_ike);
}

typedef void (protocol_t)(enum expect expected, const char *);

struct protocol {
	const char *name;
	protocol_t *parser;
};

const struct protocol protocols[] = {
	{ "ike", ike, },
	{ "ah", ah, },
	{ "esp", esp, },
};

static void all(const char *algstr)
{
	for (const struct protocol *protocol = protocols;
	     protocol < protocols + elemsof(protocols);
	     protocol++) {
		protocol->parser(IGNORE, algstr);
	}
}

static void test_proposal(const char *arg)
{
	const char *eq = strchr(arg, '=');
	for (const struct protocol *protocol = protocols;
	     protocol < protocols + elemsof(protocols);
	     protocol++) {
		if (streq(arg, protocol->name)) {
			protocol->parser(IGNORE, NULL);
			return;
		}
		if (startswith(arg, protocol->name)
		    && arg + strlen(protocol->name) == eq) {
			protocol->parser(IGNORE, eq + 1);
			return;
		}
	}
	if (eq != NULL) {
		fprintf(stderr, "unrecognized PROTOCOL in '%s'", arg);
		exit(1);
	}
	all(arg);
}

static void test(void)
{
	/*
	 * esp=
	 */

	esp(true, NULL);
	esp(false, "");

	esp(true, "aes");
	esp(pfs, "aes;modp2048");
	esp(true, "aes-sha1");
	esp(true, "aes-sha1");
	esp(pfs, "aes-sha1-modp2048");
	esp(true, "aes-128");
	esp(true, "aes-128-sha1");
	esp(true, "aes-128-sha1");
	esp(pfs, "aes-128-sha1-modp2048");

	esp(true, "aes_gcm_a-128-null");
	esp(pfs && !fips, "3des-sha1;modp1024");
	esp(pfs && !fips, "3des-sha1;modp1536");
	esp(pfs, "3des-sha1;modp2048");
	esp(pfs && !ikev1, "3des-sha1;dh21");
	esp(pfs && !ikev1, "3des-sha1;ecp_521");
	esp(pfs, "3des-sha1;dh23");
	esp(pfs, "3des-sha1;dh24");
	esp(true, "3des-sha1");
	esp(!fips, "null-sha1");

	esp(true, "aes_cbc");
	esp(true, "aes-sha");
	esp(true, "aes-sha1");
	esp(true, "aes-sha2");
	esp(true, "aes-sha256");
	esp(true, "aes-sha384");
	esp(true, "aes-sha512");
	esp(true, "aes128-sha1");
	esp(true, "aes128-aes_xcbc");
	esp(true, "aes192-sha1");
	esp(true, "aes256-sha1");
	esp(true, "aes256-sha");
	esp(true, "aes256-sha2");
	esp(true, "aes256-sha2_256");
	esp(true, "aes256-sha2_384");
	esp(true, "aes256-sha2_512");
	esp(!fips, "camellia");
	esp(!fips, "camellia128");
	esp(!fips, "camellia192");
	esp(!fips, "camellia256");

	/* this checks the bit sizes as well */
	esp(true, "aes_ccm");
	esp(true, "aes_ccm_a-128-null");
	esp(true, "aes_ccm_a-192-null");
	esp(true, "aes_ccm_a-256-null");
	esp(true, "aes_ccm_b-128-null");
	esp(true, "aes_ccm_b-192-null");
	esp(true, "aes_ccm_b-256-null");
	esp(true, "aes_ccm_c-128-null");
	esp(true, "aes_ccm_c-192-null");
	esp(true, "aes_ccm_c-256-null");
	esp(true, "aes_gcm");
	esp(true, "aes_gcm_a-128-null");
	esp(true, "aes_gcm_a-192-null");
	esp(true, "aes_gcm_a-256-null");
	esp(true, "aes_gcm_b-128-null");
	esp(true, "aes_gcm_b-192-null");
	esp(true, "aes_gcm_b-256-null");
	esp(true, "aes_gcm_c-128-null");
	esp(true, "aes_gcm_c-192-null");
	esp(true, "aes_gcm_c-256-null");

	esp(true, "aes_ccm_a-null");
	esp(true, "aes_ccm_b-null");
	esp(true, "aes_ccm_c-null");
	esp(true, "aes_gcm_a-null");
	esp(true, "aes_gcm_b-null");
	esp(true, "aes_gcm_c-null");

	esp(true, "aes_ccm-null");
	esp(true, "aes_gcm-null");

	esp(true, "aes_ccm-256-null");
	esp(true, "aes_gcm-192-null");

	esp(true, "aes_ccm_256-null");
	esp(true, "aes_gcm_192-null");

	esp(true, "aes_ccm_8-null");
	esp(true, "aes_ccm_12-null");
	esp(true, "aes_ccm_16-null");
	esp(true, "aes_gcm_8-null");
	esp(true, "aes_gcm_12-null");
	esp(true, "aes_gcm_16-null");

	esp(true, "aes_ccm_8-128-null");
	esp(true, "aes_ccm_12-192-null");
	esp(true, "aes_ccm_16-256-null");
	esp(true, "aes_gcm_8-128-null");
	esp(true, "aes_gcm_12-192-null");
	esp(true, "aes_gcm_16-256-null");

	esp(true, "aes_ccm_8_128-null");
	esp(true, "aes_ccm_12_192-null");
	esp(true, "aes_ccm_16_256-null");
	esp(true, "aes_gcm_8_128-null");
	esp(true, "aes_gcm_12_192-null");
	esp(true, "aes_gcm_16_256-null");

	/* other */
	esp(true, "aes_ctr");
	esp(true, "aesctr");
	esp(true, "aes_ctr128");
	esp(true, "aes_ctr192");
	esp(true, "aes_ctr256");
	esp(!fips, "serpent");
	esp(!fips, "twofish");

	esp(pfs && !fips, "camellia_cbc_256-hmac_sha2_512_256;modp8192"); /* long */
	esp(pfs && !fips, "null_auth_aes_gmac_256-null;modp8192"); /* long */
	esp(pfs, "3des-sha1;modp8192"); /* allow ';' when unambigious */
	esp(pfs, "3des-sha1-modp8192"); /* allow '-' when unambigious */
	esp(false, "aes-sha1,3des-sha1;modp8192");
	esp(pfs, "aes-sha1-modp8192,3des-sha1-modp8192"); /* silly */
	esp(pfs, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */

	esp(pfs && !fips && !ikev1, "aes;none");
	esp(false, "aes;none,aes");
	esp(pfs && !fips && !ikev1, "aes;none,aes;modp2048");
	esp(pfs && !fips && !ikev1, "aes-sha1-none");
	esp(pfs && !fips && !ikev1, "aes-sha1;none");

	/*
	 * should this be supported - for now man page says not
	 * esp("modp1536");
	 */

	/* ESP tests that should fail */

	esp(impair, "3des168-sha1"); /* wrong keylen */
	esp(impair, "3des-null"); /* non-null integ */
	esp(impair, "aes128-null"); /* non-null-integ */
	esp(impair, "aes224-sha1"); /* wrong keylen */
	esp(impair, "aes-224-sha1"); /* wrong keylen */
	esp(false, "aes0-sha1"); /* wrong keylen */
	esp(false, "aes-0-sha1"); /* wrong keylen */
	esp(impair, "aes512-sha1"); /* wrong keylen */
	esp(false, "aes-sha1555"); /* unknown integ */
	esp(impair, "camellia666-sha1"); /* wrong keylen */
	esp(false, "blowfish"); /* obsoleted */
	esp(false, "des-sha1"); /* obsoleted */
	esp(impair, "aes_ctr666"); /* bad key size */
	esp(false, "aes128-sha2_128"); /* _128 does not exist */
	esp(false, "aes256-sha2_256-4096"); /* double keysize */
	esp(false, "aes256-sha2_256-128"); /* now what?? */
	esp(false, "vanitycipher");
	esp(false, "ase-sah"); /* should get rejected */
	esp(false, "aes-sah1"); /* should get rejected */
	esp(false, "id3"); /* should be rejected; idXXX removed */
	esp(false, "aes-id3"); /* should be rejected; idXXX removed */
	esp(impair, "aes_gcm-md5"); /* AEAD must have auth null */
	esp(false, "mars"); /* support removed */
	esp(impair, "aes_gcm-16"); /* don't parse as aes_gcm_16 */
	esp(false, "aes_gcm-0"); /* invalid keylen */
	esp(false, "aes_gcm-123456789012345"); /* huge keylen */
	esp(false, "3des-sha1;dh22"); /* support for dh22 removed */

	esp(impair, "3des-sha1;modp8192,3des-sha2"); /* ;DH must be last */
	esp(impair, "3des-sha1-modp8192,3des-sha2"); /* -DH must be last */

	esp(pfs, "3des-sha1-modp8192,3des-sha2-modp8192");
	esp(pfs, "3des-sha1-modp8192,3des-sha2;modp8192");
	esp(pfs, "3des-sha1;modp8192,3des-sha2-modp8192");
	esp(pfs, "3des-sha1;modp8192,3des-sha2;modp8192");
	esp(impair, "3des-sha1-modp8192,3des-sha2-modp2048");

	/*
	 * ah=
	 */

	/* AH tests that should succeed */

	ah(true, NULL);
	ah(false, "");
	ah(!fips, "md5");
	ah(true, "sha");
	ah(pfs, "sha;modp2048");
	ah(true, "sha1");
	ah(true, "sha2");
	ah(true, "sha256");
	ah(true, "sha384");
	ah(true, "sha512");
	ah(true, "sha2_256");
	ah(true, "sha2_384");
	ah(true, "sha2_512");
	ah(true, "aes_xcbc");
	ah(pfs && !fips && !ikev1, "sha2-none");
	ah(pfs && !fips && !ikev1, "sha2;none");
	ah(pfs, "sha1-modp8192,sha1-modp8192,sha1-modp8192"); /* suppress duplicates */

	/* AH tests that should fail */

	ah(impair, "aes-sha1");
	ah(false, "vanityhash1");
	ah(impair, "aes_gcm_c-256");
	ah(false, "id3"); /* should be rejected; idXXX removed */
	ah(impair, "3des");
	ah(impair, "null");
	ah(impair, "aes_gcm");
	ah(impair, "aes_ccm");
	ah(false, "ripemd"); /* support removed */

	/*
	 * ike=
	 */

	/* IKE tests that should succeed */

	ike(true, NULL);
	ike(false, "");
	ike(true, "3des-sha1");
	ike(true, "3des-sha1");
	ike(!fips, "3des-sha1;modp1536");
	ike(true, "3des;dh21");
	ike(true, "3des-sha1;dh21");
	ike(true, "3des-sha1-ecp_521");
	ike(!ikev1, "aes_gcm");
	ike(true, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */
	ike(false, "aes;none");

	/* IKE tests that should fail */

	ike(false, "id2"); /* should be rejected; idXXX removed */
	ike(false, "3des-id2"); /* should be rejected; idXXX removed */
	ike(false, "aes_ccm"); /* ESP/AH only */
}

static void usage(void)
{
	fprintf(stderr,
		""
		"Usage:\n"
		"  algparse [ <option> ... ] -t | <protocol> | <proposals> | <protocol>=<proposals>\n"
		"Where:\n"
		"  -v1: only IKEv1 algorithms\n"
		"  -v2: only IKEv2 algorithms\n"
		"  -fips: put NSS in FIPS mode\n"
		"  -v --verbose: more verbose\n"
		"  -i --impair: disable all algorithm parser checks\n"
		"  -d --debug: really verbose\n"
		"  -tp: run proposal tests\n"
		"  -ta: run algorithm tests\n"
		"  -d -nssdir: directory containing crypto database\n"
		"  -P -nsspw -password: password to unlock crypto database\n"
		"  <protocol>: the protocol, one of 'ike', 'esp', or 'ah'\n"
		"  <proposals>: a comma separated list of proposals to parse\n"
		"For instance:\n"
		"  algparse -v1 ike\n"
		"        expand the default IKEv1 'ike' algorithm table\n"
		"        (with IKEv1, this is the default algorithms, with IKEv2 it is not)\n"
		"  algparse -v1 ike=esp\n"
		"        expand 'aes' using the IKEv1 'ike' parser and defaults\n"
		"  algparse -v1 aes\n"
		"        expand 'aes' using the the IKEv1 'ike', 'esp', and 'ah' parsers and defaults\n"
		);
}

int main(int argc, char *argv[])
{
	log_to_stderr = false;
	tool_init_log(argv[0]);

	if (argc == 1) {
		usage();
		exit(1);
	}

	char **argp = argv + 1;
	for (; *argp != NULL; argp++) {
		const char *arg = *argp;
		if (arg[0] != '-') {
			break;
		}
		do {
			arg++;
		} while (arg[0] == '-');
		if (streq(arg, "?") || streq(arg, "h")) {
			usage();
			exit(0);
		} else if (streq(arg, "t") || streq(arg, "tp")) {
			test_proposals = true;
		} else if (streq(arg, "ta")) {
			test_algs = true;
		} else if (streq(arg, "v1")) {
			ikev1 = true;
		} else if (streq(arg, "v2")) {
			ikev2 = true;
		} else if (streq(arg, "pfs") || streq(arg, "pfs=yes") || streq(arg, "pfs=on")) {
			pfs = true;
		} else if (streq(arg, "pfs=no") || streq(arg, "pfs=off")) {
			pfs = false;
		} else if (streq(arg, "fips") || streq(arg, "fips=yes") || streq(arg, "fips=on")) {
			lsw_set_fips_mode(LSW_FIPS_ON);
		} else if (streq(arg, "fips=no") || streq(arg, "fips=off")) {
			lsw_set_fips_mode(LSW_FIPS_OFF);
		} else if (streq(arg, "fips=unknown")) {
			lsw_set_fips_mode(LSW_FIPS_UNKNOWN);
		} else if (streq(arg, "v") || streq(arg, "verbose")) {
			verbose = true;
		} else if (streq(arg, "debug")) {
			debug = true;
		} else if (streq(arg, "impair")) {
			impair = true;
		} else if (streq(arg, "d") || streq(arg, "nssdir")) {
			char *nssdir = *++argp;
			if (nssdir == NULL) {
				fprintf(stderr, "missing nss directory\n");
				exit(1);
			}
			lsw_conf_nssdir(nssdir);
		} else if (streq(arg, "P") || streq(arg, "nsspw") || streq(arg, "password")) {
			char *nsspw = *++argp;
			if (nsspw == NULL) {
				fprintf(stderr, "missing nss password\n");
				exit(1);
			}
			lsw_conf_nsspassword(nsspw);
		} else {
			fprintf(stderr, "unknown option: %s\n", *argp);
			exit(1);
		}
	}

	fips = libreswan_fipsmode();

	/*
	 * Need to ensure that NSS is initialized before calling
	 * ike_alg_init().  Sanity checks and algorithm testing
	 * require a working NSS.
	 *
	 * When testing the algorithms in FIPS mode (i.e., executing
	 * crypto code) NSS needs to be pointed at a real FIPS mode
	 * NSS directory.
	 */
	lsw_nss_buf_t err;
	bool nss_ok = lsw_nss_setup((fips && test_algs) ? lsw_init_options()->nssdir : NULL,
				    LSW_NSS_READONLY, lsw_nss_get_password, err);
	if (!nss_ok) {
		fprintf(stderr, "unexpected %s\n", err);
		exit(1);
	}

	/*
	 * Only be verbose after NSS has started.  Otherwise fake and
	 * real FIPS modes give different results.
	 */
	log_to_stderr = verbose;

	init_ike_alg();

	/*
	 * Only enabling debugging and impairing after things have
	 * started.  Otherwise there's just TMI.
	 */
	if (debug) {
		cur_debugging |= DBG_PROPOSAL_PARSER | DBG_CRYPT;
	}
	if (impair) {
		cur_debugging |= IMPAIR_PROPOSAL_PARSER;
	}

	if (test_algs) {
		test_ike_alg();
	}

	if (*argp) {
		if (test_proposals) {
			fprintf(stderr, "-t conflicts with algorithm list\n");
			exit(1);
		}
		for (; *argp != NULL; argp++) {
			test_proposal(*argp);
		}
	} else if (test_proposals) {
		test();
	}

	report_leaks();

	lsw_nss_shutdown();

	if (failures > 0) {
		fprintf(stderr, "%d FAILURES\n", failures);
		exit(1);
	}

	exit(0);
}
