#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswfips.h"

#include "ike_alg.h"
#include "alg_info.h"

static bool run_tests = false;
static bool verbose = false;
static bool debug = false;
static bool impair = false;
static bool ikev1 = false;
static bool ikev2 = false;
static bool fips = false;
static int failures = 0;

enum expect { FAIL = false, PASS = true, IGNORE, };

static struct proposal_policy policy = {
	.ikev1 = false,
	.ikev2 = false,
};

#define CHECK(TYPE,PARSE) {						\
		policy.ikev1 = ikev1;					\
		policy.ikev2 = ikev2;					\
		if (algstr == NULL) {					\
			printf("[%s]\n", #PARSE);			\
		} else {						\
			printf("[%s=%s]\n", #PARSE, algstr);		\
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

static void esp(struct proposal_policy policy, enum expect expected, const char *algstr)
{
	policy.alg_is_ok = kernel_alg_is_ok;
	CHECK(esp, esp);
}

static void ah(struct proposal_policy policy, enum expect expected, const char *algstr)
{
	policy.alg_is_ok = kernel_alg_is_ok;
	CHECK(esp, ah);
}

static void ike(struct proposal_policy policy, enum expect expected, const char *algstr)
{
	policy.alg_is_ok = ike_alg_is_ike;
	CHECK(ike, ike);
}

typedef void (protocol_t)(struct proposal_policy policy, enum expect expected, const char *);

struct protocol {
	const char *name;
	protocol_t *parser;
};

const struct protocol protocols[] = {
	{ "ike", ike, },
	{ "ah", ah, },
	{ "esp", esp, },
};

static void all(const struct proposal_policy policy, const char *algstr)
{
	for (const struct protocol *protocol = protocols;
	     protocol < protocols + elemsof(protocols);
	     protocol++) {
		protocol->parser(policy, IGNORE, algstr);
	}
}

static void test_proposal(const struct proposal_policy policy, const char *arg)
{
	const char *eq = strchr(arg, '=');
	for (const struct protocol *protocol = protocols;
	     protocol < protocols + elemsof(protocols);
	     protocol++) {
		if (streq(arg, protocol->name)) {
			protocol->parser(policy, IGNORE, NULL);
			return;
		}
		if (startswith(arg, protocol->name)
		    && arg + strlen(protocol->name) == eq) {
			protocol->parser(policy, IGNORE, eq + 1);
			return;
		}
	}
	if (eq != NULL) {
		fprintf(stderr, "unrecognized PROTOCOL in '%s'", arg);
		exit(1);
	}
	all(policy, arg);
}

static void test(const struct proposal_policy policy)
{
	/*
	 * esp=
	 */

	esp(policy, true, NULL);
	esp(policy, false, "");

	esp(policy, true, "aes");
	esp(policy, true, "aes;modp2048");
	esp(policy, true, "aes-sha1");
	esp(policy, true, "aes-sha1");
	esp(policy, true, "aes-sha1-modp2048");
	esp(policy, true, "aes-128");
	esp(policy, true, "aes-128-sha1");
	esp(policy, true, "aes-128-sha1");
	esp(policy, true, "aes-128-sha1-modp2048");

	esp(policy, true, "aes_gcm_a-128-null");
	esp(policy, !fips, "3des-sha1;modp1024");
	esp(policy, !fips, "3des-sha1;modp1536");
	esp(policy, true, "3des-sha1;modp2048");
	esp(policy, !ikev1, "3des-sha1;dh21");
	esp(policy, !ikev1, "3des-sha1;ecp_521");
	esp(policy, true, "3des-sha1;dh23");
	esp(policy, true, "3des-sha1;dh24");
	esp(policy, true, "3des-sha1");
	esp(policy, !fips, "null-sha1");

	esp(policy, true, "aes_cbc");
	esp(policy, true, "aes-sha");
	esp(policy, true, "aes-sha1");
	esp(policy, true, "aes-sha2");
	esp(policy, true, "aes-sha256");
	esp(policy, true, "aes-sha384");
	esp(policy, true, "aes-sha512");
	esp(policy, true, "aes128-sha1");
	esp(policy, true, "aes128-aes_xcbc");
	esp(policy, true, "aes192-sha1");
	esp(policy, true, "aes256-sha1");
	esp(policy, true, "aes256-sha");
	esp(policy, true, "aes256-sha2");
	esp(policy, true, "aes256-sha2_256");
	esp(policy, true, "aes256-sha2_384");
	esp(policy, true, "aes256-sha2_512");
	esp(policy, !fips, "camellia");
	esp(policy, !fips, "camellia128");
	esp(policy, !fips, "camellia192");
	esp(policy, !fips, "camellia256");

	/* this checks the bit sizes as well */
	esp(policy, true, "aes_ccm");
	esp(policy, true, "aes_ccm_a-128-null");
	esp(policy, true, "aes_ccm_a-192-null");
	esp(policy, true, "aes_ccm_a-256-null");
	esp(policy, true, "aes_ccm_b-128-null");
	esp(policy, true, "aes_ccm_b-192-null");
	esp(policy, true, "aes_ccm_b-256-null");
	esp(policy, true, "aes_ccm_c-128-null");
	esp(policy, true, "aes_ccm_c-192-null");
	esp(policy, true, "aes_ccm_c-256-null");
	esp(policy, true, "aes_gcm");
	esp(policy, true, "aes_gcm_a-128-null");
	esp(policy, true, "aes_gcm_a-192-null");
	esp(policy, true, "aes_gcm_a-256-null");
	esp(policy, true, "aes_gcm_b-128-null");
	esp(policy, true, "aes_gcm_b-192-null");
	esp(policy, true, "aes_gcm_b-256-null");
	esp(policy, true, "aes_gcm_c-128-null");
	esp(policy, true, "aes_gcm_c-192-null");
	esp(policy, true, "aes_gcm_c-256-null");

	esp(policy, true, "aes_ccm_a-null");
	esp(policy, true, "aes_ccm_b-null");
	esp(policy, true, "aes_ccm_c-null");
	esp(policy, true, "aes_gcm_a-null");
	esp(policy, true, "aes_gcm_b-null");
	esp(policy, true, "aes_gcm_c-null");

	esp(policy, true, "aes_ccm-null");
	esp(policy, true, "aes_gcm-null");

	esp(policy, true, "aes_ccm-256-null");
	esp(policy, true, "aes_gcm-192-null");

	esp(policy, true, "aes_ccm_256-null");
	esp(policy, true, "aes_gcm_192-null");

	esp(policy, true, "aes_ccm_8-null");
	esp(policy, true, "aes_ccm_12-null");
	esp(policy, true, "aes_ccm_16-null");
	esp(policy, true, "aes_gcm_8-null");
	esp(policy, true, "aes_gcm_12-null");
	esp(policy, true, "aes_gcm_16-null");

	esp(policy, true, "aes_ccm_8-128-null");
	esp(policy, true, "aes_ccm_12-192-null");
	esp(policy, true, "aes_ccm_16-256-null");
	esp(policy, true, "aes_gcm_8-128-null");
	esp(policy, true, "aes_gcm_12-192-null");
	esp(policy, true, "aes_gcm_16-256-null");

	esp(policy, true, "aes_ccm_8_128-null");
	esp(policy, true, "aes_ccm_12_192-null");
	esp(policy, true, "aes_ccm_16_256-null");
	esp(policy, true, "aes_gcm_8_128-null");
	esp(policy, true, "aes_gcm_12_192-null");
	esp(policy, true, "aes_gcm_16_256-null");

	/* other */
	esp(policy, true, "aes_ctr");
	esp(policy, true, "aesctr");
	esp(policy, true, "aes_ctr128");
	esp(policy, true, "aes_ctr192");
	esp(policy, true, "aes_ctr256");
	esp(policy, !fips, "serpent");
	esp(policy, !fips, "twofish");
	esp(policy, !fips, "camellia_cbc_256-hmac_sha2_512_256;modp8192"); /* long */
	esp(policy, !fips, "null_auth_aes_gmac_256-null;modp8192"); /* long */
	esp(policy, true, "3des-sha1;modp8192"); /* allow ';' when unambigious */
	esp(policy, true, "3des-sha1-modp8192"); /* allow '-' when unambigious */
	esp(policy, true, "aes-sha1,3des-sha1;modp8192"); /* set modp8192 on all algs */
	esp(policy, true, "aes-sha1-modp8192,3des-sha1-modp8192"); /* silly */
	esp(policy, true, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */

	/*
	 * should this be supported - for now man page says not
	 * esp(policy, "modp1536");
	 */

	/* ESP tests that should fail */

	esp(policy, impair, "3des168-sha1"); /* wrong keylen */
	esp(policy, impair, "3des-null"); /* non-null integ */
	esp(policy, impair, "aes128-null"); /* non-null-integ */
	esp(policy, impair, "aes224-sha1"); /* wrong keylen */
	esp(policy, impair, "aes-224-sha1"); /* wrong keylen */
	esp(policy, false, "aes0-sha1"); /* wrong keylen */
	esp(policy, false, "aes-0-sha1"); /* wrong keylen */
	esp(policy, impair, "aes512-sha1"); /* wrong keylen */
	esp(policy, false, "aes-sha1555"); /* unknown integ */
	esp(policy, impair, "camellia666-sha1"); /* wrong keylen */
	esp(policy, false, "blowfish"); /* obsoleted */
	esp(policy, false, "des-sha1"); /* obsoleted */
	esp(policy, impair, "aes_ctr666"); /* bad key size */
	esp(policy, false, "aes128-sha2_128"); /* _128 does not exist */
	esp(policy, false, "aes256-sha2_256-4096"); /* double keysize */
	esp(policy, false, "aes256-sha2_256-128"); /* now what?? */
	esp(policy, false, "vanitycipher");
	esp(policy, false, "ase-sah"); /* should get rejected */
	esp(policy, false, "aes-sah1"); /* should get rejected */
	esp(policy, false, "id3"); /* should be rejected; idXXX removed */
	esp(policy, false, "aes-id3"); /* should be rejected; idXXX removed */
	esp(policy, impair, "aes_gcm-md5"); /* AEAD must have auth null */
	esp(policy, false, "mars"); /* support removed */
	esp(policy, impair, "aes_gcm-16"); /* don't parse as aes_gcm_16 */
	esp(policy, false, "aes_gcm-0"); /* invalid keylen */
	esp(policy, false, "aes_gcm-123456789012345"); /* huge keylen */
	esp(policy, false, "3des-sha1;dh22"); /* support for dh22 removed */

	esp(policy, false, "3des-sha1;modp8192,3des-sha2"); /* ;DH must be last */
	esp(policy, impair, "3des-sha1-modp8192,3des-sha2"); /* -DH must be last */

	esp(policy, true, "3des-sha1-modp8192,3des-sha2-modp8192"); /* ok */
	esp(policy, false, "3des-sha1-modp8192,3des-sha2;modp8192"); /* ;DH must be last */
	esp(policy, false, "3des-sha1;modp8192,3des-sha2;modp8192"); /* ;DH must be last */
	esp(policy, false, "3des-sha1;modp8192,3des-sha2;modp8192"); /* ;DH must be last */
	esp(policy, impair, "3des-sha1-modp8192,3des-sha2-ecp_521"); /* ;DH must match */

	esp(policy, false, "3des-sha1;modp8192,3des-sha1-modp8192"); /* ;DH must be last when dup */
	esp(policy, false, "3des-sha1;modp8192,3des-sha1;modp8192"); /* ;DH must be last when dup */

	/*
	 * ah=
	 */

	/* AH tests that should succeed */

	ah(policy, true, NULL);
	ah(policy, false, "");
	ah(policy, !fips, "md5");
	ah(policy, true, "sha");
	ah(policy, true, "sha;modp2048");
	ah(policy, true, "sha1");
	ah(policy, true, "sha2");
	ah(policy, true, "sha256");
	ah(policy, true, "sha384");
	ah(policy, true, "sha512");
	ah(policy, true, "sha2_256");
	ah(policy, true, "sha2_384");
	ah(policy, true, "sha2_512");
	ah(policy, true, "aes_xcbc");
	ah(policy, true, "sha1-modp8192,sha1-modp8192,sha1-modp8192"); /* suppress duplicates */

	/* AH tests that should fail */

	ah(policy, impair, "aes-sha1");
	ah(policy, false, "vanityhash1");
	ah(policy, impair, "aes_gcm_c-256");
	ah(policy, false, "id3"); /* should be rejected; idXXX removed */
	ah(policy, impair, "3des");
	ah(policy, impair, "null");
	ah(policy, impair, "aes_gcm");
	ah(policy, impair, "aes_ccm");
	ah(policy, false, "ripemd"); /* support removed */

	/*
	 * ike=
	 */

	/* IKE tests that should succeed */

	ike(policy, true, NULL);
	ike(policy, false, "");
	ike(policy, true, "3des-sha1");
	ike(policy, true, "3des-sha1");
	ike(policy, !fips, "3des-sha1;modp1536");
	ike(policy, true, "3des;dh21");
	ike(policy, true, "3des-sha1;dh21");
	ike(policy, true, "3des-sha1-ecp_521");
	ike(policy, !ikev1, "aes_gcm");
	ike(policy, true, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */

	/* IKE tests that should fail */

	ike(policy, false, "id2"); /* should be rejected; idXXX removed */
	ike(policy, false, "3des-id2"); /* should be rejected; idXXX removed */
	ike(policy, false, "aes_ccm"); /* ESP/AH only */
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
		"  -v: more verbose\n"
		"  -impair: disable all algorithm parser checks\n"
		"  -t: run testsuite\n"
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
		} else if (streq(arg, "t")) {
			run_tests = true;
		} else if (streq(arg, "v1")) {
			ikev1 = true;
		} else if (streq(arg, "v2")) {
			ikev2 = true;
		} else if (streq(arg, "fips") || streq(arg, "fips=yes") || streq(arg, "fips=on")) {
			lsw_set_fips_mode(LSW_FIPS_ON);
		} else if (streq(arg, "fips=no") || streq(arg, "fips=off")) {
			lsw_set_fips_mode(LSW_FIPS_OFF);
		} else if (streq(arg, "fips=unknown")) {
			lsw_set_fips_mode(LSW_FIPS_UNKNOWN);
		} else if (streq(arg, "v")) {
			verbose = true;
		} else if (streq(arg, "debug")) {
			debug = true;
		} else if (streq(arg, "impair")) {
			impair = true;
		} else {
			fprintf(stderr, "unknown option: %s\n", *argp);
			exit(1);
		}
	}

	fips = libreswan_fipsmode();

	/*
	 * Need to ensure that NSS is initialized before calling
	 * ike_alg_init().  Some sanity checks require a working NSS.
	 */
	lsw_nss_buf_t err;
	if (!lsw_nss_setup(NULL, 0, NULL, err)) {
		fprintf(stderr, "unexpected %s\n", err);
		exit(1);
	}

	/*
	 * Only be verbose after NSS has started.  Otherwise fake and
	 * real FIPS modes give different results.
	 */
	log_to_stderr = verbose;

	ike_alg_init();

	/*
	 * Only enabling debugging and impairing after things have
	 * started.  Otherwise there's just TMI.
	 */
	if (debug) {
		cur_debugging |= DBG_PROPOSAL_PARSER;
	}
	if (impair) {
		cur_debugging |= IMPAIR_PROPOSAL_PARSER;
	}

	if (*argp) {
		if (run_tests) {
			fprintf(stderr, "-t conflicts with algorithm list\n");
			exit(1);
		}
		for (; *argp != NULL; argp++) {
			test_proposal(policy, *argp);
		}
	} else if (run_tests) {
		test(policy);
	}

	report_leaks();

	lsw_nss_shutdown();

	if (failures > 0) {
		fprintf(stderr, "%d FAILURES\n", failures);
		exit(1);
	}

	exit(0);
}
