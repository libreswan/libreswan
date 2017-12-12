#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswfips.h"

#include "ike_alg.h"
#include "alg_info.h"

#define CHECK(TYPE,PARSE) {						\
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
		} else {						\
			passert(err_buf[0]);				\
			printf("\tERROR: %s\n", err_buf);		\
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

static void esp(struct parser_policy policy, const char *algstr)
{
	policy.alg_is_ok = kernel_alg_is_ok;
	CHECK(esp, esp);
}

static void ah(struct parser_policy policy, const char *algstr)
{
	policy.alg_is_ok = kernel_alg_is_ok;
	CHECK(esp, ah);
}

static void ike(struct parser_policy policy, const char *algstr)
{
	policy.alg_is_ok = ike_alg_is_ike;
	CHECK(ike, ike);
}

typedef void (protocol_t)(struct parser_policy policy, const char *);

struct protocol {
	const char *name;
	protocol_t *parser;
};

const struct protocol protocols[] = {
	{ "ike", ike, },
	{ "ah", ah, },
	{ "esp", esp, },
};

static void all(const struct parser_policy policy, const char *algstr)
{
	for (const struct protocol *protocol = protocols;
	     protocol < protocols + elemsof(protocols);
	     protocol++) {
		protocol->parser(policy, algstr);
	}
}

static void test_proposal(const struct parser_policy policy, const char *arg)
{
	const char *eq = strchr(arg, '=');
	for (const struct protocol *protocol = protocols;
	     protocol < protocols + elemsof(protocols);
	     protocol++) {
		if (streq(arg, protocol->name)) {
			protocol->parser(policy, NULL);
			return;
		}
		if (startswith(arg, protocol->name)
		    && arg + strlen(protocol->name) == eq) {
			protocol->parser(policy, eq + 1);
			return;
		}
	}
	if (eq != NULL) {
		fprintf(stderr, "unrecognized PROTOCOL in '%s'", arg);
		exit(1);
	}
	all(policy, arg);
}

static void test(const struct parser_policy policy)
{
	/*
	 * esp=
	 */

	printf("\n---- ESP tests that should succeed ----\n");

	esp(policy, NULL);
	esp(policy, "");
	esp(policy, "aes_gcm_a-128-null");
	esp(policy, "3des-sha1;modp1024");
	esp(policy, "3des-sha1;modp1536");
	esp(policy, "3des-sha1;modp2048");
	esp(policy, "3des-sha1;dh21");
	esp(policy, "3des-sha1;ecp_521");
	esp(policy, "3des-sha1;dh23");
	esp(policy, "3des-sha1;dh24");
	esp(policy, "3des-sha1");
	esp(policy, "null-sha1");
	esp(policy, "aes");
	esp(policy, "aes_cbc");
	esp(policy, "aes-sha");
	esp(policy, "aes-sha1");
	esp(policy, "aes-sha2");
	esp(policy, "aes-sha256");
	esp(policy, "aes-sha384");
	esp(policy, "aes-sha512");
	esp(policy, "aes128-sha1");
	esp(policy, "aes128-aes_xcbc");
	esp(policy, "aes192-sha1");
	esp(policy, "aes256-sha1");
	esp(policy, "aes256-sha");
	esp(policy, "aes256-sha2");
	esp(policy, "aes256-sha2_256");
	esp(policy, "aes256-sha2_384");
	esp(policy, "aes256-sha2_512");
	esp(policy, "camellia");
	esp(policy, "camellia128");
	esp(policy, "camellia192");
	esp(policy, "camellia256");

	/* this checks the bit sizes as well */
	esp(policy, "aes_ccm");
	esp(policy, "aes_ccm_a-128-null");
	esp(policy, "aes_ccm_a-192-null");
	esp(policy, "aes_ccm_a-256-null");
	esp(policy, "aes_ccm_b-128-null");
	esp(policy, "aes_ccm_b-192-null");
	esp(policy, "aes_ccm_b-256-null");
	esp(policy, "aes_ccm_c-128-null");
	esp(policy, "aes_ccm_c-192-null");
	esp(policy, "aes_ccm_c-256-null");
	esp(policy, "aes_gcm");
	esp(policy, "aes_gcm_a-128-null");
	esp(policy, "aes_gcm_a-192-null");
	esp(policy, "aes_gcm_a-256-null");
	esp(policy, "aes_gcm_b-128-null");
	esp(policy, "aes_gcm_b-192-null");
	esp(policy, "aes_gcm_b-256-null");
	esp(policy, "aes_gcm_c-128-null");
	esp(policy, "aes_gcm_c-192-null");
	esp(policy, "aes_gcm_c-256-null");

	esp(policy, "aes_ccm_a-null");
	esp(policy, "aes_ccm_b-null");
	esp(policy, "aes_ccm_c-null");
	esp(policy, "aes_gcm_a-null");
	esp(policy, "aes_gcm_b-null");
	esp(policy, "aes_gcm_c-null");

	esp(policy, "aes_ccm-null");
	esp(policy, "aes_gcm-null");

	esp(policy, "aes_ccm-256-null");
	esp(policy, "aes_gcm-192-null");

	esp(policy, "aes_ccm_256-null");
	esp(policy, "aes_gcm_192-null");

	esp(policy, "aes_ccm_8-null");
	esp(policy, "aes_ccm_12-null");
	esp(policy, "aes_ccm_16-null");
	esp(policy, "aes_gcm_8-null");
	esp(policy, "aes_gcm_12-null");
	esp(policy, "aes_gcm_16-null");

	esp(policy, "aes_ccm_8-128-null");
	esp(policy, "aes_ccm_12-192-null");
	esp(policy, "aes_ccm_16-256-null");
	esp(policy, "aes_gcm_8-128-null");
	esp(policy, "aes_gcm_12-192-null");
	esp(policy, "aes_gcm_16-256-null");

	esp(policy, "aes_ccm_8_128-null");
	esp(policy, "aes_ccm_12_192-null");
	esp(policy, "aes_ccm_16_256-null");
	esp(policy, "aes_gcm_8_128-null");
	esp(policy, "aes_gcm_12_192-null");
	esp(policy, "aes_gcm_16_256-null");

	/* other */
	esp(policy, "aes_ctr");
	esp(policy, "aesctr");
	esp(policy, "aes_ctr128");
	esp(policy, "aes_ctr192");
	esp(policy, "aes_ctr256");
	esp(policy, "serpent");
	esp(policy, "twofish");
	esp(policy, "camellia_cbc_256-hmac_sha2_512_256;modp8192"); /* long */
	esp(policy, "null_auth_aes_gmac_256-null;modp8192"); /* long */
	esp(policy, "3des-sha1;modp8192"); /* allow ';' when unambigious */
	esp(policy, "3des-sha1-modp8192"); /* allow '-' when unambigious */
	esp(policy, "aes-sha1,3des-sha1;modp8192"); /* set modp8192 on all algs */
	esp(policy, "aes-sha1-modp8192,3des-sha1-modp8192"); /* silly */
	esp(policy, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */

	/*
	 * should this be supported - for now man page says not
	 * esp(policy, "modp1536");
	 */

	printf("\n---- ESP tests that should fail----\n");

	esp(policy, "3des168-sha1"); /* should get rejected */
	esp(policy, "3des-null"); /* should get rejected */
	esp(policy, "aes128-null"); /* should get rejected */
	esp(policy, "aes224-sha1"); /* should get rejected */
	esp(policy, "aes512-sha1"); /* should get rejected */
	esp(policy, "aes-sha1555"); /* should get rejected */
	esp(policy, "camellia666-sha1"); /* should get rejected */
	esp(policy, "blowfish"); /* obsoleted */
	esp(policy, "des-sha1"); /* obsoleted */
	esp(policy, "aes_ctr666"); /* bad key size */
	esp(policy, "aes128-sha2_128"); /* _128 does not exist */
	esp(policy, "aes256-sha2_256-4096"); /* double keysize */
	esp(policy, "aes256-sha2_256-128"); /* now what?? */
	esp(policy, "vanitycipher");
	esp(policy, "ase-sah"); /* should get rejected */
	esp(policy, "aes-sah1"); /* should get rejected */
	esp(policy, "id3"); /* should be rejected; idXXX removed */
	esp(policy, "aes-id3"); /* should be rejected; idXXX removed */
	esp(policy, "aes_gcm-md5"); /* AEAD must have auth null */
	esp(policy, "mars"); /* support removed */
	esp(policy, "aes_gcm-16"); /* don't parse as aes_gcm_16 */
	esp(policy, "aes_gcm-0"); /* invalid keylen */
	esp(policy, "aes_gcm-123456789012345"); /* huge keylen */
	esp(policy, "3des-sha1;dh22"); /* support for dh22 removed */
	esp(policy, "3des-sha1;modp8192,3des-sha2"); /* ;DH must be last */
	esp(policy, "3des-sha1-modp8192,3des-sha2;modp8192"); /* ;DH confusion */

	/*
	 * ah=
	 */

	printf("\n---- AH tests that should succeed ----\n");

	ah(policy, NULL);
	ah(policy, "");
	ah(policy, "md5");
	ah(policy, "sha");
	ah(policy, "sha1");
	ah(policy, "sha2");
	ah(policy, "sha256");
	ah(policy, "sha384");
	ah(policy, "sha512");
	ah(policy, "sha2_256");
	ah(policy, "sha2_384");
	ah(policy, "sha2_512");
	ah(policy, "aes_xcbc");
	ah(policy, "sha1-modp8192,sha1-modp8192,sha1-modp8192"); /* suppress duplicates */

	printf("\n---- AH tests that should fail ----\n");

	ah(policy, "aes-sha1");
	ah(policy, "vanityhash1");
	ah(policy, "aes_gcm_c-256");
	ah(policy, "id3"); /* should be rejected; idXXX removed */
	ah(policy, "3des");
	ah(policy, "null");
	ah(policy, "aes_gcm");
	ah(policy, "aes_ccm");
	ah(policy, "ripemd"); /* support removed */

	/*
	 * ike=
	 */

	printf("\n---- IKE tests that should succeed ----\n");

	ike(policy, NULL);
	ike(policy, "");
	ike(policy, "3des-sha1");
	ike(policy, "3des-sha1");
	ike(policy, "3des-sha1;modp1536");
	ike(policy, "3des-sha1;dh21");
	ike(policy, "3des-sha1-ecp_521");
	ike(policy, "aes_gcm");
	ike(policy, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */

	printf("\n---- IKE tests that should fail ----\n");

	ike(policy, "id2"); /* should be rejected; idXXX removed */
	ike(policy, "3des-id2"); /* should be rejected; idXXX removed */
	ike(policy, "aes_ccm"); /* ESP/AH only */
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

	struct parser_policy policy = {
		.ikev1 = false,
		.ikev2 = false,
	};
	bool run_tests = false;
	bool verbose = false;

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
			policy.ikev1 = true;
		} else if (streq(arg, "v2")) {
			policy.ikev2 = true;
		} else if (streq(arg, "fips") || streq(arg, "fips=yes") || streq(arg, "fips=on")) {
			lsw_set_fips_mode(LSW_FIPS_ON);
		} else if (streq(arg, "fips=no") || streq(arg, "fips=off")) {
			lsw_set_fips_mode(LSW_FIPS_OFF);
		} else if (streq(arg, "fips=unknown")) {
			lsw_set_fips_mode(LSW_FIPS_UNKNOWN);
		} else if (streq(arg, "v")) {
			verbose = true;
		} else {
			fprintf(stderr, "unknown option: %s\n", *argp);
			exit(1);
		}
	}

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
	 * Only be verbose after NSS has started.  Otherwize fake and
	 * real FIPS modes give different results.
	 */
	log_to_stderr = verbose;

	ike_alg_init();

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
	exit(0);
}
