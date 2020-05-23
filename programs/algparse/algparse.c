#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswfips.h"
#include "lswconf.h"

#include "ike_alg.h"
#include "proposals.h"

static bool test_proposals = false;
static bool test_algs = false;
static bool verbose = false;
static bool debug = false;
static bool impaired = false;
static enum ike_version ike_version = IKEv2;
static unsigned parser_version = 0;
static bool ignore_parser_errors = false;
static bool fips = false;
static bool pfs = false;
static int failures = 0;

enum status { PASSED = 0, FAILED = 1, ERROR = 126, };
enum expect { FAIL = false, PASS = true, COUNT, };

#define CHECK(CHECK,PARSE,OK) {						\
		struct proposal_policy policy = {			\
			.version = ike_version,				\
			.parser_version = parser_version,		\
			.alg_is_ok = OK,				\
			.pfs = pfs,					\
			.warning = warning,				\
			.check_pfs_vs_dh = CHECK,			\
			.ignore_parser_errors = ignore_parser_errors,	\
		};							\
		printf("algparse ");					\
		if (impaired) {						\
			printf("-impair ");				\
		}							\
		if (parser_version > 0) {				\
			printf("-p%d ", parser_version);		\
		}							\
		if (fips) {						\
			printf("-fips ");				\
		}							\
		switch (ike_version) {					\
		case IKEv1: printf("-v1 "); break;			\
		case IKEv2: printf("-v2 "); break;			\
		default: break;						\
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
		struct proposal_parser *parser =			\
			PARSE##_proposal_parser(&policy);		\
		struct proposals *proposals =				\
			proposals_from_str(parser, algstr);		\
		if (proposals != NULL) {				\
			pexpect(parser->error[0] == '\0');		\
			FOR_EACH_PROPOSAL(proposals, proposal) {	\
				LSWLOG_FILE(stdout, log) {		\
					lswlogf(log, "\t");		\
					fmt_proposal(log, proposal);	\
				}					\
			}						\
			proposals_delref(&proposals);			\
			if (expected == FAIL) {				\
				failures++;				\
				fprintf(stderr,				\
					"UNEXPECTED PASS: %s%s%s\n",	\
					#PARSE,				\
					algstr == NULL ? "" : "=",	\
					algstr == NULL ? "" : algstr);	\
			}						\
		} else {						\
			pexpect(parser->error[0]);			\
			printf("\tERROR: %s\n", parser->error);		\
			if (expected == PASS) {				\
				failures++;				\
				fprintf(stderr,				\
					"UNEXPECTED FAIL: %s%s%s\n",	\
					#PARSE,				\
					algstr == NULL ? "" : "=",	\
					algstr == NULL ? "" : algstr);	\
			} else if (expected == COUNT) {			\
				failures++;				\
			}						\
		}							\
		free_proposal_parser(&parser);				\
		fflush(NULL);						\
	}

/*
 * Dump warnings to stdout.
 */
static int warning(const char *fmt, ...)
{
	printf("\tWARNING: ");
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	return 0;
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
	CHECK(true, esp, kernel_alg_is_ok);
}

static void ah(enum expect expected, const char *algstr)
{
	CHECK(true, ah, kernel_alg_is_ok);
}

static void ike(enum expect expected, const char *algstr)
{
	CHECK(false, ike, ike_alg_is_ike);
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
		protocol->parser(COUNT, algstr);
	}
}

static void test_proposal(const char *arg)
{
	const char *eq = strchr(arg, '=');
	for (const struct protocol *protocol = protocols;
	     protocol < protocols + elemsof(protocols);
	     protocol++) {
		if (streq(arg, protocol->name)) {
			protocol->parser(COUNT, NULL);
			return;
		}
		if (startswith(arg, protocol->name) &&
		    arg + strlen(protocol->name) == eq) {
			protocol->parser(COUNT, eq + 1);
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

#ifdef USE_AES
	esp(true, "aes");
	esp(true, "aes;modp2048");
# ifdef USE_SHA1
	esp(true, "aes-sha1");
	esp(true, "aes-sha1");
	esp(true, "aes-sha1-modp2048");
	esp(true, "aes-128-sha1");
	esp(true, "aes-128-sha1");
	esp(true, "aes-128-sha1-modp2048");
# endif
	esp(true, "aes-128");
	esp(true, "aes_gcm_a-128-null");
#endif
#ifdef USE_3DES
# ifdef USE_DH2
	esp(true, "3des-sha1;modp1024");
# else
	esp(false, "3des-sha1;modp1024");
# endif
# ifdef USE_SHA1
	esp(!fips, "3des-sha1;modp1536");
	esp(true, "3des-sha1;modp2048");
	esp(ike_version == IKEv2, "3des-sha1;dh21");
	esp(ike_version == IKEv2, "3des-sha1;ecp_521");
	esp(false, "3des-sha1;dh23");
	esp(false, "3des-sha1;dh24");
	esp(true, "3des-sha1");
# endif
#endif
#ifdef USE_SHA1
	esp(!fips, "null-sha1");
#endif
#ifdef USE_AES
	esp(true, "aes_cbc");
# ifdef USE_SHA1
	esp(true, "aes-sha");
	esp(true, "aes-sha1");
	esp(true, "aes128-sha1");
# endif
# ifdef USE_SHA2
	esp(true, "aes-sha2");
	esp(true, "aes-sha256");
	esp(true, "aes-sha384");
	esp(true, "aes-sha512");
# endif
	esp(!fips, "aes128-aes_xcbc");
# ifdef USE_SHA1
	esp(true, "aes192-sha1");
	esp(true, "aes256-sha1");
	esp(true, "aes256-sha");
# endif
# ifdef USE_SHA2
	esp(true, "aes256-sha2");
	esp(true, "aes256-sha2_256");
	esp(true, "aes256-sha2_384");
	esp(true, "aes256-sha2_512");
# endif
#endif
#ifdef USE_CAMELLIA
	esp(!fips, "camellia");
	esp(!fips, "camellia128");
	esp(!fips, "camellia192");
	esp(!fips, "camellia256");
#endif

#ifdef USE_AES
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
#endif
#ifdef USE_SERPENT
	esp(!fips, "serpent");
#endif
#ifdef USE_TWOFISH
	esp(!fips, "twofish");
#endif

#ifdef USE_CAMELLIA
	esp(!fips, "camellia_cbc_256-hmac_sha2_512_256;modp8192"); /* long */
#endif
	esp(true, "null_auth_aes_gmac_256-null;modp8192"); /* long */
#ifdef USE_3DES
# ifdef USE_SHA1
	esp(true, "3des-sha1;modp8192"); /* allow ';' when unambiguous */
	esp(true, "3des-sha1-modp8192"); /* allow '-' when unambiguous */
# endif
#endif
#ifdef USE_AES
# ifdef USE_3DES
#  ifdef USE_SHA1
	esp(!pfs, "aes-sha1,3des-sha1;modp8192");
	esp(true, "aes-sha1-modp8192,3des-sha1-modp8192"); /* silly */
#  endif
# endif
# ifdef USE_SHA1
	esp(true, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */
# endif

	esp(ike_version == IKEv2, "aes;none");
	esp(ike_version == IKEv2 && !pfs, "aes;none,aes");
	esp(ike_version == IKEv2, "aes;none,aes;modp2048");
# ifdef USE_SHA1
	esp(ike_version == IKEv2, "aes-sha1-none");
	esp(ike_version == IKEv2, "aes-sha1;none");
# endif
#endif

	/*
	 * should this be supported - for now man page says not
	 * esp("modp1536");
	 */

	/* ESP tests that should fail */
	/* So these do not require ifdef's to prevent bad exit code */

	esp(impaired, "3des168-sha1"); /* wrong keylen */
	esp(impaired, "3des-null"); /* non-null integ */
	esp(impaired, "aes128-null"); /* non-null-integ */
	esp(impaired, "aes224-sha1"); /* wrong keylen */
	esp(impaired, "aes-224-sha1"); /* wrong keylen */
	esp(false, "aes0-sha1"); /* wrong keylen */
	esp(false, "aes-0-sha1"); /* wrong keylen */
	esp(impaired, "aes512-sha1"); /* wrong keylen */
	esp(false, "aes-sha1555"); /* unknown integ */
	esp(impaired, "camellia666-sha1"); /* wrong keylen */
	esp(false, "blowfish"); /* obsoleted */
	esp(false, "des-sha1"); /* obsoleted */
	esp(impaired, "aes_ctr666"); /* bad key size */
	esp(false, "aes128-sha2_128"); /* _128 does not exist */
	esp(false, "aes256-sha2_256-4096"); /* double keysize */
	esp(false, "aes256-sha2_256-128"); /* now what?? */
	esp(false, "vanitycipher");
	esp(false, "ase-sah"); /* should get rejected */
	esp(false, "aes-sah1"); /* should get rejected */
	esp(false, "id3"); /* should be rejected; idXXX removed */
	esp(false, "aes-id3"); /* should be rejected; idXXX removed */
	esp(impaired, "aes_gcm-md5"); /* AEAD must have auth null */
	esp(false, "mars"); /* support removed */
	esp(impaired, "aes_gcm-16"); /* don't parse as aes_gcm_16 */
	esp(false, "aes_gcm-0"); /* invalid keylen */
	esp(false, "aes_gcm-123456789012345"); /* huge keylen */
	esp(false, "3des-sha1;dh22"); /* support for dh22 removed */

	esp(!pfs, "3des-sha1;modp8192,3des-sha2"); /* ;DH must be last */
	esp(!pfs, "3des-sha1-modp8192,3des-sha2"); /* -DH must be last */

	esp(true, "3des-sha1-modp8192,3des-sha2-modp8192");
	esp(true, "3des-sha1-modp8192,3des-sha2;modp8192");
	esp(true, "3des-sha1;modp8192,3des-sha2-modp8192");
	esp(true, "3des-sha1;modp8192,3des-sha2;modp8192");
	esp(!pfs, "3des-sha1-modp8192,3des-sha2-modp2048");

	/*
	 * ah=
	 */

	ah(true, NULL);
	ah(false, "");
#ifdef USE_MD5
	ah(!fips, "md5");
#endif
#ifdef USE_SHA1
	ah(true, "sha");
	ah(true, "sha;modp2048");
	ah(true, "sha1");
#endif
#ifdef USE_SHA2
	ah(true, "sha2");
	ah(true, "sha256");
	ah(true, "sha384");
	ah(true, "sha512");
	ah(true, "sha2_256");
	ah(true, "sha2_384");
	ah(true, "sha2_512");
#endif
#ifdef USE_AES
	ah(!fips, "aes_xcbc");
#endif
#ifdef USE_SHA2
	ah(ike_version == IKEv2, "sha2-none");
	ah(ike_version == IKEv2, "sha2;none");
#endif
#ifdef USE_SHA1
	ah(true, "sha1-modp8192,sha1-modp8192,sha1-modp8192"); /* suppress duplicates */
	ah(impaired, "aes-sha1");
#endif
	ah(false, "vanityhash1");
#ifdef USE_AES
	ah(impaired, "aes_gcm_c-256");
#endif
	ah(false, "id3"); /* should be rejected; idXXX removed */
#ifdef USE_3DES
	ah(impaired, "3des");
#endif
	ah(impaired, "null");
#ifdef USE_AES
	ah(impaired, "aes_gcm");
	ah(impaired, "aes_ccm");
#endif
	ah(false, "ripemd"); /* support removed */

	/*
	 * ike=
	 */

	ike(true, NULL);
	ike(false, "");
	ike(true, "3des-sha1");
	ike(true, "3des-sha1");
	ike(!fips, "3des-sha1;modp1536");
	ike(true, "3des;dh21");
	ike(true, "3des-sha1;dh21");
	ike(true, "3des-sha1-ecp_521");
	ike(ike_version == IKEv2, "aes_gcm");
	ike(true, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192"); /* suppress duplicates */
	ike(false, "aes;none");
	ike(false, "id2"); /* should be rejected; idXXX removed */
	ike(false, "3des-id2"); /* should be rejected; idXXX removed */
	ike(false, "aes_ccm"); /* ESP/AH only */
	ike(impaired, "aes_gcm-sha1-none-modp2048");
	ike(impaired, "aes_gcm+aes_gcm-sha1-none-modp2048");
	ike(false, "aes+aes_gcm"); /* mixing AEAD and NORM encryption */
}

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"\n"
		"    algparse [ <option> ... ] -tp | -ta | [<protocol>=][<proposal>{,<proposal>}] ...\n"
		"\n"
		"Parse one or more proposals using the algorithm parser.\n"
		"Either specify the proposals to be parsed on the command line\n"
		"(exit non-zero if a proposal is not valid):\n"
		"\n"
		"    [<protocol>=][<proposals>]\n"
		"        <protocol>: the 'ike', 'esp' or 'ah' specific parser to use\n"
		"            if omitted, the proposal is parsed using all three parsers\n"
		"        <proposals>: a comma separated list of proposals\n"
		"            if omitted, a default algorithm list is used\n"
		"\n"
		"or run a pre-defined testsuite (exit non-zero if a test fails):\n"
		"\n"
		"    -tp: run the proposal testsuite\n"
		"    -ta: also run the algorithm testsuite\n"
		"\n"
		"Additional options:\n"
		"\n"
		"    -v2 | -ikev2: configure for IKEv2 (default)\n"
		"    -v1 | -ikev1: configure for IKEv1\n"
		"    -pfs | -pfs=yes | -pfs=no: specify PFS (perfect forward privicy)\n"
		"         default: no\n"
		"    -fips | -fips=yes | -fips=no: force NSS's FIPS mode\n"
		"         default: determined by system environment\n"
		"    -d <dir> | -nssdir <dir>: directory containing crypto database\n"
		"         default: '"IPSEC_NSSDIR"'\n"
		"    -P <password> | -nsspw <password> | -password <password>:\n"
		"        <password> to unlock crypto database\n"
		"    -v --verbose: be more verbose\n"
		"    -d --debug: enable debug logging\n"
		"    --impair: disable all algorithm parser checks\n"
		"    --ignore: ignore parser errors (or at least some)\n"
		"    -p1: simple parser\n"
		"    -p2: complex parser\n"
		"\n"
		"Examples:\n"
		"\n"
		"    algparse -v1 ike=\n"
		"        expand the default IKEv1 'ike' algorithm table\n"
		"        (with IKEv1, this is the default algorithms, with IKEv2 it is not)\n"
		"    algparse -v2 ike=aes-sha1-dh23\n"
		"        expand 'aes-sha1-dh23' using the the IKEv2 'ike' parser\n"
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
		} else if (streq(arg, "p1")) {
			parser_version = 1;
		} else if (streq(arg, "p2")) {
			parser_version = 2;
		} else if (streq(arg, "v1") || streq(arg, "ikev1")) {
			ike_version = IKEv1;
		} else if (streq(arg, "v2") || streq(arg, "ikev2")) {
			ike_version = IKEv2;
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
		} else if (streq(arg, "ignore")) {
			ignore_parser_errors = true;
		} else if (streq(arg, "impair")) {
			impaired = true;
		} else if (streq(arg, "d") || streq(arg, "nssdir")) {
			char *nssdir = *++argp;
			if (nssdir == NULL) {
				fprintf(stderr, "missing nss directory\n");
				exit(ERROR);
			}
			lsw_conf_nssdir(nssdir);
		} else if (streq(arg, "P") || streq(arg, "nsspw") || streq(arg, "password")) {
			char *nsspw = *++argp;
			if (nsspw == NULL) {
				fprintf(stderr, "missing nss password\n");
				exit(ERROR);
			}
			lsw_conf_nsspassword(nsspw);
		} else {
			fprintf(stderr, "unknown option: %s\n", *argp);
			exit(ERROR);
		}
	}

	NSS_NoDB_Init("."); /* or else fips mode detection fails */
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
		exit(ERROR);
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
	if (impaired) {
		impair.proposal_parser = true;
	}

	if (test_algs) {
		test_ike_alg();
	}

	if (*argp) {
		if (test_proposals) {
			fprintf(stderr, "-t conflicts with algorithm list\n");
			exit(ERROR);
		}
		for (; *argp != NULL; argp++) {
			test_proposal(*argp);
		}
	} else if (test_proposals) {
		test();
		if (failures > 0) {
			fprintf(stderr, "%d FAILURES\n", failures);
		}
	}

	report_leaks();

	lsw_nss_shutdown();

	exit(failures > 0 ? FAILED : PASSED);
}
