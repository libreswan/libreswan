#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "fips_mode.h"
#include "crypt_symkey.h"		/* for init_crypt_symkey() */
#include "ike_alg.h"
#include "proposals.h"

static bool test_proposals = false;
static bool test_algs = false;
static bool verbose = false;
static bool debug = false;
static enum ike_version ike_version = IKEv2;
static bool ignore_transform_lookup_error = false;
static bool fips = false;
static bool pfs = false;
static bool addke = false;
static int failures = 0;

#define ERROR 124

enum expect { FAIL = false, PASS = true, COUNT, };

/*
 * Kernel not available so fake it.
 */
static bool kernel_alg_is_ok(const struct ike_alg *alg,
			     const struct logger *logger)
{
	if (alg->type == &ike_alg_kem) {
		/* require an in-process/ike implementation of DH */
		return ike_alg_is_ike(alg, logger);
	} else {
		/* no kernel to ask! */
		return true;
	}
}

typedef void (protocol_t)(enum expect expected, const char *, struct logger *logger);

struct protocol {
	const char *name;
	struct proposal_parser *(*parser)(const struct proposal_policy *policy);
	bool pfs_vs_dh;
	bool (*alg_is_ok)(const struct ike_alg *alg, const struct logger *logger);
};

const struct protocol ike_protocol = {
	"ike", ike_proposal_parser, .pfs_vs_dh = false, .alg_is_ok = ike_alg_is_ike,
};

const struct protocol ah_protocol = {
	"ah", ah_proposal_parser, .pfs_vs_dh = true, .alg_is_ok = kernel_alg_is_ok,
};

const struct protocol esp_protocol = {
	"esp", esp_proposal_parser, .pfs_vs_dh = true, .alg_is_ok = kernel_alg_is_ok,
};

const struct protocol *protocols[] = {
	&ike_protocol,
	&ah_protocol,
	&esp_protocol,
};

static void check(const struct protocol *protocol,
		  enum expect expected,
		  const char *algstr,
		  struct logger *logger)
{
	/* print the test */
	printf("algparse ");
	if (fips) {
		printf("-fips ");
	}
	if (addke) {
		printf("-addke ");
	}
	switch (ike_version) {
	case IKEv1: printf("-v1 "); break;
	case IKEv2: printf("-v2 "); break;
	default: break;
	}
	if (pfs) {
		printf("-pfs ");
	}
	if (algstr == NULL) {
		printf("'%s'", protocol->name);
	} else {
		printf("'%s=%s'", protocol->name, algstr);
	}
	switch (expected) {
	case PASS: printf(" (expect SUCCESS)"); break;
	case FAIL: printf(" (expect ERROR)"); break;
	case COUNT: break;
	}
	printf("\n");
	fflush(NULL);

	/* run the test */
	struct proposal_policy policy = {
		.version = ike_version,
		.alg_is_ok = protocol->alg_is_ok,
		.pfs = pfs,
		.addke = addke,
		.stream = WHACK_STREAM,
		.logger = logger,
		.check_pfs_vs_ke = protocol->pfs_vs_dh,
		.ignore_transform_lookup_error = ignore_transform_lookup_error,
	};
	struct proposal_parser *parser =
		protocol->parser(&policy);
	struct proposals *proposals =
		proposals_from_str(parser, algstr);

	/* print the results */
	if (proposals != NULL) {
		pexpect(parser->diag == NULL);
		FOR_EACH_PROPOSAL(proposals, proposal) {
			JAMBUF(buf) {
				jam(buf, "\t");
				jam_proposal(buf, proposal);
				fprintf(stdout, PRI_SHUNK"\n",
					pri_shunk(jambuf_as_shunk(buf)));
			}
		}
		free_proposals(&proposals);
		if (expected == FAIL) {
			failures++;
			fprintf(stderr,
				"UNEXPECTED PASS: %s%s%s\n",
				protocol->name,
				(algstr == NULL ? "" : "="),
				(algstr == NULL ? "" : algstr));
		}
	} else {
		pexpect(parser->diag != NULL);
		printf("\tERROR: %s\n", str_diag(parser->diag));
		if (expected == PASS) {
			failures++;
			fprintf(stderr,
				"UNEXPECTED FAIL: %s%s%s\n",
				protocol->name,
				(algstr == NULL ? "" : "="),
				(algstr == NULL ? "" : algstr));
		} else if (expected == COUNT) {
			failures++;
		}
	}
	free_proposal_parser(&parser);
	fflush(NULL);
}

static void all(const char *algstr, struct logger *logger)
{
	FOR_EACH_ELEMENT(protocolp, protocols) {
		const struct protocol *protocol = (*protocolp);
		check(protocol, COUNT, algstr, logger);
	}
}

static void test_proposal(const char *arg, struct logger *logger)
{
	const char *eq = strchr(arg, '=');
	FOR_EACH_ELEMENT(protocolp, protocols) {
		const struct protocol *protocol = (*protocolp);
		if (streq(arg, protocol->name)) {
			check(protocol, COUNT, NULL, logger);
			return;
		}
		if (startswith(arg, protocol->name) &&
		    arg + strlen(protocol->name) == eq) {
			check(protocol, COUNT, eq + 1, logger);
			return;
		}
	}
	if (eq != NULL) {
		fprintf(stderr, "unrecognized PROTOCOL in '%s'", arg);
		exit(1);
	}
	all(arg, logger);
}

static void test_esp(struct logger *logger)
{
#define esp(EXPECTED, ALGSTR) check(&esp_protocol, EXPECTED, ALGSTR, logger)

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

	esp(false, "3des168-sha1"); /* wrong keylen */
	esp(false, "3des-null"); /* non-null integ */
	esp(false, "aes128-null"); /* non-null-integ */
	esp(false, "aes224-sha1"); /* wrong keylen */
	esp(false, "aes-224-sha1"); /* wrong keylen */
	esp(false, "aes0-sha1"); /* wrong keylen */
	esp(false, "aes-0-sha1"); /* wrong keylen */
	esp(false, "aes512-sha1"); /* wrong keylen */
	esp(false, "aes-sha1555"); /* unknown integ */
	esp(false, "camellia666-sha1"); /* wrong keylen */
	esp(false, "blowfish"); /* obsoleted */
	esp(false, "des-sha1"); /* obsoleted */
	esp(false, "aes_ctr666"); /* bad key size */
	esp(false, "aes128-sha2_128"); /* _128 does not exist */
	esp(false, "aes256-sha2_256-4096"); /* double keysize */
	esp(false, "aes256-sha2_256-128"); /* now what?? */
	esp(false, "vanitycipher");
	esp(false, "ase-sah"); /* should get rejected */
	esp(false, "aes-sah1"); /* should get rejected */
	esp(false, "id3"); /* should be rejected; idXXX removed */
	esp(false, "aes-id3"); /* should be rejected; idXXX removed */
	esp(false, "aes_gcm-md5"); /* AEAD must have auth null */
	esp(false, "mars"); /* support removed */
	esp(false, "aes_gcm-16"); /* don't parse as aes_gcm_16 */
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

	esp(addke && ike_version == IKEv2, "aes_gcm;modp2048-modp2048");

#undef esp
}

static void test_ah(struct logger *logger)
{
#define ah(EXPECTED, ALGSTR) check(&ah_protocol, EXPECTED, ALGSTR, logger)

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
	ah(false, "aes-sha1");
#endif
	ah(false, "vanityhash1");
#ifdef USE_AES
	ah(false, "aes_gcm_c-256");
#endif
	ah(false, "id3"); /* should be rejected; idXXX removed */
#ifdef USE_3DES
	ah(false, "3des");
#endif
	ah(false, "null");
#ifdef USE_AES
	ah(false, "aes_gcm");
	ah(false, "aes_ccm");
#endif
	ah(false, "ripemd"); /* support removed */

	ah(addke && ike_version == IKEv2, "sha2;modp2048-modp2048");

#undef ah
}

static void test_ike(struct logger *logger)
{

#define ike(EXPECTED, ALGSTR) check(&ike_protocol, EXPECTED, ALGSTR, logger)

	ike(true, NULL);
	ike(false, "");
	ike(true, "3des-sha1");
	ike(true, "3des-sha1");
	ike(!fips, "3des-sha1;modp1536");
	ike(true, "3des;dh21");
	ike(true, "3des-sha1;dh21");
	ike(true, "3des-sha1-ecp_521");
	ike(ike_version == IKEv2, "3des+aes");
	ike(false, "aes;none");
	ike(false, "id2"); /* should be rejected; idXXX removed */
	ike(false, "3des-id2"); /* should be rejected; idXXX removed */
	ike(false, "aes_ccm"); /* ESP/AH only */

	/* quads */

	ike(false, "aes-sha1-sha2-ecp_521");
	ike(false, "aes-sha2-sha2;ecp_521");
	/* fqn */
	ike(ike_version == IKEv2, "aes-sha1_96-sha2-ecp_521");
	ike(ike_version == IKEv2, "aes-sha1_96-sha2;ecp_521");

	/* toss duplicates */

	ike(ike_version == IKEv2, "aes+aes-sha1+sha1-modp8192+modp8192");
	/* cycle through 3des-sha2-modp4096 */
	ike(ike_version == IKEv2, "3des+aes+aes-sha2+sha1+sha1-modp4096+modp8192+modp8192");
	ike(ike_version == IKEv2, "aes+3des+aes-sha1+sha2+sha1-modp8192+modp4096+modp8192");
	ike(ike_version == IKEv2, "aes+aes+3des-sha1+sha1+sha2-modp8192+modp8192+modp4096");
	/* keys */
	ike(ike_version == IKEv2, "aes+aes128+aes256"); /* toss 128/256 */
	ike(ike_version == IKEv2, "aes128+aes+aes256"); /* toss 256 */
	ike(ike_version == IKEv2, "aes128+aes256+aes");
	/* proposals */
	ike(true, "aes-sha1-modp8192,aes-sha1-modp8192,aes-sha1-modp8192");
	ike(true, "aes-sha1-modp8192,aes-sha2-modp8192,aes-sha1-modp8192"); /* almost middle */

	/* aead */

	ike(ike_version == IKEv2, "aes_gcm");
	ike(ike_version == IKEv2, "aes_gcm-sha2");
	ike(ike_version == IKEv2, "aes_gcm-sha2-modp2048");
	ike(ike_version == IKEv2, "aes_gcm-sha2;modp2048");
	ike(false, "aes_gcm-modp2048"); /* ';' required - PRF */
	ike(ike_version == IKEv2, "aes_gcm;modp2048");
	ike(ike_version == IKEv2, "aes_gcm-none");
	ike(ike_version == IKEv2, "aes_gcm-none-sha2");
	ike(ike_version == IKEv2, "aes_gcm-none-sha2-modp2048");
	ike(ike_version == IKEv2, "aes_gcm-none-sha2;modp2048");
	ike(false, "aes_gcm-none-modp2048");  /* ';' required - INTEG */
	ike(ike_version == IKEv2, "aes_gcm-none;modp2048");
	ike(false, "aes_gcm-sha1-none-modp2048"); /* old syntax */
	ike(false, "aes_gcm-sha1-none;modp2048"); /* old syntax */
	ike(false, "aes+aes_gcm"); /* mixing AEAD and NORM encryption */

	/* syntax */

	ike(false, ","); /* empty algorithm */
	ike(false, "aes,"); /* empty algorithm */
	ike(false, "aes,,aes"); /* empty algorithm */
	ike(false, ",aes"); /* empty algorithm */

	ike(false, "-"); /* empty algorithm */
	ike(false, "+"); /* empty algorithm */
	ike(false, ";"); /* empty algorithm */

	ike(false, "aes-"); /* empty algorithm */
	ike(false, "aes+"); /* empty algorithm */
	ike(false, "aes;"); /* empty algorithm */
	ike(false, "-aes"); /* empty algorithm */
	ike(false, "+aes"); /* empty algorithm */
	ike(false, ";aes"); /* empty algorithm */
	ike(false, "aes+-"); /* empty algorithm */
	ike(false, "aes+;"); /* empty algorithm */
	ike(false, "aes++"); /* empty algorithm */

	/* addke */

	ike(addke && ike_version == IKEv2, "aes;modp2048-modp2048");
	ike(addke && ike_version == IKEv2, "aes;addke1=modp2048");
	ike(ike_version == IKEv2, "aes-sha2;prf=sha1;kem=dh20"); /*additive*/
	ike(false, "kem=dh20"); /* missing encrypt */

#undef ike
}

static void test(struct logger *logger)
{
	test_esp(logger);
	test_ah(logger);
	test_ike(logger);
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
		"    -addke | -addke=yes | -addke=no: specify additional Key Exchange algorithms\n"
		"         default: no\n"
		"    -fips | -fips=yes | -fips=no: force NSS's FIPS mode\n"
		"         default: determined by system environment\n"
		"    -v --verbose: be more verbose\n"
		"    --debug: enable debug logging\n"
		/* -d <NSSDB> is reserved */
		"    -P <password> | -nsspw <password> | -password <password>: NSS password\n"
		"    --impair: disable all algorithm parser checks\n"
		"    --ignore: ignore parser errors (or at least some)\n"
		"    -p1: simple parser\n"
		"    -p2: complex parser\n"
		"\n"
		"Examples:\n"
		"\n"
		"    algparse -v1 ike\n"
		"        expand the default IKEv1 'ike' algorithm table\n"
		"        (with IKEv1, this is the default algorithms, with IKEv2 it is not)\n"
		"    algparse -v2 ike=aes-sha1-dh23\n"
		"        expand 'aes-sha1-dh23' using the the IKEv2 'ike' parser\n"
		);
}

int main(int argc, char *argv[])
{
	log_to_stderr = false;
	struct logger *logger = tool_logger(argc, argv);

	if (argc == 1) {
		usage();
		exit(1);
	}

	struct nss_flags nss = {
		.open_readonly = true,
	};

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
		} else if (streq(arg, "tp")) {
			test_proposals = true;
		} else if (streq(arg, "ta")) {
			test_algs = true;
		} else if (streq(arg, "v1") || streq(arg, "ikev1")) {
			ike_version = IKEv1;
		} else if (streq(arg, "v2") || streq(arg, "ikev2")) {
			ike_version = IKEv2;
		} else if (streq(arg, "pfs") || streq(arg, "pfs=yes") || streq(arg, "pfs=on")) {
			pfs = true;
		} else if (streq(arg, "pfs=no") || streq(arg, "pfs=off")) {
			pfs = false;
		} else if (streq(arg, "addke") || streq(arg, "addke=yes") || streq(arg, "addke=on")) {
			addke = true;
		} else if (streq(arg, "addke=no") || streq(arg, "addke=off")) {
			addke = false;
		} else if (streq(arg, "fips") || streq(arg, "fips=yes") || streq(arg, "fips=on")) {
			set_fips_mode(FIPS_MODE_ON);
		} else if (streq(arg, "fips=no") || streq(arg, "fips=off")) {
			set_fips_mode(FIPS_MODE_OFF);
		} else if (streq(arg, "v") || streq(arg, "verbose")) {
			verbose = true;
		} else if (streq(arg, "debug")) {
			/* -d <NSSDB> is reserved */
			debug = true;
		} else if (streq(arg, "ignore")) {
			ignore_transform_lookup_error = true;
		} else if (streq(arg, "P") || streq(arg, "nsspw") || streq(arg, "password")) {
			nss.password = *++argp;
			if (nss.password == NULL) {
				fprintf(stderr, "missing nss password\n");
				exit(ERROR);
			}
		} else {
			fprintf(stderr, "unknown option: %s\n", *argp);
			exit(ERROR);
		}
	}

	/*
	 * Need to ensure that NSS is initialized before calling
	 * ike_alg_init().  Sanity checks and algorithm testing
	 * require a working NSS.
	 */
	init_nss(NULL, nss, logger);
	init_crypt_symkey(logger);
	fips = is_fips_mode();

	/*
	 * Only be verbose after NSS has started.  Otherwise fake and
	 * real FIPS modes give different results.
	 */
	log_to_stderr = verbose;

	init_ike_alg(logger);

	/*
	 * Only enabling debugging and impairing after things have
	 * started.  Otherwise there's just TMI.
	 */
	if (debug) {
		cur_debugging |= DBG_PROPOSAL_PARSER | DBG_CRYPT;
	}

	if (test_algs) {
		test_ike_alg(logger);
	}

	if (*argp) {
		if (test_proposals) {
			fprintf(stderr, "-t conflicts with algorithm list\n");
			exit(ERROR);
		}
		for (; *argp != NULL; argp++) {
			test_proposal(*argp, logger);
		}
	} else if (test_proposals) {
		test(logger);
		if (failures > 0) {
			fprintf(stderr, "%d FAILURES\n", failures);
		}
	}

	report_leaks(logger);

	shutdown_nss();

	exit(failures > 0 ? PLUTO_EXIT_FAIL : PLUTO_EXIT_OK);
}
