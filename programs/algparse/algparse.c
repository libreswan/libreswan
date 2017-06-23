#include <stddef.h>
#include <stdlib.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"
#include "lswfips.h"

#include "ike_alg.h"
#include "alg_info.h"


#define CHECK(TYPE,PARSE) {						\
		printf("%*s[%s=%s]%*s ",				\
		       3 - (int)strlen(#PARSE), "",			\
		       #PARSE, algstr,					\
		       max(0, 20 - (int)strlen(algstr)), "");		\
		fflush(NULL);						\
		char err_buf[512] = "";	/* ??? big enough? */		\
		struct alg_info_##TYPE *e =				\
			alg_info_##PARSE##_create_from_str(policy,	\
							   algstr,	\
							   err_buf,	\
							   sizeof(err_buf)); \
		if (e != NULL) {					\
			passert(err_buf[0] == '\0');			\
			char algbuf[512] = "";				\
			alg_info_##TYPE##_snprint(algbuf, sizeof(algbuf), e); \
			printf("   OK: %s\n", algbuf);			\
			alg_info_free(&e->ai);				\
		} else {						\
			passert(err_buf[0]);				\
			printf("ERROR: %s\n", err_buf);			\
		}							\
		fflush(NULL);						\
	}

static void esp(lset_t policy, const char *algstr)
{
	CHECK(esp, esp);
}

static void ah(lset_t policy, const char *algstr)
{
	CHECK(esp, ah);
}

static void ike(lset_t policy, const char *algstr)
{
	CHECK(ike, ike);
}

static void all(lset_t policy, const char *algstr)
{
	typedef void (protocol_t)(lset_t policy, const char *);
	protocol_t *const protocols[] = { ike, ah, esp, NULL, };
	for (protocol_t *const *protocol = protocols;
	     *protocol != NULL;
	     protocol++) {
		(*protocol)(policy, algstr);
	}
}

static void test(lset_t policy)
{
	/*
	 * esp=
	 */

	printf("\n---- ESP tests that should succeed ----\n");

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
	esp(policy, "aes_ccm_a-128-null");
	esp(policy, "aes_ccm_a-192-null");
	esp(policy, "aes_ccm_a-256-null");
	esp(policy, "aes_ccm_b-128-null");
	esp(policy, "aes_ccm_b-192-null");
	esp(policy, "aes_ccm_b-256-null");
	esp(policy, "aes_ccm_c-128-null");
	esp(policy, "aes_ccm_c-192-null");
	esp(policy, "aes_ccm_c-256-null");
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
	esp(policy, "3des-sha1;dh22"); /* support for dh22 removed */
	esp(policy, "3des-sha1-dh21"); /* ';' vs '-' */
	esp(policy, "3des-sha1;dh21,3des-sha2"); /* DH must be last */

	/*
	 * ah=
	 */

	printf("\n---- AH tests that should succeed ----\n");

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

	ike(policy, "");
	ike(policy, "3des-sha1");
	ike(policy, "3des-sha1");
	ike(policy, "3des-sha1;modp1536");
	ike(policy, "3des-sha1;dh21");
	ike(policy, "3des-sha1-ecp_521");
	ike(policy, "aes_gcm");

	printf("\n---- IKE tests that should fail ----\n");

	ike(policy, "id2"); /* should be rejected; idXXX removed */
	ike(policy, "3des-id2"); /* should be rejected; idXXX removed */
}

static void usage(void)
{
	fprintf(stderr, "Usage: [ -v1 ] [ -v2 ] [ -fips ] [ -v ] [ [<protocol>=]<proposals> ...]\n");
}

int main(int argc, char *argv[])
{
	log_to_stderr = false;
	tool_init_log(argv[0]);

	if (argc == 1) {
		usage();
		exit(1);
	}

	lset_t policy = LEMPTY;

	char **argp = argv + 1;
	for (; *argp != NULL; argp++) {
		const char *arg = *argp;
		if (arg[0] != '-') {
			break;
		}
		do {
			arg++;
		} while (arg[0] == '-');
		if (strcmp(arg, "?") == 0 || strcmp(arg, "h") == 0) {
			usage();
			exit(0);
		} else if (strcmp(arg, "v1") == 0) {
			policy |= POLICY_IKEV1_ALLOW;
		} else if (strcmp(arg, "v2") == 0) {
			policy |= (POLICY_IKEV2_ALLOW | POLICY_IKEV2_PROPOSE);
		} else if (strcmp(arg, "fips") == 0 || strcmp(arg, "fips=yes") == 0 || strcmp(arg, "fips=on") == 0) {
			lsw_set_fips_mode(LSW_FIPS_ON);
		} else if (strcmp(arg, "fips=no") == 0 || strcmp(arg, "fips=off") == 0) {
			lsw_set_fips_mode(LSW_FIPS_OFF);
		} else if (strcmp(arg, "fips=unknown") == 0) {
			lsw_set_fips_mode(LSW_FIPS_UNKNOWN);
		} else if (strcmp(arg, "v") == 0) {
			log_to_stderr = true;
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

	ike_alg_init();

	if (*argp) {
		for (; *argp != NULL; argp++) {
			const char *arg = *argp;
			/*
			 * now parse [PROTOCOL=]...
			 */
#define starts_with(ARG,STRING) strncmp(ARG,STRING,strlen(STRING))
			if (starts_with(arg, "ike=") == 0) {
				ike(policy, arg + 4);
			} else if (starts_with(arg, "esp=") == 0) {
				esp(policy, arg + 4);
			} else if (starts_with(arg, "ah=") == 0) {
				ah(policy, arg + 3);
			} else {
				all(policy, arg);
			}
		}
	} else {
		test(policy);
	}

	report_leaks();

	lsw_nss_shutdown();
	tool_close_log();
	exit(0);
}
