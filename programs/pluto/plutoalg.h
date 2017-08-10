struct connection;
struct esp_info;

/* status info */
extern void kernel_alg_show_status(void);
extern void kernel_alg_show_connection(const struct connection *c, const char *instance);

struct ike_info;
#define IKEALGBUF_LEN strlen("00000_000-00000_000-00000")

extern bool ikev1_verify_esp(int ealg, unsigned int key_len, int aalg,
				const struct alg_info_esp *alg_info);

extern bool ikev1_verify_ah(int aalg, const struct alg_info_esp *alg_info);

struct alg_info_ike *ikev1_default_ike_info(void);
