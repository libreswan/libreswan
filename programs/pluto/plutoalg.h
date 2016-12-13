struct connection;

/* status info */
extern void kernel_alg_show_status(void);
extern void kernel_alg_show_connection(const struct connection *c, const char *instance);

struct ike_info;
#define IKEALGBUF_LEN strlen("00000_000-00000_000-00000")

extern struct alg_info_ike *alg_info_ike_create_from_str(const char *alg_str,
							 char *err_buf, size_t err_buf_len);

extern bool ikev1_verify_esp(int ealg, unsigned int key_len, int aalg,
				const struct alg_info_esp *alg_info);

extern bool ikev1_verify_ah(int aalg, const struct alg_info_esp *alg_info);

void fill_in_esp_info_ike_algs(struct esp_info *esp_info);
