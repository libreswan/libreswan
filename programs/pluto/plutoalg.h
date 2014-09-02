struct connection;

/* status info */
extern void kernel_alg_show_status(void);
extern void kernel_alg_show_connection(struct connection *c, const char *instance);

struct ike_info;
#define IKEALGBUF_LEN strlen("00000_000-00000_000-00000")

extern struct alg_info_ike *alg_info_ike_create_from_str(const char *alg_str,
							 char *err_buf, size_t err_buf_len);

extern void alg_info_snprint_phase2(char *buf, size_t buflen,
				    struct alg_info_esp *alg_info);

extern bool ikev1_verify_phase2(int ealg, unsigned int key_len, int aalg,
				struct alg_info_esp *alg_info);
   
