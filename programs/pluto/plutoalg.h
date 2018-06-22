struct connection;
struct esp_info;

/* status info */
extern void kernel_alg_show_status(void);
extern void kernel_alg_show_connection(const struct connection *c, const char *instance);

struct ike_info;
#define IKEALGBUF_LEN strlen("00000_000-00000_000-00000")
