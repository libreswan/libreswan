
#include <nss.h>
#include <pk11pub.h>

typedef struct {
	PK11Context     *ctx_nss;
} aes_xcbc_context;

extern void aes_xcbc_init(aes_xcbc_context *);
extern void aes_xcbc_write(aes_xcbc_context *, const unsigned char *, size_t);
extern void aes_xcbc_final(unsigned char *, aes_xcbc_context *);

