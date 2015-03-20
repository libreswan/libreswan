#ifndef _IKEV2_PRF_H
#define _IKEV2_PRF_H
struct v2prf_stuff {
	chunk_t t;
	const struct hash_desc *prf_hasher;
	chunk_t *skeyseed;
	chunk_t ni;
	chunk_t nr;
	chunk_t spii;
	chunk_t spir;
	u_char counter[1]; /* why is this an array of 1? */
	unsigned int availbytes;
	unsigned int nextbytes;
};

extern void v2prfplus(struct v2prf_stuff *vps);
extern void v2genbytes(chunk_t *need,
		       unsigned int needed, const char *name,
		       struct v2prf_stuff *vps);

#endif
