#ifndef VULCANPK_FUNCS_H
#define VULCANPK_FUNCS_H
extern unsigned char * mapvulcanpk(void);
extern void unmapvulcanpk(unsigned char *mapping);
extern void print_status(u_int32_t stat);
extern void hexdump(const unsigned char *base, unsigned int offset, int len);
struct pkprogram;
extern void execute_pkprogram(unsigned char *mapping, struct pkprogram *prog);
extern void vulcanpk_init(volatile unsigned char *mapping);

#endif



