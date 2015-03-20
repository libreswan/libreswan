#include <malloc.h>
#include "slab_fake.h"

struct cache_sizes {
	size_t cs_size;
	void    *cs_cachep;
	void    *cs_dmacachep;
};

struct cache_sizes malloc_sizes[] = {
#define CACHE(x) { .cs_size = (x) },
#include <linux/kmalloc_sizes.h>
	{ 0, }
#undef CACHE
};

void init_kmalloc(void)
{
	struct cache_sizes *sizes;

	sizes = malloc_sizes;
	while (sizes->cs_size) {
		sizes->cs_cachep = &sizes->cs_size;
		sizes->cs_dmacachep = &sizes->cs_size;
		sizes++;
	}
}

void *vmalloc(unsigned long size)
{
	return malloc(size);
}

void vfree(void *addr)
{
	return free(addr);
}

void *kmem_cache_alloc(int *cachep, int flags)
{
	return malloc(*cachep);
}

void *__kmalloc(unsigned long size, int flags)
{
	return malloc(size);
}
