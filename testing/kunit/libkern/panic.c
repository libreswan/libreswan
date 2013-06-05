#include <assert.h>
#include <stdio.h>

int panic(void)
{
	printf("Kernel PANIC\n");
	assert(0);
}
