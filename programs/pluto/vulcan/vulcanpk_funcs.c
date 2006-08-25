#include <sys/mman.h>
#include <dev/hifn/hifn7751reg.h>

#include "dev/hifn/vulcanpk_funcs.h"
#include <sys/types.h>
#include <fcntl.h>

//typedef int bool;

/*
 * Bus read/write barrier methods. (taken from i386/include/bus.h )
 *
 *	void bus_space_write_barrier(void)
 *
 *
 * Note that BUS_SPACE_BARRIER_WRITE doesn't do anything other than
 * prevent reordering by the compiler; all Intel x86 processors currently
 * retire operations outside the CPU in program order.
 */

static __inline void
bus_space_write_barrier(void)
{
  __asm __volatile("" : : : "memory");
}

static int vulcan_fd=-1;

unsigned char * mapvulcanpk(void)
{
	unsigned char *mapping;

	if(vulcan_fd == -1) {
	    vulcan_fd=open("/dev/vulcanpk", O_RDWR);
	    
	    if(vulcan_fd == -1) {
		perror("vulcan mapping open");
		exit(6);
	    }
	}

	/* HIFN_1_PUB_MEMEND */
	mapping = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, vulcan_fd, 0);
	
	if(mapping == NULL) {
		perror("mmap");
		exit(4);
	}
	
	return mapping;

}
void unmapvulcanpk(unsigned char *mapping)
{
    munmap(mapping, 4096);
    if(vulcan_fd!=-1) close(vulcan_fd);
    vulcan_fd=-1;
}

/* in include/, because you never know when you will need it */
#include "hexdump.c"

void print_status(u_int32_t stat)
{
	printf("status: %08x ", stat);
	if(stat & HIFN_PUBSTS_DONE) {
		printf("done ");
	}
	if(stat & HIFN_PUBSTS_CARRY) {
		printf("carry ");
	}
	if(stat & 0x4) {
		printf("sign(2) ");
	}
	if(stat & 0x8) {
		printf("zero(3) ");
	}
	if(stat & HIFN_PUBSTS_FIFO_EMPTY) {
		printf("empty ");
	}
	if(stat & HIFN_PUBSTS_FIFO_FULL) {
		printf("full ");
	}
	if(stat & HIFN_PUBSTS_FIFO_OVFL) {
		printf("overflow ");
	}
	if(stat & HIFN_PUBSTS_FIFO_WRITE) {
		printf("write=%d ", (stat & HIFN_PUBSTS_FIFO_WRITE)>>16);
	}
	if(stat & HIFN_PUBSTS_FIFO_READ) {
		printf("read=%d ", (stat & HIFN_PUBSTS_FIFO_READ)>>24);
	}
	printf("\n");
}


#define PUB_WORD(offset) *(volatile u_int32_t *)(&mapping[offset])
#define PUB_WORD_WRITE(offset, value) if(pk_verbose_execute) printf("write-1 %04x = %08x\n", offset, value), PUB_WORD(offset)=value

inline static void write_pkop(unsigned char *mapping,
		       u_int32_t oplen, u_int32_t op)
{
	volatile u_int32_t *opfifo;

	opfifo = (volatile u_int32_t *)(mapping+HIFN_1_PUB_FIFO_OPLEN);

	opfifo[0]=oplen;
	opfifo[1]=op;
}

#define PKVALUE_BITS  3072
#define PKVALUE_LEN   (PKVALUE_BITS/8)

#define PK_AVALUES 16
#define PK_BVALUES 16

struct pkprogram {
    bool           valuesLittleEndian;
    unsigned char  chunksize;           /* how many 64-byte chunks/register */
    unsigned char *aValues[PK_AVALUES];
    unsigned short aValueLen[PK_AVALUES];
    unsigned int   oOffset;
    unsigned char *oValue;
    unsigned int   oValueLen;
    u_int32_t      pk_program[32];
    int            pk_proglen;
};

int pk_verbose_execute=0;


static void copyPkValueTo(unsigned char *mapping, struct pkprogram *prog,
		   const char *typeStr, 
		   int pkRegNum,
		   unsigned char *pkValue, unsigned short pkValueLen)
{
    int registerSize = prog->chunksize*64;
    unsigned int pkRegOff = HIFN_1_PUB_MEM + (pkRegNum*registerSize);
    unsigned char *pkReg = mapping + pkRegOff;

	if(prog->valuesLittleEndian) {
		memcpy(pkReg, pkValue, pkValueLen);
		memset(pkReg+pkValueLen, 0, (registerSize-pkValueLen));
	} else {
		int vi, vd;
		unsigned char pkRegTemp[PKVALUE_LEN];

		/*
		 * we use a temp area, because probably things go badly
		 * if we do byte accesses.
		 */
		memset(pkRegTemp, 0, PKVALUE_LEN);
		for(vd=pkValueLen-1, vi=0; vi<registerSize && vd >=0; vi++, vd--) {
			pkRegTemp[vi]=pkValue[vd];
		}
		memcpy(pkReg, pkRegTemp, registerSize);
	}
	
	if(pk_verbose_execute) {
		printf("%s[%d]: before\n", typeStr, pkRegNum);
		hexdump(mapping, pkRegOff, registerSize);
	}
}

static void copyPkValueFrom(unsigned char *mapping, struct pkprogram *prog,
		     const char *typeStr, 
		     int pkRegNum,
		     unsigned char *pkValue, unsigned short pkValueLen)
{
    int registerSize = prog->chunksize*64;
    unsigned int pkRegOff = HIFN_1_PUB_MEM + (pkRegNum*registerSize);
    unsigned char *pkReg = mapping + pkRegOff;

    if(prog->valuesLittleEndian) {
	memcpy(pkValue, pkReg, pkValueLen);
    } else {
	int vi, vd;

	unsigned char pkRegTemp[PKVALUE_LEN];

	/*
	 * we use a temp area, because probably things go badly
	 * if we do byte accesses.
	 */
	memcpy(pkRegTemp, pkReg, PKVALUE_LEN);

	memset(pkValue, 0, pkValueLen);
	for(vd=pkValueLen-1, vi=0; vi<registerSize && vd >=0; vi++, vd--) {
	    pkValue[vd]=pkRegTemp[vi];
	}
	
	if(pk_verbose_execute) {
		printf("%s[%d]: after extract\n", typeStr, pkRegNum);
		hexdump(pkValue, 0, pkValueLen);
	}
    }
}

static void dump_registers(unsigned char *mapping, unsigned int registerSize)
{
    unsigned int pkNum;
    unsigned int maxregister = (HIFN_1_PUB_MEMSIZE/registerSize)-1;

    for(pkNum = 0;
	pkNum <= maxregister;
	pkNum++)
    {
	unsigned int pkRegOff = HIFN_1_PUB_MEM + (pkNum*registerSize);
	printf("register[%d]\n", pkNum);
	hexdump(mapping, pkRegOff, registerSize);
    }
}



#if !defined(ENHANCED_MODE)
static inline u_int32_t xlat2compat_oplen(u_int32_t oplen)
{
	unsigned int red,exp,mod;
	red = (oplen >> 24)&0xff;
	exp = (oplen >> 8)&0xfff;
	mod = (oplen >> 0)&0xff;
	  
	oplen = ((red&0xf) << 18) | ((exp&0x7ff) << 7) | (mod & 0x7f);
	
	return oplen;
}

static inline u_int32_t xlat2compat_op(u_int32_t op)
{
	unsigned int opcode,m,b,a;
	opcode = (op>>24)&0xff;
	m      = (op>>16)&0xff;
	b      = (op>>8)&0xff;
	a      = op & 0xff;
	
	op = (opcode << 18)|(m<<12)|(b<<6)|(a<<0);
	
	/* assert that "opcode" is not invalid, may be good */
	return op;
}
#endif

void execute_pkprogram(unsigned char *mapping, struct pkprogram *prog)
{
	/* make sure PK engine is done */
    unsigned int registerSize = prog->chunksize*64;
	int count=5;
	int i, pc;
	volatile u_int32_t stat;
	volatile u_int32_t *opfifo;

	while(count-->0 &&
	      ((stat = PUB_WORD(HIFN_1_PUB_STATUS)) & HIFN_PUBSTS_DONE) != HIFN_PUBSTS_DONE) {
		usleep(1000);
	}
	if(count == 0) {
		printf("failed to complete: %08x\n", stat);
		exit(6);
	}

	/*
	 * copy source operands into memory, clearing other parts.
	 * hopefully, will turn into a single PCI burst write.
	 */
	for(i=0; i<PK_AVALUES; i++) {
	    if(prog->aValues[i] != NULL) {
		copyPkValueTo(mapping, prog, "a", i, prog->aValues[i], prog->aValueLen[i]);
	    } else {
		unsigned char *pkReg = mapping + HIFN_1_PUB_MEM + (i*registerSize);
		/* clear memory */
		memset(pkReg, 0, registerSize);
	    }
	}
	
	/* a write barrier, and a cache flush would be good idea here */
	bus_space_write_barrier();
	usleep(1000);

	/* now copy the instructions to the FIFO. */

#if !defined(ENHANCED_MODE)
	/*
	 * oops. FIFO is broken, so write them out to oplen/op,
	 * after converting them to compat mode instructions.
	 */
	pc = 0;
	opfifo = (volatile u_int32_t *)(mapping+HIFN_1_PUB_OPLEN);
	if(pk_verbose_execute) print_status(PUB_WORD(HIFN_1_PUB_STATUS));
	PUB_WORD_WRITE(HIFN_1_PUB_STATUS, PUB_WORD(HIFN_1_PUB_STATUS));
	if(pk_verbose_execute) print_status(PUB_WORD(HIFN_1_PUB_STATUS));

	while(pc < prog->pk_proglen) {
	    u_int32_t op, oplen;

	    oplen = prog->pk_program[pc];
	    op    = prog->pk_program[pc+1];

	    if(pk_verbose_execute) {
		print_status(PUB_WORD(HIFN_1_PUB_STATUS));
		printf("original instruction at %d oplen=%08x/op=%08x\n",
		       pc, oplen, op);
	    }

	    oplen = xlat2compat_oplen(prog->pk_program[pc++]);
	    op = xlat2compat_op(prog->pk_program[pc++]);
	    
	    if(pk_verbose_execute) {
		printf("executing instruction %d (of %d) (%08x/%08x)\n",
		       pc, prog->pk_proglen, oplen, op);
	    }
	    opfifo[0]=oplen;
	    opfifo[1]=op;

	    if(pc < prog->pk_proglen) {
		count=5;
		while(--count>0 &&
		      ((stat = PUB_WORD(HIFN_1_PUB_STATUS)) & HIFN_PUBSTS_DONE) != HIFN_PUBSTS_DONE) {
		    usleep(1000);
		}
	    }
	}
#else
	opfifo = (volatile u_int32_t *)(mapping+HIFN_1_PUB_FIFO_OPLEN);
	memcpy(opfifo, prog->pk_program, prog->pk_proglen*8);
#endif

	bus_space_write_barrier();
	usleep(1000);
	/* wait for DONE bit */
	if(pk_verbose_execute) print_status(PUB_WORD(HIFN_1_PUB_STATUS));
	count=50;
	
	while(--count>0 &&
	      ((stat = PUB_WORD(HIFN_1_PUB_STATUS)) & HIFN_PUBSTS_DONE) != HIFN_PUBSTS_DONE) {
	    usleep(1000);
	}
	if(count == 0) {
	    printf("failed to complete: %08x\n", stat);
	    print_status(stat);
	    exit(6);
	}

	if(pk_verbose_execute) {
	    printf("after running:\n");
	    dump_registers(mapping, prog->chunksize*64);
	}
	    
	/* output is usually in b[1] */
	copyPkValueFrom(mapping, prog, "a", prog->oOffset,
			prog->oValue, prog->oValueLen);
}

void vulcanpk_init(unsigned char *mapping)
{
        volatile unsigned int stat;

	PUB_WORD(HIFN_1_PUB_RESET)=0x1;
	while((stat = PUB_WORD(HIFN_1_PUB_RESET)) & 0x01) {
		sleep(1);
	}


#if defined(ENHANCED_MODE)
	PUB_WORD_WRITE(HIFN_1_PUB_MODE, PUB_WORD(HIFN_1_PUB_MODE)|HIFN_PKMODE_ENHANCED);
#endif

	/* enable RNG again */
	PUB_WORD_WRITE(HIFN_1_RNG_CONFIG, PUB_WORD(HIFN_1_RNG_CONFIG) | HIFN_RNGCFG_ENA);

	/* clear out PUBLIC DONE */
	PUB_WORD_WRITE(HIFN_1_PUB_STATUS, PUB_WORD(HIFN_1_PUB_STATUS));
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
