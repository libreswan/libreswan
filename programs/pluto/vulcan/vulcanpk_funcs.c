unsigned char * mapvulcanpk(void)
{
	unsigned char *mapping;
	int fd=open("/dev/vulcanpk", O_RDWR);
	
	if(fd == -1) {
	  perror("open");
	  exit(6);
	}

	/* HIFN_1_PUB_MEMEND */
	mapping = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	
	if(mapping == NULL) {
		perror("mmap");
		exit(4);
	}
	
	return mapping;
}

void hexdump(caddr_t bb, int len)
{
	unsigned char *b = bb;
	int i;
  
	for(i = 0; i < len; i++) {
		if(!(i % 16)) {
			printf("%04x:", i);
		}
		printf(" %02x", b[i]); 
		if(!((i + 1) % 16)) {
			printf("\n");
		}
	}
	if(i % 16) {
		printf("\n");
	}
}

void print_status(u_int32_t stat)
{
	printf("status: %08x ", stat);
	if(stat & HIFN_PUBSTS_DONE) {
		printf("done ");
	}
	if(stat & HIFN_PUBSTS_CARRY) {
		printf("carry ");
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
		printf("write=%d ", (stat & HIFN_PUBSTS_FIFO_READ)>>24);
	}
	printf("\n");
}


#define PUB_WORD(offset) *(volatile u_int32_t *)(&mapping[offset])

inline void write_pkop(unsigned char *mapping,
		       u_int32_t oplen, u_int32_t op)
{
	volatile u_int32_t *opfifo;

	opfifo = (volatile u_int32_t *)(mapping+HIFN_1_PUB_FIFO_OPLEN);

	opfifo[0]=oplen;
	opfifo[1]=op;
}

#define PKVALUE_BITS  3072
#define PKVALUE_LEN   (PKVALUE_BITS/8)

#define PK_AVALUES 7
#define PK_BVALUES 7

struct pkprogram {
	bool           valuesLittleEndian;
	unsigned char *aValues[PK_AVALUES];
	unsigned short aValueLen[PK_AVALUES];
	unsigned int   oOffset;
	unsigned char *oValue;
	u_int32_t      pk_program[32];
};

int pk_verbose_execute=0;


void copyPkValues(unsigned char *mapping, struct pkprogram *prog
		  char *typeStr, 
		  int pkRegNum,
		  unsigned char *pkValue, unsigned short pkValueLen)
{
	unsigned char *pkReg = mapping + HIFN_1_PUB_MEM + (pkRegNum*PKVALUE_LEN);

	if(!prog->valuesLittleEndian) {
		memcpy(pkReg, pkValue, PKVALUE_LEN);
	} else {
		int vi, vd;
		
		for(vd=pkValueLen-1, vi=0; vi<PKVALUE_LEN && vd >=0; vi++, vd--) {
			pkReg[vi]=pkValue[vd];
		}
	}
	
	if(pk_verbose_execute) {
		printf("%s[%d]:\n", typeStr, pkRegNum);
		hexdump(pkReg, PKVALUE_LEN);
	}
}


void execute_pkprogram(unsigned char *mapping, struct pkprogram *prog)
{
	/* make sure PK engine is done */
	int count=5;
	int i, pc;
	volatile u_int32_t stat;

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
			copyPkValue(mapping, prog, "a", i, prog->aValues[i]);
		} else {
			unsigned char *pkReg = mapping + HIFN_1_PUB_MEM + (i*PKVALUE_LEN);
			/* clear memory */
			memset(pkReg, 0, PKVALUE_LEN);
		}
	}
	
	/* a write barrier, and a cache flush would be good idea here */
	usleep(1000);

	/* run each instruction, one at a time */
	for(pc=0; prog->pk_program[pc]!=0 && pc < 32; pc+=2) {
		volatile u_int32_t *opfifo;

		/* do not use fifo for now, sigh */
		opfifo = (volatile u_int32_t *)(mapping+HIFN_1_PUB_OPLEN);

		printf("executing instruction %d\n", pc);
		opfifo[0]=prog->pk_program[pc];
		opfifo[1]=prog->pk_program[pc+1];

		/* wait for DONE bit */
		count=5;

		while(count-->0 &&
		      ((stat = PUB_WORD(HIFN_1_PUB_STATUS)) & HIFN_PUBSTS_DONE) != HIFN_PUBSTS_DONE) {
			usleep(1000);
		}
		if(count == 0) {
			printf("failed to complete: %08x\n", stat);
			exit(6);
		}

		for(i=0; i<PK_AVALUES; i++) {
			unsigned char *pkReg = mapping + HIFN_1_PUB_MEM + (i*PKVALUE_LEN);
			if(prog->aValues[i] && pk_verbose_execute) {
				printf("a[%d]:\n", i);
				hexdump(pkReg, PKVALUE_LEN);
			}
		}
	}
      
	/* output is usually in b[2] */
	{
		unsigned char *pkReg = mapping + HIFN_1_PUB_MEM + (prog->oOffset*PKVALUE_LEN);
		printf("result[%d]:\n", prog->oOffset);
		hexdump(pkReg, 16);
	}
}

void vulcanpk_init(unsigned char *mapping)
{
	PUB_WORD(HIFN_1_PUB_RESET)=0x1;
	while((stat = PUB_WORD(HIFN_1_PUB_RESET)) & 0x01) {
		sleep(1);
	}


	//PUB_WORD(HIFN_1_PUB_MODE) = PUB_WORD(HIFN_1_PUB_MODE)|HIFN_PKMODE_ENHANCED;
	/* enable RNG again */
	PUB_WORD(HIFN_1_RNG_CONFIG) = PUB_WORD(HIFN_1_RNG_CONFIG) | HIFN_RNGCFG_ENA;

	/* clear out PUBLIC DONE */
	PUB_WORD(HIFN_1_PUB_STATUS) = HIFN_PUBSTS_DONE;
}

