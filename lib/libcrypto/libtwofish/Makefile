OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

CFLAGS=-O3 -fomit-frame-pointer -Wall $(EXTRA_CFLAGS)
INC=-I../include 

LIBOBJ=twofish.o twofish_cbc.o
BLIB=libtwofish.a

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c $< -o $@

$(BLIB): $(LIBOBJ)
	$(AR) $(ARFLAGS) $(BLIB) $(LIBOBJ)

programs: $(BLIB)

install:
	@exit 0

test: test_main.o $(BLIB)
	$(CC) -o $@ $^ 

clean:
	rm -f *.[oa] core $(TARGET) test
