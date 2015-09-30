UNITTEST=verify
CFLAGS+=${NSSFLAGS}
SOURCES1=verify.c
verify: ${SOURCES1}
programs checkprograms: ${UNITTEST}
	@true

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif
