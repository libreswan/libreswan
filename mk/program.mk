# Make life easy, just include everything that is needed.

ifndef top_srcdir
include $(dir $(lastword $(MAKEFILE_LIST)))dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk
include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/manpages.mk

LEX=flex
BISON=bison
RM=rm

INCLUDES+=-I${LIBRESWANSRCDIR} -I${KLIPSINC} -I${LIBRESWANSRCDIR}/include ${NSSFLAGS}

CFLAGS+=-pthread

# XXX: hack until everything uses a consistent .c.o rule.
CFLAGS+=$(USERLAND_CFLAGS)
CFLAGS+=${PORTINCLUDE} ${INCLUDES} ${CROSSFLAGS}

LIBS?=${PROGLIBS} ${LSWLOGLIB} ${LIBRESWANLIB} ${CRYPTOLIBS}

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

ifndef PROGRAMDIR
PROGRAMDIR=${LIBEXECDIR}
endif

ifndef CONFDSUBDIR
CONFDSUBDIR=.
endif

# the list of stuff to be built for "make programs"
CONFIGLIST=$(CONFFILES) $(CONFDFILES)
PROGRAMSLIST=${PROGRAM} $(CONFIGLIST)

ifeq ($(srcdir),.)
all programs config man clean install install-programs:
	$(MAKE) -C $(builddir) $@
else
all: programs
programs: $(PROGRAMSLIST)
config: $(CONFIGLIST)
clean:	cleanall
install: doinstall
install-programs: doinstall
endif

ifneq ($(PROGRAM),check)
check: $(PROGRAM)
endif

doinstall: $(PROGRAMSLIST)
	@mkdir -p $(PROGRAMDIR) $(CONFDIR) $(CONFDDIR) $(CONFDDIR)/$(CONFDSUBDIR) $(EXAMPLECONFDIR)
	@if [ -n "$(PROGRAM)" ]; then $(INSTALL) $(INSTBINFLAGS) $(PROGRAM) $(PROGRAMDIR); fi
	@$(foreach f, $(CONFFILES), \
		g=`if [ -r $f ]; then echo $f; else echo ${SRCDIR}/$f; fi`; \
		if [ ! -f $(CONFDIR)/$f ]; then $(INSTALL) $(INSTCONFFLAGS) $$g $(CONFDIR)/$f || exit 1; fi;\
		$(INSTALL) $(INSTCONFFLAGS) $$g $(EXAMPLECONFDIR)/$f-sample || exit 1; \
	)
	@$(foreach f, $(EXCONFFILES), \
		g=`if [ -r $f ]; then echo $f; else echo ${SRCDIR}/$f; fi`; \
		$(INSTALL) $(INSTCONFFLAGS) $$g $(EXAMPLECONFDIR)/$f-sample || exit 1; \
	)
	@$(foreach f, $(CONFDFILES), \
		g=`if [ -r $f ]; then echo $f; else echo ${SRCDIR}/$f; fi`; \
		if [ ! -f $(CONFDDIR)/$(CONFDSUBDIR)/$f ]; then $(INSTALL) $(INSTCONFFLAGS) $$g $(CONFDDIR)/$(CONFDSUBDIR)/$f || exit 1; fi;\
	)

list-local-programs:
	@if [ -n "$(PROGRAM)" ]; then echo $(PROGRAMDIR)/$(PROGRAM); fi
	@$(foreach f, $(CONFFILES), \
		echo $(CONFDIR)/$f;\
		echo $(EXAMPLECONFDIR)/$f-sample;\
	)
	@$(foreach f, $(EXCONFFILES), \
		echo $(EXAMPLECONFDIR)/$f-sample;\
	)
	@$(foreach f, $(CONFDFILES), \
		echo $(CONFDDIR)/${CONFDSUBDIR}/$f;\
	)

# set values for implicit rules.
LOADLIBS=${OBJS} 

LDLIBS=${LIBS} ${USERLINK} ${LIBS} ${EXTRALIBS} -lgmp ${NSSLIBS}


%: %.o $(OBJS) ${LIBS}
	$(CC) $(CFLAGS) -o $@ $@.o ${OBJS} $(LDFLAGS) $(LDLIBS) $(USERLINK) 

# cancel direct version
%: %.c

# cancel direct version
%: %.c

%.o: ${SRCDIR}%.c
	${CC} -c ${CFLAGS} $<

%.i: %.c 
	$(CC) $(CFLAGS) -E -o $@ $< 

%: ${SRCDIR}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver ${LIBRESWANSRCDIR}/Makefile.top
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi

%: ${SRCDIR}%.pl ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver
	@echo  'PL' $< '->' $@
	@${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.pl" = $< ]; then chmod +x $@; fi

distclean: clean

mostlyclean: clean

realclean: clean

cleanall::
ifneq ($(strip $(PROGRAM)),)
	@if [ -r ${SRCDIR}$(PROGRAM).in ]; then rm -f $(PROGRAM); fi
	@if [ -r ${SRCDIR}$(PROGRAM).pl ]; then rm -f $(PROGRAM); fi
	@if [ -r ${SRCDIR}$(PROGRAM).c ];  then rm -f $(PROGRAM); fi
	@if [ -n "$(OBJS)" ];     then rm -f $(PROGRAM); fi
endif
	@rm -f *.o

checkprograms:
