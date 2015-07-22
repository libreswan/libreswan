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
CONFIGLIST=$(CONFFILES) $(CONFDFILES) $(CONFDSUBDIRFILES)
PROGRAMSLIST=${PROGRAM} $(CONFIGLIST)

# XXX: Switch directory hack
local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) buildall
clean-local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) cleanall
install-local-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) doinstall
buildall: $(PROGRAMSLIST)

foreach-file = @set -eu ; $(foreach f, $(1), \
		file=$(f) ; \
		destdir=$(strip $(2)) ; \
		src=$(firstword $(wildcard $(srcdir)/$(f)) $(builddir)/$(f)) ; \
		$(3) \
	)

doinstall:
	$(call foreach-file, $(PROGRAM),  $(PROGRAMDIR), \
		echo Install: $$src '->' $$destdir/$$file ; \
		mkdir -p $$destdir ; \
		$(INSTALL) $(INSTBINFLAGS) $$src $$destdir/$$file ; \
	)
	$(call foreach-file, $(CONFFILES), $(CONFDIR), \
		if [ ! -f $$destdir/$$file ]; then \
			echo Install: $$src '->' $$destdir/$$file ; \
			mkdir -p $$destdir ; \
			$(INSTALL) $(INSTCONFFLAGS) $$src $$destdir/$$file ; \
		fi ; \
		echo Install: $$src '->' $(EXAMPLECONFDIR)/$$file-sample ; \
		mkdir -p $(EXAMPLECONFDIR) ; \
		$(INSTALL) $(INSTCONFFLAGS) $$src $(EXAMPLECONFDIR)/$$file-sample ; \
	)
	@$(call foreach-file, $(EXCONFFILES), $(EXAMPLECONFDIR), \
		echo Install: $$src '->' $$destdir/$$file-sample ; \
		$(INSTALL) $(INSTCONFFLAGS) $$src $$destdir/$$file-sample ; \
	)
	@$(call foreach-file, $(CONFDFILES), $(CONFDDIR), \
		if [ ! -f $$destdir/$$file ]; then \
			echo Install: $$src '->' $$destdir/$$file ; \
			mkdir -p $$destdir ; \
			$(INSTALL) $(INSTCONFFLAGS) $$src $$destdir/$$file ; \
		fi ; \
	)
	@$(call foreach-file, $(CONFDSUBDIRFILES), $(CONFDDIR)/$(CONFDSUBDIR), \
		if [ ! -f $$destdir/$$file ]; then \
			echo Install: $$src '->' $$destdir/$$file ; \
			mkdir -p $$destdir ; \
			$(INSTALL) $(INSTCONFFLAGS) $$src $$destdir/$$file ; \
		fi ; \
	)

list-local-base:
	@$(call foreach-file, $(PROGRAM), $(PROGRAMDIR), \
		echo $$destdir/$$file ; \
	)
	@$(call foreach-file, $(CONFFILES), $(CONFDIR), \
		echo $$destdir/$$file ; \
		echo $(EXAMPLECONFDIR)/$$file-sample ; \
	)
	@$(call foreach-file, $(EXCONFFILES), $(EXAMPLECONFDIR), \
		echo $$destdir/$$file-sample ; \
	)
	@$(call foreach-file,  $(CONFDFILES), $(CONFDDIR), \
		echo $$destdir/$$file ; \
	)
	@$(call foreach-file,  $(CONFDSUBDIRFILES), $(CONFDDIR)/$(CONFDSUBDIR), \
		echo $$destdir/$$file ; \
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

cleanall::
ifneq ($(strip $(PROGRAM)),)
	@if [ -r ${SRCDIR}$(PROGRAM).in ]; then rm -f $(PROGRAM); fi
	@if [ -r ${SRCDIR}$(PROGRAM).pl ]; then rm -f $(PROGRAM); fi
	@if [ -r ${SRCDIR}$(PROGRAM).c ];  then rm -f $(PROGRAM); fi
	@if [ -n "$(OBJS)" ];     then rm -f $(PROGRAM); fi
endif
	@rm -f *.o
