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

# XXX: hack until everything uses a consistent .c.o rule.
CFLAGS += -pthread
CFLAGS += $(USERLAND_CFLAGS)
CFLAGS += $(PORTINCLUDE)
CFLAGS += -I$(KLIPSINC)
CFLAGS += -I$(top_srcdir)/include
CFLAGS += $(NSSFLAGS)
CFLAGS += $(CROSSFLAGS)

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

local-clean-base:
	rm -f $(builddir)/*.o $(foreach p,$(PROGRAMSLIST), $(builddir)/$(p))

local-install-base: $(builddir)/Makefile
	$(MAKE) -C $(builddir) doinstall
buildall: $(PROGRAMSLIST)

src-file = $(firstword $(wildcard $(srcdir)/$(1) $(builddir)/$(1)))

foreach-file = @set -eu ; $(foreach f, $(1), \
		file=$(f) ; \
		destdir=$(strip $(2)) ; \
		src=$(call src-file,$(f)) ; \
		$(3) \
	)

doinstall:
	$(call foreach-file, $(PROGRAM),  $(PROGRAMDIR), \
		echo Install: $$src '->' $$destdir/$$file ; \
		mkdir -p $$destdir ; \
		$(INSTALL) $(INSTBINFLAGS) $$src $$destdir/$$file ; \
	)
	set -eu ; $(foreach file, $(CONFFILES), \
		if [ ! -f $(CONFDIR)/$(file) ]; then \
			echo Install: $(call src-file,$(file)) '->' $(CONFDIR)/$(file) ; \
			mkdir -p $(CONFDIR) ; \
			$(INSTALL) $(INSTCONFFLAGS) $($(file).INSTFLAGS) $(call src-file,$(file)) $(CONFDIR)/$(file) ; \
		fi ; \
	)
	$(call foreach-file, $(CONFFILES), $(CONFDIR), \
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
	)
	@$(call foreach-file, $(CONFFILES), $(CONFDIR), \
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

ifdef OBJS

# To avoid problems with implicit make rules creating and then
# deleting $(PROGRAM).o, $(OBJS) must include the main object
# (typically $(PROGRAM).o).  Since there is no difference between how
# objects and archives are handled, $(OBJS) includes both.  Duplicate
# archives do no halm.
$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(USERLINK)

MK_DEPEND_FILES = $(OBJS)
MK_DEPEND_CFLAGS = $(CFLAGS)
include $(top_srcdir)/mk/depend.mk

else

%: ${SRCDIR}%.in ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver
	@echo  'IN' $< '->' $@
	${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $@; fi

%: ${SRCDIR}%.pl ${LIBRESWANSRCDIR}/Makefile.inc ${LIBRESWANSRCDIR}/Makefile.ver
	@echo  'PL' $< '->' $@
	@${TRANSFORM_VARIABLES} < $< > $@
	@if [ -x $< ]; then chmod +x $@; fi
	@if [ "${PROGRAM}.pl" = $< ]; then chmod +x $@; fi

endif
