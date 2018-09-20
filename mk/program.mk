# Make life easy, just include everything that is needed.

ifndef top_srcdir
include $(dir $(lastword $(MAKEFILE_LIST)))dirs.mk
endif

# Unless PROGRAM_MANPAGE has been pre-defined (only done by whack and
# only to suppress its man page), force MANPAGES to include a MANPAGE
# for this program.

PROGRAM_MANPAGE ?= $(addsuffix .8, $(PROGRAM))
MANPAGES += $(PROGRAM_MANPAGE)

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
CONFIGLIST=$(CONFFILES) $(CONFDSUBDIRFILES)
PROGRAMSLIST=${PROGRAM} $(CONFIGLIST)

local-base: $(PROGRAMSLIST)

local-clean-base:
	rm -f $(builddir)/*.o $(foreach p,$(PROGRAMSLIST), $(builddir)/$(p))

src-file = $(firstword $(wildcard $(srcdir)/$(1) $(builddir)/$(1)))

foreach-file = set -eu ; $(foreach f, $(1), \
		file=$(f) ; \
		destdir=$(strip $(2)) ; \
		src=$(call src-file,$(f)) ; \
		$(3) \
	)

local-install-base:
	@$(call foreach-file, $(PROGRAM),  $(PROGRAMDIR), \
		echo $$src '->' $$destdir/$$file ; \
		mkdir -p $$destdir ; \
		$(INSTALL) $(INSTBINFLAGS) $$src $$destdir/$$file ; \
	)
	@set -eu ; $(foreach file, $(CONFFILES), \
		if [ ! -f $(CONFDIR)/$(file) ]; then \
			echo $(call src-file,$(file)) '->' $(CONFDIR)/$(file) ; \
			mkdir -p $(CONFDIR) ; \
			$(INSTALL) $(INSTCONFFLAGS) $($(file).INSTFLAGS) $(call src-file,$(file)) $(CONFDIR)/$(file) ; \
		fi ; \
	)
	@$(call foreach-file, $(CONFFILES), $(CONFDIR), \
		echo $$src '->' $(EXAMPLECONFDIR)/$$file-sample ; \
		mkdir -p $(EXAMPLECONFDIR) ; \
		$(INSTALL) $(INSTCONFFLAGS) $$src $(EXAMPLECONFDIR)/$$file-sample ; \
	)
	@$(call foreach-file, $(EXCONFFILES), $(EXAMPLECONFDIR), \
		echo $$src '->' $$destdir/$$file-sample ; \
		$(INSTALL) $(INSTCONFFLAGS) $$src $$destdir/$$file-sample ; \
	)
	@$(call foreach-file, $(CONFDSUBDIRFILES), $(CONFDDIR)/$(CONFDSUBDIR), \
		if [ ! -f $$destdir/$$file ]; then \
			echo $$src '->' $$destdir/$$file ; \
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
	@$(call foreach-file,  $(CONFDSUBDIRFILES), $(CONFDDIR)/$(CONFDSUBDIR), \
		echo $$destdir/$$file ; \
	)

ifdef OBJS

# To avoid problems with implicit make rules creating and then
# deleting $(PROGRAM).o, $(OBJS) must include the main object
# (typically $(PROGRAM).o).  Since there is no difference between how
# objects and archives are handled, $(OBJS) includes both.  Duplicate
# archives do no harm.
#
# Need to depend on Makefile so that when $(OBJS) changes (for
# instance something is removed), a re-link is triggered.

$(PROGRAM): $(OBJS) $(srcdir)/Makefile
	cd $(builddir) && $(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(USERLINK)

include $(top_srcdir)/mk/depend.mk

else

%: %.in $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	@echo  'IN' $< '->' $(builddir)/$@
	${TRANSFORM_VARIABLES} < $< > $(builddir)/$@
	@if [ -x $< ]; then chmod +x $(builddir)/$@; fi
	@if [ "${PROGRAM}.in" = $< ]; then chmod +x $(builddir)/$@; fi

%: %.pl $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	@echo  'PL' $< '->' $(builddir)/$@
	@${TRANSFORM_VARIABLES} < $< > $(builddir)/$@
	@if [ -x $< ]; then chmod +x $(builddir)/$@; fi
	@if [ "${PROGRAM}.pl" = $< ]; then chmod +x $(builddir)/$@; fi

endif

include $(top_srcdir)/mk/builddir.mk
