# Make life easy, just include everything that is needed.

ifndef top_srcdir
include $(dir $(lastword $(MAKEFILE_LIST)))dirs.mk
endif

# Unless PROGRAM_MANPAGE has been pre-defined (only done by whack and
# only to suppress its man page), force MANPAGES to include a MANPAGE
# for this program.

PROGRAM_MANPAGE ?= $(addprefix ipsec-, $(addsuffix .8, $(PROGRAM)))
MANPAGES += $(PROGRAM_MANPAGE)

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/version.mk
include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/manpages.mk

ifneq ($(LD_LIBRARY_PATH),)
LDFLAGS+=-L$(LD_LIBRARY_PATH)
endif

ifndef PROGRAMDIR
PROGRAMDIR=$(DESTDIR)$(LIBEXECDIR)
endif

local-base: $(PROGRAM)

local-clean-base:
	rm -f $(foreach p,$(PROGRAM), $(builddir)/$(p))
	rm -f $(builddir)/*.o $(builddir)/*/*.o
	rm -f $(builddir)/*.c $(builddir)/*/*.c

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

list-local-base:
	@$(call foreach-file, $(PROGRAM), $(PROGRAMDIR), \
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
	cd $(builddir) && \
	$(CC) $(USERLAND_CFLAGS) \
		$(USERLAND_INCLUDES) \
		$(CFLAGS) \
		-o $@ $(OBJS) \
		$(USERLAND_LDFLAGS) \
		$(LDFLAGS)

endif

include $(top_srcdir)/mk/rules.mk
