
# INITSYSTEMDIR is where the start stop scripts go
FINALINITSYSTEMDIR ?= $(PREFIX)/etc/$(INITSYSTEM)
INITSYSTEMDIR ?= $(DESTDIR)$(FINALINITSYSTEMDIR)

FINALINITSYSTEMEXAMPLESDIR ?= $(PREFIX)/share/examples/$(INITSYSTEM)
INITSYSTEMEXAMPLESDIR ?= $(DESTDIR)$(FINALINITSYSTEMEXAMPLESDIR)

INSTINITSYSTEMFLAGS ?= $(INSTBINFLAGS)

INITSYSTEMFILES = pluto

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE=

local: $(INITSYSTEMFILES)
local-install: $(INITSYSTEMFILES)
	@$(call foreach-file, $(INITSYSTEMFILES),  $(INITSYSTEMDIR), \
		if test ! -f $$destdir/$$file ; then \
			echo $$src '->' $$destdir/$$file ; \
			mkdir -p $$destdir ; \
			$(INSTALL) $(INSTBINFLAGS) $$src $$destdir/$$file ; \
		else \
			echo "#" $$src '->' $$destdir/$$file ; \
		fi \
	)
	@$(call foreach-file, $(INITSYSTEMFILES),  $(INITSYSTEMEXAMPLESDIR), \
		echo $$src '->' $$destdir/$$file ; \
		mkdir -p $$destdir ; \
		$(INSTALL) $(INSTBINFLAGS) $$src $$destdir/$$file ; \
	)
	. /etc/rc.subr ; \
	load_rc_config pluto ; \
	case " $$rc_directories " in \
	*" $(FINALINITSYSTEMDIR) "* ) ;; \
	* ) \
		echo "" ; \
		echo "" ; \
		echo "WARNING:" ; \
		echo "" ; \
		echo "    FINALINITSYSTEMDIR=$(FINALINITSYSTEMDIR) is not included in:" ; \
		echo "        $${rc_directories}" ; \
		echo "" ; \
		;; \
	esac

list-local-base: local-list-base
.PHONY: local-list-base
local-list-base:
	@$(call foreach-file, $(INITSYSTEMFILES), $(INITSYSTEMDIR), \
		echo $$destdir/$$file ; \
	)
	@$(call foreach-file, $(INITSYSTEMFILES), $(INITSYSTEMEXAMPLESDIR), \
		echo $$destdir/$$file ; \
	)

ifdef top_srcdir
include $(top_srcdir)/mk/program.mk
else
include ../../mk/program.mk
endif
