ifndef top_srcdir
include ../../mk/dirs.mk
endif
include $(top_srcdir)/mk/config.mk

INSTINITSYSTEMFLAGS ?= $(INSTBINFLAGS)

INITSYSTEMFILES = pluto

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE=

local-base: $(INITSYSTEMFILES)
local-install-base: $(INITSYSTEMFILES)
	@set -eu $(foreach file, $(INITSYSTEMFILES), ; \
		if test ! -f $(INITSYSTEMDIR)/$(file) ; then \
			echo $(builddir)$(file) '->' $(INITSYSTEMDIR)/$(file) ; \
			mkdir -p $(INITSYSTEMDIR) ; \
			$(INSTALL) $(INSTBINFLAGS) $(builddir)/$(file) $(INITSYSTEMDIR)/$(file) ; \
		else \
			echo "#" $(builddir)/$(file) '->' $(INITSYSTEMDIR)/$(file) ; \
		fi \
	)
	@set -eu $(foreach file, $(INITSYSTEMFILES), ; \
		echo $(builddir)$(file) '->' $(INITSYSTEMEXAMPLESDIR)/$(file) ; \
		mkdir -p $(INITSYSTEMEXAMPLESDIR) ; \
		$(INSTALL) $(INSTBINFLAGS) $(builddir)/$(file) $(INITSYSTEMEXAMPLESDIR)/$(file) ; \
	)
ifneq ($(BSD_VARIANT),openbsd)
	@. /etc/rc.subr ; \
	load_rc_config pluto ; \
	case " $$rc_directories " in \
	*" $(FINALINITSYSTEMDIR) "* ) ;; \
	* ) \
		echo "" ; \
		echo "" ; \
		echo "    WARNING:" ; \
		echo "" ; \
		echo "        FINALINITSYSTEMDIR=$(FINALINITSYSTEMDIR) is not included in" ; \
		echo "        the /etc/rc.conf variable:" ; \
		echo "" ; \
		echo "            rc_directories=\"$${rc_directories}\"" ; \
		echo "" ; \
		;; \
	esac
endif

list-local-base:
	@set -eu $(foreach file, $(INITSYSTEMFILES), ; echo $(FINALINITSYSTEMDIR)/$(file))
	@set -eu $(foreach file, $(INITSYSTEMFILES), ; echo $(INITSYSTEMEXAMPLESDIR)/$(file))	)

include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/rules.mk
