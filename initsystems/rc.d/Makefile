ifndef top_srcdir
include ../../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/install.mk

INSTINITSYSTEMFLAGS ?= $(INSTBINFLAGS)

INITSYSTEMFILES = pluto

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE=

local-base: $(INITSYSTEMFILES)
local-install-base: $(INITSYSTEMFILES)
	@set -eu ; $(call install-directory, $(EXAMPLEINITSYSTEMDIR))
	@set -eu ; $(foreach file, $(INITSYSTEMFILES), \
		$(call install-file, $(INSTBINFLAGS), \
			$(builddir)/$(file), $(EXAMPLEINITSYSTEMDIR)/$(file)) ; \
	)
ifeq ($(INSTALL_INITSYSTEM),true)
	@set -ue ; $(call install-directory, $(INITSYSTEMDIR))
	@set -eu ; $(foreach file, $(INITSYSTEMFILES), \
		$(call install-missing-file, $(INSTBINFLAGS), \
			$(EXAMPLEINITSYSTEMDIR)/$(file), $(INITSYSTEMDIR)/$(file)) ; \
	)
endif
ifeq ($(INSTALL_INITSYSTEM),true)
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
endif

list-local-base:
	@set -eu $(foreach file, $(INITSYSTEMFILES), ; echo $(FINALINITSYSTEMDIR)/$(file))
	@set -eu $(foreach file, $(INITSYSTEMFILES), ; echo $(INITSYSTEMEXAMPLESDIR)/$(file))	)

include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/rules.mk

# assumes a single word
pluto: $(BSD_VARIANT).sh $(TRANSFORM_DEPS) | $(builddir)
	$(transform_script)
