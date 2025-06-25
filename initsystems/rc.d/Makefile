include ../../mk/dirs.mk
include $(top_srcdir)/mk/config.mk

RC_D_FILE = pluto

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE=

local-base: $(RC_D_FILE)
local-install-base: $(RC_D_FILE) local-base
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_RC_D_DIR))
	@set -eu ; $(call install-file, $(INSTBINFLAGS), \
		$(builddir)/$(RC_D_FILE), \
		$(DESTDIR)$(EXAMPLE_RC_D_DIR)/$(RC_D_FILE))
ifeq ($(INSTALL_INITSYSTEM),true)
	@set -ue ; $(call install-directory, $(DESTDIR)$(RC_D_DIR))
	@set -eu ; $(call install-missing-file, $(INSTBINFLAGS), \
		$(DESTDIR)$(EXAMPLE_RC_D_DIR)/$(RC_D_FILE), \
		$(DESTDIR)$(RC_D_DIR)/$(RC_D_FILE))
endif
ifeq ($(INSTALL_INITSYSTEM),true)
ifneq ($(BSD_VARIANT),openbsd)
	@. /etc/rc.subr ; \
	load_rc_config pluto ; \
	case " $$rc_directories " in \
	*" $(RC_D_DIR) "* ) ;; \
	* ) \
		echo "" ; \
		echo "" ; \
		echo "    WARNING:" ; \
		echo "" ; \
		echo "        RC_D_DIR=$(RC_D_DIR) is not included in" ; \
		echo "        the /etc/rc.conf variable:" ; \
		echo "" ; \
		echo "            rc_directories=\"$${rc_directories}\"" ; \
		echo "" ; \
		;; \
	esac
endif
endif

list-local-base:
	@set -eu ; echo $(EXAMPLE_RC_D_DIR)/$(RC_D_FILE)
ifeq ($(INSTALL_INITSYSTEM),true)
	@set -eu ; echo $(RC_D_DIR)/$(RC_D_FILE)
endif

# assumes a single word
pluto: $(BSD_VARIANT).sh $(TRANSFORM_DEPS) | $(builddir)/
	$(transform_script)

include $(top_srcdir)/mk/install.mk
include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/rules.mk

