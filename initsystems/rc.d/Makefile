ifndef top_srcdir
include ../../mk/dirs.mk
endif

include $(top_srcdir)/mk/config.mk
include $(top_srcdir)/mk/install.mk

RC_D_FILES = pluto

# XXX: Hack to suppress the man page.  Should one be added?
PROGRAM_MANPAGE=

local-base: $(RC_D_FILES)
local-install-base: $(RC_D_FILES)
	@set -eu ; $(call install-directory, $(DESTDIR)$(EXAMPLE_RC_D_DIR))
	@set -eu ; $(foreach file, $(RC_D_FILES), \
		$(call install-file, $(INSTBINFLAGS), \
			$(builddir)/$(file), $(DESTDIR)$(EXAMPLE_RC_D_DIR)/$(file)) ; \
	)
ifeq ($(INSTALL_INITSYSTEM),true)
	@set -ue ; $(call install-directory, $(DESTDIR)$(RC_D_DIR))
	@set -eu ; $(foreach file, $(RC_D_FILES), \
		$(call install-missing-file, $(INSTBINFLAGS), \
			$(DESTDIR)$(EXAMPLE_RC_D_DIR)/$(file), $(DESTDIR)$(RC_D_DIR)/$(file)) ; \
	)
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
	@set -eu $(foreach file, $(RC_D_FILES), ; echo $(RC_D_DIR)/$(file))
	@set -eu $(foreach file, $(RC_D_FILES), ; echo $(EXAMPLE_RC_D_DIR)/$(file))

include $(top_srcdir)/mk/targets.mk
include $(top_srcdir)/mk/rules.mk

# assumes a single word
pluto: $(BSD_VARIANT).sh $(TRANSFORM_DEPS) | $(builddir)
	$(transform_script)
