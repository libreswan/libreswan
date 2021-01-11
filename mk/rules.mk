# generic make rules for libreswan

# Targets needing the builddir should add:
#
#     | $(builddir)
#
# as a soft/order-only dependency.

$(builddir):
	mkdir -p $(builddir)

# script transforms

# Some Makefiles use $(buildir)/SCRIPT as the target while others use
# just SCRIPT.  Accommodate both.

define transform_script
	@echo  'IN' $< '->' $(builddir)/$@
	${TRANSFORM_VARIABLES} < $< > $(builddir)/$*.tmp
	@if [ -x $< ]; then chmod +x $(builddir)/$*.tmp; fi
	@if [ "${PROGRAM}" = $* ]; then chmod +x $(builddir)/$*.tmp; fi
	mv $(builddir)/$*.tmp $(builddir)/$*
endef

%: %.sh $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	$(transform_script)

%: %.in $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	$(transform_script)

%: %.pl $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	$(transform_script)

$(builddir)/%: %.sh $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	$(transform_script)

$(builddir)/%: %.in $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	$(transform_script)

$(builddir)/%: %.pl $(top_srcdir)/Makefile.inc $(top_srcdir)/Makefile.ver | $(builddir)
	$(transform_script)

# In addition to compiling the .c file to .o, generate a dependency
# file.  Force all output to the build directory.  $(basename
# $(notdir)) is an approximation of UNIX basename.
#
# -DHERE_BASENAME is because it is a pita to create a basename from
#  __FILE__ using a static C expression
# -MP: add a fake header target for when a header is deleted
# -MMD: only list user header files
# -MT: the target (otherwise $(builddir)/$(notdir $@) is used
# -MF: where to write the dependency

ifdef OBJS

.c.o:
	$(CC) $(USERLAND_CFLAGS) \
		$(USERLAND_INCLUDES) \
		-DHERE_BASENAME=\"$(notdir $<)\" $(CFLAGS) \
		-MF $(builddir)/$(basename $(notdir $@)).d \
		-MP -MMD -MT $@ \
		-o $(builddir)/$(notdir $@) \
		-c $(abspath $<)

# Assume each source file has its own generated dependency file that
# is updated whenever the corresponding output is updated.  Given
# these files, create an include file that includes them.
#
# Use := so it is evaluated immediately, using the context from
# parsing this file (and ot later).

mk.depend.file := $(lastword $(MAKEFILE_LIST))
mk.depend.dependencies.file := $(builddir)/Makefile.depend.mk
$(mk.depend.dependencies.file): $(srcdir)/Makefile $(mk.depend.file) | $(builddir)
	set -e ; \
	for f in $(OBJS) ; do \
		case $$f in \
			*.c ) echo "-include \$$(builddir)/$$(basename $$f .c).d # $$f" ;; \
			*.o ) echo "-include \$$(builddir)/$$(basename $$f .o).d # $$f" ;; \
			* ) echo "# $$f ignored by Makefile.dep" ;; \
		esac ; \
	done > $@.tmp
	mv $@.tmp $@

clean: mk.depend.clean
.PHONY: mk.depend.clean
mk.depend.clean:
	rm -f $(mk.depend.dependencies.file)
	rm -f $(builddir)/*.d

-include $(mk.depend.dependencies.file)

endif
