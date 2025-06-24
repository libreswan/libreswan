# generic make rules for libreswan

# Targets needing a build directory should add:
#
#     | $(builddir)/
#
# as a soft/order-only dependency.

%/:
	mkdir -p $@

# script transforms

# Some Makefiles use $(buildir)/SCRIPT as the target while others use
# just SCRIPT.  Accommodate both.

define transform_script
	@echo  'IN' $< '->' $(builddir)/$(notdir $@)
	${TRANSFORM_VARIABLES} < $< > $(builddir)/$(notdir $@).tmp
	@if [ -x $< ]; then chmod +x $(builddir)/$(notdir $@).tmp; fi
	@if [ "${PROGRAM}" = $(notdir $@) ]; then chmod +x $(builddir)/$(notdir $@).tmp; fi
	mv $(builddir)/$(notdir $@).tmp $(builddir)/$(notdir $@)
endef

TRANSFORM_DEPS = \
	$(top_srcdir)/mk/version.mk \
	$(top_srcdir)/mk/config.mk \
	$(wildcard $(top_srcdir)/Makefile.inc.local)

%: %.sh $(TRANSFORM_DEPS) | $(builddir)/
	$(transform_script)

%: %.in $(TRANSFORM_DEPS) | $(builddir)/
	$(transform_script)

%: %.pl $(TRANSFORM_DEPS) | $(builddir)/
	$(transform_script)

$(builddir)/%: %.sh $(TRANSFORM_DEPS) | $(builddir)/
	$(transform_script)

$(builddir)/%: %.in $(TRANSFORM_DEPS) | $(builddir)/
	$(transform_script)

$(builddir)/%: %.pl $(TRANSFORM_DEPS) | $(builddir)/
	$(transform_script)

ifdef OBJS

# In addition to compiling the .c file to .o, generate a dependency
# file.  Force all output to the build directory.
#
# -DHERE_FILENAME, used by where_t, is because it is a PITA to create
#  a path from __FILE__ using a static C expression
#
# Two rules are provided.  The standard rule, and a rule for the case
# where the .c file is generated.
#
# These rules accomodate sources in a sub-directory.
#
# -MP: add a fake header target for when a header is deleted
# -MMD: only list user header files
# -MT: the target (otherwise $(builddir)/$(notdir $@) is used
# -MF: where to write the dependency
#
# Note: when GMAKE tries to match this rule it will try adding
# $(VPATH), which means it will find $(builddir)/*.c.

%.o: %.c
	$(CC) $(USERLAND_CFLAGS) $(USERLAND_INCLUDES) $(CFLAGS) \
		-DHERE_FILENAME='"$(patsubst /%,%,$(path_srcdir)/$(*).c)"' \
		-MP -MMD -MT $(*).o -MF $(builddir)/$(*).d \
		-o $(builddir)/$(*).o \
		-c $<

# Assume each source file has its own generated dependency file that
# is updated whenever the corresponding output is updated.  Given
# these files, create an include file that includes them.
#
# Use := so it is evaluated immediately, using the context from
# parsing this file (and not later).

mk.depend.file := $(lastword $(MAKEFILE_LIST))
mk.depend.dependencies.file := $(builddir)/Makefile.depend.mk
$(mk.depend.dependencies.file): $(srcdir)/Makefile $(mk.depend.file) | $(builddir)/
	( set -e $(foreach OBJ, $(OBJS), \
	&& echo "-include $(builddir)/$(basename $(OBJ)).d # $(OBJ)") \
	) > $@.tmp
	mv $@.tmp $@

clean: mk.depend.clean
.PHONY: mk.depend.clean
mk.depend.clean:
	rm -f $(mk.depend.dependencies.file)
	rm -f $(builddir)/*.d
	rm -f $(builddir)/*/*.d

-include $(mk.depend.dependencies.file)

endif
