# Targets needing the builddir should add:
#
#     | $(builddir)
#
# as a soft/order-only dependency.
$(builddir):
	mkdir -p $(builddir)
