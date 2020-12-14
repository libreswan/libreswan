# these need get fixed not to use root

top_srcdir = ../..

.PHONY: deb
deb: | $(top_srcdir)/debian
	cd $(top_srcdir) && debuild -i -us -uc -b
	rm -fr $(top_srcdir)/debian
#debuild -S -sa

DEBIAN_IPSEC_BASE_VERSION=$(shell make --directory $(top_srcdir) --silent showversion | sed -e "s/\([0-9]\{1,3\}\)\.\([0-9]\{1,3\}\)\(.*\)/\1.\2~\3/" | sed "s/~-/~/")

# racy
$(top_srcdir)/debian:
	cp -r . $(top_srcdir)/debian
	cat $(top_srcdir)/debian/changelog
	grep "IPSECBASEVERSION" $(top_srcdir)/debian/changelog && \
		sed -i "s/@IPSECBASEVERSION@/$(DEBIAN_IPSEC_BASE_VERSION)/g" $(top_srcdir)/debian/changelog || \
		echo "missing IPSECBASEVERSION in debian/changelog. This is not git repository?"
	cat $(top_srcdir)/debian/changelog

showdebversion:
	@echo $(DEBIAN_IPSEC_BASE_VERSION)
