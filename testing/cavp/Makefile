include ../../mk/dirs.mk

default: check
.PHONY: check default
check: ikev2.cavp ikev1_dsa.cavp ikev1_psk.cavp

.PRECIOUS: %.fax
%.fax: | $(builddir)
	curl -o $(builddir)/$@.bz2 https://download.libreswan.org/cavs/$@.bz2
	bunzip2 $(builddir)/$@.bz2

.PRECIOUS: %.out
%.out: %.fax $(top_builddir)/programs/pluto/cavp | $(builddir)
	$(top_builddir)/programs/pluto/cavp \
		$(builddir)/$*.fax \
		> $(builddir)/$*.tmp
	mv  $(builddir)/$*.tmp  $(builddir)/$*.out

%.cavp: %.out
	diff -u $(builddir)/$*.fax $(builddir)/$*.out
	touch $(builddir)/$*.cavp

clean: clean.cavp
clean.cavp:
	rm -f $(builddir)/*.cavp
	rm -f $(builddir)/*.fax
	rm -f $(builddir)/*.fax.bz2
	rm -f $(builddir)/*.out
	rm -f $(builddir)/*.tmp
