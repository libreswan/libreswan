
HTMLDIR=/var/www/html/results

.PHONY: install
install: | $(HTMLDIR)
	cd ../.. && make WEB_SUMMARYDIR=$(HTMLDIR) web

# Grab a small sample of the test results.
#
# Since interesting logs are all compressed any plain logs can be
# excluded.

fetch $(HTMLDIR):
	: grab all the top-level files
	rsync -i --copy-links --exclude '*/' \
		'testing.libreswan.org:results/*' \
		$(HTMLDIR)
	: grab a couple directories
	ssh testing.libreswan.org 'ls -d results/v3*/' \
		| cut -d/ -f2 \
		| tail -5 | head -4 \
		| tee /dev/stderr \
		| rsync -a -i --files-from - --recursive \
		  testing.libreswan.org:results/ \
		  $(HTMLDIR)
