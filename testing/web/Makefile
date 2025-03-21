# WEB make targets, for Libreswan
#
# Copyright (C) 2017-2024 Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

include ../../mk/dirs.mk
include ../../mk/config.mk
include ../../mk/testing.mk

WEB_RUTDIR ?= $(TESTING_RUTDIR)
WEB_SUMMARYDIR ?= $(TESTING_WEBDIR)
WEB_HASH ?= $(TESTING_HASH)
WEB_RESULTSDIR ?= $(TESTING_WEBDIR)/$(TESTING_RUNDIR)
WEB_SUBDIR ?= $(TESTING_RUNDIR)

KVM_UTILSDIR = $(abs_top_srcdir)/testing/utils

#
# Force the creation and/or update of the web pages
#

.PHONY: web
web: web-summarydir
web: web-resultsdir
web: web-resultdir

.PHONY: print-web-variable
print-web-variable:
	@echo "$(strip $($(VARIABLE)))"

.PHONY: web-publish
web-publish: web-summarydir
web-publish: web-resultsdir
	cd $(top_srcdir) && $(KVM_UTILSDIR)/kvmresults.py \
		--exit-ok \
		--quick \
		--test-kind '' \
		--test-status '' \
		--publish-summary $(WEB_RESULTSDIR)/summary.json \
		--publish-status $(WEB_SUMMARYDIR)/status.json \
		--publish-results $(WEB_RESULTSDIR) \
		--publish-hash $(WEB_HASH) \
		--publish-result-html $(abs_srcdir)/result.html \
		$(if $(PUBLISH_SOURCE_URL), --publish-source-url $(PUBLISH_SOURCE_URL)) \
		testing/pluto

%/:
	mkdir $*

#
# Build or update the web pages ready for a new test run
#
# For the results directory, just install the HTML / javascript files
# (kvmrunner.py will fill in all the json files).  For the summary
# directory, do a full update so that all the previous runs are
# included.

.PHONY: web-test-prep
web-test-prep: web-resultsdir
web-test-prep: web-summarydir

#
# Create or update just the summary web page.
#
# This is a cheap short-cut that, unlike "web", doesn't update the
# sub-directory's html.
#

.PHONY: web-summarydir
web-summarydir: $(WEB_SUMMARYDIR)/commits.json
web-summarydir: $(WEB_SUMMARYDIR)/tsconfig.json
web-summarydir: $(WEB_SUMMARYDIR)/index.html
web-summarydir: $(addprefix $(WEB_SUMMARYDIR)/, $(wildcard *.css))
web-summarydir: $(WEB_SUMMARYDIR)/favicon.ico
web-summarydir: $(WEB_SUMMARYDIR)/summaries.json

$(WEB_SUMMARYDIR)/index.html: summary.html | $(WEB_SUMMARYDIR)/
	cp $< $@

$(WEB_SUMMARYDIR)/%.css: %.css | $(WEB_SUMMARYDIR)/
	cp $< $@

$(WEB_SUMMARYDIR)/favicon.ico: favicon.ico | $(WEB_SUMMARYDIR)/
	cp $< $@

# Update the pooled summary (summaries.json) of all the test runs

$(WEB_SUMMARYDIR)/summaries.json: \
			$(wildcard $(WEB_SUMMARYDIR)/*/summary.json) \
			json-summaries.sh \
			| $(WEB_SUMMARYDIR)/
	: use find: can be too many files for glob
	: use -H: handle WEB_SUMMARYDIR being a softlink
	: use -maxdepth 2: no need to go below WEB_SUMMARYDIR/*/*/
	find -H $(WEB_SUMMARYDIR) \
		-maxdepth 2 \
		-type f \
		-name summary.json \
		-print \
	| ./json-summaries.sh $(WEB_RUTDIR) - > $@.tmp
	mv $@.tmp $@

# fudge dependency by using */summary.json
$(WEB_SUMMARYDIR)/commits.json: \
			$(wildcard $(WEB_SUMMARYDIR)/*/summary.json) \
			gime-json-commits.sh \
			gime-first-run-hash.sh \
			| $(WEB_SUMMARYDIR)/
	: pick up all commits unconditionally and topo sorted
	./gime-json-commits.sh ${WEB_SUMMARYDIR} ${WEB_RUTDIR} \
		$(shell set -x ; ./gime-first-run-hash.sh $(WEB_SUMMARYDIR) $(WEB_RUTDIR)) \
		| jq -s > $@.tmp
	mv $@.tmp $@


#
# Create or update a test run's results page.
#

WEB_RESULTS_INDEX = $(sort $(WEB_RESULTSDIR)/index.html $(wildcard $(WEB_SUMMARYDIR)/*/index.html))

.PHONY: web-resultsdir
web-resultsdir: $(WEB_RESULTS_INDEX)

$(WEB_RESULTS_INDEX): \
$(WEB_SUMMARYDIR)/%/index.html: results.html \
		| $(WEB_SUMMARYDIR)/ $(WEB_SUMMARYDIR)/%/
	cp $? $(WEB_SUMMARYDIR)/$*
	mv $(WEB_SUMMARYDIR)/$*/results.html $(WEB_SUMMARYDIR)/$*/index.html

#
# generate json
#

web-results-json: $(WEB_RESULTSDIR)/results.json
web-results-json: $(WEB_RESULTSDIR)/summary.json


#
# Update the html in all the result directories
#
# Not part of web-summarydir, web-resultsdir or web-results-html

WEB_RESULTS_HTML = $(wildcard $(WEB_SUMMARYDIR)/*-g*/results.html)
web-site: $(WEB_RESULTS_HTML)

#
# Conditional rules for building an individual test run's results
# page.  Requires WEB_SUMMARYDIR or WEB_RESULTSDIR.
#

$(WEB_RESULTSDIR)/summary.json: | $(WEB_RESULTSDIR)
	cd $(top_srcdir) && $(KVM_UTILSDIR)/kvmresults.py \
		--exit-ok \
		--quick \
		--test-kind '' \
		--test-status '' \
		--publish-summary $@.tmp \
		--publish-status $(WEB_SUMMARYDIR)/status.json \
		--publish-results $(WEB_RESULTSDIR) \
		--publish-hash $(WEB_HASH) \
		testing/pluto
	mv $@.tmp $@

#
# hack to compile json code
#

%/tsconfig.json: tsconfig.json.in $(wildcard *.js *.tc) | %/
	sed \
		-e 's;@@DEST_DIR@@;$(realpath $(dir $@));' \
		-e 's;@@SOURCE_DIR@@;$(abs_srcdir);'\
		tsconfig.json.in \
		> $@.tmp
	tsc --project $@.tmp
	mv $@.tmp $@


.PHONY: web-resultdir
WEB_RESULT_INDEX += $(wildcard $(WEB_SUMMARYDIR)/*/*/index.html)
web-resultdir: $(WEB_RESULT_INDEX)

$(WEB_RESULT_INDEX): \
$(WEB_SUMMARYDIR)/%/index.html: result.html
	cp result.html $(WEB_SUMMARYDIR)/$*/index.html
