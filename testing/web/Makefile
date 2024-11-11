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

KVM_RUTDIR ?= $(abs_top_srcdir)
WEB_RUTDIR ?= $(KVM_RUTDIR)

KVM_WEBDIR ?= $(abs_top_srcdir)/RESULTS
WEB_SUMMARYDIR ?= $(KVM_WEBDIR)

WEB_MAKEDIR ?= $(srcdir)
WEB_UTILSDIR ?= $(abs_top_srcdir)/testing/utils

WEB_BRANCH_NAME ?= $(shell git -C $(WEB_RUTDIR) describe --abbrev=0)
WEB_BRANCH_TAG ?= $(WEB_BRANCH_NAME)

WEB_HASH ?= $(shell git -C $(WEB_RUTDIR) show --no-patch --format=%H HEAD)
WEB_ABBREV_HASH = $(shell git -C $(WEB_RUTDIR) show --no-patch --format="%h" $(WEB_HASH))
WEB_BRANCH_COUNT = $(shell git -C $(WEB_RUTDIR) rev-list --count $(WEB_BRANCH_TAG)..$(WEB_HASH))
WEB_SUBDIR = $(WEB_BRANCH_NAME)-$(WEB_BRANCH_COUNT)-g$(WEB_ABBREV_HASH)

WEB_RESULTSDIR ?= $(WEB_SUMMARYDIR)/$(WEB_SUBDIR)

#
# Force the creation and/or update of the web pages
#

.PHONY: web
web: | $(WEB_SUMMARYDIR)/
	$(MAKE) web-summarydir
	$(MAKE) web-resultsdir
	$(MAKE) web-resultdir

.PHONY: print-web-variable
print-web-variable:
	@echo "$(strip $($(VARIABLE)))"

.PHONY: web-publish
web-publish: | $(WEB_RESULTSDIR)
	cd $(top_srcdir) && $(WEB_UTILSDIR)/kvmresults.py \
		--exit-ok \
		--quick \
		--test-kind '' \
		--test-status '' \
		--publish-summary $(WEB_RESULTSDIR)/summary.json \
		--publish-status $(WEB_SUMMARYDIR)/status.json \
		--publish-results $(WEB_RESULTSDIR) \
		--publish-hash $(WEB_HASH) \
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
			json-summaries.sh
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
			gime-first-run-hash.sh
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
		| $(WEB_SUMMARYDIR)/%/
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
	cd $(top_srcdir) && $(WEB_UTILSDIR)/kvmresults.py \
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

#
# update the json in all the results directories; very slow so only
# enabled when WEB_SCRATCH_REPODIR is set and things are not pointing
# at this directory.
#

ifdef WEB_SCRATCH_REPODIR
ifneq ($(abspath $(WEB_SCRATCH_REPODIR)),$(abspath .))

.PHONY: web-results-json
web-site web-results-json: $(sort $(wildcard $(WEB_SUMMARYDIR)/*-g*/results.json))

$(WEB_SUMMARYDIR)/%/results.json: $(WEB_UTILSDIR)/kvmresults.py $(WEB_UTILSDIR)/fab/*.py
	./json-results.sh $(WEB_SCRATCH_REPODIR) $(dir $@)

endif
endif

ifdef WEB_RESULTSDIR
$(WEB_RESULTSDIR)/%/index.html: result.html \
		| $(WEB_RESULTSDIR)/%/
	cp $? $(WEB_RESULTSDIR)/$*
	mv $(WEB_RESULTSDIR)/$*/result.html $(WEB_RESULTSDIR)/$*/index.html
endif
