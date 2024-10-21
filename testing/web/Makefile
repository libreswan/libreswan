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

KVM_WEBDIR ?= $(abs_top_srcdir)/RESULTS
KVM_RUTDIR ?= $(abs_top_srcdir)

WEB_SUMMARYDIR ?= $(KVM_WEBDIR)
WEB_UTILSDIR ?= $(abs_top_srcdir)/testing/utils
WEB_RUTDIR ?= $(KVM_RUTDIR)

# these are verbose so multiple invocations can be spotted
ifndef WEB_SUBDIR
WEB_SUBDIR ?= $(shell ./gime-git-description.sh $(WEB_RUTDIR))
endif
ifndef WEB_HASH
WEB_HASH := $(shell git -C $(WEB_RUTDIR) show --no-patch --format=%H HEAD)
endif
WEB_RESULTSDIR ?= $(WEB_SUMMARYDIR)/$(WEB_SUBDIR)
WEB_SOURCES ?= $(wildcard $(addprefix , *.css *.js *.html))
ifndef WEB_TIME
WEB_TIME := $(shell ./now.sh)
endif

#
# Force the creation and/or update of the web pages
#

.PHONY: web
web: | $(WEB_SUMMARYDIR)
	$(MAKE) web-summarydir
	$(MAKE) web-resultsdir
	$(MAKE) web-publish

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
web-test-prep: web-testsdir

.PHONY: web-test-post
web-test-post: web-tests-json

#
# Create or update just the summary web page.
#
# This is a cheap short-cut that, unlike "web", doesn't update the
# sub-directory's html.
#

.PHONY: web-summarydir
web-summarydir: $(WEB_SUMMARYDIR)/commits.json
web-summarydir: $(WEB_SUMMARYDIR)/index.html
web-summarydir: $(WEB_SUMMARYDIR)/lsw-summary-graph.css
web-summarydir: $(WEB_SUMMARYDIR)/lsw-table.css
web-summarydir: $(WEB_SUMMARYDIR)/summaries.json
web-summarydir: $(WEB_SUMMARYDIR)/summary.css
web-summarydir: $(WEB_SUMMARYDIR)/tsconfig.json
web-summarydir: $(WEB_SUMMARYDIR)/favicon.ico
web-summarydir: | $(WEB_SUMMARYDIR)/status.json

$(WEB_SUMMARYDIR)/index.html: summary.html | $(WEB_SUMMARYDIR)
	cp $< $@

$(WEB_SUMMARYDIR)/%.css: %.css | $(WEB_SUMMARYDIR)
	cp $< $@

$(WEB_SUMMARYDIR)/favicon.ico: favicon.ico | $(WEB_SUMMARYDIR)
	cp $< $@

$(WEB_SUMMARYDIR):
	mkdir $(WEB_SUMMARYDIR)

# no dependencies, just needs to exist
$(WEB_SUMMARYDIR)/status.json:
	./json-status.sh "initialized" > $@.tmp
	mv $@.tmp $@

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
WEB_COMMITSDIR = $(WEB_SUMMARYDIR)/commits
$(WEB_SUMMARYDIR)/commits.json: $(WEB_COMMITSDIR)/$(WEB_HASH).json $(wildcard $(WEB_COMMITSDIR)/*.json)
	: pick up all commits unconditionally and unsorted.
	find $(WEB_COMMITSDIR) -name '*.json' \
		| xargs --no-run-if-empty cat \
		| jq -s 'unique_by(.hash)' > $@.tmp
	mv $@.tmp $@

#
# Create or update a test run's results page.
#

.PHONY: web-resultsdir
web-resultsdir:

web-resultsdir: $(WEB_RESULTSDIR)/index.html
web-resultsdir: $(WEB_RESULTSDIR)/lsw-summary-graph.css
web-resultsdir: $(WEB_RESULTSDIR)/lsw-table.css
web-resultsdir: $(WEB_RESULTSDIR)/results.css
web-resultsdir: $(WEB_RESULTSDIR)/tsconfig.json
web-resultsdir: $(WEB_RESULTSDIR)/favicon.ico

web-results-json: $(WEB_RESULTSDIR)/results.json
web-results-json: $(WEB_RESULTSDIR)/summary.json

$(WEB_RESULTSDIR)/index.html: results.html | $(WEB_RESULTSDIR)
	cp $< $@

$(WEB_RESULTSDIR)/%.css: %.css | $(WEB_RESULTSDIR)
	cp $< $@

$(WEB_RESULTSDIR)/favicon.ico: favicon.ico | $(WEB_RESULTSDIR)
	cp $< $@

$(WEB_RESULTSDIR): | $(WEB_SUMMARYDIR)
	mkdir $(WEB_RESULTSDIR)

#
# Create the tests directory
#

web-testsdir: | $(WEB_TESTSDIR)
$(WEB_TESTSDIR):
	mkdir $@

.PHONY:
web-tests-json:
	./json-tests.sh $(WEB_RUTDIR) $(WEB_TESTSDIR) $(WEB_RESULTSDIR)

#
# Update the html in all the result directories
#
# Not part of web-summarydir, web-resultsdir or web-results-html

WEB_RESULTS_HTML = $(wildcard $(WEB_SUMMARYDIR)/*-g*/results.html)
web-site: $(WEB_RESULTS_HTML)

$(WEB_SUMMARYDIR)/%/results.html: $(WEB_SOURCES)
	$(MAKE) web-resultsdir \
		WEB_SUMMARYDIR=$(WEB_SUMMARYDIR) WEB_RESULTSDIR=$(dir $@)

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

%/tsconfig.json: tsconfig.json.in $(wildcard *.js *.tc) | %
	sed \
		-e 's;@@DEST_DIR@@;$(realpath $(dir $@));' \
		-e 's;@@SOURCE_DIR@@;$(abs_srcdir);'\
		tsconfig.json.in \
		> $@.tmp
	tsc --project $@.tmp
	mv $@.tmp $@

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

#
# Equivalent of help
#

define web-config

Web Configuration:

    The test results can be published as a web page using either of
    the make variables:

    $(call kvm-var-value,LSW_WEBDIR)
    $(call kvm-var-value,WEB_SUMMARYDIR)

        The top-level html directory containing a summary of all test
        runs.

	The results from individual test runs are stored under this
        directory.

    $(call kvm-var-value,WEB_SUBDIR)
    $(call kvm-var-value,WEB_RESULTSDIR)

        Sub-directory to store the current test run's results.

	By default, the test run's results are stored as the
	sub-directory $$(WEB_SUBDIR) under $$(WEB_SUMMARYDIR), and
	$$(WEB_SUBDIR) is formatted as TAG-OFFSET-gREV-BRANCH using
	information from $$(WEB_RUTDIR)'s current commit (see also
	`git describe --long`).

    $(call kvm-var-value,WEB_RUTDIR)

        The git repository to use when constructing the web pages (for
        instance the list of commits).

	By default, the current directory is used.

Internal targets:

    web-site:

        update the web site

    web-results-json:

        update the results.json in all the test run sub-directories
        under $$(WEB_SUMMARYDIR)

	very slow

	requires $$(WEB_SCRATCH_REPODIR) set and pointing at a
	dedicated git repository

Web targets:

    web-summarydir:

	build or update the top-level summary web page under
	$$(WEB_SUMMARYDIR) (the test run sub-directories are not
	updated, see above).

    web-resultsdir:

        build or update $$(WEB_RESULTSDIR)

    web-commitsdir:

        build or update both $$(WEB_COMMITSDIR) and
	$$(WEB_SUMMARYDIR)/commits.json

    web-page:

        build or update the web page in $(LSW_WEBDIR) including the
        results from the most recent test run

endef

.PHONY: web-config web-help
web-config web-help:
	$(info $(web-config))
