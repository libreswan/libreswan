# WEB make targets, for Libreswan
#
# Copyright (C) 2017-2018 Andrew Cagney
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

# If the $(LSW_WEBDIR) directory exists, publish the results in
# HTML/json form.
#
# Because web-page dependencies are very heavy (invoking git et.al.)
# much of this code needs to be made conditional.

LSW_WEBDIR ?= $(top_srcdir)/RESULTS
WEB_SUMMARYDIR ?= $(LSW_WEBDIR)
ifneq ($(wildcard $(WEB_SUMMARYDIR)),)
WEB_ENABLED ?= true
endif

WEB_UTILSDIR ?= testing/utils
WEB_SOURCEDIR ?= testing/web
WEB_REPODIR ?= .
# these are verbose so multiple invocations can be spotted
WEB_SUBDIR ?= $(shell set -x ; $(WEB_SOURCEDIR)/gime-git-description.sh $(WEB_REPODIR))

# shortcuts to use when web is enabled, set up to evaluate once as
# they can be a little expensive.  These make variable can only be
# used inside of WEB_ENABLED blocks.

ifdef WEB_ENABLED
ifndef WEB_HASH
WEB_HASH := $(shell set -x ; cd $(WEB_REPODIR) ; git show --no-patch --format=%H HEAD)
endif
ifndef WEB_RESULTSDIR
WEB_RESULTSDIR := $(WEB_SUMMARYDIR)/$(WEB_SUBDIR)
endif
ifndef WEB_SOURCES
WEB_SOURCES := $(wildcard $(addprefix $(WEB_SOURCEDIR)/, *.css *.js *.html))
endif
ifndef WEB_TIME
WEB_TIME := $(shell $(WEB_SOURCEDIR)/now.sh)
endif
endif

#
# Force the creation and/or update of the web pages
#
# Since $(WEB_SUMMARYDIR) (aka $(LSW_WEBDIR)) is created (via a
# dependency) before invoking the sub-$(MAKE), the sub-$(MAKE) will
# always see a configuration where web pages are enabled.
#
# Order matters: the results directory is created first so that so
# that the web-summarydir will pick up its contents.

web web-page: | $(WEB_SUMMARYDIR)
	$(MAKE) web-resultsdir web-summarydir

$(WEB_SUMMARYDIR):
	mkdir $(WEB_SUMMARYDIR)

#
# Build or update the web pages ready for a new test run
#
# For the results directory, just install the HTML / javascript files
# (kvmrunner.py will fill in all the json files).  For the summary
# directory, do a full update so that all the previous runs are
# included.

.PHONY: web-test-prep web-page web
web-test-prep:
ifdef WEB_ENABLED
web-test-prep: web-results-html web-summarydir
endif

#
# Update the web site
#
# Well almost everything, result .json files are not updated by
# default - very slow.
#

.PHONY: web-site
web-site:

#
# Create or update just the summary web page.
#
# This is a cheap short-cut that, unlike "web", doesn't update the
# sub-directory's html.
#

.PHONY: web-summarydir
web-summarydir:

#
# Create or update a test run's results page.
#

.PHONY: web-resultsdir
web-resultsdir:

#
# Create or update just the summary web page.
#
# This is a cheap short-cut that, unlike "web", doesn't update the
# sub-directory's html.
#

ifdef WEB_ENABLED

.PHONY: web-summary-html
web-site web-summarydir: web-summary-html
web-summary-html: $(WEB_SUMMARYDIR)/index.html
$(WEB_SUMMARYDIR)/index.html: $(WEB_SOURCES) | $(WEB_SUMMARYDIR)
	cp $(WEB_SOURCES) $(WEB_SUMMARYDIR)
	cp $(WEB_SOURCEDIR)/summary.html $(WEB_SUMMARYDIR)/index.html

endif

#
# Update the pooled summaries from all the test runs
#

ifdef WEB_ENABLED

.PHONY: web-summaries-json
web-site web-summarydir web-summaries-json: $(WEB_SUMMARYDIR)/summaries.json
$(WEB_SUMMARYDIR)/summaries.json: $(wildcard $(WEB_SUMMARYDIR)/*-g*/summary.json) $(WEB_SOURCEDIR)/json-summaries.sh
	find $(WEB_SUMMARYDIR) \
		\( -type f -name summary.json -print \) \
		-o \( -type d -path '$(WEB_SUMMARYDIR)/*/*' -prune \) \
	| $(WEB_SOURCEDIR)/json-summaries.sh $(WEB_REPODIR) - > $@.tmp
	mv $@.tmp $@

endif

#
# update the status.json
#
# no dependencies, just ensure it exists.

ifdef WEB_ENABLED

.PHONY: web-status-json
web-site web-summarydir web-status-json: $(WEB_SUMMARYDIR)/status.json
$(WEB_SUMMARYDIR)/status.json:
	$(WEB_SOURCEDIR)/json-status.sh "initialized" > $@.tmp
	mv $@.tmp $@

endif

#
# Update the commits.json database
#
# Since identifying all commits.json's dependencies is expensive - it
# depends on parsing WEB_SUMMARYDIR and WEB_REPODIR - it is
# implemented as a recursive make target - that way the computation is
# only done when needed.
#
# Should the generation script be modified then this will trigger a
# rebuild of all relevant commits.
#
# In theory, all the .json files needing an update can be processed
# using a single make invocation.  Unfortunately the list can get so
# long that it exceeds command line length limits, so a slow pipe is
# used instead.

ifdef WEB_ENABLED

WEB_COMMITSDIR = $(WEB_SUMMARYDIR)/commits
FIRST_COMMIT = $(shell $(WEB_SOURCEDIR)/earliest-commit.sh $(WEB_SUMMARYDIR) $(WEB_REPODIR))

.PHONY: web-commits-json $(WEB_SUMMARYDIR)/commits.json
web-site web-summarydir web-commits-json: $(WEB_SUMMARYDIR)/commits.json
$(WEB_SUMMARYDIR)/commits.json: web-commitsdir
	: pick up all commits unconditionally and unsorted.
	find $(WEB_COMMITSDIR) -name '*.json' \
		| xargs --no-run-if-empty cat \
		| jq -s 'unique_by(.hash)' > $@.tmp
	mv $@.tmp $@

.PHONY: web-commitsdir
web-commitsdir: | $(WEB_COMMITSDIR)
	: -s suppresses the sub-make message ... is up to date
	: watch out for the sub-make re-valuating make variables
	( cd $(WEB_REPODIR) && git rev-list $(FIRST_COMMIT)^.. ) \
	| awk '{print "$(WEB_COMMITSDIR)/" $$1 ".json"}' \
	| xargs --no-run-if-empty \
		$(MAKE) --no-print-directory -s

$(WEB_COMMITSDIR)/%.json: $(WEB_SOURCEDIR)/json-commit.sh | $(WEB_COMMITSDIR)
	echo $@
	$(WEB_SOURCEDIR)/json-commit.sh $* $(WEB_REPODIR) > $@.tmp
	mv $@.tmp $@

$(WEB_COMMITSDIR):
	mkdir $(WEB_COMMITSDIR)

endif

#
# Update the html in all the result directories
#
# Not part of web-summarydir, web-resultsdir or web-results-html

ifdef WEB_ENABLED

WEB_RESULTS_HTML = $(wildcard $(WEB_SUMMARYDIR)/*-g*/results.html)
web-site: $(WEB_RESULTS_HTML)

$(WEB_SUMMARYDIR)/%/results.html: $(WEB_SOURCES)
	$(MAKE) web-resultsdir \
		WEB_SUMMARYDIR=$(WEB_SUMMARYDIR) WEB_RESULTSDIR=$(dir $@)

endif

#
# Conditional rules for building an individual test run's results
# page.  Requires WEB_SUMMARYDIR or WEB_RESULTSDIR.
#

ifdef WEB_ENABLED

.PHONY: web-resultsdir web-results-html web-results-json
web-resultsdir: web-results-html web-results-json
web-results-html: $(WEB_RESULTSDIR)/index.html
web-results-json: $(WEB_RESULTSDIR)/summary.json

$(WEB_RESULTSDIR)/index.html: $(WEB_SOURCES) | $(WEB_RESULTSDIR)
	cp $(WEB_SOURCES) $(WEB_RESULTSDIR)
	cp $(WEB_SOURCEDIR)/results.html $(WEB_RESULTSDIR)/index.html

$(WEB_RESULTSDIR)/summary.json: | $(WEB_RESULTSDIR)
	$(WEB_UTILSDIR)/kvmresults.py \
		--quick \
		--test-kind '' \
		--test-status '' \
		--publish-summary $@.tmp \
		--publish-status $(WEB_SUMMARYDIR)/status.json \
		--publish-results $(WEB_RESULTSDIR) \
		--publish-hash $(WEB_HASH) \
		testing/pluto
	mv $@.tmp $@

$(WEB_RESULTSDIR): | $(WEB_SUMMARYDIR)
	mkdir $(WEB_RESULTSDIR)

endif

#
# update the json in all the results directories; very slow so only
# enabled when WEB_SCRATCH_REPODIR is set and things are not pointing
# at this directory.
#

ifdef WEB_ENABLED
ifdef WEB_SCRATCH_REPODIR
ifneq ($(abspath $(WEB_SCRATCH_REPODIR)),$(abspath .))

.PHONY: web-results-json
web-site web-results-json: $(sort $(wildcard $(WEB_SUMMARYDIR)/*-g*/results.json))

$(WEB_SUMMARYDIR)/%/results.json: $(WEB_UTILSDIR)/kvmresults.py $(WEB_UTILSDIR)/fab/*.py
	$(WEB_SOURCEDIR)/json-results.sh $(WEB_SCRATCH_REPODIR) $(dir $@)

endif
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
	information from $$(WEB_REPODIR)'s current commit (see also
	`git describe --long`).

    $(call kvm-var-value,WEB_REPODIR)

        The git repository to use when constructing the web pages (for
        instance the list of commits).

	By default, the current directory is used.

Internal targets:

    web-site:

        update the web site

    web-results-html:

        update the HTML files in all the test run sub-directories
	under $$(WEB_SUMMARYDIR)

    web-commits-json:

        update the commits.json file in $$(WEB_SUMMARYDIR)

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

    web-page:

        build or update the web page in $(LSW_WEBDIR) including the
        results from the most recent test run

endef

.PHONY: web-config web-help
web-config web-help:
	$(info $(web-config))
