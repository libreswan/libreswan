# WEB make targets, for Libreswan
#
# Copyright (C) 2017 Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

#
# If enabled WEB_SUMMARYDIR, or WEB_RESULTSDIR is is set), publish the
# results in HTML/json form.
#
# The variable must be explicitly set via Makefile.inc.local, from the
# command line, or from the environment.  Otherwise rules that invoke
# "git" (for instance any rule requiring a definition of
# $(WEB_RESULTSDIR)) are enabled.

LSW_WEBDIR ?= $(top_srcdir)/RESULTS

WEB_UTILSDIR = testing/utils
WEB_SOURCEDIR = testing/web
WEB_REPODIR ?= .

ifndef WEB_SUMMARYDIR
WEB_SUMMARYDIR := $(if $(wildcard $(LSW_WEBDIR)),$(LSW_WEBDIR))
endif
# This is verbose so it being invoked is easy to spot
WEB_SUBDIR ?= $(shell set -x ; $(WEB_SOURCEDIR)/gime-git-description.sh $(WEB_REPODIR))
ifndef WEB_RESULTSDIR
WEB_RESULTSDIR := $(if $(WEB_SUMMARYDIR),$(WEB_SUMMARYDIR)/$(WEB_SUBDIR))
endif

#
# Rules for building web pages during test runs.
#

.PHONY: web-test-prep web-page web

ifeq ($(wildcard $(LSW_WEBDIR)),)
web-test-prep:
else
web-test-prep: web-resultsdir web-summarydir
endif

# this invokes $(WEB_SUBDIR) a lot; easier to ignore than fix
web web-page: | $(LSW_WEBDIR)
	$(MAKE) web-summarydir \
		WEB_SUMMARYDIR=$(LSW_WEBDIR) WEB_RESULTSDIR=$(LSW_WEBDIR)/$(WEB_SUBDIR)
	$(MAKE) web-resultsdir \
		WEB_SUMMARYDIR=$(LSW_WEBDIR) WEB_RESULTSDIR=$(LSW_WEBDIR)/$(WEB_SUBDIR)
	$(WEB_UTILSDIR)/kvmresults.py \
		--quick \
		--test-kind '' \
		--test-status '' \
		--publish-status $(LSW_WEBDIR)/status.json \
		--publish-results $(LSW_WEBDIR)/$(WEB_SUBDIR) \
		testing/pluto

$(LSW_WEBDIR):
	mkdir $(LSW_WEBDIR)

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
# Conditional rules for building the summary web page.  Requires
# WEB_SUMMARYDIR.
#

ifneq ($(WEB_SUMMARYDIR),)

WEB_SOURCES = $(wildcard $(addprefix $(WEB_SOURCEDIR)/, *.css *.js *.html))
# XXX: should this be evaluated once?
WEB_TIME := $(shell $(WEB_SOURCEDIR)/now.sh)

#
# Update the summary html pages
#

.PHONY: web-summary-html
web-site web-summarydir web-summary-html: $(WEB_SUMMARYDIR)/summary.html
$(WEB_SUMMARYDIR)/summary.html: $(WEB_SOURCES) | $(WEB_SUMMARYDIR)
	: WEB_SUMMARYDIR=$(WEB_SUMMARYDIR)
	: WEB_SOURCES=$(WEB_SOURCES)
	cp $(filter-out $(WEB_SOURCEDIR)/summary.html, $(WEB_SOURCES)) $(WEB_SUMMARYDIR)
	cp $(WEB_SOURCEDIR)/summary.html $(WEB_SUMMARYDIR)/index.html
	cp $(WEB_SOURCEDIR)/summary.html $(WEB_SUMMARYDIR)/summary.html

#
# Update the pooled summaries from all the test runs
#

.PHONY: web-summaries-json
web-site web-summarydir web-summaries-json: $(WEB_SUMMARYDIR)/summaries.json
$(WEB_SUMMARYDIR)/summaries.json: $(wildcard $(WEB_SUMMARYDIR)/*-g*/summary.json) $(WEB_SOURCEDIR)/json-summaries.sh
	$(WEB_SOURCEDIR)/json-summaries.sh \
		$(wildcard $(WEB_SUMMARYDIR)/*-g*/summary.json) \
		> $@.tmp
	mv $@.tmp $@

#
# update the status.json
#
# no dependencies, just ensure it exists.

.PHONY: web-status-json
web-site web-summarydir web-status-json: $(WEB_SUMMARYDIR)/status.json
$(WEB_SUMMARYDIR)/status.json:
	$(WEB_SOURCEDIR)/json-status.sh "initialized" > $@.tmp
	mv $@.tmp $@

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
# To avoid lots of '... is up to date', the recursive make is silent.
#
# In theory, all the .json files needing an update can be processed
# using a single make invocation.  Unfortunately the list can get so
# long that it exceeds command line length limits, so a slow pipe is
# used instead.

WEB_COMMITSDIR = $(WEB_SUMMARYDIR)/commits
FIRST_COMMIT = $(shell $(WEB_SOURCEDIR)/earliest-commit.sh $(WEB_SUMMARYDIR) $(WEB_REPODIR))
# MISSING_COMMIT_FILES = $(filter-out $(wildcard $(WEB_COMMITSDIR)/*.json), $(COMMIT_FILES))

.PHONY: web-commits-json $(WEB_SUMMARYDIR)/commits.json
web-site web-summarydir web-commits-json: $(WEB_SUMMARYDIR)/commits.json
$(WEB_SUMMARYDIR)/commits.json:
	: use a pipe to avoid to-long-line when rebuilding out-of-date commits
	: use shell variables to avoid re-evaluation
	set -e ; \
	web_sourcedir=$(WEB_SOURCEDIR) ; \
	web_repodir=$(WEB_REPODIR) ; \
	web_summarydir=$(WEB_SUMMARYDIR) ; \
	web_resultsdir=$(WEB_RESULTSDIR) ; \
	web_commitsdir=$(WEB_COMMITSDIR) ; \
	web_subdir=$(WEB_SUBDIR) ; \
	first_commit=$(FIRST_COMMIT) ; \
	$(MAKE) $${web_commitsdir} \
		WEB_SUBDIR=$${web_subdir} \
		WEB_SUMMARYDIR=$${web_summarydir} \
		WEB_RESULTSDIR=$${web_resultsdir} \
		; \
	( cd $${web_repodir} ; git rev-list --abbrev-commit $${first_commit}^..) \
	| while read commit ; do \
		echo $${web_commitsdir}/$${commit}.json ; \
		$(MAKE) --no-print-directory -s \
			WEB_SUBDIR=$${web_subdir} \
			WEB_SUMMARYDIR=$${web_summarydir} \
			WEB_RESULTSDIR=$${web_resultsdir} \
			$${web_commitsdir}/$${commit}.json ; \
	done ; \
	: pick up all commits unconditionally and unsorted. ; \
	find $${web_commitsdir} -name '*.json' \
		| xargs --no-run-if-empty cat \
		| jq -s . > $@.tmp
	mv $@.tmp $@

$(WEB_COMMITSDIR)/%.json: $(WEB_SOURCEDIR)/json-commit.sh | $(WEB_COMMITSDIR)
	$(WEB_SOURCEDIR)/json-commit.sh $* $(WEB_REPODIR) > $@.tmp
	mv $@.tmp $@

$(WEB_COMMITSDIR):
	mkdir $(WEB_COMMITSDIR)


#
# update the html in all the result directories
#
# Not part of web-summarydir

WEB_RESULTS_HTML = $(wildcard $(WEB_SUMMARYDIR)/*-g*/results.html)
.PHONY: web-results-html
web-site web-results-html: $(WEB_RESULTS_HTML)

$(WEB_SUMMARYDIR)/%/results.html: $(WEB_SOURCES)
	$(MAKE) web-resultsdir \
		WEB_SUMMARYDIR=$(WEB_SUMMARYDIR) WEB_RESULTSDIR=$(dir $@)

endif

#
# Conditional rules for building an individual test run's results
# page.  Requires WEB_SUMMARYDIR or WEB_RESULTSDIR.
#


ifneq  ($(WEB_RESULTSDIR),)

.PHONY: web-resultsdir
web-resultsdir: $(WEB_RESULTSDIR)/results.html $(WEB_RESULTSDIR)/summary.json

$(WEB_RESULTSDIR)/results.html: $(WEB_SOURCES) | $(WEB_RESULTSDIR)
	: WEB_RESULTSDIR=$(WEB_RESULTSDIR)
	: WEB_SOURCES=$(WEB_SOURCES)
	cp $(filter-out $(WEB_SOURCEDIR)/results.html, $(WEB_SOURCES)) $(WEB_RESULTSDIR)
	cp $(WEB_SOURCEDIR)/results.html $(WEB_RESULTSDIR)/index.html
	cp $(WEB_SOURCEDIR)/results.html $(WEB_RESULTSDIR)/results.html

# a stub

$(WEB_RESULTSDIR)/summary.json: | $(WEB_RESULTSDIR)
	$(WEB_SOURCEDIR)/json-summary.sh $(WEB_TIME) > $@.tmp
	mv $@.tmp $@

$(WEB_RESULTSDIR): | $(WEB_SUMMARYDIR)
	mkdir $(WEB_RESULTSDIR)

endif


#
# update the json in all the results directories; very slow so only
# enabled when WEB_SCRATCH_REPODIR is set.
#

ifneq ($(WEB_SUMMARYDIR),)
ifneq ($(WEB_SCRATCH_REPODIR),)
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
