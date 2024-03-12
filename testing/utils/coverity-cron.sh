#!/bin/bash

# coverity-cron.sh: a wrapper script to automize Coverity scan build and upload for analysis
# Dependencies:
# 0. a registered user account at Coverity's self-build server
# 1. local copy cov-build tools Download it from Coverity website.
# 2. https://github.com/antonyantony/coverity-submit to automize scan and upload
# 2.1 config file /home/build/.coverity-submit with credentials
# [ALL]
# name: Antony Antony
# userid: antonyantony
# email: antony@phenome.org
# tools: /home/build/git/cov-analysis-linux64-2021.12.1/bin/

# [libreswan]
# token: 000000000000000
# prebuild: make distclean
# build: make base
# postbuild:
# tools: /home/build/tmp/cov-analysis-linux64-2017.07/bin
# 3. Results are at
# - https://scan.coverity.com/projects/antonyantony-libreswan/view_defects

set -eu

GIT_DIR="${GIT_DIR:-/home/build/git/libreswan-coverity}"
COV_ANALYSIS_PATHS="${COV_ANALYSIS_PATHS:-'/home/build/bin:/home/build/git/cov-analysis-linux64-2021.12.1/bin'}"
COV_SUBMIT="${COV_SUBMIT:-/home/build/git/coverity-submit/coverity-submit}"
COV_LOG="${COV_LOG:-/var/tmp/libreswan-coverity-all.txt}"
#GIT repository
FETCH_REMOTE="${FETCH_REMOTE:-yes}"
GIT_BRANCH="${GIT_BRANCH:-main}"
GIT_REMOTE="${GIT_REMOTE:-origin}"

cd ${GIT_DIR}
if [ "${FETCH_REMOTE}" = "yes" ]; then
	git fetch ${GIT_REMOTE}
	git reset --hard ${GIT_REMOTE}/${GIT_BRANCH}
	git checkout ${GIT_BRANCH}
fi

V=$(make showversion)
D1=$(date "+%s")
D2=$(date )
echo  "${D1} ${D2} ${V}" >> /var/tmp/libreswan-coverity.txt
PATH="${COV_ANALYSIS_PATHS}:$PATH"
(${COV_SUBMIT} -b ${V} -t ${V} libreswan) 2>&1  >> ${COV_LOG}
