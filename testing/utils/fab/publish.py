# Publish test results as a web page
#
# Copyright (C) 2017 Andrew Cagney
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

import os
import re
import shutil
import functools
import copy
import gzip

from collections import defaultdict
from datetime import datetime
from datetime import time

from fab import jsonutil
from fab import stats
from fab import timing
from fab import argutil

JSON_RESULTS = []
JSON_SUMMARY = { }
JSON_STATUS = { }

def add_arguments(parser):
    group = parser.add_argument_group("publish arguments",
                                      "options for publishing the results as json")
    group.add_argument("--publish-results", metavar="DIRECTORY",
                       type=argutil.directory,
                       help="publish the results from the test run in %(metavar)s as json")
    group.add_argument("--publish-status", metavar="STATUS-FILE",
                       type=argutil.directory_file,
                       help="publish (with live updates) the status of the test run in %(metavar)s as json")
    group.add_argument("--publish-summary", metavar="SUMMARY-FILE",
                       type=argutil.directory_file,
                       help="publish a summary in %(metavar)s as json; default: DIRECTORY/summary.json")
    group.add_argument("--publish-hash", metavar="HASH",
                       help="hash code of the commit being tested; added to the summary")

def log_arguments(logger, args):
    logger.info("Publish arguments:")
    logger.info("  publish-results: '%s'", args.publish_results)
    logger.info("  publish-status: '%s'", args.publish_status)
    logger.info("  publish-summary: '%s'", args.publish_summary)
    logger.info("  publish-hash: '%s'", args.publish_hash)

    # sneak in some fields
    if not args.publish_results:
        return

    if args.publish_hash:
        JSON_SUMMARY["hash"] = args.publish_hash
    path = (args.publish_summary and os.path.dirname(args.publish_summary)
            or args.publish_results)
    if path:
        directory = os.path.basename(path)
        JSON_SUMMARY["directory"] = directory
        JSON_STATUS["directory"] = directory
    JSON_SUMMARY["start_time"] = datetime.now()
    JSON_STATUS["start_time"] = datetime.now()

def _add(counts, *keys):
    # fill in the missing keys.
    for key in keys[0:-1]:
        if not key in counts:
            counts[key] = {}
        counts = counts[key]
    key = keys[-1]
    if not key in counts:
        counts[key] = 0
    counts[key] = counts[key] + 1

def _mkdir_test(logger, args, result):
    dstdir = os.path.join(args.publish_results, result.test.name)
    try:
        os.mkdir(dstdir)
    except FileExistsError:
        logger.debug("directory %s already exists", dstdir)
    return dstdir

def _mkdir_test_output(logger, args, result):
    if not os.path.isdir(result.output_directory):
        return None
    outdir = os.path.join(_mkdir_test(logger, args, result), "OUTPUT")
    try:
        os.mkdir(outdir)
    except FileExistsError:
        logger.debug("directory %s already exists", outdir)
    return outdir

def _copy_new_file(src, dst, logger):
    if not os.path.isfile(src):
        logger.error("source file '%s' does not exist; we're confused", src)
        return
    if os.path.isdir(dst):
        logger.error("destination file '%s' is a directory; we're confused", dst)
        return
    # .samefile() only works when dst exists
    if os.path.isfile(dst) \
    and os.path.samefile(src, dst):
        return
    # heuristic to avoid re-copy; since mtime is being preserved
    # identical files should have identical mtimes (or that failed and
    # dst, as a copy, is newer).
    if os.path.isfile(dst) \
    and os.path.getsize(src) == os.path.getsize(dst) \
    and os.path.getmtime(src) <= os.path.getmtime(dst):
        return
    logger.info("copying '%s' to '%s'", src, dst)
    # copy file while preserving mtime et.al.
    shutil.copy2(src, dst)
    return

def test_files(logger, args, result):
    if not args.publish_results:
        return
    dstdir = _mkdir_test(logger, args, result)
    test = result.test
    ignore = re.compile(r"[~]$")
    for name in os.listdir(test.directory):
        if ignore.search(name):
            continue
        src = os.path.join(test.directory, name)
        dst = os.path.join(dstdir, name)
        _copy_new_file(src, dst, logger)
    return dstdir


def test_output_files(logger, args, result):
    if not args.publish_results:
        return
    # Only when there is an output directory does it need publishing.
    dstdir = _mkdir_test_output(logger, args, result)
    if not dstdir:
        return
    # copy plain text files
    text_name = re.compile(r"(\.txt|\.diff|^RESULT|\.json)$")
    log_name = re.compile(r"(\.log)$")
    for name in os.listdir(result.output_directory):
        # copy simple files
        src = os.path.join(result.output_directory, name)
        dst = os.path.join(dstdir, name)
        if text_name.search(name):
            _copy_new_file(src, dst, logger)
            continue
        # copy compressed files; gzip is used as that works with the
        # web's deflate?!?
        if log_name.search(name):
            dst_gz = dst + ".gz"
            # heuristic to avoid re-compression
            if os.path.isfile(dst) \
            and os.path.getmtime(src) < os.path.getmtime(dst_gz):
                continue
            logger.info("compressing '%s' to '%s'", src, dst_gz)
            with open(src, "rb") as f:
                data = f.read()
            with gzip.open(dst_gz, "wb") as f:
                f.write(data)
            continue


def json_result(logger, args, result):
    if not args.publish_results:
        return

    # accumulate results.json
    json = result.json()
    JSON_RESULTS.append(json)

    # accumulate summary.json
    _add(JSON_SUMMARY, "totals", result.test.kind, result.test.status, str(result))
    for issue in result.issues:
        for host in result.issues[issue]:
            # count the number of times it occurred
            _add(JSON_SUMMARY, "totals", result.test.kind, result.test.status, "issues", issue)


def json_results(logger, args):
    if not args.publish_results:
        return
    path = os.path.join(args.publish_results, "results.json")
    logger.info("writing results to '%s'", path)
    with open(path, "w") as output:
        jsonutil.dump(JSON_RESULTS, output)
        output.write("\n")


def json_summary(logger, args):
    if not args.publish_results:
        return

    # update totals and stop time
    JSON_SUMMARY["total"] = len(JSON_RESULTS)
    JSON_SUMMARY["current_time"] = datetime.now()

    # emit
    path = (args.publish_summary and args.publish_summary
            or os.path.join(args.publish_results, "summary.json"))
    logger.info("writing summary to '%s'", path)
    with open(path, "w") as output:
        jsonutil.dump(JSON_SUMMARY, output)
        output.write("\n")


def testlist(logger, args):
    if not args.publish_results:
        return
    path = os.path.join(args.publish_results, "TESTLIST")
    logger.info("writing TESTLIST to '%s'", path)
    with open(path, "w") as output:
        for result in JSON_RESULTS:
            output.write("%s %s %s\n" % (result["test_kind"], result["test_name"], result["test_status"]))


def json_status(logger, args, details):
    if not args.publish_status:
        return
    JSON_STATUS["current_time"] = datetime.now()
    JSON_STATUS["details"] = details
    with open(args.publish_status, "w") as output:
        jsonutil.dump(JSON_STATUS, output)
        output.write("\n")


def everything(logger, args, result):
    test_files(logger, args, result)
    test_output_files(logger, args, result)
    json_result(logger, args, result)
    json_results(logger, args)
    json_summary(logger, args)
    testlist(logger, args)
