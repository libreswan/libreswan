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

from fab import printer
from fab import jsonutil
from fab import stats
from fab import timing
from fab import argutil

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


results_to_print = printer.Print(printer.Print.test_name,
                                 printer.Print.test_kind,
                                 printer.Print.test_status,
                                 printer.Print.test_host_names,
                                 printer.Print.start_time,
                                 printer.Print.stop_time,
                                 printer.Print.result,
                                 printer.Print.issues,
                                 printer.Print.runtime,
                                 printer.Print.boot_time,
                                 printer.Print.script_time)

JSON_RESULTS = []
JSON_SUMMARY = { }

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

def _update_time(compare, key, result):
    result_time = result.get(key)
    summary_time = JSON_SUMMARY.get(key)
    if summary_time and result_time:
        JSON_SUMMARY[key] = compare(summary_time, result_time)
    elif result_time:
        JSON_SUMMARY[key] = result_time

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
        if not os.path.isfile(src):
            continue
        if os.path.isfile(dst) and os.path.samefile(src, dst):
            continue
        if os.path.isfile(dst) \
        and os.path.getsize(src) == os.path.getsize(dst) \
        and os.path.getmtime(src) < os.path.getmtime(dst):
            continue
        logger.info("copying '%s' to '%s'", src, dst)
        shutil.copyfile(src, dst)
    return dstdir


def test_output_files(logger, args, result):
    if not args.publish_results:
        return
    # Only when there is an output directory does it need publishing.
    dstdir = _mkdir_test_output(logger, args, result)
    if not dstdir:
        return
    # copy plain text files
    good = re.compile(r"(\.txt|\.diff|^RESULT)$")
    log = re.compile(r"(\.log)$")
    for name in os.listdir(result.output_directory):
        # copy simple files
        src = os.path.join(result.output_directory, name)
        dst = os.path.join(dstdir, name)
        if os.path.isfile(dst) and os.path.samefile(src, dst):
            continue
        if os.path.isfile(dst) \
        and os.path.getmtime(src) < os.path.getmtime(dst):
            continue
        if good.search(name):
            logger.info("copying '%s' to '%s'", src, dst)
            shutil.copyfile(src, dst)
            continue
        # copy compressed files; gzip is used as that works with the
        # web's deflate?!?
        dst = dst + ".gz"
        if os.path.isfile(dst) \
        and os.path.getmtime(src) < os.path.getmtime(dst):
            continue
        if log.search(name):
            logger.info("compressing '%s' to '%s'", src, dst)
            with open(src, "rb") as f:
                data = f.read()
            with gzip.open(dst, "wb") as f:
                f.write(data)
            continue


def json_result(logger, args, result):
    if not args.publish_results:
        return

    # Convert the result into json, and ...
    json_builder = printer.JsonBuilder()
    printer.build_result(logger, result, None, args, results_to_print, json_builder)
    json_result = json_builder.json()
    json_result["directory"] = result.test.name

    # ... if there is an output directory, write that also
    outdir = _mkdir_test_output(logger, args, result)
    if outdir:
        # needs to be a relative path
        json_result["output_directory"] = os.path.join(os.path.basename(os.path.dirname(outdir)),
                                                       os.path.basename(outdir))
        path = os.path.join(outdir, "result.json")
        logger.info("writing result to '%s'", path)
        with open(path, "w") as output:
            jsonutil.dump(json_result, output)
            output.write("\n")

    # accumulate the results.
    JSON_RESULTS.append(json_result)

    # accumulate the summary
    _add(JSON_SUMMARY, "totals", result.test.kind, result.test.status, str(result.resolution))
    for issue in result.issues:
        for domain in result.issues[issue]:
            # count the number of times it occurred
            _add(JSON_SUMMARY, "errors", issue)
    # extend the times
    _update_time(min, "start_time", json_result)
    _update_time(max, "stop_time", json_result)


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
    # times
    start_time = JSON_SUMMARY.get("start_time")
    stop_time = JSON_SUMMARY.get("stop_time")
    if start_time and stop_time:
        # in minutes
        runtime = round((stop_time - start_time).total_seconds() / 60.0)
        JSON_SUMMARY["runtime"] = "%d:%02d" % (runtime / 60, runtime % 60)
    # other stuff
    JSON_SUMMARY["total"] = len(JSON_RESULTS)
    if args.publish_hash:
        JSON_SUMMARY["hash"] = args.publish_hash
    # emit
    if args.publish_summary:
        path = args.publish_summary;
    else:
        path = os.path.join(args.publish_results, "summary.json")
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
    json_status = {
        "date": datetime.now(),
        "details": details,
    }
    if args.publish_results:
        # The directory is taken relative to the status (summarydir)
        # directory.
        json_status["directory"] = os.path.relpath(args.publish_results,
                                                   os.path.dirname(args.publish_status))
    with open(args.publish_status, "w") as output:
        jsonutil.dump(json_status, output)
        output.write("\n")


def everything(logger, args, result):
    test_files(logger, args, result)
    test_output_files(logger, args, result)
    json_result(logger, args, result)
    json_results(logger, args)
    json_summary(logger, args)
    testlist(logger, args)
