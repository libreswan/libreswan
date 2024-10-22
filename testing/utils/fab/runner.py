# Test driver, for libreswan
#
# Copyright (C) 2015-2022  Andrew Cagney
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
import sys
import pexpect
import threading
import queue
import re
import subprocess
import argparse
from datetime import datetime
from concurrent import futures

from fab import jsonutil
from fab import timing
from fab import virsh
from fab import testsuite
from fab import remote
from fab import logutil
from fab import post
from fab import skip
from fab import ignore
from fab import publish
from fab.hosts import GUESTS
from fab import printer

PREFIX = "******"
SUFFIX = "******"

TEST_TIMEOUT = 120
POST_MORTEM_TIMEOUT = 120

def add_arguments(parser):
    group = parser.add_argument_group("Test Runner arguments",
                                      "Arguments controlling how tests are run")
    group.add_argument("--prefix", metavar="HOST-PREFIX", action="append",
                       help="use <PREFIX><host> as the domain for <host> (for instance, PREFIXeast instead of east); if multiple prefixes are specified tests will be run in parallel using PREFIX* as a test pool")
    group.add_argument("--parallel", action="store_true",
                       help="force parallel testing; by default parallel testing is only used when more than one prefix (--prefix) has been specified")
    group.add_argument("--stop-at", metavar="SCRIPT", action="store",
                       help="stop the test at (before executing) the specified script")
    group.add_argument("--run-post-mortem", default=None, action=argparse.BooleanOptionalAction,
                       help="run the post-mortem script; by default, when there is only one test, the script post-mortem.sh is skipped")

    # Default to BACKUP under the current directory.  Name is
    # arbitrary, chosen for its hopefully unique first letter
    # (avoiding Makefile, OBJ, README, ... :-).
    group.add_argument("--backup-directory", metavar="DIRECTORY",
                       default=os.path.join("BACKUP", timing.START_TIME.strftime("%Y-%m-%d-%H%M%S")),
                       help="backup existing <test>/OUTPUT to %(metavar)s/<date>/<test> (default: %(default)s)")


def log_arguments(logger, args):
    logger.info("Test Runner arguments:")
    logger.info("  prefix: %s", args.prefix)
    logger.info("  parallel: %s", args.parallel)
    logger.info("  backup-directory: %s", args.backup_directory)
    logger.info("  run-post-mortem: %s", args.run_post_mortem)


class Task:
    def __init__(self, test, test_nr, nr_tests):
        self.test_nr = test_nr
        self.nr_tests = nr_tests
        self.test = test
        self.prefix = "%s (test %d of %d)" % (test.name, test_nr, nr_tests)

class TestDomain:

    def __init__(self, domain, test, logger):
        self.test = test
        # Get the domain
        self.logger = logger
        self.domain = domain
        self.verbose_txt = None
        self.console = None

    def __str__(self):
        return self.domain.name

    def open(self):
        # open the output file
        guest = self.domain.guest
        output = os.path.join(self.test.output_directory,
                              guest.host.name + ".console.verbose.txt")
        # buffering=1 is line buffered
        self.verbose_txt = open(output, "w", buffering=1)

    def close(self):
        if self.verbose_txt:
            self.verbose_txt.close()
            self.verbose_txt = None

    def start(self):
        console = remote.boot_and_login(self.domain)
        if not console:
            return False
        test_directory = os.path.join("/testing/pluto", self.test.name)
        console.chdir(test_directory)
        self.console = console
        return True

    def stop(self):
        self.domain.destroy(self.console)
        self.console = None

    def run(self, command, timeout=TEST_TIMEOUT):
        console = self.console
        self.logger.info("%s# %s", self.domain.guest.host.name, command)
        console.logger.debug("run '%s' expecting prompt", command)
        console.sendline(command)
        # This can throw a pexpect.TIMEOUT or pexpect.EOF exception
        match console.expect([console.prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout):
            case 0:
                status = console._check_prompt()
                console.logger.debug("run exit status %s", status)
                return status, console.before
            case 1:
                return post.Issues.TIMEOUT, console.before
            case 2:
                return post.Issues.EOF, console.before

def submit_job_for_domain(executor, jobs, logger, domain, work):
    job = executor.submit(work, domain)
    jobs[job] = domain
    logger.debug("scheduled %s on %s", job, domain)


def executor_qsize_hack(executor):
    return executor._work_queue.qsize()

def _test_domains(logger, test, domains):

    test_domains = dict()
    unused_domains = set()
    for domain in domains:
        domain.nest(logger, test.name + " ")
        # new test domain
        if domain.guest in test.guests:
            test_domain = TestDomain(domain, test, domain.logger)
            test_domains[domain.guest.name] = test_domain
        else:
            unused_domains.add(domain)

    logger.info("unused domains: %s",
                " ".join(str(e) for e in unused_domains))
    logger.info("test domains: %s",
                " ".join(str(e) for e in test_domains.values()))

    return test_domains

def _ignore_test(task, args, result_stats, logger):

    test = task.test
    ignored, details = ignore.test(logger, args, task.test)
    if ignored:
        logger.info("%s %s ignored (%s) %s", PREFIX, task.prefix, details, SUFFIX)
        # So that there's no possible confusion over the test being
        # run; remove any pre-existing OUTPUT/ directory (well move it
        # to BACKUP).
        #
        # The isdir() test followed by a simple move, while racy,
        # should be good enough.
        if os.path.isdir(test.output_directory):
            test_backup_directory = os.path.join(args.backup_directory, task.test.name)

            logger.info("moving '%s' to '%s'", test.output_directory,
                        test_backup_directory)
            # create BACKUP/ then move OUTPUT/ to BACKUP/<test>
            os.makedirs(args.backup_directory, exist_ok=True)
            os.rename(test.output_directory, test_backup_directory)
        result_stats.add_ignored(test, ignored)
        publish.everything(logger, args, post.mortem(test, args, logger, quick=True))
        return True

    return False

def _skip_test(task, args, result_stats, logger):

    # For instance, during a test re-run, skip any tests that are
    # passing.
    #
    # The check below compares the test and expected output,
    # ignoring any previous test result.  This way the results are
    # consistent with kvmresults.py which always reflects the
    # current sources.
    #
    # - modifying the expected output so that it no longer matches
    #   the last result is a fail
    #
    # - modifying the expected output so that it matches the last
    #   result is a pass

    test = task.test
    old_result = post.mortem(test, args, logger)
    if skip.result(logger, args, old_result):
        logger.info("%s %s skipped (previously %s) %s",
                    PREFIX, task.prefix, old_result, SUFFIX)
        result_stats.add_skipped(old_result)
        publish.everything(logger, args, old_result)
        return True

    return False

def _write_guest_prompt(f, command, test):
    f.write("[root@");
    f.write(command.guest.host.name)
    f.write(" ")
    f.write(test.name)
    f.write("]# ")

def _process_test(domain_prefix, domains, args, result_stats, task, logger):

    test = task.test
    old_result = None

    # Would the number of tests to be [re]run be better?
    publish.json_status(logger, args, "processing %s" % task.prefix)
    with logger.time("processing test %s", task.prefix):

        # Ignore the test completely?  So there's no possible
        # confusion over the test's status remove any existing OUTPUT/
        if _ignore_test(task, args, result_stats, logger):
            return

        # Skip the test?  Leave any old results so next run skips the
        # same way.
        if _skip_test(task, args, result_stats, logger):
            return

        test_domains = _test_domains(logger, test, domains)

        # Running the test ...
        #
        # From now on the test will be run so need to perform post
        # mortem.

        try:

            if old_result:
                logger.info("%s %s started (previously %s) ....",
                            PREFIX, task.prefix, old_result)
            else:
                logger.info("%s %s started ....", PREFIX, task.prefix)

            # Create just the OUTPUT/ directory.
            #
            # If the directory already exists, copy the contents
            # BACKUP/.  Do it file-by-file so that, at no point, the
            # OUTPUT/ directory is missing (having an OUTPUT/
            # directory implies the test was started).
            #
            # Don't try to create the path.  If the parent directory
            # is missing, this and the entire script will crash.
            # Someone did something nasty like deleted the parent
            # directory.
            #
            # By backing up each test just before it is started,
            # leaves a trail of what tests were attempted during a
            # test run.
            #
            # XXX:
            #
            # During boot, swan-transmogrify runs "chcon -R
            # testing/pluto".  Of course this means that each time a
            # test is added and/or a test is run (adding files under
            # <test>/OUTPUT), the boot process (and consequently the
            # time taken to run a test) keeps increasing.
            #
            # By moving the directory contents to BACKUP/, which is
            # not under testing/pluto/ this problem is avoided.

            try:
                os.mkdir(test.output_directory)
            except FileExistsError:
                test_backup_directory = os.path.join(args.backup_directory, task.test.name)
                logger.info("moving contents of '%s' to '%s'",
                            test.output_directory, test_backup_directory)
                # Even if OUTPUT/ is empty, move it.
                os.makedirs(test_backup_directory, exist_ok=True)
                for name in os.listdir(test.output_directory):
                    src = os.path.join(test.output_directory, name)
                    dst = os.path.join(test_backup_directory, name)
                    logger.debug("moving '%s' to '%s'", src, dst)
                    os.replace(src, dst)

            # Now that the OUTPUT directory is empty, start a debug
            # log writing to that directory; include timing for this
            # test run.

            with logger.debug_time("testing %s", task.prefix,
                                   logfile=os.path.join(test.output_directory, "debug.log"),
                                   loglevel=logutil.INFO):

                # boot the domains
                with logger.time("booting domains"):
                    for test_domain in test_domains.values():
                        with logger.time("booting %s domain" % test_domain.domain.name):
                            if not test_domain.start():
                                # final will clean up
                                return

                # Run the commands directly
                with logger.time("running commands"):

                        # Open output files.  Since the child is
                    # in NO-ECHO mode, also need to fudge up
                    # prompt and command.
                    #
                    # Should output file be opened in binary
                    # mode?

                    with open(os.path.join(test.output_directory, "all.console.verbose.txt"), "w") as all_verbose_txt:

                        # open the consoles
                        for test_domain in test_domains.values():
                            test_domain.open()

                        # If a guest command times out, don't try
                        # to run post-mortem.sh.
                        guest_timed_out = None

                        last_was_comment = False

                        for command in test.commands:

                            # The per-guest command has no guest?
                            #
                            # i.e., blank or None.  It's a comment
                            # from all.console.txt.  Skip executing it
                            # and save it in the shared
                            # all.console.verbose.txt file.

                            if not command.guest:
                                last_was_comment = True
                                all_verbose_txt.write(command.line)
                                all_verbose_txt.write("\n");
                                continue

                            # The per-guest command is a comment?
                            #
                            # i.e., it starts with '#'.  Skip
                            # executing it and save it in the output
                            # file.  (for per-GUEST output also need
                            # to fake up a new prompt).

                            test_domain = test_domains[command.guest.name]
                            guest_verbose_txt = test_domain.verbose_txt

                            if command.line.startswith("#"):
                                last_was_comment = True
                                for txt in (all_verbose_txt, guest_verbose_txt):
                                    txt.write(command.line)
                                    txt.write("\n");
                                # fudge the prompt
                                _write_guest_prompt(guest_verbose_txt, command, test)
                                continue

                            if last_was_comment:
                                all_verbose_txt.write("\n");
                            last_was_comment = False

                            # ALL gets the new prompt
                            all_verbose_txt.write(command.guest.name)
                            all_verbose_txt.write("# ")
                            # both get the command
                            for txt in (all_verbose_txt, guest_verbose_txt):
                                txt.write(command.line)
                                txt.write("\n")

                            # run the command
                            status, output = test_domain.run(command.line)
                            if output:
                                # All gets a blank line
                                all_verbose_txt.write("\n")
                                for txt in (all_verbose_txt, guest_verbose_txt):
                                    txt.write(output.decode()) # convert byte to string

                            if status is post.Issues.TIMEOUT:
                                # A timeout while running a
                                # test command is a sign that
                                # the command hung.
                                message = "%s while running command %s" % (post.Issues.TIMEOUT, command)
                                logger.warning("*** %s ***" % message)
                                for txt in (all_verbose_txt, guest_verbose_txt):
                                    txt.write("%s %s %s" % (post.LHS, message, post.RHS))
                                guest_timed_out = command.guest.name
                                break

                            if status is post.Issues.EOF:
                                # An EOF while a command is
                                # running is a sign that libvirt
                                # crashed.
                                message = "%s while running command %s" % (post.Issues.EOF, command)
                                logger.exception("*** %s ***" % message)
                                for txt in (all_verbose_txt, guest_verbose_txt):
                                    txt.write("%s %s %s" % (post.LHS, message, post.RHS))
                                guest_timed_out = command.guest.name
                                break

                            if status:
                                # XXX: Can't abort as some
                                # ping commands are expected
                                # to fail.
                                test_domain.logger.warning("command '%s' failed with status %d", command.line, status)

                            # GUEST then gets the next prompt
                            _write_guest_prompt(guest_verbose_txt, command, test)

                            all_verbose_txt.write("\n")

                        if args.run_post_mortem is False:
                            logger.warning("+++ skipping script post-mortem.sh -- disabled +++")
                        elif guest_timed_out:
                            logger.warning("+++ skipping script post-mortem.sh -- %s timed out +++" % (guest_timed_out))
                        else: # None or True
                            post_mortem_ok = True
                            script = "../../guestbin/post-mortem.sh"
                            # Tag merged file ready for post-mortem output
                            all_verbose_txt.write("%s post-mortem %s" % (post.LHS, post.LHS))
                            # run post mortem
                            for guest in test.guests:

                                test_domain = test_domains[guest.name]
                                guest_verbose_txt = test_domain.verbose_txt
                                logger.debug("running %s on %s", script, guest.name)

                                # mark domain's console
                                guest_verbose_txt.write("%s post-mortem %s" % (post.LHS, post.LHS))

                                # ALL gets the new prompt
                                all_verbose_txt.write(guest.name)
                                all_verbose_txt.write("# ")
                                # both get the command
                                for txt in (all_verbose_txt, guest_verbose_txt):
                                    txt.write(script)
                                    txt.write("\n")

                                status, output = test_domain.run(script, timeout=POST_MORTEM_TIMEOUT)
                                if output:
                                    all_verbose_txt.write("\n")
                                    for txt in (all_verbose_txt, guest_verbose_txt):
                                        txt.write(output.decode()) # convert byte to string
                                        txt.write("\n")

                                if status is post.Issues.TIMEOUT:
                                    # A post-mortem ending with a
                                    # TIMEOUT gets treated as a
                                    # FAIL.
                                    post_mortem_ok = False
                                    message = "%s while running script %s" % (post.Issues.TIMEOUT, script)
                                    logger.warning("*** %s ***" % message)
                                    for txt in (all_verbose_txt, guest_verbose_txt):
                                        txt.write("%s %s %s" % (post.LHS, message, post.RHS))
                                    continue # to next teardown

                                if status is post.Issues.EOF:
                                    # A post-mortem ending with an
                                    # EOF gets treated as
                                    # unresloved.
                                    post_mortem_ok = False
                                    message = "%s while running script %s" % (post.Issues.EOF, script)
                                    logger.exception("*** %s ***" % message)
                                    for txt in (all_verbose_txt, guest_verbose_txt):
                                        txt.write("%s %s %s" % (post.LHS, message, post.RHS))
                                    continue # to next teardown

                                if status:
                                    post_mortem_ok = False
                                    logger.error("%s failed on %s with status %s", script, guest.name, status)
                                    continue # to next teardown

                                # GUEST finishes with the old prompt
                                _write_guest_prompt(guest_verbose_txt, command, test)

                                # followed by marker
                                guest_verbose_txt.write("%s post-mortem %s" % (post.RHS, post.RHS))

                            if post_mortem_ok:
                                all_verbose_txt.write("%s post-mortem %s" % (post.RHS, post.RHS))

                        all_verbose_txt.write(post.DONE)
                        for test_domain in test_domains.values():
                            test_domain.verbose_txt.write(post.DONE)

        finally:

            for test_domain in test_domains.values():
                test_domain.close()

            if task.nr_tests <= 1:
                logger.info("single test run; leaving domains running");
            else:
                logger.info("stopping domains: %s",
                            " ".join(test_domain.domain.name for test_domain in test_domains.values()))
                for test_domain in test_domains.values():
                    test_domain.stop()

            with logger.time("post-mortem %s", task.prefix):
                # The test finished; it is assumed that post.mortem
                # can deal with a crashed test.
                #
                # Post mortem extracts the total, boot, and test times
                # from debug.log (this is so that a re-run gets the
                # same values).
                result = post.mortem(test, args, logger)
                logger.info("%s %s %s%s%s %s", PREFIX, task.prefix, result,
                            result.issues and " ", result.issues, SUFFIX)

            result.save()

            # Do this after RESULT is created so it too is published.
            publish.everything(logger, args, result)
            publish.json_status(logger, args, "finished %s" % task.prefix)

            result_stats.add_result(result, old_result)
            result_stats.log_summary(logger.info, header="updated test results:", prefix="  ")


def _process_test_queue(domain_prefix, test_queue, nr_tests, args, done, result_stats):
    # New (per-thread/process) logger!
    logger = logutil.getLogger(domain_prefix and domain_prefix or "kvmrunner")

    logger.info("preparing test domains")

    domains = list()
    for guest in GUESTS:
        domain = virsh.Domain(logger=logger, prefix=domain_prefix, guest=guest)
        domains.append(domain)
        domain.destroy()

    logger.info("processing test queue")
    try:
        while True:
            task = test_queue.get(block=False)
            task_logger = logger.nest(task.test.name + " " + domain_prefix)
            _process_test(domain_prefix, domains, args,
                          result_stats, task, task_logger)
    except queue.Empty:
        None
    finally:
        done.release()


def _parallel_test_processor(domain_prefixes, test_queue, nr_tests, args, result_stats, logger):

    done = threading.Semaphore(value=0) # block
    threads = []
    for domain_prefix in domain_prefixes:
        threads.append(threading.Thread(name=domain_prefix,
                                        target=_process_test_queue,
                                        daemon=True,
                                        args=(domain_prefix, test_queue,
                                              nr_tests, args, done,
                                              result_stats)))
        # don't start more threads then needed
        if len(threads) >= nr_tests:
            break

    for thread in threads:
        thread.start()

    # Wait for at least one thread to exit
    logger.info("waiting for first thread to finish")
    done.acquire()

    # If all went well the TEST_QUEUE is empty and this does nothing.
    # However if something is going wrong, this will stop the other
    # threads by draining the queue.
    try:
        while True:
            test = test_queue.get(block=False)
            logger.debug("discarding test %s", test)
    except queue.Empty:
        None

    # Finally wait for the other threads to exit.
    logger.info("waiting for threads to finish")
    for thread in threads:
        thread.join()


def run_tests(logger, args, tests, result_stats):

    # Convert the test list into a queue of test_task[s].
    #
    # Since the queue is "infinite", .put() should never block, assert
    # this by passing block=false?
    test_nr = 0
    test_queue = queue.Queue()
    for test in tests:
        test_nr += 1
        test_queue.put(Task(test, test_nr, len(tests)), block=False)

    domain_prefixes = args.prefix or [""]
    if args.parallel or len(domain_prefixes) > 1:
        logger.info("using the parallel test processor and domain prefixes %s to run %d tests", domain_prefixes, len(tests))
        _parallel_test_processor(domain_prefixes, test_queue, len(tests), args, result_stats, logger)
    else:
        domain_prefix = domain_prefixes[0]
        done = threading.Semaphore(value=0) # block
        logger.info("using the serial test processor and domain prefix '%s'", domain_prefix)
        _process_test_queue(domain_prefix, test_queue, len(tests), args, done, result_stats)
    publish.json_status(logger, args, "finished")
