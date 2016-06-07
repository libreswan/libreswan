# Test driver, for libreswan
#
# Copyright (C) 2015, 2016 Andrew Cagney <cagney@gnu.org>
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

import os
import sys
import pexpect
import time
from datetime import datetime
from concurrent import futures

from fab import virsh
from fab import testsuite
from fab import remote
from fab import logutil
from fab import utils
from fab import post


def add_arguments(parser):
    group = parser.add_argument_group("Test Runner arguments",
                                      "Arguments controlling how tests are run")
    group.add_argument("--workers", default="1", type=int,
                       help="default: %(default)s")
    group.add_argument("--prefix", metavar="DOMAIN-PREFIX", default="",
                       help="prefix to prepend to each domain")

    group.add_argument("--skip-passed", action="store_true",
                       help="skip tests that passed during the previous test run")
    group.add_argument("--skip-failed", action="store_true",
                       help="skip tests that failed during the previous test run")
    group.add_argument("--skip-incomplete", action="store_true",
                       help="skip tests that did not complete during the previous test run")
    group.add_argument("--skip-untested", action="store_true",
                       help="skip tests that have not been previously run")

    group.add_argument("--attempts", type=int, default=1,
                       help="number of times to attempt a test before giving up; default %(default)s")

    # Default to BACKUP under the current directory.  Name is
    # arbitrary, chosen for its hopefully unique first letter
    # (avoiding Makefile, OBJ, README, ... :-).
    parser.add_argument("--backup-directory", metavar="DIRECTORY", default="BACKUP",
                        help="backup existing <test>/OUTPUT to %(metavar)s/<date>/<test> (default: %(default)s)")

def log_arguments(logger, args):
    logger.info("Test Runner arguments:")
    logger.info("  workers: %s", args.workers)
    logger.info("  prefix: %s", args.prefix)
    logger.info("  skip-passed: %s", args.skip_passed)
    logger.info("  skip-failed: %s", args.skip_failed)
    logger.info("  skip-incomplete: %s", args.skip_incomplete)
    logger.info("  skip-untested: %s", args.skip_untested)
    logger.info("  attempts: %s", args.attempts)
    logger.info("  backup-directory: %s", args.backup_directory)

TEST_TIMEOUT = 120

class TestDomain:

    def __init__(self, domain_name, host_name, test):
        self.test = test
        # Get the domain
        self.domain = virsh.Domain(domain_name=domain_name, host_name=host_name)
        self.logger = logutil.getLogger(__name__, test.name, domain_name)
        # A valid console indicates that the domain is up.
        self.console = self.domain.console()

    def __str__(self):
        return self.domain.name

    def crash(self):
        # The objective here is to cause any further operations (on
        # another thread say) to crash!  Swap out any existing domain
        # and console so any attempt to operate on or manipulate the
        # target crashes.
        domain, self.domain = self.domain, None
        # This forces a new console to be opened kicking off any
        # existing connection.
        self.logger.info("closing any existing console by forcing a console re-open")
        console = domain.console()
        # Finally clean up.
        self.disconnect_console(domain, console, self.logger.info)

    def close(self):
        self.disconnect_console(self.domain, self.console, self.logger.debug)

    def disconnect_console(self, domain, console, log):
        # disconnect the current console.
        if console:
            log("sending ^] to close virsh; expecting EOF")
            console.sendcontrol("]")
            console.expect(pexpect.EOF)
        # close the old console.
        if self.console:
            output = self.console.output()
            if output:
                log("closing console output log")
                output.close()
            log("closing console")
            self.console.close()
        self.console = None

    def shutdown(self):
        remote.shutdown(self.domain)

    def boot(self):
        if self.console:
            self.console = remote.reboot(self.domain, self.console)
        else:
            self.console = remote.start(self.domain)

    def login(self):
        remote.login(self.domain, self.console)
        test_directory = remote.directory(self.domain, self.console,
                                          self.test.directory)
        self.logger.info("'cd' to %s", test_directory)
        self.console.chdir(test_directory)

    def boot_and_login(self):
        self.boot()
        self.login()

    def read_file_run(self, basename):
        self.logger.info("starting script %s", basename)
        filename = os.path.join(self.test.directory, basename)
        start_time = time.time()
        with open(filename, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    self.logger.info("[%s]# %s", basename, line)
                    status = self.console.run(line, timeout=TEST_TIMEOUT)
                    if status:
                        # XXX: Can't abort as some ping commands are
                        # expected to fail.
                        self.logger.warning("command '%s' failed with status %d", line, status)
            self.logger.info("script %s finished after %d seconds",
                             basename, time.time() - start_time)


class TestDomains:

    def __init__(self, logger, test, domain_prefix, host_names):
        self.logger = logger
        # Create a table of test domain objects; they are used during
        # cleanup; and they are used as the values of the JOBS table.
        self.test_domains = {}
        for host_name in host_names:
            domain_name = domain_prefix + host_name
            test_domain = TestDomain(domain_name, host_name, test)
            self.test_domains[host_name] = test_domain

    def __enter__(self):
        self.logger.debug("all test domains: %s", self.test_domains)
        return self.test_domains

    def __exit__(self, type, value, traceback):
        # Finally, and after any cancel(), try closing all the
        # test domains unconditinally.
        self.logger.info("closing all test domains")
        for test_domain in self.test_domains.values():
            test_domain.close()


def submit_job_for_domain(executor, jobs, logger, domain, work):
    job = executor.submit(work, domain)
    jobs[job] = domain
    logger.debug("scheduled %s on %s", job, domain)


def run_test(test, args, boot_executor):
    # Lots of WITH/TRY blocks so things always clean up.

    # Time just this test
    logger = logutil.getLogger(__name__, test.name)

    with TestDomains(logger, test, args.prefix, testsuite.HOST_NAMES) as all_test_domains:

        logger.info("starting test")

        test_domains = set()
        for host_name in test.host_names:
            test_domains.add(all_test_domains[host_name])
            logger.debug("test domains: %s", strset(test_domains))

        idle_domains = set()
        for test_domain in all_test_domains.values():
            if test_domain not in test_domains:
                idle_domains.add(test_domain)
        logger.info("idle domains: %s", strset(idle_domains))

        boot_test_domains(logger, test_domains, idle_domains, boot_executor)

        # re-direct the test-result log file
        for test_domain in test_domains:
            output = os.path.join(test.output_directory,
                                  test_domain.domain.host_name + ".console.verbose.txt")
            test_domain.console.output(open(output, "w"))

        # Run the scripts directly
        logger.info("running scripts: %s", " ".join(str(script) for script in test.scripts))
        for script in test.scripts:
            test_domain = all_test_domains[script.host_name]
            test_domain.read_file_run(script.script)

        logger.info("finishing test")


def strset(s):
    return " ".join(str(e) for e in s)

def boot_test_domains(logger, test_domains, idle_domains, executor):

    try:

        # There's a tradeoff here between speed and reliability.
        #
        # In theory, the boot process is mostly I/O bound.
        # Consequently, having lots of domains boot in parallel should
        # be harmless.
        #
        # In reality, the [fedora] boot process is very much CPU bound
        # (a rule of thumb is two cores per domain).  Consequently, it
        # is best to serialize the boot/login process.  This is done
        # using a futures pool shared across test runners.

        # Python doesn't have an easy way to obtain the jobs submitted
        # for the current test so track them locally using the JOBS
        # map.
        #
        # If there's a crash, any remaining members of JOBS are
        # canceled or killed in the finally block below.

        jobs = {}

        for test_domain in idle_domains:
            submit_job_for_domain(executor, jobs, logger, test_domain,
                                  TestDomain.shutdown)

        logger.info("boot and login domains: %s", strset(test_domains))
        for domain in test_domains:
            submit_job_for_domain(executor, jobs, logger, domain,
                                  TestDomain.boot_and_login)

        # Wait for the jobs to finish.  If one crashes, propogate the
        # exception - will force things into the finally block.
        logger.debug("waiting for jobs %s", jobs)
        for job in futures.as_completed(jobs):
            logger.debug("job %s on %s completed", job, jobs[job])
            # propogate any exception
            job.result()

    finally:

        # Control-c, timeouts, along with any other crash, and even a
        # normal exit, all end up here!

        # Start with a list of jobs still in the queue; one or more of
        # them may be running.
        done, not_done = futures.wait(jobs, timeout=0)
        logger.debug("jobs done %s not done %s", done, not_done)

        # First: cancel all outstanding jobs (otherwise killing one
        # job would just result in the next job starting).  Calling
        # cancel() on running jobs has no effect so need to stop them
        # some other way; ulgh!
        not_canceled = set()
        for job in not_done:
            logger.info("trying to cancel job %s on %s", job, jobs[job])
            if job.cancel():
                logger.info("job %s on %s canceled", job, jobs[job])
            else:
                logger.info("job %s on %s did not cancel", job, jobs[job])
                not_canceled.add(job)

        # Second: cause any un-canceled jobs (presumably they are
        # running) to crash.  The crash() call, effectively, pulls
        # the rug out from under the code interacting with the
        # domain.
        for job in not_canceled:
            logger.info("trying to crash job %s on %s", job, jobs[job])
            jobs[job].crash()

        # Finally wait again, but this time infinitely as all jobs
        # should already be done.
        futures.wait(jobs)

def run_tests(logger, args, tests, test_stats, result_stats, start_time):

    test_count = 0
    for test in tests:

        test_stats.add(test, "total")
        test_count += 1
        # Would the number of tests to be [re]run be better?
        test_prefix = "****** %s (test %d of %d)" % (test.name, test_count, len(tests))

        ignore, details = testsuite.ignore(test, args)
        if ignore:
            result_stats.add_ignored(test, ignore)
            test_stats.add(test, "ignored")
            # No need to log all the ignored tests when an
            # explicit sub-set of tests is being run.  For
            # instance, when running just one test.
            if not args.test_name:
                logger.info("%s: ignore (%s)", test_prefix, details)
            continue

        # Implement "--retry" as described above: if retry is -ve,
        # the test is always run; if there's no result, the test
        # is always run; skip passed tests; else things get a
        # little wierd.

        # Be lazy with gathering the results, don't run the
        # sanitizer or diff.
        #
        # XXX: There is a bug here where the only difference is
        # white space.  The test will show up as failed when it
        # previousl showed up as a whitespace pass.
        #
        # The presence of the RESULT file is a proxy for detecting
        # that the test was incomplete.
        old_result = post.mortem(test, args, test_finished=None,
                                 skip_diff=True, skip_sanitize=True)
        if args.skip_passed and old_result.finished and old_result.passed is True or \
           args.skip_failed and old_result.finished and old_result.passed is False or \
           args.skip_incomplete and old_result.finished is False or \
           args.skip_untested and old_result.finished is None:
            logger.info("%s: skipped (previously %s)", test_prefix, old_result)
            test_stats.add(test, "skipped")
            result_stats.add_skipped(old_result)
            continue

        if old_result:
            test_stats.add(test, "retry")
            logger.info("%s: starting (previously %s) ...", test_prefix, old_result)
        else:
            logger.info("%s: starting ...", test_prefix)
        test_stats.add(test, "tests")

        # Move the contents of the existing OUTPUT directory to
        # BACKUP_DIRECTORY.  Do it file-by-file so that, at no
        # point, the directory is empty.
        #
        # By moving each test just before it is started a trail of
        # what tests were attempted at each run is left.
        #
        # XXX: During boot, swan-transmogrify runs "chcon -R
        # testing/pluto".  Of course this means that each time a
        # test is added and/or a test is run (adding files under
        # <test>/OUTPUT), the boot process (and consequently the
        # time taken to run a test) keeps increasing.
        #
        # Always moving the directory contents to the
        # BACKUP_DIRECTORY mitigates this some.

        backup_directory = None
        if os.path.exists(test.output_directory):
            backup_directory = os.path.join(args.backup_directory,
                                            start_time.strftime("%Y%m%d%H%M%S"),
                                            test.name)
            logger.info("moving contents of '%s' to '%s'",
                        test.output_directory, backup_directory)
            # Copy "empty" OUTPUT directories too.
            args.dry_run or os.makedirs(backup_directory, exist_ok=True)
            for name in os.listdir(test.output_directory):
                src = os.path.join(test.output_directory, name)
                dst = os.path.join(backup_directory, name)
                logger.debug("moving '%s' to '%s'", src, dst)
                args.dry_run or os.replace(src, dst)

        debugfile = None
        result = None

        # At least one iteration; above will have filtered out
        # skips and ignores
        for attempt in range(args.attempts):
            test_stats.add(test, "attempts")

            # Create the OUTPUT directory.
            try:
                if not args.dry_run:
                    os.mkdir(test.output_directory)
                elif os.exists(test.output_directory):
                    raise FileExistsError()
            except FileExistsError:
                # On first attempt, the OUTPUT directory will
                # be empty (see above) so no need to save.
                if attempt > 0:
                    backup_directory = os.path.join(test.output_directory, str(attempt))
                    logger.info("moving contents of '%s' to '%s'",
                                test.output_directory, backup_directory)
                    args.dry_run or os.makedirs(backup_directory, exist_ok=True)
                    for name in os.listdir(test.output_directory):
                        if os.path.isfile(src):
                            src = os.path.join(test.output_directory, name)
                            dst = os.path.join(backup_directory, name)
                            logger.debug("moving '%s' to '%s'", src, dst)
                            args.dry_run or os.replace(src, dst)

            # Start a debug log in the OUTPUT directory; include
            # timing for this specific test attempt.
            with logutil.TIMER, logutil.Debug(logger, os.path.join(test.output_directory, "debug.log")):
                logger.info("****** test %s attempt %d of %d started at %s ******",
                            test.name, attempt+1, args.attempts, datetime.now())

                if backup_directory:
                    logger.info("contents of '%s' moved to '%s'",
                                test.output_directory, backup_directory)
                backup_directory = None

                ending = "undefined"
                try:
                    if not args.dry_run:
                        with futures.ThreadPoolExecutor(max_workers=args.workers) as boot_executor:
                            run_test(test, args, boot_executor)
                    ending = "finished"
                    result = post.mortem(test, args, test_finished=True,
                                         update=(not args.dry_run))
                    if not args.dry_run:
                        # Store enough to fool the script
                        # pluto-testlist-scan.sh and leave a
                        # marker to indicate that the test
                        # finished.
                        logger.info("storing result in '%s'", test.result_file())
                        with open(test.result_file(), "w") as f:
                            f.write('"result": "%s"\n' % result)
                except pexpect.TIMEOUT as e:
                    logger.exception("**** test %s timed out ****", test.name)
                    ending = "timed-out"
                    # Still peform post-mortem so that errors are
                    # captured, but force the result to incomplete.
                    result = post.mortem(test, args, test_finished=False,
                                         update=(not args.dry_run))
                # Since the OUTPUT directory exists, all paths to
                # here should have a non-null RESULT.
                test_stats.add(test, "attempts", ending, str(result))
                if result.errors:
                    logger.info("****** test %s %s %s ******", test.name, result, result.errors)
                else:
                    logger.info("****** test %s %s ******", test.name, result)
                if result.passed:
                    break

        # Above will have set RESULT.  During a control-c or crash
        # the below will not be executed.

        test_stats.add(test, "tests", str(result))
        result_stats.add_result(result, old_result)

        test_stats.log_summary(logger.info, header="updated test stats:", prefix="  ")
        result_stats.log_summary(logger.info, header="updated test results:", prefix="  ")
