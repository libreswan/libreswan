# Test driver, for libreswan
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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
import threading
import queue
import re
import subprocess
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
from fab import tcpdump

def add_arguments(parser):
    group = parser.add_argument_group("Test Runner arguments",
                                      "Arguments controlling how tests are run")
    group.add_argument("--workers", default="1", type=int,
                       help="specify the number of worker threads to use when rebooting domains; default: %(default)s")
    group.add_argument("--prefix", metavar="HOST-PREFIX", action="append",
                       help="use <PREFIX><host> as the domain for <host> (for instance, PREFIXeast instead of east); if multiple prefixes are specified tests will be run in parallel using PREFIX* as a test pool")
    group.add_argument("--parallel", action="store_true",
                       help="force parallel testing; by default parallel testing is only used when more than one prefix (--prefix) has been specified")
    group.add_argument("--stop-at", metavar="SCRIPT", action="store",
                       help="stop the test at (before executing) the specified script")
    group.add_argument("--tcpdump", action="store_true",
                       help="enable experimental TCPDUMP support")

    # Default to BACKUP under the current directory.  Name is
    # arbitrary, chosen for its hopefully unique first letter
    # (avoiding Makefile, OBJ, README, ... :-).
    group.add_argument("--backup-directory", metavar="DIRECTORY",
                       default=os.path.join("BACKUP", timing.START_TIME.strftime("%Y-%m-%d-%H%M%S")),
                       help="backup existing <test>/OUTPUT to %(metavar)s/<date>/<test> (default: %(default)s)")


def log_arguments(logger, args):
    logger.info("Test Runner arguments:")
    logger.info("  workers: %s", args.workers)
    logger.info("  prefix: %s", args.prefix)
    logger.info("  parallel: %s", args.parallel)
    logger.info("  stop-at: %s", args.stop_at)
    logger.info("  tcpdump: %s", args.tcpdump)
    logger.info("  backup-directory: %s", args.backup_directory)


TEST_TIMEOUT = 120

class TestDomain:

    def __init__(self, domain_prefix, host_name, test):
        self.test = test
        # Get the domain
        self.domain = virsh.Domain(host_name=host_name, domain_prefix=domain_prefix)
        self.logger = logutil.getLogger(domain_prefix, __name__, test.name, host_name)
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

    def boot_and_login(self):
        self.console = remote.boot_to_login_prompt(self.domain, self.console)
        remote.login(self.domain, self.console)
        test_directory = remote.directory(self.domain, self.console,
                                          self.test.directory)
        if not test_directory:
            abspath = os.path.abspath(self.test.directory)
            self.logger.error("directory %s not mounted on %s", abspath, self.domain)
            raise Exception("directory '%s' not mounted on %s" % (abspath, self.domain))
        self.logger.info("'cd' to %s", test_directory)
        self.console.chdir(test_directory)

    def read_file_run(self, basename):
        with self.logger.time("running script %s", basename):
            filename = os.path.join(self.test.directory, basename)
            with open(filename, "r") as file:
                for line in file:
                    line = line.strip()
                    if line:
                        self.logger.info("[%s]# %s", basename, line)
                        status = self.console.run(line, timeout=TEST_TIMEOUT)
                        if status:
                            # XXX: Can't abort as some ping commands
                            # are expected to fail.
                            self.logger.warning("command '%s' failed with status %d", line, status)


def submit_job_for_domain(executor, jobs, logger, domain, work):
    job = executor.submit(work, domain)
    jobs[job] = domain
    logger.debug("scheduled %s on %s", job, domain)


def executor_qsize_hack(executor):
    return executor._work_queue.qsize()

def _boot_test_domains(logger, test, domain_prefix, executor):

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

        # Hack to get at the work queue.
        logger.info("%d shutdown/reboot jobs ahead of us in the queue", executor_qsize_hack(executor))

        test_domains = {}
        unused_domains = set()
        for host_name in testsuite.HOST_NAMES:
            # Test domains have the method "crash()" used below.
            test_domain = TestDomain(domain_prefix, host_name, test)
            if host_name in test.host_names:
                test_domains[host_name] = test_domain
            else:
                unused_domains.add(test_domain)

        logger.info("submitting shutdown jobs for unused domains: %s",
                    " ".join(str(e) for e in unused_domains))
        for test_domain in unused_domains:
            submit_job_for_domain(executor, jobs, logger, test_domain,
                                  TestDomain.shutdown)

        logger.info("submitting boot-and-login jobs for test domains: %s",
                    " ".join(str(e) for e in test_domains.values()))
        for test_domain in test_domains.values():
            submit_job_for_domain(executor, jobs, logger, test_domain,
                                  TestDomain.boot_and_login)

        # Hack to get at the work queue.
        logger.info("submitted %d jobs; currently %d jobs pending",
                    len(jobs), executor_qsize_hack(executor))

        # Wait for the jobs to finish.  If one crashes, propogate the
        # exception - will force things into the finally block.

        logger.debug("submitted jobs: %s", jobs)
        for job in futures.as_completed(jobs):
            logger.debug("job %s on %s completed", job, jobs[job])
            # propogate any exception
            job.result()

        return test_domains

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
        # running) to crash.  The crash() call, effectively, pulls the
        # rug out from under the code interacting with the domain.

        for job in not_canceled:
            logger.info("trying to crash job %s on %s", job, jobs[job])
            jobs[job].crash()

        # Finally wait again, but this time infinitely as all jobs
        # should already be done.

        futures.wait(jobs)


def _process_test(domain_prefix, test, args, test_stats, result_stats, test_count, tests_count, boot_executor):

    logger = logutil.getLogger(domain_prefix, __name__, test.name)

    prefix = "******"
    suffix = "******"
    test_stats.add(test, "total")

    test_runtime = test_boot_time = test_script_time = test_start_time = test_total_time = None

    # Would the number of tests to be [re]run be better?
    test_prefix = "%s (test %d of %d)" % (test.name, test_count, tests_count)
    with logger.time("processing test %s", test_prefix) as test_total_time:

        ignored, include_ignored, details = ignore.test(logger, args, test)
        if ignored and not include_ignored:
            result_stats.add_ignored(test, ignored)
            test_stats.add(test, "ignored")
            # No need to log all the ignored tests when an explicit
            # sub-set of tests is being run.  For instance, when running
            # just one test.
            if not args.test_name:
                logger.info("$s %s ignored (%s) %s",
                            prefix, test_prefix, details, suffix)
            return

        # Be lazy with gathering the results, don't run the sanitizer or
        # diff.
        #
        # XXX: There is a bug here where the only difference is white
        # space.  The test will show up as failed when it previously
        # showed up as a white-space pass.
        #
        # The presence of the RESULT file is a proxy for detecting that
        # the test was incomplete.

        old_result = post.mortem(test, args, test_finished=None,
                                 skip_diff=True, skip_sanitize=True)
        if skip.result(logger, args, old_result):
            logger.info("%s %s skipped (previously %s) %s",
                        prefix, test_prefix, old_result, suffix)
            test_stats.add(test, "skipped")
            result_stats.add_skipped(old_result)
            return

        if old_result:
            test_stats.add(test, "tests", "retry")
            logger.info("%s %s started (previously %s) ....",
                        prefix, test_prefix, old_result)
        else:
            test_stats.add(test, "tests", "try")
            logger.info("%s %s started ....", prefix, test_prefix)
        test_stats.add(test, "tests")

        # Create the OUTPUT/ directory; if it already exists, move any
        # contents to BACKUP/.  Do it file-by-file so that, at no
        # point, the OUTPUT/ directory missing (presence of OUTPUT/
        # implies the test was started).
        #
        # By backing up each test just before it is started, a trail
        # of what tests were attempted during each run is created.
        #
        # XXX:
        #
        # During boot, swan-transmogrify runs "chcon -R
        # testing/pluto".  Of course this means that each time a test
        # is added and/or a test is run (adding files under
        # <test>/OUTPUT), the boot process (and consequently the time
        # taken to run a test) keeps increasing.
        #
        # By moving the directory contents to BACKUP/, which is not
        # under testing/pluto/ this problem is avoided.

        try:
            os.mkdir(test.output_directory)
        except FileExistsError:
            backup_directory = os.path.join(args.backup_directory, test.name)
            logger.info("moving contents of '%s' to '%s'",
                        test.output_directory, backup_directory)
            # Even if OUTPUT/ is empty, copy it.
            os.makedirs(backup_directory, exist_ok=True)
            for name in os.listdir(test.output_directory):
                src = os.path.join(test.output_directory, name)
                dst = os.path.join(backup_directory, name)
                logger.debug("moving '%s' to '%s'", src, dst)
                os.replace(src, dst)

        # Now that the OUTPUT directory is empty, start a debug log
        # writing to that directory; include timing for this test run.

        with logger.debug_time("testing %s", test_prefix,
                               logfile=os.path.join(test.output_directory,
                                                    "debug.log"),
                               loglevel=logutil.INFO) as test_runtime:

            with logger.time("booting domains") as test_boot_time:
                try:
                    test_domains = _boot_test_domains(logger, test, domain_prefix, boot_executor)
                except pexpect.TIMEOUT:
                    logger.exception("timeout while booting domains", test.name)
                    # Bail before RESULT is written - being unable to
                    # boot the domains is a disaster.
                    return


            # Run the scripts directly
            with logger.time("running scripts %s",
                             " ".join(("%s:%s" % (host, script))
                                      for host, script in test.host_script_tuples)) as test_script_time:
                with tcpdump.Dump(logger, domain_prefix, test.output_directory,
                                  [test_domain.domain for test_domain in test_domains.values()],
                                  enable=args.tcpdump):

                    try:

                        # re-direct the test-result log file
                        for test_domain in test_domains.values():
                            output = os.path.join(test.output_directory,
                                                  test_domain.domain.host_name + ".console.verbose.txt")
                            test_domain.console.output(open(output, "w"))

                        for host, script in test.host_script_tuples:
                            if args.stop_at == script:
                                logger.error("stopping test run at (before executing) script %s", script)
                                break
                            test_domain = test_domains[host]
                            test_domain.read_file_run(script)
                        result = post.mortem(test, args, test_finished=True, update=True)

                    except pexpect.TIMEOUT as e:
                        logger.exception("**** timeout out while running script %s ****", script)
                        # Still peform post-mortem so that errors are
                        # captured, but force the result to
                        # incomplete.
                        result = post.mortem(test, args, test_finished=False, update=True)

                    finally:

                        # Close the redirected test-result log files
                        for test_domain in test_domains.values():
                            logfile = test_domain.console.output()
                            logfile.close()

                        # Always disconnect from the test domains.
                        logger.info("closing all test domains")
                        for test_domain in test_domains.values():
                            logfile = test_domain.console.output()
                            if logfile:
                                logfile.close()
                            test_domain.close()

    # Above will have set RESULT.  Exceptions such as control-c or
    # a crash bypass this code.

    logger.info("%s %s %s%s%s %s", prefix, test_prefix, result,
                result.errors and " ", result.errors, suffix)

    # Since the test finished, emit enough JSON to fool scripts like
    # pluto-testlist-scan.sh.
    #
    # This also leaves a simple marker to indicate that the test
    # finished.
    #
    # A more robust way of doing this would be to mark each of the
    # console logs as complete as it is closed.
    #
    # More detailed information can be extracted from the debug.log.
    hosts = {}
    for host in sorted(test.host_names):
        if host in result.errors:
            hosts[host] = [error for error in result.errors[host]]
        else:
            hosts[host] = ["passed"]
    RESULT = {
        jsonutil.result.testname: test.name,
        jsonutil.result.expect: test.expected_result,
        jsonutil.result.result: str(result),
        jsonutil.result.time: jsonutil.ftime(datetime.now()),
        jsonutil.result.runtime: round(test_runtime.seconds(), 1),
        jsonutil.result.boot_time: round(test_boot_time.seconds(), 1),
        jsonutil.result.script_time: round(test_script_time.seconds(), 1),
        jsonutil.result.total_time: round(test_total_time.seconds(), 1),
        jsonutil.result.hosts: hosts,
    }
    j = jsonutil.dumps(RESULT)
    logger.info("filling '%s' with json: %s", test.result_file(), j)
    with open(test.result_file(), "w") as f:
        f.write(j)
        f.write("\n")

    test_stats.add(test, "tests", str(result))
    result_stats.add_result(result, old_result)
    test_stats.log_summary(logger.info, header="updated test stats:", prefix="  ")
    result_stats.log_summary(logger.info, header="updated test results:", prefix="  ")


def _serial_test_processor(domain_prefix, tests, args, test_stats, result_stats, boot_executor, logger):

    test_count = 0
    tests_count = len(tests)
    for test in tests:
        test_count += 1
        _process_test(domain_prefix, test, args, test_stats, result_stats, test_count, tests_count, boot_executor)


class Task:
    def __init__(self, test, count, total):
        self.count = count
        self.total = total
        self.test = test


def _process_test_queue(domain_prefix, test_queue, args, done, test_stats, result_stats, boot_executor):
    logger = logutil.getLogger(domain_prefix, __name__)
    try:
        while True:
            task = test_queue.get(block=False)
            _process_test(domain_prefix, task.test, args, test_stats, result_stats, task.count, task.total, boot_executor)
    except queue.Empty:
        None
    finally:
        done.release()


def _parallel_test_processor(domain_prefixes, tests, args, test_stats, result_stats, boot_executor, logger):

    # Convert the test list into a queue.
    #
    # Since the queue is "infinite", .put() should never block. Assert
    # this.
    count = 0
    test_queue = queue.Queue()
    for test in tests:
        count += 1
        test_queue.put(Task(test, count, len(tests)), block=False)

    done = threading.Semaphore(value=0) # block
    threads = []
    for domain_prefix in domain_prefixes:
        threads.append(threading.Thread(name=domain_prefix,
                                        target=_process_test_queue,
                                        daemon=True,
                                        args=(domain_prefix, test_queue,
                                              args, done,
                                              test_stats, result_stats,
                                              boot_executor)))
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
            logger.info("discarding test %s", test)
    except queue.Empty:
        None

    # Finally wait for the other threads to exit.
    logger.info("waiting for threads to finish")
    for thread in threads:
        thread.join()


def run_tests(logger, args, tests, test_stats, result_stats):
    if args.workers == 1:
        logger.info("using 1 worker thread to reboot domains")
    else:
        logger.info("using a pool of %s worker threads to reboot domains", args.workers)
    with futures.ThreadPoolExecutor(max_workers=args.workers) as boot_executor:
        domain_prefixes = args.prefix or [""]
        if args.parallel or len(domain_prefixes) > 1:
            logger.info("using the parallel test processor and domain prefixes %s", domain_prefixes)
            _parallel_test_processor(domain_prefixes, tests, args, test_stats, result_stats, boot_executor, logger)
        else:
            domain_prefix = domain_prefixes[0]
            logger.info("using the serial test processor and domain prefix '%s'", domain_prefix)
            _serial_test_processor(domain_prefix, tests, args, test_stats, result_stats, boot_executor, logger)
