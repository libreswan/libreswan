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
from concurrent import futures
from fab import virsh
from fab import testsuite
from fab import remote
from fab import logutil
from fab import utils
from fab import post


def add_arguments(parser):
    group = parser.add_argument_group("Run arguments", "Arguments controlling how tests are run")
    group.add_argument("--workers", default="1", type=int,
                       help="default: %(default)s")


def log_arguments(logger, args):
    logger.info("Runner arguments:")
    logger.info("  workers: %s", args.workers)


TEST_TIMEOUT = 120

class TestDomain:

    def __init__(self, domain_name, test):
        self.test = test
        # Get the domain
        self.domain = virsh.Domain(domain_name)
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

    def __init__(self, logger, test, domain_names):
        self.logger = logger
        # Create a table of test domain objects; they are used during
        # cleanup; and they are used as the values of the JOBS table.
        self.test_domains = {}
        for domain_name in domain_names:
            test_domain = TestDomain(domain_name, test)
            self.test_domains[domain_name] = test_domain

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


def wait_for_jobs(jobs, logger):
    logger.debug("waiting for jobs %s", jobs)
    for job in futures.as_completed(jobs):
        logger.debug("job %s on %s completed", job, jobs[job])
        # propogate any exception
        job.result()


def execute_on_domains(executor, jobs, logger, domains, work):
    for domain in domains:
        submit_job_for_domain(executor, jobs, logger, domain, work)
    wait_for_jobs(jobs, logger)


def run_test(test, max_workers=1):
    # Lots of WITH/TRY blocks so things always clean up.

    # Time just this test
    logger = logutil.getLogger(__name__, test.name)
    logger.info("starting test")

    with TestDomains(logger, test, testsuite.DOMAIN_NAMES) as all_test_domains:
        try:

            # Python doesn't have an easy way to obtain an executor's
            # current jobs (futures) so track them using the JOBS map.
            # If there's a crash, any remaining members of JOBS are
            # canceled or killed in the finally block below.  The
            # executor is cleaned up explicitly in the finally clause.
            executor = futures.ThreadPoolExecutor(max_workers=max_workers)
            jobs = {}
            run_test_on_executor(executor, jobs, logger, test, all_test_domains)

        finally:

            # Control-c, timeouts, along with any other crash, and
            # even a normal exit, all end up here!
            logger.info("finishing test")

            # Start with a list of jobs still in the queue; one or
            # more of them may be running.
            done, not_done = futures.wait(jobs, timeout=0)
            logger.debug("jobs done %s not done %s", done, not_done)
            # First: cancel all outstanding jobs (otherwise killing
            # one job would just result in the next job starting).
            # Calling cancel() on running jobs has no effect so need
            # to stop them some other way; ulgh!
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
            # finally shutdown the executor; it will reap all the
            # crashed jobs.
            executor.shutdown()

def strset(s):
    return " ".join(str(e) for e in s)

def run_test_on_executor(executor, jobs, logger, test, all_test_domains):

    test_domains = set()
    for domain_name in test.domain_names():
        test_domains.add(all_test_domains[domain_name])
    logger.debug("test domains: %s", strset(test_domains))

    idle_test_domains = set()
    for test_domain in all_test_domains.values():
        if test_domain not in test_domains:
            idle_test_domains.add(test_domain)
    logger.info("idle domains: %s", strset(idle_test_domains))
    for test_domain in idle_test_domains:
        submit_job_for_domain(executor, jobs, logger, test_domain,
                              TestDomain.shutdown)
    wait_for_jobs(jobs, logger)
    
    # There's a tradeoff here between speed and reliability.
    #
    # In theory, since booting is largely I/O bound, and the host has
    # multiple cores, it should be possible to have several domains
    # booting in parallel; hence separate boot and login jobs (domains
    # continue to boot after the boot jobs finish).
    #
    # In reality, the boot process sometimes becomes gets bogged down,
    # taking longer than expected, and resulting in timeouts.  For
    # instance, if more than two domains are booting at once, or the
    # host is busy with other jobs.

    boot_and_login = True
    if boot_and_login:
        logger.info("boot and login domains: %s", strset(test_domains))
        execute_on_domains(executor, jobs, logger, test_domains, TestDomain.boot_and_login)
    else:
        logger.info("boot domains: %s", strset(test_domains))
        execute_on_domains(executor, jobs, logger, test_domains, TestDomain.boot)
        logger.info("login domains: %s", strset(test_domains))
        execute_on_domains(executor, jobs, logger, test_domains, TestDomain.login)

    # re-direct the test-result log file
    for test_domain in test_domains:
        output = os.path.join(test.output_directory,
                              test_domain.domain.name + ".console.verbose.txt")
        test_domain.console.output(open(output, "w"))

    for scripts in test.scripts():
        tasks = " ".join(("%s:%s") % (domain_name, script) for domain_name, script in scripts.items())
        logger.info("running scripts: %s", tasks)
        for domain_name, script in scripts.items():
            submit_job_for_domain(executor, jobs, logger, all_test_domains[domain_name],
                                  lambda test_domain: test_domain.read_file_run(script))
        wait_for_jobs(jobs, logger)
