#!/usr/bin/env python3
import sys
import sys
import time
import os
import subprocess
import re
import argparse
import logging
from fab import shell
from fab import argutil

try:
    import pexpect
    import setproctitle
except ImportError as e:
    module = str(e)[16:]
    sys.exit("we require the python module %s " % module)

# XXX: This function's behaviour should not depend on the presence of
# FILENAME.
def read_exec_shell_cmd(child, filename, timer):
    if os.path.exists(filename):
        f_cmds = None
        try:
            f_cmds = open(filename, "r")
            for line in f_cmds:
                line = line.strip()
                # We need the lines with # for the cut --- tuc
                # sections if line and not line[0] == '#':
                if line:
                    child.run(line, timeout=timer)
        finally:
            if f_cmds:
                f_cmds.close
    else:
        child.run(filename, timeout=timer)

def connect_to_kvm(args):

    vmlist = subprocess.getoutput("sudo virsh list")
    running = 0
    for line in vmlist.split("\n")[2:]:
       try:
            num,host,state = line.split()
            if host == args.hostname and state == "running":
               running = 1
               print("Found %s running already" % args.hostname)
               continue
       except:
               pass

    if args.reboot:
       waittime = 20
       if not running:
            print("Booting %s - pausing %s seconds" % (args.hostname,waittime))
            subprocess.getoutput("sudo virsh start %s" % args.hostname)
            time.sleep(waittime)
       else:
            subprocess.getoutput("sudo virsh reboot %s" % args.hostname)
            print("Rebooting %s - pausing %s seconds" % (args.hostname,waittime))
            time.sleep(waittime)

    print("Taking %s console by force" % args.hostname)
    cmd = "sudo virsh console --force %s" % args.hostname
    timer = 120
    # Need to use spawnu with python3.
    child = shell.Remote(cmd, hostname=args.hostname, username="root")
    child.output(sys.stdout)
    prompt = child.prompt
    print("Shell prompt '%s'" % prompt.pattern)

    done = 0
    tries = 60
    print("Waiting on %s login: or shell prompt" % (args.hostname))
    while not done and tries != 0:
      try:
        print("sending ctrl-c return")
        #child = pexpect.spawn (cmd)
        #child.sendcontrol('c')
        child.sendline ('')
        print("found, waiting on login: or shell prompt")
        res = child.expect (['login: ', prompt], timeout=3)
        if res == 0:
           print("sending login name root")
           child.sendline ('root')
           print("found, expecting password prompt")
           child.expect ('Password:', timeout=1)
           print("found, sending password")
           child.sendline ('swan')
           print("waiting on root shell prompt")
           child.expect (prompt, timeout=1)
           print("done")
           done = 1
        elif res == 1:
          print('----------------------------------------------------')
          print('Already logged in as root on %s' % args.hostname)
          print('----------------------------------------------------')
          done = 1
      except:
        print("(%s [%s] waiting)" % (args.hostname,tries))
        tries -= 1
        time.sleep(1)

    if not done:
        print('console is not answering on host %s, aborting'%args.hostname)
        return None

    # Make certain that both ends are in sync and set up as expected.
    child.sync()

    return child

def run_final (args, child):
    timer = 30
    output_file = "./OUTPUT/%s.console.verbose.txt" % (args.hostname)
    f = open(output_file, 'a')
    child.logfile = f
    cmd = "./final.sh"
    if os.path.exists(cmd):
        read_exec_shell_cmd(child, cmd, timer)
    f.close
    return

def compile_on(args, child):
    child.chdir(args.sourcedir)
    timer = 900
    cmd = "%s/testing/guestbin/swan-build" % (args.sourcedir)
    status = child.run(cmd, timeout=timer)
    if status:
        sys.exit(status)

def make_install(args, child):
    child.chdir(args.sourcedir)
    timer=300
    cmd = "%s/testing/guestbin/swan-install" % (args.sourcedir)
    status = child.run(cmd, timeout=timer)
    if status:
        sys.exit(status)

def run_test(args, child):
    #print 'HOST : ', args.hostname
    #print 'TEST : ', args.testname

    timer = 120
    child.chdir("%s/pluto/%s " % (args.testdir, args.testname))

    output_file = "./OUTPUT/%s.console.verbose.txt" % (args.hostname)
    f = open(output_file, 'w')
    child.logfile = f

    # do we need to prep x509?
    if args.x509:
	# call to runkvm.py forced it
        x509 = "--x509"
    else:
        x509 = ""
	
    cmd = "./%sinit.sh" %  (args.hostname)
    read_exec_shell_cmd(child, cmd, timer)

    cmd = "./%srun.sh" %  (args.hostname)
    if os.path.exists(cmd):
        read_exec_shell_cmd(child, cmd, timer)
        run_final(args,child)
        f.close
    else:
        f.close

def main():
    setproctitle.setproctitle("swankvm")
    parser = argparse.ArgumentParser(description='runkvm arguments.')
    parser.add_argument('--testname', '-t', action='store', help='The name of the test to run.')
    parser.add_argument('--hostname', '-H', action='store', default='', help='The name of the host to run.')
    parser.add_argument('--compile', action="store_true", help='compile the source on host <hostname>.')
    parser.add_argument('--install', action="store_true", help='run make install module_install .')
    parser.add_argument('--x509', action="store_true", help='tell the guest to setup the X509 certs in NSS.')
    parser.add_argument('--final', action="store_true", help='run final.sh on the host.')
    parser.add_argument('--reboot', action="store_true", help='first reboot the host')
    parser.add_argument('--sourcedir', action='store', default='/source', help='source <directory> to build')
    parser.add_argument('--testdir', action='store', default='/testing', help='test <directory> to run tests from')
    parser.add_argument('--runtime', type=argutil.timeout, default=None,
                        help='max run-time (timeout) for the run command (default infinite)')
    parser.add_argument("--log-level", default="warning", metavar="LEVEL",
                        help="Set logging level to %(metavar)s (default: %(default)s)")
    # unused parser.add_argument('--timer', default=120, help='timeout for each command for expect.')
    parser.add_argument('domain', action='store', nargs='?', help="name of the domain to connect to")
    parser.add_argument('command', action='store', nargs='?', help="command to run")
    args = parser.parse_args()
    # HACK: Merge the hostname arguments
    args.hostname = args.hostname or args.domain
    if not args.hostname:
        print("Either hostname or domain must be specified")
        sys.exit(1)

    logging.basicConfig(level=args.log_level.upper())

    child = connect_to_kvm(args)

    if not child:
        sys.exit("Failed to launch/connect to %s - aborted" % args.hostname)

    if args.command:
        child.chdir(args.sourcedir)
        status = child.run(args.command, timeout=args.runtime)
        sys.exit(status)

    if args.compile:
        compile_on(args, child)

    if args.install:
        make_install(args, child)

    if (args.testname and not args.final):
        run_test(args,child)

    if args.final:
        run_final(args,child)

    # if there's nothing else to do, create an interactive shell.
    batch_mode = args.command or args.compile or args.install or args.testname or args.final or args.reboot
    if not batch_mode:

        print()
        print()
        child.output(None)
        print("Escape character is ^]")
        # Hack so that the prompt appears
        child.output(sys.stdout)
        child.run("")
        child.output(None)
        # Normal mode
        child.stty_sane()
        child.interact()

if __name__ == "__main__":
    main()
