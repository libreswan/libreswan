#!/usr/bin/env python
import sys
import getopt, sys
import time
import os, commands
import re
from fab import shell

try:
    import argparse
    import pexpect
    import setproctitle
except ImportError , e:
    module = str(e)[16:]
    sys.exit("we require the python module %s " % module)

# XXX: Hack so that shell.Remote can be used.  Should be passed around
# instead of CHILD.
REMOTE = None

# XXX: This function's behaviour should not depend on the presence of
# FILENAME.
def read_exec_shell_cmd( ex, filename, timer):
    if os.path.exists(filename):
        f_cmds = None
        try:
            f_cmds = open(filename, "r")
            for line in f_cmds:
                line = line.strip()    
                # We need the lines with # for the cut --- tuc
                # sections if line and not line[0] == '#':
                if line:
                    REMOTE.run(line, timeout=timer)
        finally:
            if f_cmds:
                f_cmds.close
    else:
        REMOTE.run(filename, timeout=timer)

def connect_to_kvm(args):

    prompt = str(shell.PromptPattern(username="root", hostname=args.hostname))
    print "Shell prompt: " + prompt

    vmlist = commands.getoutput("sudo virsh list")
    running = 0
    for line in vmlist.split("\n")[2:]:
       try:
            num,host,state = line.split()
            if host == args.hostname and state == "running":
               running = 1
               print "Found %s running already" % args.hostname
               continue
       except:
               pass

    if args.reboot:
       waittime = 20
       if not running:
            print "Booting %s - pausing %s seconds" % (args.hostname,waittime)
            commands.getoutput("sudo virsh start %s" % args.hostname)
            time.sleep(waittime)
       else:
            commands.getoutput("sudo virsh reboot %s" % args.hostname)
            print "Rebooting %s - pausing %s seconds" % (args.hostname,waittime)
            time.sleep(waittime)

    print "Taking %s console by force" % args.hostname
    cmd = "sudo virsh console --force %s" % args.hostname
    timer = 120
    child = pexpect.spawn(cmd)
    child.delaybeforesend = 0
    child.logfile = sys.stdout

    done = 0
    tries = 60
    print "Waiting on %s login: or shell prompt" % (args.hostname)
    while not done and tries != 0:
      try:
        print "sending ctrl-c return"
        #child = pexpect.spawn (cmd)
        #child.sendcontrol('c')
        child.sendline ('')
        print "found, waiting on login: or shell prompt"
        res = child.expect (['login: ', prompt], timeout=3) 
	if res == 0:
           print "sending login name root"
           child.sendline ('root')
           print "found, expecting password prompt"
           child.expect ('Password:', timeout=1)
           print "found, sending password"
           child.sendline ('swan')
           print "waiting on root shell prompt"
           child.expect ('root.*', timeout=1)
           print "done"
           done = 1
        elif res == 1:
          print  '----------------------------------------------------'
          print  'Already logged in as root on %s' % args.hostname
          print  '----------------------------------------------------'
          done = 1
      except:
        print "(%s [%s] waiting)" % (args.hostname,tries)
        tries -= 1
        time.sleep(1)
 
    if not done:
        print 'console is not answering on host %s, aborting'%args.hostname
        return 0

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

def compile_on(args, remote):
    remote.chdir(args.sourcedir)
    timer = 900
    cmd = "%s/testing/guestbin/swan-build" % (args.sourcedir)
    status = remote.run(cmd, timeout=timer)
    if status:
        sys.exit(status)

def make_install(args, remote):
    remote.chdir(args.sourcedir)
    timer=300
    cmd = "%s/testing/guestbin/swan-install" % (args.sourcedir)
    status = remote.run(cmd, timeout=timer)
    if status:
        sys.exit(status)

def run_test(args, child):
    #print 'HOST : ', args.hostname 
    #print 'TEST : ', args.testname

    timer = 120
    REMOTE.chdir("%s/pluto/%s " % (args.testdir, args.testname))

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
    parser.add_argument('--run', action='store', help='run <command> then exit')
    parser.add_argument('--runtime', type=float, default=120, help='max run-time (timeout) for the run command')
    # unused parser.add_argument('--timer', default=120, help='timeout for each command for expect.')
    args = parser.parse_args()

    if args.final:
        child = connect_to_kvm(args)
    else :
        child = connect_to_kvm(args) 

    if not child:
        sys.exit("Failed to launch/connect to %s - aborted" % args.hostname)

    # This puts the remote end into the correct stty mode.
    REMOTE = shell.Remote(child, hostname=args.hostname, username="root")

    if args.run:
        REMOTE.chdir(args.sourcedir)
        status = REMOTE.run(args.run, timeout=args.runtime)
        sys.exit(status)

    if args.compile:
        compile_on(args, REMOTE) 

    if args.install:
        make_install(args, REMOTE) 

    if (args.testname and not args.final):
        run_test(args,child)

    if args.final:
        run_final(args,child)

if __name__ == "__main__":
    main()
