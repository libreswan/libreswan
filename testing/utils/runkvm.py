#!/usr/bin/env python
import sys
import getopt, sys
import time
import os, commands
import re

try:
    import argparse
    import pexpect
    import setproctitle
except ImportError , e:
    module = str(e)[16:]
    sys.exit("we requires the python module %s "%module)

def read_exec_shell_cmd( ex, filename, prompt, timer):
    if os.path.exists(filename):
        f_cmds = open(filename, "r")
        for line in f_cmds:
            line = line.strip()    
            # We need the lines with # for the cut --- tuc sections
            # if line and not line[0] == '#':
            if line:
                print  line
                ex.sendline(line)  
                ex.expect (prompt,timeout=timer, searchwindowsize=100) 
    else:
        print  filename 
        ex.sendline(filename)
        ex.expect (prompt,timeout=timer, searchwindowsize=100)
    return

def connect_to_kvm(args):
    cmd = "sudo virsh console %s"%args.hostname
    timer = 180
    child = pexpect.spawn (cmd)
    prompt = "root@%s " % (args.hostname) 

    a = child.expect (['Escape.*', 'Active console session exists for this domain', prompt])
    if a==0:
        child.sendline ('')
        i = child.expect (['login: ', 'Active console session exists', prompt], timeout=120) 
        if i==0:
            child.sendline ('root')
            child.expect ('Password:')
            child.sendline ('swan')
            child.expect ('root.*')
            print  'logged in as root on %s'%args.hostname
        elif i==1:
            print 'console is busy on host  %s'%args.hostname
            sys.exit(1) 
    elif i==1:
        print 'console is busy on host  %s'%args.hostname
        sys.exit(1) 

    if args.reboot:
        cmd = "reboot "
        print 'rebooting %s'%args.hostname
        child.sendline(cmd)
        i = child.expect (['login: ', 'Active console session exists', prompt], timeout=120) 
        if i==0:
            child.sendline ('root')
            child.expect ('Password:')
            child.sendline ('swan')
            child.expect ('root.*')
            print  'logged in as root on %s'%args.hostname
    child.sendline ('TERM=dumb; export TERM; unset LS_COLORS')
    child.setecho(False) ## this does not seems to work
    child.sendline("stty -echo")
    return child

def run_final (args, child):

    timer = 180
    prompt = "root@%s %s"%(args.hostname, args.testname)
    output_file = "./OUTPUT/%s.console.txt" % (args.hostname)
    f = open(output_file, 'a') 
    child.logfile = f
    cmd = "./final.sh"
    if os.path.exists(cmd):
        read_exec_shell_cmd( child, cmd, prompt, timer)
    f.close 
    return

def compile_on (args,child):
    timer = 900
    prompt = "root@%s source"%args.hostname
    cmd = "cd /source/"
    read_exec_shell_cmd( child, cmd, prompt, timer)
    cmd = "/testing/guestbin/swan-build"
    read_exec_shell_cmd( child, cmd, prompt, timer)

    return  

def make_install (args, child):
    timer=300
    prompt = "root@%s source"%args.hostname
    cmd = "cd /source/"
    read_exec_shell_cmd( child, cmd, prompt, timer)
    cmd = "/testing/guestbin/swan-install"
    read_exec_shell_cmd( child, cmd, prompt, timer)
    return

def run_test(args, child):
    print 'HOST : ', args.hostname 
    print 'TEST : ', args.testname

    timer = 180
    prompt = "root@%s %s"%(args.hostname, args.testname)

    cmd = "cd /testing/pluto/%s " % (args.testname)
    print cmd
    child.sendline(cmd)
    child.expect (prompt, searchwindowsize=100) 

    output_file = "./OUTPUT/%s.console.txt" % (args.hostname)
    f = open(output_file, 'w') 
    child.logfile = f

    # do we need to prep x509?
    if args.x509:
	# call to runkvm.py forced it
	x509 = "--x509"
    else:
	x509 = ""
	testdir = os.getcwd()
	testparams = open("%s/testparams.sh"%testdir, "r").readlines()
	for line in testparams:
		try:
			(testkey, testvalue) = line.split('=')
			if testkey == "x509" or testkey == "X509":
				x509 = "--x509"
		except:
			pass
	
    cmd = '/testing/guestbin/swan-prep --testname %s --hostname %s %s'%(args.testname,args.hostname, x509)
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = "rm -fr /tmp/pluto.log"
    read_exec_shell_cmd( child, cmd, prompt, timer) 

    cmd = 'ln -s /testing/pluto/%s/OUTPUT/pluto.%s.log /tmp/pluto.log'%(args.testname,args.hostname)
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = "./%sinit.sh" %  (args.hostname) 
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = "./%srun.sh" %  (args.hostname) 
    if os.path.exists(cmd):
        read_exec_shell_cmd( child, cmd, prompt, timer)
        f.close
        run_final(args,child)
    else:
	    f.close 
    return  

def main():

    parser = argparse.ArgumentParser(description='runkvm arguments.')
    parser.add_argument('--testname', '-t', action='store', help='The name of the test to run.')
    parser.add_argument('--hostname', '-H', action='store', default='east', help='The name of the host to run.')
    parser.add_argument('--compile', action="store_true", help='compile the source on host <hostname>.')
    parser.add_argument('--install', action="store_true", help='run make install module_install .')
    parser.add_argument('--x509', action="store_true", help='tell the guest to setup the X509 certs in NSS.')
    parser.add_argument('--final', action="store_true", help='run final.sh on the host.')
    parser.add_argument('--reboot', action="store_true", help='first reboot the host')
    parser.add_argument('--timer', default=120, help='timeout for each command for expect.')
    args = parser.parse_args()

    child = connect_to_kvm(args)
    if args.compile:
        compile_on(args,child) 

    if args.install:
        make_install(args,child) 

    if (args.testname and not args.final):
        run_test(args,child)

    if args.final:
	    run_final(args,child)

    return

if __name__ == "__main__":
    main()
