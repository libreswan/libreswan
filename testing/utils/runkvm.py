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
                # give the prompt time to appear
		time.sleep(0.5)
                print "%s: %s"%(prompt.replace("\\",""), line)
                ex.sendline(line)
                try:
                    ex.expect (prompt,timeout=timer, searchwindowsize=100) 
                except:
                    print "%s failed to send line: %s"%(prompt,line)
                    return
    else:
        print  filename 
        ex.sendline(filename)
        try:
            ex.expect (prompt,timeout=timer, searchwindowsize=100)
        except:
            print "%s failed to send filename: %s"%(prompt,filename)
    return

def connect_to_kvm(args):
    vmlist = commands.getoutput("sudo virsh list")
    running = 0
    for line in vmlist.split("\n")[2:]:
       try:
            num,host,state = line.split()
            if host == args.hostname and state == "running":
               running = 1
               print "Found %s running already"%args.hostname
               continue
       except:
               pass

    if args.reboot:
       waittime = 30
       if not running:
            print "Booting %s - pauzing %s seconds"%(args.hostname,waittime)
            commands.getoutput("sudo virsh start %s"%args.hostname)
            time.sleep(waittime)
       else:
            commands.getoutput("sudo virsh reboot %s"%args.hostname)
            print "Rebooting %s - pauzing %s seconds"%(args.hostname,waittime)
            time.sleep(waittime)

    print "Taking %s console by force"%args.hostname
    cmd = "sudo virsh console --force %s"%args.hostname
    timer = 180
    child = pexpect.spawn (cmd)
    # don't match full prompt, we want it to work regardless cwd
    prompt = "root@%s " % (args.hostname) 

    done = 0
    tries = 30
    print "Waiting on %s login: or %s prompt"%(args.hostname, prompt)
    while not done and tries != 0:
      try:
        child = pexpect.spawn (cmd)
        child.sendcontrol('c')
        child.sendline ('')
        res = child.expect (['login: ', prompt], timeout=3) 
	if res == 0:
           child.sendline ('root')
           child.expect ('Password:', timeout=1)
           child.sendline ('swan')
           child.expect ('root.*', timeout=1)
           done = 1
        elif res == 1:
          print  '----------------------------------------------------'
          print  'Already logged in as root on %s'%args.hostname
          print  '----------------------------------------------------'
          done = 1
      except:
        print "(%s [%s] waiting)"%(args.hostname,tries)
        tries -= 1
        time.sleep(1)
 
    if not done:
        print 'console is not answering on host %s, aborting'%args.hostname
        return 0


    child.sendline ('TERM=dumb; export TERM; unset LS_COLORS')
    child.setecho(False) ## this does not seems to work
    child.sendline("stty sane")
    child.sendline("stty -echo")
    return child

def run_final (args, child):
    timer = 30
    prompt = "\[root@%s %s\]# "%(args.hostname, args.testname)
    output_file = "./OUTPUT/%s.console.verbose.txt" % (args.hostname)
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
    #print 'HOST : ', args.hostname 
    #print 'TEST : ', args.testname

    timer = 120
    # we MUST match the entire prompt, or elsewe end up sending too soon and getting mangling!
    prompt = "\[root@%s %s\]# "%(args.hostname, args.testname)

    cmd = "cd /testing/pluto/%s " % (args.testname)
    print "%s: %s"%(prompt.replace("\\",""),cmd)
    child.sendline(cmd)
    try:
        child.expect (prompt, searchwindowsize=100,timeout=timer) 
    except:
        print "%s: failed to cd into test case at %s"%(args.hostname,args.testname)
        return

    output_file = "./OUTPUT/%s.console.verbose.txt" % (args.hostname)
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
	
    cmd = "./%sinit.sh" %  (args.hostname) 
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = "./%srun.sh" %  (args.hostname) 
    if os.path.exists(cmd):
        read_exec_shell_cmd( child, cmd, prompt, timer)
        f.close
    else:
	    f.close 
    return  

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
    # unused parser.add_argument('--timer', default=120, help='timeout for each command for expect.')
    args = parser.parse_args()

    child = connect_to_kvm(args)
    if not child:
	sys.exit("Failed to launch/connect to %s - aborted"%args.hostname)

    if args.compile:
        compile_on(args,child) 

    if args.install:
        make_install(args,child) 

    if (args.testname and not args.final):
        run_test(args,child)

    if args.final:
	    run_final(args,child)


if __name__ == "__main__":
    main()
