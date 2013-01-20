#!/usr/bin/env python
import pexpect
import sys
import getopt, sys
import time
import os, commands
import setproctitle
import re

try:
    import argparse
except ImportError , e:
    module = str(e)[16:]
    sys.exit("we requires the python argparse module")

def read_exec_shell_cmd( ex, filename, prompt, timer):
    if os.path.exists(filename):
        f_cmds = open(filename, "r")
        for line in f_cmds:
            line = line.strip()    
            if line and not line[0] == '#':
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

def compile_on (args,child):
    timer = 900
    prompt = "root@%s source"%args.hostname
    cmd = "cd /source/"
    read_exec_shell_cmd( child, cmd, prompt, timer)
    cmd = "rm -fr OBJ*"
    read_exec_shell_cmd( child, cmd, prompt, timer)
    cmd = "make programs module 2>&1 > compile-log.txt"
    read_exec_shell_cmd( child, cmd, prompt, timer)

    return  

def make_install (args, child):
    timer=300
    prompt = "root@%s source"%args.hostname
    cmd = "cd /source/"
    read_exec_shell_cmd( child, cmd, prompt, timer)
    cmd = "make install mdoule_install  2>&1 >> compile-log.txt"
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

    cmd = '/testing/guestbin/swan-prep --testname %s --hostname %s'%(args.testname,args.hostname)
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = "rm -fr /tmp/pluto.log"
    read_exec_shell_cmd( child, cmd, prompt, timer) 

    cmd = 'ln -s /testing/pluto/%s/OUTPUT/pluto.%s.log /tmp/pluto.log'%(args.testname,args.hostname)
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = './testparams.sh'
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = "./%sinit.sh" %  (args.hostname) 
    read_exec_shell_cmd( child, cmd, prompt, timer)

    cmd = "./%srun.sh" %  (args.hostname) 
    if os.path.exists(cmd):
        read_exec_shell_cmd( child, cmd, prompt, timer)
        time.sleep(60)

    cmd = "END of test %s" % (args.testname)
    f.write(cmd)
    f.close 

    return  

def main():

    parser = argparse.ArgumentParser(description='runkvm arguments.')
    parser.add_argument('--testname', '-t', action='store', help='The name of the test to run.')
    parser.add_argument('--hostname', '-H', action='store', default='east', help='The name of the host to run.')
    parser.add_argument('--compile', action="store_true", help='compile the source on host <hostname>.')
    parser.add_argument('--install', action="store_true", help='run make install module_install .')
    parser.add_argument('--reboot', action="store_true", help='first reboot the host')
    parser.add_argument('--timer', default=120, help='timeout for each command for expect.')
    args = parser.parse_args()

    child = connect_to_kvm(args)
    if args.compile:
        compile_on(args,child) 

    if args.install:
        make_install(args,child) 

    if args.testname:
        run_test(args,child)
    return

if __name__ == "__main__":
    main()
