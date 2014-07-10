#!/usr/bin/python
import threading
import time
import os, commands
import getopt, sys
import sys
import re
import ujson
import os,sys,socket,shutil
import logging

try:
	import argparse
	import pexpect
	import setproctitle
except ImportError as e:
	module = str(e)[16:]
	sys.exit("we requires the python module %s "%module)

#hosts = ['east', 'west', 'road', 'nic', 'north']
r_init = threading.Event()
i_ran = threading.Event()
n_init = threading.Event()


class guest (threading.Thread):
	def __init__(self, hostname, role, testname, args, install=None, compile=None):
		threading.Thread.__init__(self)
		self.hostname = hostname
		self.role = role
		self.testname = testname 
		self.status = "NEW"
		self.bootwait = args.bootwait

		self.reboot = True
		if args.noreboot:
			self.reboot = None

	def run(self):
		self.start = time.time()
		e = self.boot_n_grab_console()
		logging.info("%s Exiting  ran %s sec %s",  self.hostname, (time.time() - self.start), e)
		self.status = "INIT"
		if e:
			self.clean_abort();
		else:
			e = self.run_test()

		if not e:
			e = "end" 
		self.log_line('./OUTPUT/RESULT', e)

	def boot_n_grab_console(self):
		e = self.connect_to_kvm()
		if e:
			self.clean_abort();
			return e

		
	def clean_abort(self):
	   # we are aborting set all waiting events end of show.
	   logging.debug("%s set all eventes to abort", self.hostname)
	   r_init.set()
	   n_init.set()
	   i_ran.set()
				

	def run_test(self):

		# now on we MUST match the entire prompt, 
		# or elsewe end up sending too soon and getting mangling!

		prompt = "\[root@%s %s\]# "%(self.hostname, self.testname)
		logging.debug ("%s role %s running test %s prompt %s",
				self.hostname, self.role, self.testname, prompt.replace("\\",""))

		child = self.child
		timer = 120
		ret = True

		cmd = "cd /testing/pluto/%s " % (self.testname)
		child.sendline(cmd)
		try:
			child.expect (prompt, searchwindowsize=100,timeout=timer) 
		except:
			err = "failed [%s] test directory" %(cmd)
			logging.error("%s", self.hostname, err)
			return err

		if(self.role == "initiator"):
			start = time.time()
			logging.info("%s wait for responder and may be nic to initialize", 
					self.hostname)
			n_init.wait()
			logging.debug("%s wait for responder to initialize", self.hostname)
			r_init.wait()
			logging.info("%s initiator is ready waited %s", self.hostname,
					(time.time() - start))

		output_file = "./OUTPUT/%s.console.verbose.txt" % (self.hostname)
		f = open(output_file, 'w')
		child.logfile = f
		
		self.status = "INIT-RUN"
		cmd = "./%sinit.sh" %  (self.hostname) 
		e = read_exec_shell_cmd( child, cmd, prompt, timer, self.hostname)

		if (self.role == "responder"):
			r_init.set()

		if (self.role == "nic"):
			n_init.set()

		if e :
			f.close
			return e

		cmd = "./%srun.sh" %  (self.hostname) 
		if os.path.exists(cmd):
			e = read_exec_shell_cmd( child, cmd, prompt, timer, self.hostname)
			i_ran.set()
			if e:
				f.close
				return e
		else: 
			start = time.time()
			print("waiting for initiator to finish run")
			i_ran.wait()
			print("initiator is ran waited %s"%(time.time() - start))

		cmd = "./final.sh"
		if os.path.exists(cmd):
			e =  read_exec_shell_cmd( child, cmd, prompt, timer, self.hostname)
			if e:
				f.close 
				return e   
		f.close

	def log_line(self, filename, msg):

		if not self.testname:
			return

		logline = dict ()
		#output_file = "./OUTPUT/RESULT"
		f = open(filename, 'a')
		logline ["epoch"] = time.time()
		logline ["hostname"]  =  self.hostname 
		logline ["testname"]  =  self.testname 
		logline ["msg"] = msg 
		logline ["runtime"] = time.time() - self.start
		logline ["time"] = time.strftime("%Y-%m-%d %H:%M", time.localtime())
		f.write(ujson.dumps(logline, ensure_ascii=True,  double_precision=2))
		f.write("\n")
		f.close

	def connect_to_kvm(self):

		prompt = "\[root@%s " % (self.hostname) 

		vmlist = commands.getoutput("sudo virsh list")
		running = 0
		for line in vmlist.split("\n")[2:]:
			try:
				num,host,state = line.split()
				if host == self.hostname and state == "running":
					running = 1
					print("Found %s running already"%self.hostname)
					continue
			except:
				pass

		bootwait = self.bootwait
		pause = bootwait

		if bootwait > 15:
			pause = 15

		if not running:
				print("Booting %s - pausing %s seconds"%(self.hostname,pause))
				v_start = commands.getoutput("sudo virsh start %s"%self.hostname)
				re_e = re.search(r'error:', line, re.I )
				if re_e:
					self.log_line('./OUTPUT/stop-tests-now', v_start)
					self.log_line('../stop-tests-now', v_start)
					# show ends here
					

				time.sleep(pause)
		elif self.reboot :
				commands.getoutput("sudo virsh reboot %s"%self.hostname)
				print("Rebooting %s - pausing %s seconds"%(self.hostname,pause))
				time.sleep(pause)

		print("Taking %s console by force"%self.hostname)
		cmd = "sudo virsh console --force %s"%self.hostname
		timer = 120
		child = pexpect.spawn(cmd)
		child.delaybeforesend = 0.1
		self.child = child
		# child.logfile = sys.stdout
		# don't match full prompt, we want it to work regardless cwd

		done = 0
		tries =  bootwait - pause + 1

		print("Waiting on %s login: %s"%(self.hostname, prompt))
		while not done and tries != 0:
				try:
					child.sendline ('')
					print("found, waiting on login: or %s"%prompt)
					res = child.expect (['login: ', prompt], timeout=3) 
					if res == 0:
							print("sending login name root")
							child.sendline ('root')
							print("found, expecting password prompt")
							child.expect ('Password:', timeout=1)
							print("found, sending password")
							child.sendline ('swan')
							print("waiting on root shell prompt")
							child.expect ('root.*', timeout=1)
							print("got prompt %s"%prompt.replace("\\",""))
							done = 1
					elif res == 1:
							print('----------------------------------------------')
							print(' Already logged in as root on %s'%prompt.replace("\\",""))
							print('----------------------------------------------')
							done = 1
				except:
					print("(%s [%s] waiting)"%(self.hostname,tries))
					tries -= 1
					time.sleep(1)

		if not done:
			err = '%s abort console is not answering'%self.hostname
			logging.error(err)
			self.log_line('../stop-tests-now', err)
			return err

		child.sendline ('TERM=dumb; export TERM; unset LS_COLORS')
		res = child.expect (['login: ', prompt], timeout=3) 
		child.setecho(False) ## this does not seems to work
		child.sendline("stty sane")
		res = child.expect (['login: ', prompt], timeout=3) 
		child.sendline("stty -onlcr")
		res = child.expect (['login: ', prompt], timeout=3) 
		child.sendline("stty -echo")
		res = child.expect (['login: ', prompt], timeout=3) 

# end of class 

def shut_down_hosts(args, test_hosts):

	running = []
	all_hosts = list(DEFAULTCONFIG['swanhosts'])
	all_hosts.extend(DEFAULTCONFIG['regualrhosts'])

	if args.noreboot:
		logging.debug("all hosts [%s] shutdown list", ' '.join(map(str, all_hosts)))
		logging.debug("remove [%s] from shutdown list", ' '.join(map(str, test_hosts)))
		for h in hosts:
			for t in test_hosts:
				if h == t:
					all_hosts.remove(t)

	logging.debug("shutdown list [%s] ", ' '.join(map(str, all_hosts)))

	vmlist = commands.getoutput("sudo virsh list")
	for line in vmlist.split("\n")[2:]:
		try:
			num,host,state = line.split()
			for h in all_hosts:
				if h == host:
					running.append(host)
					cmd = "sudo virsh shutdown %s"%host
					logging.debug("Found %s %s shutodwn send %s", host, state, cmd)
					shut = commands.getoutput(cmd)
		except:
			pass 

	tries = args.shutdownwait
	while len(running) and tries != 0:
		logging.info("Found %s guests [%s] running. Wait upto %d seconds to shutdown", len(running),
				' '.join(map(str, running)), tries)

		del running[:]
		try:
			vmlist = commands.getoutput("sudo virsh list")
			for line in vmlist.split("\n")[2:]:
				try:
					num,host,state = line.split()
					for h in all_hosts:
						if h == host:
							running.append(host)
				except:
					pass 
		except:
			pass
		tries -= 1
		time.sleep(1)
	if len(running):
		e = "abort not able to shutdown %s guests: [%s]" % (len(running), ' '.join(map(str, running)))
		logging.error (e)
		return e

def orient (t):
	test_hosts = []
	if not os.path.exists("eastrun.sh"):
		t["responder"] = "east"
	else:
		sys.exit ("ABORT can't identify RESPONDER no %s/eastinit.sh"%os.getcwd())

	if os.path.exists("nicinit.sh"):
		t["nic"] = "nic"
		test_hosts.append(t["nic"])
	
	pcap_file = "swan12.pcap" 
	tcpdump_dev ="swan12"
	tcpdump_filter = "not stp and not port 22"

	if os.path.exists("westrun.sh"):
		t["initiator"] = "west"
	elif os.path.exists("roadrun.sh"):
		t["initiator"] = "road"
	elif os.path.exists("northrun.sh"):
		t["initiator"] = "north"
		pcap_file = "swan13.pcap" 
		tcpdump_dev = "swan13"
	else:
		sys.exit("ABORT can't identify INITIATOR in directory %s"%os.getcwd())

	test_hosts.append(t["initiator"])
	test_hosts.append(t["responder"])

	cmd = "/sbin/tcpdump -s 0 -w ./OUTPUT/%s -n -i %s %s &" %(pcap_file, tcpdump_dev, tcpdump_filter) 

	return cmd, test_hosts

def read_exec_shell_cmd(ex, filename, prompt, timer, hostname = ""):

	if os.path.exists(filename):
		logging.debug("%s execute commands from file %s", hostname, filename)
		f_cmds = open(filename, "r")
		for line in f_cmds:
			if os.path.isfile("./OUTPUT/stop-tests-now"):
				return "aborting found ./OUTPUT/stop-tests-now"

			line = line.strip()    
			# We need the lines with # for the cut --- tuc sections
			# if line and not line[0] == '#':
			if line:
				print("%s: %s"%(prompt.replace("\\",""), line))
				ex.sendline(line)
				try:
					ex.expect (prompt,timeout=timer, searchwindowsize=100) 
				except:
					err = "%s failed to send line: %s"%(prompt,line)
					logging.error(err)
					f_cmds.close
					return err

		f_cmds.close

	else:
		# not a file name but a command send it as it is.
		print(filename)
		ex.sendline(filename)
		try:
			ex.expect (prompt,timeout=timer, searchwindowsize=100)
		except:
			err = "%s failed to send command: %s"%(prompt, filename)
			logging.debug("%s %s", hostname, err)
			return	err
# kill any lingering tcpdumps
def kill_zombie_tcpdump():
	pids = commands.getoutput("pidof tcpdump")
	for pid in (pids.split()):
		logging.info("Killing existing tcpdump process %s", pid)
		os.kill(int(pid),9)

# kill all hanging previous of instance of this script.
def kill_zombies(proctitle):
	me = os.getpid()
	zombie_pids = commands.getoutput("pidof %s"%proctitle)
	for pid in ( zombie_pids.split() ):
		if int(pid) != int(me):
			logging.info ("Killing existing %s VM controllers pid %s from [%s] my pid %s", proctitle, pid, zombie_pids, me)
			os.kill(int(pid),9)
	kill_zombie_tcpdump()

def init_output_dir():
	output_dir="%s/OUTPUT"%os.getcwd()

	if os.path.isdir(output_dir):
		shutil.rmtree(output_dir) 
	os.mkdir(output_dir, 0o777) 
	
def sanitize(cmd):
	sanity =  commands.getoutput(cmd)
	logging.info ("sanitizer output %s", sanity.replace("\n", " "))
	return sanity

def write_result(args, start, testname, sanity, result = 'FAILED', e = None):

	if sanity:
		for line in sanity.split("\n")[2:]:
			try:
				key,name,value = line.split()
				if key == "result":
					result = value
			except:
				pass

	logline = dict ()
	output_file = "./OUTPUT/RESULT"
	f = open(output_file, 'a')
	logline ["epoch"] = time.time()
	logline ["testname"]  =  testname 
	logline ["result"] = result 
	logline ["time"] = time.strftime("%Y-%m-%d %H:%M", time.localtime())
	logline ["runtime"] = time.time() - start
	if e:
		logline ["error"] = e 
	f.write(ujson.dumps(logline, ensure_ascii=True, double_precision=2))
	f.write("\n")
	f.close

DEFAULTCONFIG =  { 
	'resultsdir' : '/home/build/testresults',
	'sanitizer' : "../../utils/sanitize.sh",
	'bootwait' : 60, 
	'swanhosts' : ['east', 'west', 'rooad', 'north'],
	'regualrhosts' : ['nic'],
	'shutdownwait': 21
}

def cmdline():
	parser = argparse.ArgumentParser(description='dotest arguments.')

	parser.add_argument("--newrun",
						default=None, action="store_true",
						help="overwrite the results in %s. Default None"%DEFAULTCONFIG['resultsdir'])
	parser.add_argument("--resultdir",
						default=DEFAULTCONFIG['resultsdir'],
						help="test results directory %s"%DEFAULTCONFIG['resultsdir'])
	parser.add_argument("--sanitizer",
						default=DEFAULTCONFIG['sanitizer'],
						help="sanitizer script. %s"%DEFAULTCONFIG['sanitizer'])
	parser.add_argument("-v", "--verbose",
						default=1, type=int,
						help="increase verbosity: 0 = only warnings, 1 = info, 2 = debug. Default info")
	parser.add_argument("--bootwait",
						default=DEFAULTCONFIG['bootwait'], type=int,
						help="seconds to reboot guest. Default %s seconds"%DEFAULTCONFIG['bootwait'])
	parser.add_argument("--shutdownwait",
						default=DEFAULTCONFIG['shutdownwait'], type=int, 
						help="seconds to wait for guest to shutdown. Default %s seconds"%DEFAULTCONFIG['shutdownwait'])
	parser.add_argument('--testname', '-t',
						help='The name of the test to run.')
	parser.add_argument('--noreboot',
						default=None, action="store_true", 
						help='Dont reboot vm. Default reboot')
	parser.add_argument('--leavezombies',
						default=None, action="store_true", 
						help='leave other instances running. Default kill all other swantest and lingering tcpdump') 

	args = parser.parse_args()

	proctitle="swantest"
	if not args.leavezombies:
		kill_zombies(proctitle)

	setproctitle.setproctitle(proctitle)
	logger =  logging.getLogger()
	if args.verbose == 0:
		logger.setLevel(logging.WARN) 
	elif args.verbose == 1:
		logger.setLevel(logging.INFO) 
	elif args.verbose == 2:
		logger.setLevel(logging.DEBUG) 

	return args

def do_test(args, start=''):
	if not start:
		start = time.time() 

	args = cmdline() 

	testname = ''
	if args.testname:
		testname =	args.testname
	else: 
		testname = os.path.basename(os.getcwd())

	logging.info("***** KVM PLUTO RUNNING test %s *******", testname)

	t = dict()
	tcpdump_cmd, test_hosts = orient(t)

	e = shut_down_hosts(args, test_hosts)

	init_output_dir()

	if e:
		write_result(args, start, testname, None, "abort", e) 
		kill_zombie_tcpdump()
		# we can't call exit(1) "make check" will abort then
		return e

	os.system(tcpdump_cmd)

	r_init.clear()
	i_ran.clear()
	n_init.clear()

	# Create new threads
	th_responder = guest(t["responder"], "responder", testname, args)
	if "nic" in t:
		th_nic = guest(t["nic"], "nic", testname, args)
	th_initiator = guest(t["initiator"], "initiator", testname, args)

	# Start new Threads
	th_responder.start() 
	if "nic" in t:
		th_nic.start()	
	else:
		n_init.set()

	th_initiator.start()

	th_responder.join()
	th_initiator.join()
	if "nic" in t:
		th_nic.join()

	kill_zombie_tcpdump()

	s = sanitize(args.sanitizer)
	write_result(args, start, testname, s)

def do_test_list(args, start):
	r = "./TESTLIST"
	if not os.path.exists(r):
		return None 

	logging.info("** found file %s **" , r)

	date_dir = time.strftime("%Y-%m-%d", time.localtime())
	output_dir = args.resultdir + '/' + date_dir 
	if not os.path.exists(args.resultdir):
		try:
			os.mkdir(args.resultdir, 0o755)
		except:
			logging.error("failed to create directory %s", args.resultdir)
	else:
		logging.info("testresult directory %s exist", args.resultdir)

	if not os.path.exists(output_dir):
		try:
			os.mkdir(output_dir, 0o755)
		except:
			logging.error("failed to create directory %s", output_dir)
	else:
		logging.info("sub directory %s exist", output_dir)

	s = './stop-tests-now'
	if os.path.exists('./stop-tests-now'):
		os.unlink(s)
		logging.debug("removing existing %s"%s)

	f = open(r, 'r')
	for line in f: 
		logging.debug("%s", line)
		if os.path.exists('./stop-tests-now'):
			logging.error("* stop all tests now. Found ./stop-tests-now *")
			return True 

		try:
			testtype, testdir, testexpect = line.split() 
		except:
			continue

		if testtype[0] == '#':
			# skip the comments
			continue
		elif testtype == "skiptest":
			logging.error("****** %s", line)
			continue
		elif testtype  != "kvmplutotest":
			logging.error("****** skip test %s yet to be migrated to kvm style ", testdir)
			continue
		elif not os.path.exists(testdir):
			logging.error("**** Skipping non-existing cwd %s/%s *****",
					os.getcwd(), testdir)
			continue 

		r_dir = output_dir + '/' + testdir  + '/OUTPUT/RESULT'
		if (not args.newrun) and os.path.exists(r_dir):
			logging.info("result [%s] exist and not newrun. skip this test", r_dir)
			continue 
		else:
			logging.debug("%s is not there run this test", r_dir)

		os.chdir(testdir)
		if os.path.exists('./stop-tests-now'):
			logging.error("****** skip test %s found stop-tests-now *****", testdir) 

		logging.debug("****** next test %s *****", testdir) 
		do_test(args)
		os.chdir("../")
		if os.path.exists(output_dir):
			try:
				cmd="/usr/bin/rsync -q -aP %s %s/"%(testdir, output_dir)
				logging.debug("%s %s", os.getcwd(), cmd)
				os.system(cmd)
			except:
				pass
		else:
			logging.inofo("missing output dir %s. don't copy results",output_dir)

	f.close
	return True

def main():
	start = time.time() 
	args = cmdline() 

	if not do_test_list(args, start): #try if there is a TESTLIST
		do_test(args,start)  # no TESTLIST. Lets try single test

if __name__ == "__main__":
	main()
