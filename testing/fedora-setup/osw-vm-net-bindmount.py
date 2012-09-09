#!/usr/bin/python

import sys, syslog, os, commands, glob

hostname = ""
cmdline = open("/proc/cmdline","r").read().strip()
for entry in cmdline.split(" "):
	try:
		opt,val = entry.split("=",1)
		if opt == "umid":
			hostname = val
	except:
		pass

if not hostname:
	msg = "openswan testing: could not find my hostname, aborted"
	print msg , "\n"
	syslog.syslog(syslog.LOG_ALERT,msg)
	sys.exit()

if not os.path.isdir("/testing/baseconfigs/%s"%hostname):
	msg = "The hostname %s is not known to the testing system"
	print msg , "\n"
	syslog.syslog(syslog.LOG_ALERT,msg)
	sys.exit()

commands.getoutput("mount --bind /testing/baseconfigs/%s/etc/sysconfig/network /etc/sysconfig/network"%hostname)
ifaces = glob.glob("/testing/baseconfigs/%s/etc/sysconfig/network-scripts/ifcfg*"%hostname)
for iface in ifaces:
	fname = os.path.basename(iface)
	if not os.path.isfile("/etc/sysconfig/network-scripts/%s"%fname):
		fp = open("/etc/sysconfig/network-scripts/%s"%fname,"w")
		fp.close()
	commands.getoutput("mount --bind %s /etc/sysconfig/network-scripts/%s"%(iface,fname))

