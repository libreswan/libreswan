#!/usr/bin/python

import syslog

hostname = ""
cmdline = open("/proc/cmdline","r").read()
for entry in cmdline.split(" "):
	try:
		opt,val = entry.split("=",1)
		if opt == "umid":
			hostname = val
	except:
		pass

if not hostname:
	msg = "openswan testing: could not find my hostname, aborted")
	print msg , "\n"
	syslog.syslog(syslog.ALERT,msg)
	sys.exit()

if not os.path.isdir("/testing/baseconfigs/%s"%hostname):
	msg = "The hostname %s is not known to the testing system"
	print msg , "\n"
	syslog.syslog(syslog.ALERT,msg)
	sys.exit()

#print "bind mounting /etc/sysconfig/network and /etc/sysconfig/network-scripts"
mount --bind /testing/baseconfigs/west/etc/sysconfig/network /etc/sysconfig/network
mount --bind /testing/baseconfigs/west/etc/sysconfig/network-scripts /etc/sysconfig/network-scripts


