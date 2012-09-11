#!/usr/bin/python

import sys, os, commands, glob

# use the known MAC address to figure out who we are
# we use the eth0 table from baseconfigs/net*sh
macs = {}
macs['nic'] = "12:00:00:de:ad:ba"
macs['beet'] = "12:00:00:de:76:ba"
macs['carrot'] = "12:00:00:de:76:bb"
macs['east'] = "12:00:00:dc:bc:ff"
macs['west'] = "12:00:00:ab:cd:ff"
macs['north'] = "12:00:00:de:cd:49"
macs['pole'] = "12:00:00:de:cd:01"
macs['road'] = "12:00:00:ab:cd:02"
macs['sunrise'] = "12:00:00:dc:bc:01"
macs['sunset'] = "12:00:00:ab:cd:01"
macs['japan'] = "12:00:00:ab:cd:02"

eth0 = commands.getoutput("ip link show eth0")
for hostname in macs.keys():
	mac =  macs[hostname]
	if mac in eth0:
		# print "we are %s"%hostname
		# we seem to have found our identity
		commands.getoutput("mount --bind /testing/baseconfigs/%s/etc/sysconfig/network /etc/sysconfig/network"%hostname)
		ifaces = glob.glob("/testing/baseconfigs/%s/etc/sysconfig/network-scripts/ifcfg*"%hostname)
		routes = glob.glob("/testing/baseconfigs/%s/etc/sysconfig/network-scripts/route*"%hostname)
		for entry in (ifaces + routes):
			fname = os.path.basename(entry)
			if not os.path.isfile("/etc/sysconfig/network-scripts/%s"%fname):
				fp = open("/etc/sysconfig/network-scripts/%s"%fname,"w")
				fp.close()
			commands.getoutput("mount --bind %s /etc/sysconfig/network-scripts/%s"%(entry,fname))
		sys.exit()
sys.exit("Failed to find our swan hostname based on the mac of eth0")
