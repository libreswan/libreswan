#!/usr/bin/python
#
# Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
#
# Based on old perl and shell code:
# Copyright (C) 2003 Sam Sgro <sam@freeswan.org> 
# Copyright (C) 2005-2008 Michael Richardson <mcr@xelerance.com>
# Copyright (C) 2005-2009 Paul Wouters <paul@xelerance.com>
#
# Based on "verify" from the FreeS/WAN distribution, (C) 2001 Michael 
# Richardson <mcr@freeswan.org>
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

import os, sys, subprocess

# x = subprocess.check_output("/usr/bin/ls -l /tmp/",stderr=subprocess.STDOUT,shell=True)


retcode = 0

confdir = os.getenv("IPSEC_CONFS")
if not confdir:
	# should get substituted by 'make programs'
	confdir = "@IPSEC_DIR@"
	# TEMP DELME
	confdir = "/etc"

ipsecbin = "@IPSEC_SBINDIR@/ipsec"
# TEMP DELME
ipsecbin = "/usr/sbin/ipsec"

if not os.path.isfile(ipsecbin):
	# hopefully somewhere in our path then
	ipsecbin = "ipsec"

if not os.path.isfile("%s/ipsec.conf"%confdir):
	try:
		p = subprocess.Popen("%s --config"%ipsecbin, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
		output, err = p.communicate()
		output = output.strip()
		if os.path.isfile("%s/ipsec.conf"%output):
			confdir = output
	except:
		sys.exit("Failed to find ipsec.conf")

# Should we print in colour by default?
colour = 0
try:
	p = subprocess.Popen("consoletype", stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
	output, err = p.communicate()
	output = output.strip()
	if output in ("vc","tty","pty"):
		colour = 1
except:
	try:
		p = subprocess.Popen("tput colors", stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
		output, err = p.communicate()
		if int(output) > 0:
			colour = 1
	except:
		pass

if colour:
	print "display in colour"
else:
	print "no colour used"


def printfun(text):
	# suppress newline
	sys.stdout.write("%-60s"%text);

def print_result(rcode, rtext):
	global colour
	global retcode
	OK = '\033[92m'
	WARN = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'

	if rcode == "FAIL":
		if not rtext:
			rtext = "FAILED"
		if colour:
			print "\t[%s%s%s]"%(FAIL,rtext,ENDC)
		else:
			print "\t[%s]"%rtext
	elif rcode == "WARN":
		if not rtext:
			rtext = "WARNING"
		if colour:
			print "\t[%s%s%s]"%(WARN,rtext,ENDC)
		else:
			print "\t[%s]"%rtext
	elif rcode == "OK":
		if not rtext:
			rtext = "OK"
		if colour:
			print "\t[%s%s%s]"%(OK,rtext,ENDC)
		else:
			print "\t[%s]"%rtext
	else:
		print "INTERNAL ERROR - unknown rcode:%s"%rcode




# Verification routines begin here...
#
# Check DNS Configuration based on a hostname
# $1 = Hostname (string)
# eg: checkdnshost oetest.freeswan.org
#sub checkdnshost {
#    run "host -t key $_[0]";
#    ($keypresent)=grep /(0x4200|16896)/, @out;
#    if($keypresent) 
#    { 
#	printfun "   Looking for KEY in forward dns zone: $_[0]";
#	deprecated; 
#    }
#
#
#    printfun "   Looking for TXT in forward dns zone: $_[0]";
#    run "host -t txt $_[0]";
#    ($txtpresent)=grep /X-IPsec-Server/,@out;
#    errchk "$txtpresent", "MISSING";
#}

# Check DNS Configuration based on IP address
# $1 = IP Address (string)
# eg: checkdnsip 127.0.0.2
#sub checkdnsip {
#    $fortxt=$_[0];
#    $revtxt=join('.',reverse(split(/\./, $fortxt))).".in-addr.arpa.";
#    printfun "   Looking for TXT in reverse dns zone: $revtxt";
#    run "host -t txt $revtxt";
#    ($txtpresent)=grep /X-IPsec-Server/,@out;
#    errchk "$txtpresent", "MISSING";
#
#    if($txtpresent) {
#	$txtpresent=~ s/.*X-IPsec-Server\([0-9].*\)=//; $txtpresent=~ s/[\"\ ].*//;
#	$gwip=$txtpresent;
#	chomp($gwip);
#	$gwrev=join('.',reverse(split(/\./, $gwip))).".in-addr.arpa.";
#	# Check for a KEY record for the indicated IPSec GW.
#	run "host -t key $gwrev";
#	($keypresent)=grep /(0x4200|16896)/, @out;
#	if($keypresent) 
#	{ 
#	    printfun "   Looking for KEY in reverse dns zone: $gwrev";
#	    deprecated; 
#	    $print_deprecated = 1; 
#
#	}
#	# If the host is its own gateway, then we know we've got a TXT record.
#	if($gwip ne $fortxt) {	
#	    printfun "Looking for TXT in reverse dns zone: $gwrev";
#	    run "host -t txt $gwrev";
#	    ($txtpresent)=grep /X-IPsec-Server/,@out;
#	    errchk "$txtpresent", "MISSING";
#	}
#
#    }
#}

def udp500check():
	printfun(" Pluto listening for IKE on udp 500")
	if 1==1:
		p = subprocess.Popen(["/usr/sbin/ss", "-n", "-l", "-u", "sport = :500"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
		output, err = p.communicate()
		if ":500" in output:
			print_result("OK","OK")
		else:
			print "fail in else:%s"%output
			print_result("FAIL","FAILED")
	else:
			print "except hit?"
			print_result("FAIL","FAILED")

# not yet implemented in *swan
def tcp500check():
	printfun(" Pluto listening for IKE on tcp 500")
	try:
		p = subprocess.Popen(["/usr/sbin/ss", "-n", "-l", "-t", "sport = :500"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
		output, err = p.communicate()
		if ":500" in output:
			print_result("OK","OK")
		else:
			print_result("WARN","NOT IMP")
	except:
			print_result("WARN","NOT IMP")

def udp4500check():
	printfun(" Pluto listening for IKE/NAT-T on udp 4500")
	try:
		p = subprocess.Popen(["/usr/sbin/ss", "-n", "-l", "-u", "sport = :4500"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
		output, err = p.communicate()
		if ":4500" in output:
			print_result("OK","OK")
		else:
			print_result("FAIL","DISABLED")
	except:
			print_result("FAIL","DISABLED")

# not yet implemented in *swan
def tcp4500check():
	printfun(" Pluto listening for IKE/NAT-T on tcp 4500")
	try:
		p = subprocess.Popen(["/usr/sbin/ss", "-n", "-l", "-t", "sport = :4500"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
		output, err = p.communicate()
		if ":4500" in output:
			print_result("OK","OK")
		else:
			print_result("WARN","NOT IMP")
	except:
			print_result("WARN","NOT IMP")

# not yet implemented in *swan
def tcp10000check():
	printfun(" Pluto listening for IKE on tcp 10000 (cisco)")
	try:
		p = subprocess.Popen(["/usr/sbin/ss", "-n", "-l", "-t", "sport = :10000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
		output, err = p.communicate()
		if ":10000" in output:
			print_result("OK","OK")
		else:
			print_result("WARN","NOT IMP")
	except:
			print_result("WARN","NOT IMP")


def main():
	udp500check()
	tcp500check()
	udp4500check()
	tcp4500check()
	tcp10000check()






if __name__ == "__main__":
	main()

## 
## 
## sub checktunnel {
##     $csource=$_[0]; $cdest=$_[1]; $ctun=$_[2]; $all="0.0.0.0/0";
## 
##     printfun "Checking $ctun from $csource to $cdest";
##     run "iptables -t nat -L POSTROUTING -n";
##     @out=grep !/(Chain POSTROUTING|target)/, @out;
##     foreach (@out) {
## 	( $target, $prot, $opt, $source, $dest ) = split(' ',$_);
## 	if(((($source eq $csource) || ($source eq $all)) && (($dest eq $cdest) || ($dest = $all))) && $target eq "ACCEPT")
## 	{ 
## 	    errchk "@out";
## 	    $reterr = 1;
## 	}
## 	else
## 	{
## 	    @err="$target from $source to $dest kills tunnel $source -> $cdest\n";
## 	    errchk "","FAILED";
## 	    $reterr = 1;
## 	}
##     }
## }
## 
## sub installstartcheck {
## 	print "Checking your system to see if IPsec got installed and started correctly:\n";
## 
## 	printfun "Version check and ipsec on-path";
## 	run "ipsec --version";
## 	errchk "@out";
## 	print grep /Linux/, @out;
## 
##         printfun "Checking for IPsec support in kernel";
## 	if ( -e "/proc/net/ipsec_eroute" || -e "/proc/net/pfkey" ) { $test="1" }
## 	errchk "$test";
## 
## # This requires KLIPS NAT-T patch > 2.4.x
## 	if ( -e "/proc/net/ipsec_eroute") {
## 
## 	  printfun " KLIPS: checking for NAT Traversal support";
## 	  if ( -e "/sys/module/ipsec/parameters/natt_available") {
## 		run "cat /sys/module/ipsec/parameters/natt_available";
## 		if("@out" =="1\n")
## 		   { warnchk "", "OLD STYLE"; }
## 		else {
## 		   if("@out" == "2\n")
## 			{ errchk "OK"; }
## 		   else
## 			{ warnchk "", "UNKNOWN"; }
## 		}
## 	   } else { warnchk "","UNKNOWN"; }
## 
## 	  printfun " KLIPS: checking for OCF crypto offload support ";
## 	  if ( -e "/sys/module/ipsec/parameters/ocf_available") {
## 		run "cat /sys/module/ipsec/parameters/ocf_available";
## 		if("@out" =="1\n")
## 		   { errchk "OK"; }
## 		else {
## 			{ warnchk "", "N/A"; }
## 		}
## 	   } else { warnchk "","UNKNOWN"; }
## 
## 	}
## 
## # Check for SAref kernel
## 	  if ( -e "/proc/net/ipsec/saref") {
## 		printfun " Kernel: IPsec SAref kernel support";
## 		run "grep 'refinfo patch applied' /proc/net/ipsec/saref";
## 		if("@out" eq "refinfo patch applied\n")
## 			{ errchk "OK"; }
## 		else
## 			{ warnchk "", "N/A"; }
## 
## 		printfun " Kernel: IPsec SAref Bind kernel support";
## 		run "grep 'bindref patch applied' /proc/net/ipsec/saref";
## 		if("@out" eq "bindref patch applied\n")
## 			{ errchk "OK"; }
## 		else
## 			{ warnchk "", "N/A"; }
## 	   } else {
## 		printfun " SAref kernel support";
## 			{ warnchk "", "N/A"; }
## 	   }
## 
##         if ( -e "/proc/net/pfkey") {
##         printfun " NETKEY:  Testing XFRM related proc values";
##         open("cat", "/proc/sys/net/ipv4/conf/default/send_redirects");
## 	if(<cat> == "1")
## 	    {
## 		errchk "";
## 	        $reterr = 1;
## 		print "\n  Please disable /proc/sys/net/ipv4/conf/*/send_redirects\n  or NETKEY will cause the sending of bogus ICMP redirects!\n\n"; 
## 	    }
## 	else { errchk "1"; } 
## 	
##         open("cat", "/proc/sys/net/ipv4/conf/default/accept_redirects");
## 	if(<cat> == "1")
## 	    {
## 	        $reterr = 1;
## 		errchk "";
## 		print "\n  Please disable /proc/sys/net/ipv4/conf/*/accept_redirects\n  or NETKEY will accept bogus ICMP redirects!\n\n"; 
## 	    }
## 	else { errchk "1"; } 
## 
##         open("cat", "/proc/sys/net/core/xfrm_larval_drop");
## 	if(<cat> == "0")
## 	    {
## 	        $reterr = 1;
## 		errchk "";
## 		print "\n  Please enable /proc/sys/net/core/xfrm_larval_drop\n  or NETKEY will cause non-POSIX compliant long time-outs\n\n"; 
## 	    }
## 	else { errchk "1"; } 
## 	}
## 
##         if ( -c "/dev/hw_random" || -c "/dev/hwrng" ) {
##         printfun "Hardware RNG detected, testing if used properly";
##         run "pidof rngd";
##         ($processid) = @out;
##         chomp($processid);
##         if( $processid eq ""  ) {
## 		run "pidof clrngd";
## 		($processid2) = @out;
## 		if( $processid2 eq ""  ) {
## 			errchk "";
## 			print "\n  Hardware RNG is present but 'rngd' or 'clrngd' is not running.\n  No harware random used!\n\n";
## 			$reterr = 1;
## 			}
## 		else { errchk "1"; }
## 	}
## 	else { errchk "1"; }
## 	}
## 
## 
## 	# Wouldn't this test fail if your mucked up your interface definition?
## 	printfun "Checking that pluto is running";
## 	run "ipsec whack --status";
## 	errchk "@out";
## 	if (grep /interface/, @out)
## 	{
## 	    udp500check;
## 	    udp4500check;
## 	}
## }
## 
## sub tunnelchecks {
##     open("dev", "/proc/net/dev");
##     if((grep !/(ipsec|lo:|Inter|packets)/, <dev>) > 1) 
##     {
## 	printfun "Two or more interfaces found, checking IP forwarding";
##         my ($data, $n);
## 	open FILE, "/proc/sys/net/ipv4/ip_forward" or die $!;
## 	$n = read FILE, $data, 1;
## 	if($data == 1)
## 	{ 
## 	    $reterr = 1;
## 	    errchk "0"; 
## 	} 
## 
## 	printfun "Checking NAT and MASQUERADEing";
## 	# This assumes KLIPS eroute information, we should add support
## 	# for NETKEY, but ip xfrm is very annoying to parse
## 	if(( -e "/proc/net/nf_conntrack" || -e "/proc/net/ip_conntrack")
## && -e "/proc/net/ipsec_eroute" )
## 	{
## 		run "iptables -t nat -L -n";
## 		if(grep /(NAT|MASQ)/, @out)
## 		{
## 		    printf "\n";
## 		    open("cat", "/proc/net/ipsec_eroute");
## 		    foreach(grep /tun0x/, <cat>)
## 		    {      
## 			@eroute=split(' ',$_);
## 			checktunnel $eroute[1], $eroute[3], $eroute[5];
## 		    }
## 		}
## 		else
## 		{
## 		    errchk "1";
## 		}
## 	}
## 	    else
## 	{ 
## 		errchk "OK";
## 	}
##     }
## }
## 
## sub cmdchecks {
##     # check for vital commands
##     printfun "Checking for 'ip' command";
##     run "which ip";
##     errchk "@out";
## 
##     printfun "Checking /bin/sh is not /bin/dash";
##     if (-e "/bin/dash") {
## 	run "cmp /bin/sh /bin/dash";
## 	($dash)=grep(/differ/, @out);
## 	if(!$dash) {
## 		warnchk "", "WARNING";
## 	} else {
## 		errchk "OK";
## 	}
##     } else {
## 		errchk "OK";
##     }
## 
##     printfun "Checking for 'iptables' command";
##     run "which iptables";
##     errchk "@out";
## 
## 
##     open("cat","$conf/ipsec.conf");
##     foreach(grep /crlcheckinterval/,<cat>)
##      {
##       if(!$curlcheckdone) {
##               $curlcheckdone=1;
##               printfun "Checking for 'curl' command for CRL fetching";
##               run "which curl";
##               errchk "@out";
##              }
##      }
## # perhaps check for ip xfrm support, but forget about setkey.
## #    if ( -e "/proc/net/pfkey") {
## #       printfun "Checking for 'setkey' command for NETKEY IPsec stack support";
## #       run "which setkey";
## #       errchk "@out";
## #    }
## }
##     
## sub dnschecks {
##     # Check the running hostname.
##     printf "\nOpportunistic Encryption DNS checks:\n";
##     run "hostname"; 
##     ($hostname)=@out; chomp $hostname;
##     checkdnshost $hostname;
##     
##     # Check all the public IP addresses...
##     run "/sbin/ifconfig -a";
##     foreach (grep /inet addr/,@out)
##     {
## 	$_=~ s/^\s*//;
##         @temp=split(/[:\ ]+/, $_);
## 	push(@address,$temp[2]);
##     }
##     # Purge all non-routeable IPs...
##     @address=grep !/^(127.*|10.*|172.1[6789]+.*.*|172.2+.*.*|172.3[01]+.*.*|192.168.*.*|169.254.*.*)/,@address;
##     printfun "   Does the machine have at least one non-private address?";
##     errchk @address;
##     foreach(@address=grep !$check{$_}++,@address)
##     {
## 	checkdnsip $_;
##     }
## }
## 
## # Main function begins here!
## # Harvest options, ensure they're valid.
## use Getopt::Long;
## %optctl = ("host" => \$hostname,"ip" => \$ip, "colour" => \$colour);
## GetOptions(\%optctl, "host=s" ,"ip=s", "colour!");
## 
## # Exit if we get passed an option we don't recognize.
## if($Getopt::Long::error) { exit 1; }
## 
## 
## # If you've passed --host or --ip, do only those checks.
## if($hostname || $ip)
## {
## # Check this --host for OE.
##     if($hostname)
##     {
## 	printf "Checking $hostname for Opportunistic Encryption:\n";
## 	checkdnshost $hostname;
## 	run "host -t A $hostname";
## 	if(($ipaddr) = grep (/address/i, @out))
## 	{
## 	    $ipaddr=~ s/.*address\ //;
## 	    chomp $ipaddr;
## 	    checkdnsip $ipaddr;
## 	}
## 	else
## 	{
## 	    printf "$hostname does not resolve to an IP, no reverse lookup tests possible.\n";
## 	}
##     }
## # Check this IP for OE.
##     if($ip)
##     {
## 	printf "Checking IP $ip for Opportunistic Encryption:\n";
## 	checkdnsip $ip;
##     }
## }
## else
## {
##     # Call the default routines...
##     # Root check...
##     if($> != "0") 
##     {
## 	print "To check this machine, you need to run \"$me\" as root.\n"; exit;
##     }
##     else
##     {
## 	installstartcheck;
## 	tunnelchecks;
## 	cmdchecks;
## 	run "ipsec addconn --configsetup";
##         ($oe)=grep(/oe=\'yes\'/, @out);
## 	if( $oe) {
## 		dnschecks;
##         	if($print_deprecated)
##         	{
##         	print "
## 
##    RFC 3445 restricts the use of the KEY RR to DNSSEC applications. The use of 
##    a KEY record sub-type for Opporunistic Encryption (OE) has been deprecated.
##    TXT records are used to provide all OE functionality.\n";
##         	}
## 	} else {
## 		printfun "Opportunistic Encryption Support";
## 		warnchk "", "DISABLED";
##         }
##     }
##     # finally, run the config file through the parser checks
##     run "ipsec auto addconn --checkconfig";
## }
## exit $reterr
