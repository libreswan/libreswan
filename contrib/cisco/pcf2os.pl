#!/usr/bin/perl
#
# (C) 2004 Ken Bantoft <ken@xelerance.com>
#
# This script converts most Cisco VPN client .pcf files to Openswan's
# ipsec.conf and ipsec.secrets format
#

die "Usage: ./pcf2os.pl cisco-config.pcf\n\n"  if ! $ARGV[0];

open(PCF,$ARGV[0]);
while(<PCF>) {
	chop;
# print "[$_]";
	if (m/^description/i) {
	s/.*=//;
	s/\ /\_/g;
	$desc=$_;
}
if  (m/^host/i) {
	s/.*=//;
	$right=$_;
}

if (m/^groupname/i) {
	s/.*=//;
	$groupname=$_;
}	

if (m/^grouppwd/i) {
	s/.*=//;
	$grouppassword=$_;
}	



}
close(PCF);

print "ipsec.conf\n\n";
print "conn $desc\n";
print "     ike=3des-md5-modp1024\n";
print "     aggrmode=yes\n";
print "     authby=secret\n";
print "     left=%defaultroute\n";
print "     leftid=\@$groupname\n";
print "     leftxauthclient=yes\n";
print "     leftmodecfgclient=yes\n";
print "     right=$right\n";
print "     rightxauthserver=yes\n";
print "     rightmodecfgserver=yes\n";
print "     pfs=no\n";
print "     auto=add\n";

print "\n\n";
print "ipsec.secrets:\n\n";
print "\@$groupname $right : PSK \"$grouppassword\"\n";

