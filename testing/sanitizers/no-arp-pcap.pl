#!/usr/bin/perl

while(<>) {
	s/icmp([0-9 ]*):/icmp:/;
	s/(.*)echo request seq .* \(DF\)(.*)/\1echo request (DF)\2/;
	s/(.*)echo reply seq .*/\1echo reply/;
	s/\.isakmp/.500/g;

	next if(/^arp who-has/);
	next if(/^arp reply/);

	if (/.domain/) {
	  next;
	}
	if (/.53/) {
	  next;
	}

	print;
}

