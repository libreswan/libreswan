#!/usr/bin/perl

$interfaces=$ARGV[0];
$networkscriptdir=$ARGV[1];

open(INTERFACES,"$interfaces") || die "interfaces: $interfaces $!\n";

chdir($networkscriptdir) || die "Can not chdir to $networkscriptdir: $!\n";

$stanza=0;

while(<INTERFACES>) {
  next if (/^\#/);
  chop;

  if($stanza) {
    if(/^\s*address\s*([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)/) {
      print IFCFG "IPADDR=$1\n";
      next;
    } elsif(/^\s*network\s*([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)/) {
      print IFCFG "NETMASK=$1\n";
      next;
    } elsif(/^\s*netmask\s*([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)/) {
      print IFCFG "NETMASK=$1\n";
      next;
    } elsif(/^\s*broadcast\s*([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)/) {
      print IFCFG "BROADCAST=$1\n";
      next;
    } elsif(/^\s*gateway\s*([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*)/) {
      print IFCFG "GATEWAY=$1\n";
      print IFCFG "GATEWAYDEV=$device\n";
    } elsif(/^\s*up\s*route\s*add\s*-(.*)/) {
      open(STATICROUTES, ">>../static-routes") || die "can not open ../static-routes: $!\n";
      print STATICROUTES "$device $1\n";
      close(STATICROUTES);
    } elsif(/iface/) {
      close(IFCFG);
      $stanza=0;
    } elsif(/^$/) {
      close(IFCFG);
      $stanza=0;
      next;
    } else {
      print STDERR "ignoring command $_\n";
    }
  }

  if(!$stanza) {
    #print "Processing $_\n";
    if(/\s*iface (.*) inet static/) {
      $device=$1;
      $stanza=1;
      open(IFCFG, ">ifcfg-$device") || die "Can not open ifcfg-$device: $!\n";
      print IFCFG "ONBOOT=yes\n";
    }
  }
}

      
    

