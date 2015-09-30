#!/usr/bin/perl

# this script verifies that there is at least 1, and at most 8 ICMP
# messages in the file. The ICMP messages will typically not be consistent
# due to ICMP rate limiting.

# note that we keep track of things on a per destination basis.

%count=undef;

while(<>) {
  chomp;

  #  192.0.2.254 > 192.0.2.1: icmp: host 192.0.1.1 unreachable - admin prohibited filter [tos 0xc0]


  if(/(.*) \> (.*)\: icmp: .* .* unreachable/) {
    $from=$1;
    $to=$2;

    $message{$to}=$_;
    $count{$to}++;

    #print "Processed $_\n";
  } else {
    print $_."\n";
  }
}

foreach $to (keys %count) {

  next if($to eq "");
  if($count{$to} >= 1 &&
     $count{$to} <= 8) {
    print $message{$to}."  <=> 1-8\n";
  } else {
    print $message{$to}."  FOUND ".$count{$to}." TIMES\n";
  }
}

