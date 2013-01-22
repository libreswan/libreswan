#!/usr/bin/perl

$TESTNAME=$ENV{'TESTNAME'};

@klips_out=();

while(<>) {
  s/^\[root@((east|west|sunrise|sunset|road|nic|north|south|pole|park|beet|carrot)) $TESTNAME\]\#/\1 \#\n/;
  s/\n \[root@((east|west|sunrise|sunset|road|nic|north|south|pole|park|beet|carrot) $TESTNAME\]\#)/\1\n/;
  # next two are old uml days
  s/^((east|west|sunrise|sunset|road|nic|north|south|pole|park|beet|carrot):\~\#)/\1\n/;
  s/\n ((east|west|sunrise|sunset|road|nic|north|south|pole|park|beet|carrot):\~\#)/\n\1\n/g;
  if(/^\s*klips_debug:/) {
    push(@klips_out, $_);
  } elsif(/^\<\d\>(klips_debug:.*)/) {
    push(@klips_out, "$1\n");
  } elsif(/^\<\d\>.*/) {
    next;
  } else {
    print;
  }
}

foreach $klips (@klips_out) {
  print $klips;
}

