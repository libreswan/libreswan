#!/usr/bin/perl

$OPENSWANSRCDIR=$ENV{'OPENSWANSRCDIR'};

if ( ! -f "${OPENSWANSRCDIR}/Makefile.ver" ) {
  print STDERR "NUKEversion.pl can not determine version number, \n";
  print STDERR "\t${OPENSWANSRCDIR}/Makefile.ver can not be found\n";
  print STDERR "Perhaps OPENSWANSRCDIR=$OPENSWANSRCDIR is wrong?\n";
  exit 1;
}

open(VERSION, "${OPENSWANSRCDIR}/Makefile.ver") ||
  die "Can not open ${OPENSWANSRCDIR}/Makefile.ver\n";

$version=undef;
while(<VERSION>) {
  next if /^\#/;
  if(/^IPSECVERSION=(.*)/) {
    $version=$1;
    last;
  }
}
close(VERSION);
if(!defined($version)) {
  die "nukeversion.pl: Makefile.ver did not have version string defined!\nPerhaps OPENSWANSRCDIR=$OPENSWANSRCDIR is wrong?\n";
}

# now process the file looking for the version string.
while(<>) {
  s/$version/VERSION/g;
  print;
}


