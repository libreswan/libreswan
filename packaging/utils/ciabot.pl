#!/usr/bin/perl -w
#
# ciabot -- Mail a git log message to a given address, for the purposes of CIA
#
# Loosely based on cvslog by Russ Allbery <rra@stanford.edu>
# Copyright 1998  Board of Trustees, Leland Stanford Jr. University
#
# Copyright 2001, 2003, 2004, 2005  Petr Baudis <pasky@ucw.cz>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2, as published by the
# Free Software Foundation.
#
# The master location of this file is in the Cogito repository
# (see http://www.kernel.org/git/).
#
# This program is designed to run as the .git/commit-post-hook script. It takes
# the commit information, massaging it and mailing it to the address given below.
#
# The calling convention of the commit-post-hook script is:
#
#	commit-post-hook $commit_sha1 $branch_name
#
# If it does not work, try to disable $xml_rpc in the configuration section
# below.
#
#
# Note that you can (and it might be actually more desirable) also use this
# script as the GIT update hook:
#
#	refname=${1#refs/heads/}
#	[ "$refname" = "master" ] && refname=
#	oldhead=$2
#	newhead=$3
#	for merged in $(git-rev-list $newhead ^$oldhead | tac); do
#		/path/to/ciabot.pl $merged $refname
#	done
#
# This is useful when you use a remote repository without working copy, where
# you only push to - the update hook will be triggered each time you push into
# that repository, and the pushed commits will be reported through CIA.

use strict;
use vars qw ($project $from_email $dest_email $noisy $rpc_uri $sendmail
		$xml_rpc $ignore_regexp $alt_local_message_target);




### Configuration

# Project name (as known to CIA).
$project = 'Libreswan';

# The from address in generated mails.
$from_email = 'commits@libreswan.org';

# Mail all reports to this address.
$dest_email = 'nightly@lists.libreswan.org';

# If using XML-RPC, connect to this URI.
$rpc_uri = 'http://cia.vc/xmlrpc.php'

# Path to your USCD sendmail compatible binary (your mailer daemon created this
# program somewhere).
$sendmail = '/usr/sbin/sendmail';

# If set, the script will send CIA the full commit message. If unset, only the
# first line of the commit message will be sent.
$noisy = 1;

# This script can communicate with CIA either by mail or by an XML-RPC
# interface. The XML-RPC interface is faster and more efficient, however you
# need to have RPC::XML perl module installed, and some large CVS hosting sites
# (like Savannah or Sourceforge) might not allow outgoing HTTP connections
# while they allow outgoing mail. Also, this script will hang and eventually
# not deliver the event at all if CIA server happens to be down, which is
# unfortunately not an uncommon condition.
$xml_rpc = 0;

# You can make this bot to totally ignore events concerning the objects
# specified below. Each object is composed of <path>/<filename>,
#
# This variable should contain regexp, against which will each object be
# checked, and if the regexp is matched, the file is ignored. Therefore ie.  to
# ignore all changes in the two files above and everything concerning module
# 'admin', use:
#
# $ignore_regexp = "^(gentoo/Manifest|elinks/src/bfu/inphist.c|admin/)";
$ignore_regexp = "";

# It can be useful to also grab the generated XML message by some other
# programs and ie. autogenerate some content based on it. Here you can specify
# a file to which it will be appended.
$alt_local_message_target = "";




### The code itself

use vars qw ($commit $tree @parent $author $committer);
use vars qw ($user $branch $rev @files $logmsg $message);
my $line;



### Input data loading


# The commit stuff
$commit = $ARGV[0];
$branch = $ARGV[1];

open COMMIT, "git-cat-file commit $commit|" or die "git-cat-file commit $commit: $!";
my $state = 0;
$logmsg = '';
while (defined ($line = <COMMIT>)) {
  if ($state == 1) {
    $logmsg .= $line;
    $noisy or $state++;
    next;
  } elsif ($state > 1) {
    next;
  }

  chomp $line;
  unless ($line) {
    $state = 1;
    next;
  }

  my ($key, $value) = split(/ /, $line, 2);
  if ($key eq 'tree') {
    $tree = $value;
  } elsif ($key eq 'parent') {
    push(@parent, $value);
  } elsif ($key eq 'author') {
    $author = $value;
  } elsif ($key eq 'committer') {
    $committer = $value;
  }
}
close COMMIT;


open DIFF, "git-diff-tree -r $parent[0] $tree|" or die "git-diff-tree $parent[0] $tree: $!";
while (defined ($line = <DIFF>)) {
  chomp $line;
  my @f;
  (undef, @f) = split(/\t/, $line, 2);
  push (@files, @f);
}
close DIFF;


# Figure out who is doing the update.
# XXX: Too trivial this way?
($user) = $author =~ /<(.*?)@/;


$rev = substr($commit, 0, 12);




### Remove to-be-ignored files

@files = grep { $_ !~ m/$ignore_regexp/; } @files
  if ($ignore_regexp);
exit unless @files;



### Compose the mail message


my ($VERSION) = '1.0';
my $ts = time;

$message = <<EM
<message>
   <generator>
       <name>CIA Perl client for Git</name>
       <version>$VERSION</version>
   </generator>
   <source>
       <project>$project</project>
EM
;
$message .= "       <branch>$branch</branch>" if ($branch);
$message .= <<EM
   </source>
   <timestamp>
       $ts
   </timestamp>
   <body>
       <commit>
           <author>$user</author>
           <revision>$rev</revision>
           <files>
EM
;

foreach (@files) {
  s/&/&amp;/g;
  s/</&lt;/g;
  s/>/&gt;/g;
  $message .= "  <file>$_</file>\n";
}

$logmsg =~ s/&/&amp;/g;
$logmsg =~ s/</&lt;/g;
$logmsg =~ s/>/&gt;/g;

$message .= <<EM
           </files>
           <log>
$logmsg
           </log>
       </commit>
   </body>
</message>
EM
;



### Write the message to an alt-target

if ($alt_local_message_target and open (ALT, ">>$alt_local_message_target")) {
  print ALT $message;
  close ALT;
}



### Send out the XML-RPC message


if ($xml_rpc) {
  # We gotta be careful from now on. We silence all the warnings because
  # RPC::XML code is crappy and works with undefs etc.
  $^W = 0;
  $RPC::XML::ERROR if (0); # silence perl's compile-time warning

  require RPC::XML;
  require RPC::XML::Client;

  my $rpc_client = new RPC::XML::Client $rpc_uri;
  my $rpc_request = RPC::XML::request->new('hub.deliver', $message);
  my $rpc_response = $rpc_client->send_request($rpc_request);

  unless (ref $rpc_response) {
    die "XML-RPC Error: $RPC::XML::ERROR\n";
  }
  exit;
}



### Send out the mail


# Open our mail program

open (MAIL, "| $sendmail -t -oi -oem") or die "Cannot execute $sendmail : " . ($?>>8);


# The mail header

print MAIL <<EOM;
From: $from_email
To: $dest_email
Content-type: text/xml
Subject: DeliverXML

EOM

print MAIL $message;


# Close the mail

close MAIL;
die "$0: sendmail exit status " . ($? >> 8) . "\n" unless ($? == 0);

# vi: set sw=2:
