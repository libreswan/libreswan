#!/usr/bin/perl

$rawconsole=1;

while(<>) {
  if(!/^PROC_DONE/ && /^PROC-(.*)/) {
    $rawconsole=0;
  }

  if($rawconsole) {
    print;
    next;
  }

  # if we are changing files, then note it.
  if(/^PROC-(.*)/) {
    $pass=$1;
    next;
  }

  # ignore the header
  next if(/total:/);
  if(/^PROC_DONE/) {
    $rawconsole=1;
    next;
  }

  ($thing, $value, $unit) = split;

  # so the key will be something like: "proc_meminfo-no-ipsec-mod-3-MemFree:"
  $values{"$pass $thing"}=$value;
}

foreach $loaded ("no-", "")
{

  # base values are those that occured from proc_meminfo-.*ipsec-mod-.*1
  $base="/tmp/proc_meminfo-" . $loaded . "ipsec-mod-01";

  print "MEMINFO: " . $loaded . " ipsec module loaded (KLIPS) base is $base\n";
  print "MEMINFO:		Free	Shared	Buffers	Cached	Active	Inactive\n";
  #print "BASE:value	";
    #print sprintf("	%d", $values{$base . " MemFree:"});
    #print sprintf("	%d", $values{$base . " MemShared:"});
    #print sprintf("	%d", $values{$base . " Buffers:"});
    #print sprintf("	%d", $values{$base . " Cached:"});
    #print sprintf("	%d", $values{$base . " Active:"});
    #print sprintf("	%d", $values{$base . " Inactive:"});
    #print "\n";

  for($pass=2; $pass <= 5; $pass++)
  #for($pass=2; $pass <= $ENV{"$MOD_LOAD_ITERATIONS"}; $pass++)
  {
    $passbase="/tmp/proc_meminfo-" . $loaded . "ipsec-mod-" . sprintf("%02d",$pass);

    #print "PASSBASE:	" .  $passbase . "\n";
    print sprintf("PASS-%02d:diff	", $pass);
    print sprintf("	%d", $values{$passbase . " MemFree:"} - $values{$base . " MemFree:"});
    print sprintf("	%d", $values{$passbase . " MemShared:"} - $values{$base . " MemShared:"});
    print sprintf("	%d", $values{$passbase . " Buffers:"} - $values{$base . " Buffers:"});
    print sprintf("	%d", $values{$passbase . " Cached:"} - $values{$base . " Cached:"});
    print sprintf("	%d", $values{$passbase . " Active:"} - $values{$base . " Active:"});
    print sprintf("	%d", $values{$passbase . " Inactive:"} - $values{$base . " Inactive:"});
    print "\n";
  }

}

#foreach $key (keys %values) {
  #print "KEY $key is ".$values{$key}."\n";
#}

