#!/usr/bin/perl

#
# this script sanitizes "ipsec look" output more thoroughly than
# ipsec-look-sanitize. The former is suitable for static conns,
# but dynamic ones come with random ESP SPIs, IVs, and presents the
# data in seemingly random order.
#

# ipsec look
#east:~# ipsec look
#east Fri Nov 29 10:12:14 GMT 2002
#192.0.2.0/24       -> 192.0.1.0/24       => tun0x1002@192.1.2.45 comp0x68dd@192.1.2.45 esp0xa7d8251a@192.1.2.45  (0)
#ipsec0->eth1 mtu=16260(1500)->1500
#comp0x6593@192.1.2.23 COMP_DEFLATE: dir=in  src=192.1.2.45 life(c,s,h)=addtime(6,0,0) refcount=5 ref=8
#comp0x68dd@192.1.2.45 COMP_DEFLATE: dir=out src=192.1.2.23 life(c,s,h)=addtime(2,0,0) refcount=5 ref=16
#esp0xa7d8251a@192.1.2.45 ESP_3DES_HMAC_MD5: dir=out src=192.1.2.23 iv_bits=64bits iv=0x052c73a614bc63c9 ooowin=64 alen=128 aklen=128 eklen=192 life(c,s,h)=addtime(2,0,0) refcount=4 ref=15
#esp0xab6836be@192.1.2.23 ESP_3DES_HMAC_MD5: dir=in  src=192.1.2.45 iv_bits=64bits iv=0x5e8f25aac7be7260 ooowin=64 alen=128 aklen=128 eklen=192 life(c,s,h)=addtime(6,0,0) refcount=4 ref=7
#tun0x1001@192.1.2.23 IPIP: dir=in  src=192.1.2.45 policy=192.0.1.0/24->192.0.2.0/24 flags=0x8<> life(c,s,h)=addtime(6,0,0) refcount=4 ref=9
#tun0x1002@192.1.2.45 IPIP: dir=out src=192.1.2.23 life(c,s,h)=addtime(2,0,0) refcount=4 ref=17
#Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
#0.0.0.0         192.1.2.254     0.0.0.0         UG       40 0          0 eth1
#192.0.1.0       192.1.2.45      255.255.255.0   UG       40 0          0 ipsec0
#192.1.2.0       0.0.0.0         255.255.255.0   U        40 0          0 eth1
#192.1.2.0       0.0.0.0         255.255.255.0   U        40 0          0 ipsec0
#east:~# kill `cat /var/run/klogd.pid`; cat /tmp/klog.log
#
#OR
#ROUTING TABLE

#
# the MSS column of the netstat output seems to change, so we now sanitize
# it to zero.
#

$debug =0;
$inlook=0;

while(<>) {
  # look for "ipsec look" first.

  if($debug) {
    print STDERR "inlook:$inlook ineroute:$ineroute intncfg: $intncfg inspigrp: $inspigrp inroute: $inroute\nProcessing $_\n";
  }

  if(!$inlook && / ipsec look/) {
    $inlook=1;

    # also reset tunnel list.
    @tunnels=();
    @esps=();
    @sa_list=();
    %spigrp=undef;
    %ips=undef;

    # eat the date that is on the next line.
    print;

    $_=<>;
    # east Thu Nov  7 22:22:34 GMT 2002
    s/(.*) ... ... .* ..:..:.. (?:GMT|EDT|EST|EET|CET|UTC) ..../\1 NOW/;

    $ineroute=1;
    $intncfg=0;
    $inspigrp=0;
    $inroute=0;
    print;
    next;

  } elsif(!$inlook) {
    print;
    next;

  } elsif(m/^(east|west|sunrise|sunset|road|nic|north|south|pole|park|beet|carrot)\s\#/) {
    $inlook=0;
    $inroute=0;
    print;
    next;
  }

  ## okay we are in the look itself.

  if($inlook) {
    if($ineroute) {
      # okay, in the eroute display, we have to chop it up, and then any SAs that we see,
      # keeping track of them, so that we can in fact come back and print them in the
      # order which they appeared in the eroute table, rather than the spigrp list.
      # 192.1.2.23/32      -> 192.0.1.3/32       => tun0x1002@192.1.2.45 esp0x515a1ad5@192.1.2.45  (8)
      # 192.1.2.45/32      -> 192.1.2.23/32:3    => tun0x1002@192.1.2.23:6 (10)
      # 1111111111111111111111111111111111111111111 22222-end
      #
      # 2001:db8:1:2::23/128 -> 2001:db8:1:2::45/128 => tun0x1001@2001:db8:1:2::45 esp0x7e46e5a3@2001:db8:1:2::45  (0)	    11111111111111111111111111111111111111111111111 22222-end
      #
      # regexp fills $1-$7 as above
      #
      if((m,^([\d.]+/[\d:]+\s+\-\>\s+[\d.]+/[\d:]+\s+\=\>) (.*)$,) ||
	      (m,^(.*:.*\-\>.*:.*\=\>) (.*)$,)) {
	# okay, rebuild $_ with sanitized versions, and record the order of the
	# tunnels by dest IP $3.
	
	$eroute=$1;
	$group=$2;
	@sas=split(/ /, $group);
	
	if($debug) {
	  print STDERR "ineroute, with $#sas SAs\n";
	}
	
	@new_sa=();
	for $sa (@sas) {
	  print STDERR "Eroute processing SA: $sa\n" if $debug;
	  if($sa =~ m/(tun0x)(.{1,4})@(.*)/) {
	    $fixed_sa=$1."IPIP@".$3;
	    push(@salist, $sa);
	    push(@new_sa, $fixed_sa);
	  }
	  elsif($sa =~ m/(esp0x)(.{1,8})@(.*)/) {
	    $fixed_sa=$1."ESPSPI@".$3;
	    push(@salist, $sa);
	    push(@new_sa, $fixed_sa);
	  }
	  elsif($sa =~ m/(ah0x)(.{1,8})@(.*)/) {
	    $fixed_sa=$1."AHSPI@".$3;
	    push(@salist, $sa);
	    push(@new_sa, $fixed_sa);
	  }
	  elsif($sa =~ m/(comp0x)(.{1,4})@(.*)/) {
	    $fixed_sa=$1."COMPSPI@".$3;
	    push(@salist, $sa);
	    push(@new_sa, $fixed_sa);
	  }
	  elsif($sa =~ m,%trap, ||
		$sa =~ m,%hold, ||
		$sa =~ m,%pass, ||
		$sa =~ m,%reject, ||
		$sa =~ m,%drop,) {
	    push(@new_sa, $sa);
	  }
	  elsif($sa =~ m,\(.*\), || $sa =~ m,\s*,) {
	    print STDERR "Ignoring count $sa\n" if $debug;
	    # ignore trailing count.
	  }
	  else {
	    if($debug) {
	      print STDERR "Unknown SA type |$sa|\n";
	    }
	    push(@new_sa, "UNK:$sa");
	  }
	}
	
	print $eroute." ".join(' ', @new_sa)."\n";
	next;
      } elsif(/^(ipsec.*->eth.* mtu=.*)(\(.*\))(->.*)/) {
	$ineroute=0;
	$intncfg=1;
	print $1."(9999)".$3."\n";
	next;
      } else {
	print;
	next;
      }
    }

    if($intncfg) {
      if(/^ipsec.*->eth.* mtu=.*(.*)->.*/) {
	print;
	next;
      }

      $intncfg=0;
      $inspigrp=1;
      # fall through
    }

    if($inspigrp) {
      # suck up all of the spigrp entries, and sanitize them and emit them in
      # the order that we recorded above, and order in, then out.
      # esp0x515a1ad5@192.1.2.45 ESP_3DES_HMAC_MD5: dir=out src=192.1.2.23 iv_bits=64bits iv=0x64c818022e5c1fa9 ooowin=64 seq=8 alen=128 aklen=128 eklen=192 life(c,s,h)=bytes(1088,0,0)addtime(26,0,0)usetime(26,0,0)packets(8,0,0) idle=13 refcount=4 ref=15
      # 1111122222222 3333333333 444-end.
      #
      # note that other sanitizing is applied to $4.
      if(m,^(esp0x)([0-9a-f]{1\,8})@([\d.]+)( ESP_.*),) {
	
	$rest = $4;
	$esp1   = $1;
	$spinum = $2;
	$spiip  = $3;
	
	$rest = &sanitize_sadata($rest);
	
	$key=$esp1.$spinum."@".$spiip;
	$espline=$esp1."SPISPI@".$spiip.$rest;
	$xname="esp";
	
	&sourcerecord($rest,$key,$xname);
	
	#print "remembering that $key -> $espline\n";
	$spigrp{$key}=$espline;
      }
      elsif(m,^(ah0x)([0-9a-f]{1\,8})@([\d.]+)( AH_.*),) {
	
	$rest = $4;
	$ah1   = $1;
	$spinum = $2;
	$spiip  = $3;
	
	$rest = &sanitize_sadata($rest);
	
	$key=$ah1.$spinum."@".$spiip;
	$ahline=$ah1."SPISPI@".$spiip.$rest;
	$xname="ah";
	
	&sourcerecord($rest,$key,"ah");
	
	#print "remembering that $key -> $ahline\n";
	$spigrp{$key}=$ahline;
      }
      # tun0x1002@192.1.2.45 IPIP: dir=out src=192.1.2.23 life(c,s,h)=bytes(832,0,0)addtime(26,0,0)usetime(26,0,0)packets(8,0,0) idle=13 refcount=4 ref=16
      # 111112222 3333333333 44444444444444444444444444

      elsif(m,^(tun0x)([0-9a-f]{1\,8})@([\d.]+)( IPIP:.*),) {
	$rest = $4;
	$tun1 = $1;
	$spinum = $2;
	$spiip  = $3;
	
	$rest = &sanitize_sadata($rest);
	
	$key=$tun1.$spinum."@".$spiip;
	$tunline=$tun1."TUN#@".$spiip.$rest;
	$xname="tun";
	
	&sourcerecord($rest,$key,$xname);
	
	#print "remembering that $key -> $tunline\n";
	$spigrp{$key}=$tunline;
      }

      # comp0x68dd@192.1.2.45 COMP_DEFLATE: dir=out src=192.1.2.23 life(c,s,h)=addtime(2,0,0) refcount=5 ref=16
      # 1111112222 3333333333 4444444-end

      elsif(m,^(comp0x)([0-9a-f]{1\,4})@([\d.]+)( COMP_.*:.*),) {
	$rest = $4;
	$comp = $1;
	$spinum = $2;
	$spiip  = $3;
	
	$rest = &sanitize_sadata($rest);
	
	$key=$comp.$spinum."@".$spiip;
	$compline=$comp."COMP#@".$spiip.$rest;
	$xname="comp";
	
	&sourcerecord($rest,$key,$xname);
	
	#print "remembering that $key -> $compline\n";
	$spigrp{$key}=$compline;
      }

      elsif(/^ROUTING TABLE/ || /^Destination/ || ($inspigrp && /^$/)) {
	$inspigrp=0;
	$inroute=1;
	
	# dump the esp/spi table.
	
	#print "Dumping out groups:\n";
	foreach $sa (@salist) {
	  #print "SA: $sa\n";
	  print $spigrp{$sa}."\n";
	}
	
	#print "Dumping in groups:\n";
	foreach $ip (sort keys %ips) {
	  foreach $type ("esp","ah","comp","tun") {
	    #print "KEY: ".$ip.$type;
	    if(defined($bysource{$ip.$type})) {
	      $sa=$bysource{$ip.$type};
	      #print "-> $sa";
	      if(defined($spigrp{$sa})) {
		print $spigrp{$sa}."\n";
	      }
	    }
	    #print "\n";
	  }
	}
	
      }
    }

    if($inroute) {
      #Destination Gateway         Genmask         Flags   MSS Window  irtt Iface
      #0.0.0.0     192.1.2.254     0.0.0.0         UG       40 0          0 eth1
      s/^((?:(?:\d+\.){3}\d+\s+){3}\S+\s+)([\s\d]\d)(\s+\d+\s+\d+\s+\S+)/${1}99${3}/;
      #      =============== dotted quad IP address
      #   ========================= three of them, each followed by whitespace
      #                            === Flags
      #                                    ======== MSS
      print;
    }
  }
}

sub sourcerecord {
  local($rest,$key,$xname)=@_;

  if($rest =~ m,dir=in,) {
    if($rest =~ m/src=(\d+\.\d+\.\d+\.\d+)/) {
      $srcip=$1;
      $bysource{$srcip.$xname}=$key;
    }

    $ips{$srcip}++;
  }
}


sub sanitize_sadata {
  local($rest)=@_;

  $rest =~ s/iv=0x[0-9a-f]{32}/iv=0xIVISFORRANDOM000IVISFORRANDOM000/;
  $rest =~ s/iv=0x[0-9a-f]{16}/iv=0xIVISFORRANDOM000/;

  $rest =~ s/jiffies=[0-9a-f]{10}/jiffies=0123456789/;

  $rest =~ s/addtime\(.*,.*,.*\)//;
  $rest =~ s/usetime\(.*,.*,.*\)//;
  $rest =~ s/bytes\(.*\)//;
  $rest =~ s/life\(c,s,h\)= //g;

  $rest =~ s/bit=\S*//g;
  $rest =~ s/idle=\S*//g;
  $rest =~ s/refcount=\S*//g;
  $rest =~ s/ref=\S*//g;
  $rest =~ s/seq=\S*//g;
  $rest =~ s/ratio=\S*//g;

  $rest;
}

