#!/usr/bin/perl

# create a file like:
#
#   {alloc,free}  edst spi proto src algo enckey authkey
#
# from pseudo-random data.

$operationCount=0;
$maxOperations=8194;

$proto="esp";
$src="192.1.2.23";
$algo="3des-md5-96";
$enckey="0x4043434545464649494a4a4c4c4f4f515152525454575758";
$authkey="0x87658765876587658765876587658765";


srand(19710421); # keep it pseudo-random, repeatable for now

&init_stuff;

$saCount=0;

@edst=();
@spi=();


while($operationCount < $maxOperations) {
  $operationCount++;

  # pick a random operation.

  $op=rand(4);

  if($op < 1 && $saCount > 0) {
    # generate a free with probability 25%, if there are any to free
    # pick an SA to free.
    
    $sanum=rand($saCount);
    $edst=$edst[$sanum];
    $spi=$spi[$sanum];
    
    #print "free $edst $spi $proto $src\n";
    print "ipsec spi --saref --af inet --edst $edst --spi $spi --proto $proto --del\n";
      
    if($sanum != $saCount-1) {
      # delete it, by copying one from end.
      $edst[$sanum]=$edst[$saCount-1];
      $spi[$sanum]=$spi[$saCount-1];
    }
    $saCount--;
  } else {
    # make a new one.

    $choice=int(rand(100));
    $edst=$edst_choices[$choice];
    $spi="0x".(int(rand(16777216))+1024);

    #print "alloc $edst $spi $proto $src\n";
    print "ipsec spi --saref --af inet --edst $edst --spi $spi --proto $proto --src $src --esp $algo --enckey $enckey --authkey $authkey\n";

    $edst[$saCount]=$edst;
    $spi[$saCount]=$spi;

    $saCount++;
  }
  if($maxSa < $saCount) {
  	$maxSa = $saCount;
  }
  print "echo saCount=$saCount $maxSa\n";
}

print "# maxSa = $maxSa\n";


sub init_stuff {
  # make up 100 random edst's

  for($i=0; $i<100; $i++) {
    $a=int(rand(256)); $b=int(rand(256)); $c=int(rand(256)); $d=int(rand(256));
    $edst_choices[$i]="$a.$b.$c.$d";
  }
}
