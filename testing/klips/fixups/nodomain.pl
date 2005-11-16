#!/usr/bin/perl

$\ = "\n";		# automatically add newline on print

LINE:
while (<>) {
    chop;
    #!/bin/sed
    if (/.domain/) {
        $printit = 0;
        next LINE;
    }
    if (/.53/) {
        $printit = 0;
        next LINE;
    }
    if (/^arp/) {
	$printit = 0;
	next LINE;
    } 
}
continue {
    if ($printit)
	{ print; }
    else
	{ $printit++ unless $nflag; }
}
