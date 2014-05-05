#!/usr/bin/perl
eval 'exec /usr/bin/perl -S $0 ${1+"$@"}'
	if $running_under_some_shell;

while ($ARGV[0] =~ /^-/) {
    $_ = shift;
  last if /^--/;
    if (/^-n/) {
	$nflag++;
	next;
    }
    die "I don't recognize this switch: $_\\n";
}
$printit++ unless $nflag;

$\ = "\n";		# automatically add newline on print

LINE:
while (<>) {
    chop;
    s/(;; WHEN: ... ... .. ..:..:.. ....)/;; WHEN: DATE/;
    s/(;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ).*/${1}12345/;
    s/(\S+\s+)\d+(\s+IN\s+.*)/${1}604800${2}/;
    s/(.*.\t1604800\tIN\tNS\t).*(.uml.freeswan.org.)/$1NSSERVER/;
    s/(.*.\t1604800\tIN\tNS\t).*(.root-servers.net.)/$1NSSERVER/;
    s/(;; Query time: ).*( msec)/${1}25${2}/;
    s/(; <<>> DiG ).*(<<>> .*)/${1}VERSION${2}/;
    s/(;; MSG SIZE  rcvd: ).*/${1}SIZE/;
    print if $printit;
}
