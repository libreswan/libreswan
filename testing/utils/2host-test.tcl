#!/usr/bin/expect --

#
# $Id: 2host-test.tcl,v 1.22 2004/04/03 19:44:52 ken Exp $
#

if {! [info exists env(OPENSWANSRCDIR)]} {
    puts stderr "Please point \$OPENSWANSRCDIR to ../testing/utils/"
    exit 24
}

source $env(OPENSWANSRCDIR)/testing/utils/GetOpts.tcl
source $env(OPENSWANSRCDIR)/testing/utils/netjig.tcl

proc usage {} {
    puts stderr "Usage: 2host-test "
    puts stderr "\t-i <script>        script to initialize UML east"
    puts stderr "\t-r <script>        script to run UML east"
    puts stderr "\t-f <script>        script to finalize UML east"
    puts stderr "\t-I <script>        script to initialize UML west"
    puts stderr "\t-R <script>        script to run UML west"
    puts stderr "\t-F <script>        script to finalize UML west"
    puts stderr "\t-D                 start up the UML nic so that there is DNS"
    puts stderr "\t-H host=path,host=path start up additional UMLs as specified"
    puts stderr "\t-n <netjigprog>    path to netjig program"
    puts stderr "\t-N <netjigprog>    extra stuff to send to netjig program"
    puts stderr "\t-a                 if netjig should enable --arpreply"
    puts stderr "\t-c <file>          where to record east console"
    puts stderr "\t-C <file>          where to record west console"
    puts stderr "\t-e <file>          pcap file to play on east network"
    puts stderr "\t-w <file>          pcap file to play on west network"
    puts stderr "\t-E <file>          record east network to file"
    puts stderr "\t-W <file>          record west network to file"
    puts stderr "\t-p <file>          pcap file to play on public network"
    puts stderr "\t-P <file>          record public network to file"
    puts stderr "\t-u <uml>           User Mode Linux program to start for east"
    puts stderr "\t-U <uml>           User Mode Linux program to start for west"
    puts stderr "\t-c <file>          file to send console output to"
    exit 22
}

set do_playeast      0
set do_playwest      0
set do_playpublic    0
set do_recordeast    0
set do_recordwest    0
set do_recordpublic  0
set do_dns           0
set timeout 100
log_user 0
if {[info exists env(HOSTTESTDEBUG)]} {
    if {$env(HOSTTESTDEBUG) == "hosttest"} {
	log_user 1
    }
}

puts "Program invoked with $argv"
set arpreply ""
set umlid(extra_hosts) ""

while { [ set err [ getopt $argv "c:C:D:f:F:H:i:I:n:N:ae:E:w:W:p:P:r:R:u:U:" opt optarg]] } {
    if { $err < 0 } then {
	puts stderr "$argv0: $opt and $optarg" 
	usage
    } else {
	#puts stderr "Opt $opt arg: $optarg"

	switch -exact $opt {
	    c {
		set umlid(east,consolefile) $optarg
	    }
	    C {
		set umlid(west,consolefile) $optarg
	    }
	    D {
		process_extra_host "nic=$optarg"
	    }
	    u {
		set umlid(east,program) $optarg
	    }
	    U {
		set umlid(west,program) $optarg
	    }
	    f {
		set umlid(east,finalscript) $optarg
	    }
	    F {
		set umlid(west,finalscript) $optarg
	    }
	    r {
		set umlid(east,runscript) $optarg
	    }
	    R {
		set umlid(west,runscript) $optarg
	    }
	    H {
		process_extra_host $optarg
	    }
	    i {
		set umlid(east,initscript) $optarg
	    }
	    I {
		set umlid(west,initscript) $optarg
	    }
	    n {
		set netjig_prog $optarg
	    }
	    N {
		set netjig_extra $optarg
	    }
	    a {
		set arpreply "--arpreply"
	    }
	    e {
		set playeast $optarg
		set do_playeast 1
	    }
	    w {
		set playwest $optarg
		set do_playwest 1
	    }
	    p {
		set playpublic $optarg
		set do_playpublic 1
	    }
	    E {
		set recordeast $optarg
		set do_recordeast 1
	    }
	    W {
		set recordwest $optarg
		set do_recordwest 1
	    }
	    P {
		set recordpublic $optarg
		set do_recordpublic 1
	    }
	}
    }
}

set argv [ lrange $argv $optind end ]

if {! [file executable $netjig_prog]} {
    puts "UML startup must be provided"
    exit
}

puts "Starting up the netjig for $netjig_prog"

# we start up netjig_prog with a plain pipe, so that
# stderr from it will go to our stderr.
set debugjig ""

if {[info exists env(NETJIGTESTDEBUG)]} {
    if {$env(NETJIGTESTDEBUG) == "netjig"} {
	set debugjig "--debug"
    }
}

spawn -noecho -open [open "|$netjig_prog --cmdproto $debugjig 2>@stderr" w+]
set netjig1 $spawn_id

newswitch $netjig1 "$arpreply east"
newswitch $netjig1 "public"
newswitch $netjig1 "$arpreply west"

if {[info exists netjig_extra]} {
    playnjscript $netjig1 $netjig_extra
}

trace variable expect_out(buffer) w log_by_tracing

# start up auxiliary hosts first
foreach host $umlid(extra_hosts) {
    startuml $host
    loginuml $host
    initdns  $host
}


startuml east 
startuml west

loginuml east
loginuml west

inituml east
inituml west

if { $do_recordeast == 1 } {
    record $netjig1 east $recordeast
}

if { $do_recordwest == 1 } {
    record $netjig1 west $recordwest
}

if { $do_recordpublic == 1 } {
    record $netjig1 public $recordpublic
}

if { $do_playeast == 1 } {
    setupplay $netjig1 east $playeast
}

if { $do_playwest == 1 } {
    setupplay $netjig1 west $playwest
}

if { $do_playpublic == 1 } {
    setupplay $netjig1 public $playpublic
}

# let things settle.
after 500

# do the "run" scripts now.
runuml east
runuml west

if { $do_playeast == 0 && $do_playwest == 0 && $do_playpublic == 0 } {
    puts "WARNING: There are NO PACKET input sources, not waiting for data injection"
} else {
    waitplay $netjig1
}

puts "Asking netjig for any output"
expect -i $netjig1 -gl "*"

puts "Okay, shutting down everything"

after 500
send -i $umlid(east,spawnid) "\r"
send -i $umlid(west,spawnid) "\r"

expect {
    -i $umlid(east,spawnid) -exact "# " {}
    timeout { 
	puts "Can not find east's prompt prior to final script (timeout)"
	exit;
    }
    eof { 
	puts "Can not find east's prompt prior to final script (EOF)"
	exit;
    }
}

expect {
    -i $umlid(west,spawnid) -exact "# " {}
    timeout { 
	puts "Can not find west's prompt prior to final script (timeout)"
	exit;
    }
    eof { 
	puts "Can not find west's prompt prior to final script (EOF)"
	exit;
    }
}

puts "Shutting down east"
killuml east

puts "Shutting down west"
killuml west

foreach host $umlid(extra_hosts) {
    puts "Shutting down extra host: $host"
    killdns $host
}

send -i $netjig1 "quit\r"
send -i $netjig1 "quit\r"
set timeout 60
expect {
	-i $netjig1
	-gl eof	{}
	-gl timeout	{ puts "timeout while awaiting EOF" }
}

# 
# $Log: 2host-test.tcl,v $
# Revision 1.22  2004/04/03 19:44:52  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.21  2003/10/28 03:03:33  dhr
#
# Refine testing scripts:
# - put timeout and eof handlers in each expect script
# - kill more rogue processes: even those with unreadable(!) /proc entries
# - improve reporting of skipped tests
# - make "recordresults" do more, simplifying every caller
# - speed up UML shutdown by using "halt -p -r" (requires many reference log updates)
#
# Revision 1.20  2003/02/20 02:33:22  mcr
# 	refactored 2host-test.tcl to be N-host capable.
# 	reworked "umlplutotest" to use Xhost-test.tcl instead
# 	of 2host-test.tcl.
#
# Revision 1.19  2002/11/08 01:26:15  mcr
# 	clarified warning when there is no packet files to play.
# 	added some more play-by-play when shutting down.
#
# Revision 1.18  2002/11/02 23:03:02  mcr
# 	use new "killdns" function to stop extra hosts.
# 	do not attempt to load module, etc. on extra hosts.
#
# Revision 1.17  2002/11/01 21:19:01  mcr
# 	loginuml in kill loop was a cut&paste error.
#
# Revision 1.16  2002/11/01 09:00:07  rgb
# Disable extraneous "loginuml" immediately after "killuml" for extra
# hosts.
#
# Revision 1.15  2002/11/01 04:17:45  mcr
# 	make sure to initialize umlid(extra_hosts), for the cases
# 	when there are no ADDITIONAL_HOSTS.
#
# Revision 1.14  2002/11/01 02:28:02  mcr
# 	added -H option to *host-test.tcl so give list of additional
# 	hosts that should be started. This is in the form of
# 	host=program,host=program.
# 	Fixed up -D (use DNS) option to instead use the additional
# 	host mechanism.
#
# 	Added "ADDITIONAL_HOSTS" variable to provide a list of
# 	additional hosts that should be started for a given test.
#
# Revision 1.13  2002/10/31 18:51:36  mcr
# 	renamed old "runuml" to "waitplay".
# 	made new function "runuml" which runs a script after
# 	the init, but before the packets start to flow.
# 	There are new variables RUN_{EAST,WEST}_SCRIPT.
#
# Revision 1.12  2002/10/31 17:48:10  mcr
# 	complain, but otherwise work, if there are no input
# 	sources defined.
#
# Revision 1.11  2002/10/31 08:07:55  rgb
# Fixed public record argument option letter bug.
#
# Revision 1.10  2002/10/23 20:39:47  rgb
# Added Vars to specify input and output files for public network to umlplutotest().
#
# Revision 1.9  2002/09/30 18:57:57  mcr
# 	add option "NEED_DNS=true" to start up "nic" UML
# 	for single and 2-host tests. Enabled for "ctltest" only
# 	for now for dns testing.
#
# Revision 1.8  2002/09/13 19:32:07  mcr
# 	kill NIC UML only if it was started.
#
# Revision 1.7  2002/09/09 21:40:57  mcr
# 	optional -D starts up "nic" UML as well to get DNS.
#
# Revision 1.6  2002/09/02 15:49:27  mcr
# 	set default timeout to 100 seconds.
#
# Revision 1.5  2002/08/26 03:15:23  mcr
# 	use "killuml" function only - it now plays the finalscript,
# 	if there is one.
#
# Revision 1.4  2002/07/23 17:01:32  mcr
# 	added RCS ids
#
#
