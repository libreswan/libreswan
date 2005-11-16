#!/usr/bin/expect --

#
# $Id: Xhost-test.tcl,v 1.18 2005/02/11 01:31:19 mcr Exp $
#

if {! [info exists env(OPENSWANSRCDIR)]} {
    puts stderr "Please point \$OPENSWANSRCDIR to ../testing/utils/"
    exit 24
}

source $env(OPENSWANSRCDIR)/testing/utils/GetOpts.tcl
source $env(OPENSWANSRCDIR)/testing/utils/netjig.tcl

proc usage {} {
    puts stderr "Usage: Xhost-test "
    puts stderr "\t-D                 start up the UML nic so that there is DNS"
    puts stderr "\t-H host=path,host=path start up additional UMLs as specified"
    puts stderr "\t-n <netjigprog>    path to netjig program"
    puts stderr "\t-N <netjigprog>    extra stuff to send to netjig program"
    puts stderr "\t-a                 if netjig should enable --arpreply"
    puts stderr "\t-e <file>          pcap file to play on east network"
    puts stderr "\t-w <file>          pcap file to play on west network"
    puts stderr "\t-E <file>          record east network to file"
    puts stderr "\t-W <file>          record west network to file"
    puts stderr "\t-p <file>          pcap file to play on public network"
    puts stderr "\t-P <file>          record public network to file"
    puts stderr "\t-c <file>          file to send console output to"
    puts stderr "\n"
    puts stderr "The following environment variables are also consulted:\n"
    puts stderr "XHOST_LIST\tcontains a whitespace list of hosts which should be managed"
    puts stderr "\nFor each host, the following variables are examined:"
    puts stderr "\${HOST}_INIT_SCRIPT\tthe script to initialize the host with"
    puts stderr "\${HOST}_RUN_SCRIPT\tthe script to run the host with"
    puts stderr "\${HOST}_FINAL_SCRIPT\tthe script to run the host with"
    puts stderr "\${HOST}_START\tthe program to invoke the UML"
    puts stderr "REF_\${HOST}_CONSOLE_OUTPUT\twhere to redirect the console output to"
    puts stderr "PACKETRATE\tthe rate at which packets will be replayed"
    puts stderr "{NORTH,SOUTH,EAST,WEST}_PLAY denotes a pcap file to play on that network"
    puts stderr "{NORTH,SOUTH,EAST,WEST}_REC  denotes a pcap file to reocrd into from that network"
    exit 22
}

set umlid(neteast,setplay)      0
set umlid(netwest,setplay)      0
set umlid(netpublic,setplay)    0
set umlid(neteast,setrecord)    0
set umlid(netwest,setrecord)    0
set umlid(netpublic,setrecord)  0
set umlid(someplay) 0
set do_dns           0

set timeout 100
log_user 0
if {[info exists env(HOSTTESTDEBUG)]} {
    if {$env(HOSTTESTDEBUG) == "hosttest"} {
	log_user 1
    }
}

netjigdebug "Program invoked with $argv"
set arpreply ""
set umlid(extra_hosts) ""

foreach net $managednets {
    process_net $net
}

while { [ set err [ getopt $argv "D:H:n:N:ae:E:w:W:p:P:" opt optarg]] } {
    if { $err < 0 } then {
	puts stderr "Xhost-test.tcl: $opt and $optarg" 
	usage
    } else {
	#puts stderr "Opt $opt arg: $optarg"

	switch -exact $opt {
	    D {
		process_extra_host "nic=$optarg"
	    }
	    H {
		process_extra_host $optarg
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
		set umlid(neteast,play) $optarg
		set umlid(neteast,setplay) 1
		set umlid(someplay) 1
	    }
	    w {
		set umlid(netwest,play) $optarg
		set umlid(netwest,setplay) 1
		set umlid(someplay) 1
	    }
	    p {
		set umlid(netpublic,play) $optarg
		set umlid(netpublic,setplay) 1
		set umlid(someplay) 1
	    }
	    E {
		set umlid(neteast,record) $optarg
		set umlid(neteast,setrecord) 1
	    }
	    W {
		set umlid(netwest,record) $optarg
		set umlid(netwest,setrecord) 1
	    }
	    P {
		set umlid(netpublic,record) $optarg
		set umlid(netpublic,setrecord) 1
	    }
	}
    }
}

if {! [info exists env(XHOST_LIST)]} {
    puts stderr "You must specify at least one host to manage in \$XHOST_LIST"
    exit 23
}

foreach net $managednets {
    calc_net $net
}

set managed_hosts [split $env(XHOST_LIST) ", "]

foreach host $managed_hosts {
    process_host $host
}

set argv [ lrange $argv $optind end ]

if {! [file executable $netjig_prog]} {
    puts "UML startup must be provided - did you run \"make checkprograms\"?"
    exit
}

netjigdebug "Starting up the netjig for $netjig_prog"

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


netjigsetup $netjig1

foreach net $managednets {
    if { $umlid(net$net,arp) } {
	newswitch $netjig1 "--arpreply $net"
    } {
	newswitch $netjig1 "$net"
    }
}

if {[info exists netjig_extra]} {
    playnjscript $netjig1 $netjig_extra
}

trace variable expect_out(buffer) w log_by_tracing

# start up auxiliary hosts first
foreach host $umlid(extra_hosts) {
    startuml $host
}
foreach host $umlid(extra_hosts) {
    loginuml $host
}
foreach host $umlid(extra_hosts) {
    initdns  $host
}

# now setup regular hosts

foreach host $managed_hosts {
    startuml $host
}

foreach host $managed_hosts {
    loginuml $host
}

# XXX two of the blank lines comes out here.
foreach host $managed_hosts {
    inituml $host
}

foreach net $managednets {
    if {[info exists umlid(net$net,record)] } {
	netjigdebug "Will record network '$net' to $umlid(net$net,record)"
	record $netjig1 $net $umlid(net$net,record)
    }
}

foreach net $managednets {
    if {[info exists umlid(net$net,play)] } {
	netjigdebug "Will play pcap file $umlid(net$net,play) to network '$net'"
	setupplay $netjig1 $net $umlid(net$net,play)
    }
}

# let things settle.
after 500

# do the "run" scripts now.
foreach host $managed_hosts {
    runuml $host
}

# XXX the other blank line comes out during waitplay.
if { $umlid(someplay) == 0 } {
    netjigdebug "WARNING: There are NO PACKET input sources, not waiting for data injection"
} else {
    waitplay $netjig1
}

# run any additional scripts/passes until there are no passes left
set pass 2
set scriptcount 1
while {$scriptcount > 0} {
    set scriptcount 0
    netjigdebug "Attempting script pass $pass for $managed_hosts"
    foreach host $managed_hosts {
	set scriptcount [expr [runXuml $host $pass] + $scriptcount]
    }
    incr pass

    netjigdebug "Asking netjig for any output"
    expect -i $netjig1 -gl "*"
}
    
netjigdebug "Okay, done. Shutting down everything"

after 500
foreach host $managed_hosts {
    send -i $umlid($host,spawnid) "\r"
}

foreach host $managed_hosts {
    expect {
	-i $umlid($host,spawnid) -exact "# " {}
	timeout { 
	    puts "Can not find prompt prior to final script for $host (timeout)"
	    exit;
	}
	eof { 
	    puts "Can not find prompt prior to final script for $host (EOF)"
	    exit;
	}
    }
}

foreach host $managed_hosts {
    netjigdebug "Shutting down $host"
    killuml $host
}
sleep 5

foreach host $umlid(extra_hosts) {
    netjigdebug "Shutting down extra host: $host"
    shutdown $host
}

log_user 1
expect -i $netjig1 -gl "*"
send -i $netjig1 "quit\n"
set timeout 60
expect {
	-i $netjig1
	timeout { puts "expected EOF but got timeout in Xhost-test.tcl" }
	eof
}

# 
# $Log: Xhost-test.tcl,v $
# Revision 1.18  2005/02/11 01:31:19  mcr
# 	added a sleep to permit UMLs to finish and drain.
#
# Revision 1.17  2004/04/03 19:44:52  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.16  2004/03/21 04:36:16  mcr
# 	1) local switches now reads testparams.sh file.
# 	2) $arpreply is totally deprecated.
#
# Revision 1.15  2004/02/15 00:12:00  mcr
# 	--arpreply calculation was failing for situation
# 	where the options were specified as arguments.
# 	split process_net -> process_net/calc_net.
#
# Revision 1.14  2004/02/05 02:14:34  mcr
# 	guess which switches need --arpreply by whether or not they
# 	are getting recorded or not.
#
# Revision 1.13  2004/02/03 20:14:39  mcr
# 	networks are now managed as a list rather than explicitely.
#
# Revision 1.12  2004/02/03 04:46:32  mcr
# 	refactored some code.
# 	added north/south network play/record via environment variables.
#
# Revision 1.11  2003/10/31 02:43:33  mcr
# 	pull up of port-selector tests
#
# Revision 1.10  2003/10/28 03:03:33  dhr
#
# Refine testing scripts:
# - put timeout and eof handlers in each expect script
# - kill more rogue processes: even those with unreadable(!) /proc entries
# - improve reporting of skipped tests
# - make "recordresults" do more, simplifying every caller
# - speed up UML shutdown by using "halt -p -r" (requires many reference log updates)
#
# Revision 1.9.2.1  2003/10/29 02:09:28  mcr
# 	do orderly shutdown of DNS host.
#
# Revision 1.9  2003/08/20 06:37:53  mcr
# 	minor editorial addition to remind people.
#
# Revision 1.8  2003/08/18 16:32:31  mcr
# 	always start northpublic and southpublic switches.
# 	keep running RUNX_SCRIPT files until we find there
# 	are no definitions.
#
# Revision 1.7  2003/04/03 23:42:27  mcr
# 	oops, need to send \n not \r to netjig, now that we open
# 	a plain pipe to it, not a pty.
#
# Revision 1.6  2003/04/03 02:28:00  mcr
# 	wait for the eof, not the literal string "eof"
#
# Revision 1.5  2003/04/02 21:39:05  mcr
# 	quiet down Xhost test with use of netjigdebug.
#
# Revision 1.4  2003/04/02 02:23:15  mcr
# 	added PACKETRATE setting.
#
# Revision 1.3  2003/02/27 09:15:05  mcr
# 	added a second set of "run" targets - they get ran after
# 	the packets, but before shutdown. The lets one gather
# 	stats that may change when pluto shuts down (i.e. Delete
# 	messages will destroy the state one is looking for)
# 	also, made it such that each UML is started, logged
# 	into, and initialized concurrently, as this speeds things up
# 	a bit.
#
# Revision 1.2  2003/02/21 09:14:57  mcr
# 	fixed Xhost-test to use XHOST_LIST rather than XHOST_TESTLIST,
# 	to match the more sensible documentation.
# 	Fixed some substitution problems with variables.
#
# Revision 1.1  2003/02/20 02:33:22  mcr
# 	refactored 2host-test.tcl to be N-host capable.
# 	reworked "umlplutotest" to use Xhost-test.tcl instead
# 	of 2host-test.tcl.
#
#
#
